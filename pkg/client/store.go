package client

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The account store: plain files, no database.
//
// # Why not SQLite
//
// It was SQLite first. The pure-Go driver cannot run on android/amd64 at all --
// its libc emulation calls the lstat syscall, Android's seccomp filter kills
// the process, and the app died at startup on every x86_64 device and emulator.
// Every other pure-Go driver is that one underneath. The cgo driver works but
// makes cgo mandatory for every consumer of this package, which a planned
// Flutter desktop client turns from an inconvenience into a cross-compilation
// matrix. Either way it cost the shipped core 7-9 MB, and no query was ever
// needed to justify it -- see docs/design/23-shared-client-core.md.
//
// # The rule this store exists to keep
//
// The old Dart store rewrote one JSON file in full on every single message.
// That is the defect being fixed, and replacing it with per-chat files rewritten
// in full would be the same defect with more filenames. So:
//
//   - Anything written per message is either an append, or a replacement of a
//     file whose size does not grow with history.
//   - Anything that grows with history is append-only, and compacted rarely --
//     on a threshold, never on the write path.
//
// Concretely: a transcript is an append-only log and a new message costs one
// line. A ratchet session is its own small file, so advancing it rewrites that
// session and nothing else. The identity is one small file that changes only at
// setup and prekey top-up.
//
// # Crash safety
//
// Small files are written to a temporary name and renamed into place, which is
// atomic: a reader sees the old file or the new one, never a half-written one.
// That is the same pattern the app's own state file has used since it existed,
// and its trouble was never corruption -- it was the rewriting.
//
// Logs are appended and synced. A torn append costs the last record, which the
// reader skips as malformed; it cannot damage what came before.

// storeFormat is written into the account directory so a future change of
// layout can recognise what it is looking at. Not a migration framework: there
// is nothing deployed to migrate from, and one number beats a system nobody
// needs yet.
const storeFormat = "freizone-client-store-v1\n"

// store is one account's directory.
type store struct {
	root string
}

func openStore(root string) (*store, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("client: creating account directory: %w", err)
	}

	marker := filepath.Join(root, "format")
	switch existing, err := os.ReadFile(marker); {
	case errors.Is(err, os.ErrNotExist):
		if err := writeFileAtomic(marker, []byte(storeFormat)); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("client: reading store format: %w", err)
	case string(existing) != storeFormat:
		return nil, fmt.Errorf("client: account directory %s holds %q, not %q",
			root, strings.TrimSpace(string(existing)), strings.TrimSpace(storeFormat))
	}

	return &store{root: root}, nil
}

// path builds a path inside the store, rejecting any element that could escape
// it. Ids reaching here are account and chat ids -- bech32m, so alphanumeric --
// but they arrive from the wire, and a store that trusts them is a store that
// can be told to write anywhere.
func (s *store) path(elems ...string) (string, error) {
	for _, e := range elems {
		if err := safeElement(e); err != nil {
			return "", err
		}
	}
	return filepath.Join(append([]string{s.root}, elems...)...), nil
}

// safeElement is that check on its own, for the stores that do not live under
// this root -- media, which the caller may point anywhere (see media.go). The
// rule has to be the same in both places, so it is written once.
func safeElement(e string) error {
	if e == "" || e == "." || e == ".." || strings.ContainsAny(e, `/\`) {
		return fmt.Errorf("client: refusing unsafe path element %q", e)
	}
	return nil
}

// --- small whole-value files ------------------------------------------------

// readJSON decodes a small file, reporting found=false when there is none.
func readJSON(path string, out any) (found bool, err error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("client: reading %s: %w", filepath.Base(path), err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return false, fmt.Errorf("client: decoding %s: %w", filepath.Base(path), err)
	}
	return true, nil
}

// writeJSON replaces a small file atomically.
//
// Only for values whose size is bounded by something other than history: an
// identity, one ratchet session, one conversation's metadata. Anything that
// grows per message belongs in a log instead.
func writeJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("client: encoding %s: %w", filepath.Base(path), err)
	}
	return writeFileAtomic(path, raw)
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("client: creating %s: %w", filepath.Dir(path), err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("client: creating temporary file for %s: %w", filepath.Base(path), err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename has succeeded

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("client: writing %s: %w", filepath.Base(path), err)
	}
	// Sync before the rename: the rename being atomic says nothing about the
	// contents having reached the disk, and on a phone the process can die
	// between the two.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("client: syncing %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("client: closing %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("client: replacing %s: %w", filepath.Base(path), err)
	}
	return nil
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("client: removing %s: %w", filepath.Base(path), err)
	}
	return nil
}

// --- append-only logs -------------------------------------------------------

// appendLine adds one JSON record to a log. This is the write path for
// everything that grows with history, and it costs one line regardless of how
// much is already there.
func appendLine(path string, record any) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("client: encoding record for %s: %w", filepath.Base(path), err)
	}
	if len(raw) == 0 || containsNewline(raw) {
		return fmt.Errorf("client: record for %s is not one line", filepath.Base(path))
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("client: creating %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("client: opening %s: %w", filepath.Base(path), err)
	}
	defer f.Close()

	if _, err := f.Write(append(raw, '\n')); err != nil {
		return fmt.Errorf("client: appending to %s: %w", filepath.Base(path), err)
	}
	return f.Sync()
}

// readLines calls visit for every record in a log, oldest first.
//
// A malformed final line is skipped rather than treated as corruption: an
// append interrupted by the process dying leaves exactly that, and it costs the
// record it was writing and nothing else.
func readLines(path string, visit func(raw []byte) error) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("client: opening %s: %w", filepath.Base(path), err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLogLine)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || !json.Valid(line) {
			continue // a torn or empty line; see above
		}
		if err := visit(line); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, bufio.ErrTooLong) {
		return fmt.Errorf("client: reading %s: %w", filepath.Base(path), err)
	}
	return nil
}

// maxLogLine bounds one record. An attachment's thumbnail is the largest thing
// that can appear in one, and this leaves generous room above it.
const maxLogLine = 4 * 1024 * 1024

// rewriteLog replaces a log with the records produce yields, atomically.
//
// The only place a log is rewritten, and it must never be called from a write
// path -- compaction is a threshold decision, made when a log has grown enough
// to be worth the cost, precisely so that the per-message cost stays constant.
func rewriteLog(path string, produce func(write func(record any) error) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("client: creating %s: %w", filepath.Dir(path), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("client: creating temporary log for %s: %w", filepath.Base(path), err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	buf := bufio.NewWriter(tmp)
	writeErr := produce(func(record any) error {
		raw, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("client: encoding record: %w", err)
		}
		if _, err := buf.Write(append(raw, '\n')); err != nil {
			return fmt.Errorf("client: writing record: %w", err)
		}
		return nil
	})
	if writeErr != nil {
		tmp.Close()
		return writeErr
	}
	if err := buf.Flush(); err != nil {
		tmp.Close()
		return fmt.Errorf("client: flushing %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("client: syncing %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("client: closing %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("client: replacing %s: %w", filepath.Base(path), err)
	}
	return nil
}

// countLines reports how many records a log holds, for the compaction
// threshold. Cheap: it reads the file but decodes nothing.
func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("client: opening %s: %w", filepath.Base(path), err)
	}
	defer f.Close()

	var (
		count int
		buf   = make([]byte, 64*1024)
	)
	for {
		n, err := f.Read(buf)
		for _, b := range buf[:n] {
			if b == '\n' {
				count++
			}
		}
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil {
			return 0, fmt.Errorf("client: reading %s: %w", filepath.Base(path), err)
		}
	}
}

// listDirs names the subdirectories of a path, ignoring one that is not there.
func listDirs(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("client: listing %s: %w", filepath.Base(path), err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

func containsNewline(b []byte) bool {
	for _, c := range b {
		if c == '\n' || c == '\r' {
			return true
		}
	}
	return false
}

// tailLines returns the last lines of a log, newest first, reading at most
// maxTailBytes from the end of the file.
//
// The chat list needs one preview per conversation, and replaying a whole
// transcript to find its last message would make drawing that list cost the
// entire history behind it -- the same O(n)-per-operation defect this store
// exists to remove, moved from the write path to the read path. Reading the
// tail bounds it instead.
//
// found is false when the window held nothing usable, which is the caller's cue
// to fall back to a full replay. That happens only for a log whose last records
// are all larger than the window, which is rare and correct rather than fast.
func tailLines(path string) (lines [][]byte, found bool, err error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("client: opening %s: %w", filepath.Base(path), err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("client: sizing %s: %w", filepath.Base(path), err)
	}

	size := info.Size()
	start := int64(0)
	if size > maxTailBytes {
		start = size - maxTailBytes
	}
	buf := make([]byte, size-start)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("client: reading tail of %s: %w", filepath.Base(path), err)
	}

	raw := bytes.Split(buf, []byte{'\n'})
	// A window that began mid-file almost certainly began mid-line; that first
	// fragment is not a record and must go.
	if start > 0 && len(raw) > 0 {
		raw = raw[1:]
	}
	for i := len(raw) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(raw[i])
		if len(line) == 0 || !json.Valid(line) {
			continue
		}
		lines = append(lines, line)
	}
	return lines, len(lines) > 0, nil
}

// maxTailBytes is the window tailLines reads. Comfortably more than the last
// handful of records even when one carries a thumbnail.
const maxTailBytes = 512 * 1024
