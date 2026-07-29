// Package blobstore stores end-to-end-encrypted attachment ciphertext as
// files on disk (SRV-07). It is deliberately dumb: it knows nothing about
// who owns a blob or when it expires -- that is internal/store's job -- and
// nothing about what the bytes mean, since they are ciphertext the server
// cannot read.
//
// Files rather than a SQLite column: the driver has no incremental blob I/O,
// so a multi-megabyte column would be read and written as one []byte on the
// same single-writer connection that also serves authentication. Everything
// here streams through a fixed-size buffer instead, so memory use is
// independent of blob size.
package blobstore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// copyBufferSize bounds how much of a blob is in memory at any moment,
// during both upload and expiry sweeps.
const copyBufferSize = 32 * 1024

// tmpDirName holds partially-written uploads. A blob only moves to its final
// path once it is complete and its digest verified, so a crash or a rejected
// upload can never leave a truncated file where a valid one belongs.
const tmpDirName = "tmp"

// ErrNotFound reports that no file exists for a blob id.
var ErrNotFound = errors.New("blobstore: blob not found")

// Store is a blob directory.
type Store struct {
	root string
}

// New prepares dir (and its temp subdirectory) for use.
func New(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("blobstore: directory must not be empty")
	}
	if err := os.MkdirAll(filepath.Join(dir, tmpDirName), 0o700); err != nil {
		return nil, fmt.Errorf("blobstore: creating directory: %w", err)
	}
	return &Store{root: dir}, nil
}

// NewBlobID returns an unguessable blob id: 32 random bytes, hex-encoded.
//
// Deliberately random rather than the content digest. Content addressing
// would make identical files share an id, letting anyone who holds a file
// test whether someone else uploaded the same one -- and turning the id into
// a probe for a blob's existence. Random ids also mean unguessability is a
// second line of defence behind the ownership check.
func NewBlobID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("blobstore: generating blob id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// Put streams src into the store under blobID, returning how many bytes were
// written and their SHA-256.
//
// The caller passes the digest it expects (from the signed request header);
// on mismatch Put deletes the partial file and returns an error, so a body
// that does not match what was signed never becomes a stored blob. maxBytes
// bounds the write as a backstop -- the HTTP layer caps the body too, but
// this keeps the store safe for any caller.
//
// Writes to a temp file, fsyncs, then renames into place: a torn write can
// only ever leave a temp file for the sweeper, never a corrupt blob.
func (s *Store) Put(blobID string, src io.Reader, expectedDigest string, maxBytes int64) (written int64, digest string, err error) {
	if err := validateBlobID(blobID); err != nil {
		return 0, "", err
	}

	tmp, err := os.CreateTemp(filepath.Join(s.root, tmpDirName), "upload-*")
	if err != nil {
		return 0, "", fmt.Errorf("blobstore: creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	// Removed unless the rename below succeeds, so every failure path --
	// oversize, digest mismatch, I/O error, panic -- cleans up after itself.
	committed := false
	defer func() {
		tmp.Close()
		if !committed {
			os.Remove(tmpName)
		}
	}()

	hasher := sha256.New()
	limited := io.LimitReader(src, maxBytes+1) // +1 so exceeding the cap is detectable
	buf := make([]byte, copyBufferSize)
	written, err = io.CopyBuffer(io.MultiWriter(tmp, hasher), limited, buf)
	if err != nil {
		return 0, "", fmt.Errorf("blobstore: writing blob: %w", err)
	}
	if written > maxBytes {
		return 0, "", fmt.Errorf("blobstore: blob exceeds %d bytes", maxBytes)
	}

	digest = hex.EncodeToString(hasher.Sum(nil))
	if expectedDigest != "" && !strings.EqualFold(digest, expectedDigest) {
		return 0, "", fmt.Errorf("blobstore: digest mismatch")
	}

	// Durable before the metadata row exists, so a crash can leave an orphan
	// file (swept later) but never a row pointing at missing bytes.
	if err := tmp.Sync(); err != nil {
		return 0, "", fmt.Errorf("blobstore: syncing blob: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, "", fmt.Errorf("blobstore: closing blob: %w", err)
	}

	finalPath := s.pathFor(blobID)
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o700); err != nil {
		return 0, "", fmt.Errorf("blobstore: creating blob directory: %w", err)
	}
	if err := os.Rename(tmpName, finalPath); err != nil {
		return 0, "", fmt.Errorf("blobstore: committing blob: %w", err)
	}
	committed = true

	return written, digest, nil
}

// Open returns the blob's file for reading, for the caller to serve (e.g.
// via http.ServeContent, which needs an io.ReadSeeker for range requests).
// The caller closes it.
func (s *Store) Open(blobID string) (*os.File, error) {
	if err := validateBlobID(blobID); err != nil {
		return nil, err
	}
	f, err := os.Open(s.pathFor(blobID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("blobstore: opening blob: %w", err)
	}
	return f, nil
}

// Remove deletes a blob's file. A file that is already gone is not an error:
// removal is driven by expiry and explicit deletes that may both race, and
// either way the desired end state is reached.
func (s *Store) Remove(blobID string) error {
	if err := validateBlobID(blobID); err != nil {
		return err
	}
	if err := os.Remove(s.pathFor(blobID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("blobstore: removing blob: %w", err)
	}
	return nil
}

// SweepTmp deletes leftover temp files older than olderThan -- uploads that
// died mid-write (killed process, dropped connection). Returns how many were
// removed.
func (s *Store) SweepTmp(olderThan time.Duration, now time.Time) (int, error) {
	tmpDir := filepath.Join(s.root, tmpDirName)
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("blobstore: reading temp directory: %w", err)
	}

	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue // vanished under us; nothing to clean
		}
		if now.Sub(info.ModTime()) <= olderThan {
			continue
		}
		if err := os.Remove(filepath.Join(tmpDir, e.Name())); err == nil {
			removed++
		}
	}
	return removed, nil
}

// EachStoredID calls fn for every blob id currently on disk. Used by the
// orphan sweep to find files whose metadata row is gone (the window between
// writing the file and inserting the row, or a delete that failed halfway).
func (s *Store) EachStoredID(fn func(blobID string) error) error {
	// Two levels of fan-out directories, then the files themselves.
	return filepath.WalkDir(s.root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == tmpDirName {
				return filepath.SkipDir
			}
			return nil
		}
		return fn(d.Name())
	})
}

// pathFor fans blobs out over two levels of subdirectory taken from the id,
// so no single directory ends up with every blob in it -- which degrades
// badly on most filesystems once a server has been running a while.
func (s *Store) pathFor(blobID string) string {
	return filepath.Join(s.root, blobID[0:2], blobID[2:4], blobID)
}

// validateBlobID rejects anything that isn't a plain hex id, so a value that
// reached us from a request can never escape the blob directory via "..",
// a separator, or an absolute path.
func validateBlobID(blobID string) error {
	if len(blobID) != 64 {
		return fmt.Errorf("blobstore: invalid blob id")
	}
	for i := 0; i < len(blobID); i++ {
		c := blobID[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			return fmt.Errorf("blobstore: invalid blob id")
		}
	}
	return nil
}
