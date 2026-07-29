package blobstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return s
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func mustID(t *testing.T) string {
	t.Helper()
	id, err := NewBlobID()
	if err != nil {
		t.Fatalf("NewBlobID() error = %v", err)
	}
	return id
}

func TestPutThenOpenRoundTrips(t *testing.T) {
	s := newTestStore(t)
	id := mustID(t)
	payload := []byte("pretend this is image ciphertext")

	written, digest, err := s.Put(id, bytes.NewReader(payload), digestOf(payload), 1024)
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if written != int64(len(payload)) {
		t.Errorf("written = %d, want %d", written, len(payload))
	}
	if digest != digestOf(payload) {
		t.Errorf("digest = %s, want %s", digest, digestOf(payload))
	}

	f, err := s.Open(id)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading blob: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("got %q, want %q", got, payload)
	}
}

func TestPutRejectsDigestMismatchAndStoresNothing(t *testing.T) {
	s := newTestStore(t)
	id := mustID(t)

	// A body that doesn't match what the sender signed must not become a blob.
	_, _, err := s.Put(id, strings.NewReader("actual bytes"), digestOf([]byte("different bytes")), 1024)
	if err == nil {
		t.Fatal("expected Put() to reject a digest mismatch")
	}
	if _, err := s.Open(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("Open() after mismatch = %v, want ErrNotFound -- no partial blob may survive", err)
	}
}

func TestPutRejectsOversizeAndStoresNothing(t *testing.T) {
	s := newTestStore(t)
	id := mustID(t)
	payload := bytes.Repeat([]byte("x"), 200)

	_, _, err := s.Put(id, bytes.NewReader(payload), digestOf(payload), 100)
	if err == nil {
		t.Fatal("expected Put() to reject a blob over maxBytes")
	}
	if _, err := s.Open(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("Open() after oversize = %v, want ErrNotFound", err)
	}
}

func TestPutAcceptsExactlyMaxBytes(t *testing.T) {
	s := newTestStore(t)
	id := mustID(t)
	payload := bytes.Repeat([]byte("x"), 100)

	if _, _, err := s.Put(id, bytes.NewReader(payload), digestOf(payload), 100); err != nil {
		t.Fatalf("Put() at exactly the limit error = %v", err)
	}
}

func TestPutLeavesNoTempFilesBehind(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ok := []byte("fine")
	if _, _, err := s.Put(mustID(t), bytes.NewReader(ok), digestOf(ok), 1024); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	_, _, _ = s.Put(mustID(t), strings.NewReader("bad"), digestOf([]byte("other")), 1024)

	entries, err := os.ReadDir(filepath.Join(root, tmpDirName))
	if err != nil {
		t.Fatalf("reading temp dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("temp dir holds %d leftover file(s); both success and failure must clean up", len(entries))
	}
}

func TestBlobIDIsUnguessableAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := mustID(t)
		if len(id) != 64 {
			t.Fatalf("id length = %d, want 64", len(id))
		}
		if seen[id] {
			t.Fatal("NewBlobID() returned a duplicate")
		}
		seen[id] = true
	}
}

func TestRejectsBlobIDThatCouldEscapeTheDirectory(t *testing.T) {
	s := newTestStore(t)
	// Ids arrive from request paths, so a traversal attempt must never be
	// turned into a filesystem path.
	for _, bad := range []string{
		"../../etc/passwd",
		strings.Repeat("a", 63) + "/",
		"..",
		"",
		strings.Repeat("A", 64), // uppercase: not our canonical form
		strings.Repeat("z", 64), // not hex
	} {
		if _, err := s.Open(bad); err == nil || errors.Is(err, ErrNotFound) {
			// ErrNotFound would mean it was treated as a real lookup; we want
			// it rejected as malformed before touching the filesystem.
			t.Errorf("Open(%q) error = %v, want a validation error", bad, err)
		}
		if err := s.Remove(bad); err == nil {
			t.Errorf("Remove(%q) succeeded, want a validation error", bad)
		}
	}
}

func TestRemoveIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	id := mustID(t)
	payload := []byte("bytes")
	if _, _, err := s.Put(id, bytes.NewReader(payload), digestOf(payload), 1024); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	if err := s.Remove(id); err != nil {
		t.Fatalf("first Remove() error = %v", err)
	}
	// Expiry and an explicit delete can race; removing twice must be fine.
	if err := s.Remove(id); err != nil {
		t.Errorf("second Remove() error = %v, want nil", err)
	}
}

func TestSweepTmpRemovesOnlyStaleFiles(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	tmpDir := filepath.Join(root, tmpDirName)

	stale := filepath.Join(tmpDir, "upload-stale")
	fresh := filepath.Join(tmpDir, "upload-fresh")
	for _, p := range []string{stale, fresh} {
		if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", p, err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatalf("backdating stale temp file: %v", err)
	}

	removed, err := s.SweepTmp(time.Hour, time.Now())
	if err != nil {
		t.Fatalf("SweepTmp() error = %v", err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Error("stale temp file survived the sweep")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("an in-progress upload was swept away")
	}
}

func TestEachStoredIDListsBlobsAndSkipsTemp(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	want := map[string]bool{}
	for i := 0; i < 3; i++ {
		id := mustID(t)
		payload := []byte("blob")
		if _, _, err := s.Put(id, bytes.NewReader(payload), digestOf(payload), 1024); err != nil {
			t.Fatalf("Put() error = %v", err)
		}
		want[id] = true
	}
	// An in-flight upload must not look like a stored blob to the orphan sweep.
	if err := os.WriteFile(filepath.Join(root, tmpDirName, "upload-inflight"), []byte("x"), 0o600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	got := map[string]bool{}
	if err := s.EachStoredID(func(id string) error {
		got[id] = true
		return nil
	}); err != nil {
		t.Fatalf("EachStoredID() error = %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("listed %d ids, want %d (%v)", len(got), len(want), got)
	}
	for id := range want {
		if !got[id] {
			t.Errorf("missing blob id %s", id)
		}
	}
}
