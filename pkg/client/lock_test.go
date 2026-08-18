package client

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Opening one account twice in one process is not a mistake -- freizone-app
// does it, from the foreground session and from a push wake's isolate -- and
// the answer is the *same* Client rather than a second one. Two Clients would
// mean two mutexes, two processed-id views and two writers to one ratchet.
func TestASecondOpenInThisProcessSharesTheClient(t *testing.T) {
	dir := t.TempDir()

	first, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	second, err := Open(dir)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if first != second {
		t.Fatal("two openers of one account must get one Client, or they write over each other")
	}

	// Spelling the same directory differently must not conjure a second
	// account: a relative path and an absolute one are the same directory.
	viaRelative, err := Open(dir + string(filepath.Separator) + ".")
	if err != nil {
		t.Fatalf("Open via another spelling: %v", err)
	}
	if viaRelative != first {
		t.Error("the registry has to resolve the path, or one directory gets two owners")
	}

	for range 3 {
		if err := first.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	// Closing more often than opening is what a teardown racing a restart
	// does; it must not be an error.
	if err := first.Close(); err != nil {
		t.Errorf("closing an already-released account: %v", err)
	}
}

// The account is released when the LAST opener lets go, not the first --
// otherwise a push wake finishing would pull the directory out from under the
// foreground session that is still using it.
func TestTheAccountIsHeldUntilTheLastOpenerCloses(t *testing.T) {
	dir := t.TempDir()

	first, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	second, err := Open(dir)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}

	if err := second.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !held(dir) {
		t.Fatal("one opener closing must not release an account another still holds")
	}

	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if held(dir) {
		t.Error("the last close has to release the account")
	}
}

// A second opener asking for different media is told rather than quietly given
// the first one's. Attachments landing somewhere nobody asked for is found
// months later, by a picture that is missing.
func TestASecondOpenWithDifferentMediaIsRefused(t *testing.T) {
	dir := t.TempDir()

	c, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()

	_, err = OpenWith(dir, Options{MediaPath: t.TempDir()})
	if err == nil {
		t.Fatal("a conflicting media path must be refused, not silently ignored")
	}
	if !strings.Contains(err.Error(), "already open in this process") {
		t.Errorf("the error should say what the conflict is, got %q", err)
	}
}

// The cross-process half, which is the one the bot needs: a one-shot CLI and a
// daemon must not both hold an account. Driven through a real second process,
// because the in-process registry would otherwise answer and prove nothing.
func TestAnotherProcessIsRefused(t *testing.T) {
	if os.Getenv("FREIZONE_TEST_LOCK_HOLDER") != "" {
		return // see below: this binary is also the child
	}
	dir := t.TempDir()

	held, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer held.Close()

	// Re-run this test binary as a child, pointed at the same directory. It
	// runs the helper below rather than the suite. -test.v because the proof
	// is a log line: without it a child that *skipped* would report success
	// just as loudly as one that was genuinely refused.
	cmd := exec.Command(os.Args[0], "-test.run=TestLockHolderChild", "-test.v")
	cmd.Env = append(os.Environ(),
		"FREIZONE_TEST_LOCK_HOLDER=1",
		"FREIZONE_TEST_LOCK_DIR="+dir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed to run: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "REFUSED") {
		t.Fatalf("a second process must be refused the account, child said:\n%s", out)
	}
}

// TestLockHolderChild is the child half of the test above. It is a test only so
// that `go test` runs it; it does nothing unless the parent asked for it.
func TestLockHolderChild(t *testing.T) {
	dir := os.Getenv("FREIZONE_TEST_LOCK_DIR")
	if os.Getenv("FREIZONE_TEST_LOCK_HOLDER") == "" || dir == "" {
		t.Skip("only run as the child of TestAnotherProcessIsRefused")
	}

	c, err := Open(dir)
	if err == nil {
		c.Close()
		t.Fatal("this process should not have been able to open an account another holds")
	}
	var inUse *ErrAccountInUse
	if !errors.As(err, &inUse) {
		t.Fatalf("want ErrAccountInUse, got %T: %v", err, err)
	}
	if inUse.Path == "" {
		t.Error("the error has to name the directory, or an operator cannot act on it")
	}
	// The parent reads this from the child's output.
	t.Log("REFUSED")
}

// A failure *after* the account is taken has to give it back, or the directory
// stays locked until the process exits -- with nothing running that would
// explain why.
func TestAFailedOpenDoesNotStrandTheLock(t *testing.T) {
	dir := t.TempDir()

	// A format marker from a future layout makes openStore refuse, which is
	// the failure path between taking the lock and returning a Client.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "format"), []byte("freizone-client-store-v99\n"), 0o600); err != nil {
		t.Fatalf("writing the marker: %v", err)
	}

	if _, err := Open(dir); err == nil {
		t.Fatal("a store from another layout must be refused")
	}
	if held(dir) {
		t.Fatal("a failed open must release the account it took")
	}

	// And the proof that it is genuinely free: with the marker gone, opening
	// works.
	if err := os.Remove(filepath.Join(dir, "format")); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	c, err := Open(dir)
	if err != nil {
		t.Fatalf("Open after the obstacle went: %v", err)
	}
	c.Close()
}

// held reports whether this process still has the account in its registry.
func held(path string) bool {
	openMu.Lock()
	defer openMu.Unlock()
	_, ok := openAccounts[accountKey(path)]
	return ok
}
