package client

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Owning an account directory.
//
// # Why this exists
//
// Nothing prevented two Clients over one directory, and the result is not
// "racy under load" -- it is destructive on the first concurrent write. A
// session file is a whole-file write of an advancing ratchet, so two writers
// lose one advance and the peer sees two envelopes claiming the same message
// number: a desync that heals only by re-keying, after the messages are gone.
// processedIDs and the decrypt-failure counts live in memory, so two openers
// each hold half the truth and a redelivery gets processed twice by whichever
// one did not see it. A one-time prekey consumed by one leaves the other
// believing it unspent. And Open itself mutates -- it settles in-flight sends
// to failed -- so merely *opening* a directory a second time marks another
// opener's live send as failed.
//
// peerLocks looks like protection at the call site and is not: it is a map of
// mutexes inside one Client, and a second Client has its own.
//
// # Two different collisions, two different answers
//
// **Another process** is always a mistake, and gets an error. That is the bot's
// case: a one-shot CLI and a daemon both wanting the same account. The lock is
// held by the kernel and released when the holder dies, which is the property a
// pid file does not have -- a crash leaves no stale lock to reason about.
//
// **The same process** is not necessarily a mistake, and gets the *same
// Client*. That is freizone-app's case: a push wake runs in its own Dart
// isolate and opens the account while the foreground session already has it
// (see push_manager.dart's _wakeSyncInIsolate, and the comment there about a
// wake arriving while the app is in the foreground). Isolates are one OS
// process, so a file lock would refuse the wake -- turning a protection into a
// missed message. Handing back the one open Client is what those two callers
// actually needed all along: one mutex, one processed-id view, one ratchet.
//
// The reference count is what makes that safe to close: the account is released
// when the last opener closes it, not the first.

// ErrAccountInUse reports an account directory held by a different process.
//
// Recoverable only by that process letting go, so a caller should say which
// directory and stop rather than retry: the holder is a live daemon, and
// waiting for it would mean waiting for it to exit.
type ErrAccountInUse struct {
	Path string
}

func (e *ErrAccountInUse) Error() string {
	return fmt.Sprintf("client: account directory %s is open in another process", e.Path)
}

// lockFileName sits inside the account directory. Its contents are
// deliberately empty and carry no pid: the kernel-held lock is the fact, and
// anything written here could only ever be a stale second opinion about it.
const lockFileName = "owner.lock"

// openAccounts is the in-process registry. Keyed by the resolved absolute
// path, so two callers naming one directory differently -- a relative path and
// an absolute one, a trailing slash -- still meet.
var (
	openMu       sync.Mutex
	openAccounts = map[string]*openAccount{}
)

type openAccount struct {
	client *Client
	file   *os.File
	refs   int

	// mediaPath is remembered so a second opener asking for a *different* one
	// is told rather than silently given the first opener's. Attachments
	// landing somewhere the caller did not ask for is the kind of thing found
	// months later, by a picture that is missing.
	mediaPath string
}

// accountKey resolves path to the key the registry uses. A path that cannot be
// resolved is used as given: failing to open an account because its name could
// not be canonicalised would be worse than a registry that occasionally holds
// two keys for one directory.
func accountKey(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return filepath.Clean(abs)
}

// acquireAccount takes ownership of path, or joins the ownership this process
// already has. The returned bool reports whether the caller is the first
// opener and therefore has to build the Client.
func acquireAccount(path, mediaPath string) (*openAccount, bool, error) {
	key := accountKey(path)

	openMu.Lock()
	defer openMu.Unlock()

	if existing, ok := openAccounts[key]; ok {
		if existing.mediaPath != mediaPath {
			return nil, false, fmt.Errorf(
				"client: account %s is already open in this process with media at %s, not %s",
				path, existing.mediaPath, mediaPath)
		}
		existing.refs++
		return existing, false, nil
	}

	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, false, fmt.Errorf("client: creating account directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(path, lockFileName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("client: opening the account lock: %w", err)
	}
	if err := lockExclusive(f); err != nil {
		f.Close()
		if isLockBusy(err) {
			return nil, false, &ErrAccountInUse{Path: path}
		}
		return nil, false, fmt.Errorf("client: locking the account directory: %w", err)
	}

	entry := &openAccount{file: f, refs: 1, mediaPath: mediaPath}
	openAccounts[key] = entry
	return entry, true, nil
}

// releaseAccount drops one reference, releasing the directory when the last
// one goes.
func releaseAccount(key string) error {
	openMu.Lock()
	defer openMu.Unlock()

	entry, ok := openAccounts[key]
	if !ok {
		// Already released, or never held. Closing twice is something a
		// teardown racing a hot restart does, and it is not worth an error.
		return nil
	}
	entry.refs--
	if entry.refs > 0 {
		return nil
	}
	delete(openAccounts, key)

	// Unlock explicitly rather than relying on the close: on the platforms
	// where the lock rides on the descriptor it is the same thing, and where
	// it does not, being explicit is what makes it so.
	unlockErr := unlockFile(entry.file)
	closeErr := entry.file.Close()
	if unlockErr != nil {
		return fmt.Errorf("client: releasing the account lock: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("client: closing the account lock: %w", closeErr)
	}
	return nil
}
