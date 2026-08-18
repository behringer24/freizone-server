//go:build linux || darwin

package client

import (
	"errors"
	"os"
	"syscall"
)

// flock, not fcntl locks, and the difference matters here. An fcntl lock is
// owned by the *process*, so a second open of the same file inside one process
// silently succeeds and the protection evaporates exactly where this package
// most needs it -- freizone-app opens an account from two isolates of one
// process. flock is owned by the open file description, so the in-process case
// is a genuine collision that the registry in lock.go then answers deliberately
// (by sharing the Client) rather than by accident.
//
// Both are released by the kernel when the holder exits, which is why there is
// no pid file here and nothing to clean up after a crash.
//
// Covers android (linux) and ios (darwin) too, which is what the shipped app
// core builds for.

func lockExclusive(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

// isLockBusy distinguishes "somebody else holds it" from a real failure. Both
// errno values mean the same thing here and which one arrives is
// platform-dependent, so both are checked rather than the one this machine
// happens to produce.
func isLockBusy(err error) bool {
	return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
}
