//go:build windows

package client

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// LockFileEx is the Windows equivalent of flock for this purpose: the lock
// rides on the handle, the kernel releases it when the process exits, and
// asking for it without waiting is a flag rather than a separate call.
//
// Called through kernel32 directly rather than through golang.org/x/sys, which
// is where it would normally come from. That module is not a dependency of
// this one, and adding it would add it to freizone-app's core too, whose
// dependency list was deliberately cut to almost nothing when the store moved
// off SQLite (see docs/design/23-shared-client-core.md). Two procedures behind
// a documented ABI are not worth reversing that.
var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 0x0001
	lockfileExclusiveLock   = 0x0002
)

// errLockViolation (ERROR_LOCK_VIOLATION) is what Windows reports when another
// handle holds the range and LOCKFILE_FAIL_IMMEDIATELY stopped us waiting.
const errLockViolation = syscall.Errno(33)

func lockExclusive(f *os.File) error {
	// One byte is enough: every holder locks the same range, so the range
	// carries no meaning beyond being the thing they contend for.
	var overlapped syscall.Overlapped
	r, _, err := procLockFileEx.Call(
		f.Fd(),
		uintptr(lockfileExclusiveLock|lockfileFailImmediately),
		0, 1, 0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if r == 0 {
		return err
	}
	return nil
}

func unlockFile(f *os.File) error {
	var overlapped syscall.Overlapped
	r, _, err := procUnlockFileEx.Call(
		f.Fd(),
		0, 1, 0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if r == 0 {
		return err
	}
	return nil
}

func isLockBusy(err error) bool {
	return errors.Is(err, errLockViolation)
}
