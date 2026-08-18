//go:build !linux && !darwin && !windows

package client

import "os"

// No file locking wired up for this platform, so cross-process ownership is
// not enforced here. The in-process registry in lock.go still works, which is
// the half that matters for a shell running several isolates over one account.
//
// Every platform this package actually ships on is covered elsewhere: linux
// and darwin (which is also android and ios, the app's core) in lock_unix.go,
// windows in lock_windows.go. This file exists so a build for something else
// -- plan9, js/wasm, a new port -- compiles rather than failing on a missing
// symbol, in the same shape internal/diskstat already uses for the same
// reason.
//
// Silent rather than an error on purpose: refusing to open an account on a
// platform nobody deploys to would trade a theoretical protection for a
// certain breakage.

func lockExclusive(f *os.File) error { return nil }

func unlockFile(f *os.File) error { return nil }

func isLockBusy(err error) bool { return false }
