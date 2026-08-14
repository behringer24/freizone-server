//go:build linux || darwin

package diskstat

import "syscall"

// Free reports the free and total bytes on the filesystem containing path.
//
// syscall.Statfs_t's Bsize field is int64 on Linux and uint32 on Darwin --
// explicit uint64 conversions (rather than relying on a shared type) are
// what let this one function body build on both.
func Free(path string) (free, total uint64, err error) {
	var buf syscall.Statfs_t
	if err := syscall.Statfs(path, &buf); err != nil {
		return 0, 0, err
	}
	bsize := uint64(buf.Bsize)
	return buf.Bfree * bsize, buf.Blocks * bsize, nil
}
