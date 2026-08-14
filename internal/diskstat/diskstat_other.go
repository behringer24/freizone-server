//go:build !linux && !darwin

package diskstat

// Free reports 0/0 on platforms with no syscall.Statfs equivalent wired up
// here (e.g. a native Windows build used only for local development).
// Callers treat 0 as "unknown", not an error -- production always runs in
// Docker/Linux (see ../../freizone-farm's compose files), so this path is
// never hit there.
func Free(path string) (free, total uint64, err error) {
	return 0, 0, nil
}
