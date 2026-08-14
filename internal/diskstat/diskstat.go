// Package diskstat reports free/total space on the filesystem the server's
// data directory lives on, for the admin statistics page (internal/api/
// stats.go) -- so an operator can see disk pressure coming rather than
// finding out from a failed write.
package diskstat
