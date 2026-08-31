//go:build unix

package store

import "syscall"

// syscallUmask lets a test create files under a deliberately permissive umask,
// which is the condition under which SQLite would otherwise leave the WAL
// sidecars world-readable.
func syscallUmask(mask int) int { return syscall.Umask(mask) }
