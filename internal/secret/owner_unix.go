//go:build unix

package secret

import (
	"fmt"
	"os"
	"syscall"
)

// openNoFollow opens path for reading, refusing to traverse a final symlink and
// refusing to block.
//
// O_NOFOLLOW: a symlink here would let anyone able to create it redirect the
// read to a file they control.
//
// O_NONBLOCK: without it, open(2) on a FIFO blocks until a writer appears, so a
// FIFO left at the key path hangs startup forever before any check can run.
// The caller rejects non-regular files immediately afterwards; on a regular
// file the flag has no effect.
//
// Both are syscall flags rather than os ones, which is why this lives beside
// the ownership check.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// checkOwner refuses a key file owned by somebody other than the process
// running as.
//
// docs/specs/08-data-model.md §4 says "0400, root", and in a real install that
// is exactly what this enforces, because nodary runs as root. But *root* is not
// the invariant — ownership by the reader is. A key owned by another account is
// one that account can replace, so the check is against the effective uid,
// which is the property that actually matters and which also holds when the
// tests, or a developer, run as an ordinary user.
func checkOwner(fi os.FileInfo, path string) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil // no ownership information available; the mode check stands
	}
	if euid := os.Geteuid(); int(st.Uid) != euid {
		return fmt.Errorf("%w: %s is owned by uid %d, this process is uid %d",
			ErrBadPermissions, path, st.Uid, euid)
	}
	return nil
}
