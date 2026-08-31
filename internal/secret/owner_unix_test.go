//go:build unix

package secret

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"
)

func makeFIFO(path string, mode uint32) error {
	return syscall.Mkfifo(path, mode)
}

func linkCount(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no link count available on this platform")
	}
	return uint64(st.Nlink)
}

// fakeInfo lets the ownership rejection be tested without another uid to hand.
// The branch is one of the package's two file-security properties and had no
// test at all.
type fakeInfo struct{ uid uint32 }

func (f fakeInfo) Name() string       { return "secret.key" }
func (f fakeInfo) Size() int64        { return 65 }
func (f fakeInfo) Mode() fs.FileMode  { return 0o400 }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func TestCheckOwnerRejectsAnotherAccount(t *testing.T) {
	mine := uint32(os.Geteuid())

	if err := checkOwner(fakeInfo{uid: mine}, "/etc/nodary/secret.key"); err != nil {
		t.Errorf("a key owned by this process was refused: %v", err)
	}

	// A key owned by another account is one that account can replace.
	err := checkOwner(fakeInfo{uid: mine + 1}, "/etc/nodary/secret.key")
	if !errors.Is(err, ErrBadPermissions) {
		t.Errorf("error = %v, want ErrBadPermissions", err)
	}
}
