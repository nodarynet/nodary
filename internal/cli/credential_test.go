package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/paths"
)

// TestTheKeyComesFromSystemdsCredentialDirectoryWhenItIsThere covers the path
// that lets 01 §12's 0400 root:root sealing key be read by a unit that is not
// root.
//
// Measured on systemd 255: LoadCredential= places the file at
// $CREDENTIALS_DIRECTORY/<id>, mode 0400, owned by the unit's User=. That
// satisfies both of internal/secret's checks — no group or other bits, and
// owned by the reader — where the file in /etc satisfies neither.
func TestTheKeyComesFromSystemdsCredentialDirectoryWhenItIsThere(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", dir)

	// A unit with credentials but not this one: the variable is set and the key
	// is not there, so the real path has to win. Falling through wrongly here
	// would send every CLI invocation under any such unit at a file that does
	// not exist.
	if got := resolveKey(""); got != paths.SecretKey() {
		t.Errorf("with no credential placed, resolveKey() = %q, want %q", got, paths.SecretKey())
	}

	cred := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(cred, []byte("00\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if got := resolveKey(""); got != cred {
		t.Errorf("resolveKey() = %q, want the credential at %q", got, cred)
	}

	// An explicit --secret-key still wins: an operator who named a file meant
	// that file.
	if got := resolveKey("/somewhere/else.key"); got != "/somewhere/else.key" {
		t.Errorf("--secret-key was overridden by the credential: %q", got)
	}
}

// TestAnUnreachableHomeIsNotABrokenCredential covers the second half of running
// as a service account.
//
// `nodary-server.service` carries ProtectHome=true, which mounts /home mode 000
// inside the unit. Measured on systemd 255: stat(2) of a path under it returns
// EACCES, not ENOENT — so a control plane that has never had a credentials file
// gets a permission error from the default path and, before this, refused to
// start.
func TestAnUnreachableHomeIsNotABrokenCredential(t *testing.T) {
	// A directory nobody can traverse, standing in for ProtectHome's /home.
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root traverses a 0000 directory, so there is nothing to observe")
	}
	unreachable := filepath.Join(home, ".nodary", "credentials")

	// nil: neither path reaches the database. resolvePrincipal only queries it
	// to authenticate a credential, and the point here is that there is none.
	var out, errOut bytes.Buffer
	e := env{stdout: &out, stderr: &errOut}

	// Explicit: the operator named it, so the error is news.
	if _, ok := resolvePrincipal(e, "test", nil, unreachable, time.Now()); ok {
		t.Errorf("an explicitly named unreadable credentials file was stepped over")
	}

	// Default: there is nowhere for a credential to be, and the control plane
	// has to start.
	t.Setenv("HOME", home)
	who, ok := resolvePrincipal(e, "test", nil, "", time.Now())
	if !ok {
		t.Fatalf("an unreachable default credentials path refused the session: %s", errOut.String())
	}
	if who.Actor.Method != "local" {
		t.Errorf("acted with method %q, want \"local\"", who.Actor.Method)
	}
}
