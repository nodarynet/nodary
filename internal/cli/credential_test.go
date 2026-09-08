package cli

import (
	"os"
	"path/filepath"
	"testing"

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
