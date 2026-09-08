package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/secret"
	"github.com/nodarynet/nodary/internal/store"
)

// TestTheKeyComesFromSystemdsCredentialDirectoryWhenItIsThere covers the path
// that lets 01 §12's 0400 root:root sealing key be read by a unit that is not
// root.
//
// Measured on systemd 255: LoadCredential= places the file at
// $CREDENTIALS_DIRECTORY/<id>. In a *system* unit with User= it is 0440,
// root-owned and group-readable by the service account; a user unit shows 0400
// only because there the unit's user is already the owner. internal/secret
// accepts systemd's placement for exactly that reason — see checkAccess, which
// this test's first version was written against a user-unit measurement and got
// wrong.
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

// TestServerInstallBindsTheSealingKey arms R1-36 on a fresh control plane.
//
// BindKey had exactly one caller — the first TOTP seal — while the agent CA's
// private key is sealed by `server install` itself. So a control plane that had
// enrolled nobody named no key, and internal/identity's refusal, whose whole
// job is to stop a replaced secret.key going unnoticed, never fired. Measured
// before the fix: `SELECT secret_key_id FROM installation` returned no row.
//
// The consequence is the unrecoverable one: nodary starts cleanly under the new
// key, the agent CA can never be decrypted again, and the first symptom is an
// enrolment failing much later for a reason that names none of this.
func TestServerInstallBindsTheSealingKey(t *testing.T) {
	a := newAppliance(t)
	code, _, stderr := runWithStdin(t, "", "server", "install",
		"--root", a.dir, "--offline", "--db", a.db, "--secret-key", a.key,
		"--config", filepath.Join(a.dir, "server.toml"),
		"--user", "", "--skip-preflight", "--bind", "127.0.0.1:18443")
	if code != ExitOK {
		t.Fatalf("server install: exit %d, %s", code, stderr)
	}

	db, err := store.Open(context.Background(), a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	bound, err := identity.BoundKeyID(context.Background(), db.Read())
	if err != nil {
		t.Fatal(err)
	}
	if bound == "" {
		t.Fatal("the install sealed the agent CA and bound no key; a replaced secret.key would go unnoticed")
	}

	// And it is the key that is actually there, not any string.
	k, err := secret.Load(a.key)
	if err != nil {
		t.Fatal(err)
	}
	if bound != k.ID() {
		t.Errorf("bound to %q, but the key on disk is %q", bound, k.ID())
	}

	// Re-running does not bind again. It does mint a fresh setup link, which is
	// deliberate — so this counts the binding rather than the chain, which is
	// the property and not a proxy for it.
	before := bindRecords(t, db)
	if code, _, stderr := runWithStdin(t, "", "server", "install",
		"--root", a.dir, "--offline", "--db", a.db, "--secret-key", a.key,
		"--config", filepath.Join(a.dir, "server.toml"),
		"--user", "", "--skip-preflight", "--bind", "127.0.0.1:18443"); code != ExitOK {
		t.Fatalf("re-running the install: exit %d, %s", code, stderr)
	}
	if after := bindRecords(t, db); after != before {
		t.Errorf("a re-run added %d binding record(s) for a key already bound", after-before)
	}
}

func bindRecords(t *testing.T, db *store.DB) int {
	t.Helper()
	var n int
	if err := db.Read().QueryRow(
		`SELECT count(*) FROM audit WHERE action = 'installation.bind-key'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
