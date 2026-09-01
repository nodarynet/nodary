package identity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/paths"
)

func TestCredentialsRoundTripAtMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "home", ".nodary", "credentials")

	c, err := LoadCredentials(path)
	if err != nil {
		t.Fatalf("loading an absent file: %v", err)
	}
	if _, err := c.Token(LocalServer); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("error = %v, want ErrNoCredentials", err)
	}

	c.Set(LocalServer, Credential{Token: "nodary_pt_secret", User: "alice"})
	if err := c.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != paths.ModeCredentials {
		t.Errorf("mode = %#o, want %#o", got, paths.ModeCredentials)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got&0o077 != 0 {
		t.Errorf("directory mode = %#o, want nothing for group or other", got)
	}

	back, err := LoadCredentials(path)
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	cred, err := back.Token(LocalServer)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if cred.Token != "nodary_pt_secret" || cred.User != "alice" {
		t.Errorf("read back %+v", cred)
	}
}

// TestAnExposedCredentialsFileIsRefused: a credential others can read is a
// credential that has leaked, and reading it anyway would hide that.
func TestAnExposedCredentialsFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660, 0o666} {
		path := filepath.Join(dir, "creds")
		if err := os.WriteFile(path, []byte(`{"version":1,"servers":{}}`), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := LoadCredentials(path)
		if !errors.Is(err, ErrCredentialsExposed) {
			t.Errorf("mode %#o: error = %v, want ErrCredentialsExposed", mode, err)
		}
		if err != nil && !strings.Contains(err.Error(), "600") {
			t.Errorf("mode %#o: the message should say what the mode must be: %v", mode, err)
		}
		os.Remove(path)
	}
}

func TestCredentialsRefusesWhatItCannotRead(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		t.Helper()
		path := filepath.Join(dir, "creds")
		if err := os.WriteFile(path, []byte(body), paths.ModeCredentials); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, body := range []string{
		"",
		"not json",
		`{"version":2,"servers":{}}`,
		`{"servers":{}}`,
	} {
		if _, err := LoadCredentials(write(body)); !errors.Is(err, ErrCredentialsFormat) {
			t.Errorf("body %q: error = %v, want ErrCredentialsFormat", body, err)
		}
	}

	// A directory, or anything else that is not a regular file.
	sub := filepath.Join(dir, "asdir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(sub); !errors.Is(err, ErrCredentialsFormat) {
		t.Errorf("a directory: error = %v, want ErrCredentialsFormat", err)
	}
}

func TestSaveReplacesWithoutLeavingTheOldOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds")
	c := &Credentials{Version: credentialsVersion, Servers: map[string]Credential{}}
	c.Set(LocalServer, Credential{Token: "first"})
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	c.Set(LocalServer, Credential{Token: "second"})
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}

	back, err := LoadCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	if cred, _ := back.Token(LocalServer); cred.Token != "second" {
		t.Errorf("token = %q, want second", cred.Token)
	}
	// The atomic write must not leave its temporary file behind holding a
	// credential at a name nothing manages.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("directory holds %v, want only the credentials file", names)
	}
}

func TestResolveTokenProducesTheActorTheRecordCarries(t *testing.T) {
	f := newFixture(t)
	alice := f.add("alice", RoleOperator)
	tok, plain := f.mint("alice", KindPersonal, "laptop", time.Time{})

	p, err := ResolveToken(context.Background(), f.db.Read(), f.now, plain)
	if err != nil {
		t.Fatalf("ResolveToken: %v", err)
	}
	if p.Role != RoleOperator || p.User.ID != alice.ID || p.Token.ID != tok.ID {
		t.Fatalf("resolved %+v", p)
	}
	if p.Local() {
		t.Error("a token principal reports itself as local")
	}
	want := audit.Actor{ID: alice.ID, Method: "token", Session: tok.ID}
	if p.Actor != want {
		t.Errorf("actor = %+v, want %+v", p.Actor, want)
	}

	// The record has to say which credential was used, so revoking one can be
	// traced to everything it did.
	rec, err := f.log.Act(context.Background(), audit.Request{
		Actor: p.Actor, Action: "user.add",
	}, func(m audit.Mutation) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if rec.Actor != want {
		t.Errorf("record actor = %+v, want %+v", rec.Actor, want)
	}
}

func TestLocalRootIsAdminAndSaysSo(t *testing.T) {
	p := LocalRoot()
	if p.Role != RoleAdmin {
		t.Errorf("role = %q, want admin", p.Role)
	}
	if !p.Local() {
		t.Error("LocalRoot does not report itself as local")
	}
	// An auditor has to be able to tell a local invocation from an
	// authenticated one at a glance, which is what the method is for.
	if p.Actor.Method != "local" || p.Actor.ID != "root" {
		t.Errorf("actor = %+v, want {root local}", p.Actor)
	}
	if !Can(p.Role, PermUserManage) || !Can(p.Role, PermTokenManage) {
		t.Error("local root cannot manage users or tokens, so it cannot recover an appliance")
	}
}

func TestResolveTokenRefusesWhatAuthenticateRefuses(t *testing.T) {
	f := newFixture(t)
	f.add("alice", RoleOperator)
	tok, plain := f.mint("alice", KindPersonal, "", time.Time{})

	if _, err := ResolveToken(context.Background(), f.db.Read(), f.now, "nonsense"); !errors.Is(err, ErrBadToken) {
		t.Errorf("error = %v, want ErrBadToken", err)
	}
	if _, err := f.act("token.revoke", func(m audit.Mutation) error {
		_, err := RevokeToken(context.Background(), m, RoleAdmin, f.now, tok.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveToken(context.Background(), f.db.Read(), f.now, plain); !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("error = %v, want ErrTokenRevoked", err)
	}
}

// TestAFailedSaveLeavesNoTemporaryFile: the temporary file holds the
// credential under a name nothing manages, so a failure that leaves one behind
// is a leak that no later run would clean up.
func TestAFailedSaveLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	// A non-empty directory where the file should go: the write succeeds and
	// the rename cannot.
	path := filepath.Join(dir, "creds")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "occupied"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &Credentials{Version: credentialsVersion, Servers: map[string]Credential{}}
	c.Set(LocalServer, Credential{Token: "nodary_pt_secret"})
	if err := c.Save(path); err == nil {
		t.Fatal("Save reported success against a directory")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "creds" {
			t.Errorf("a failed save left %s behind, holding the credential", e.Name())
		}
	}
}

// TestAnEmptyStoredTokenIsNoCredential keeps a truncated or hand-edited file
// from resolving to a principal with an empty credential.
func TestAnEmptyStoredTokenIsNoCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds")
	c := &Credentials{Version: credentialsVersion, Servers: map[string]Credential{}}
	c.Set(LocalServer, Credential{User: "alice"})
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	back, err := LoadCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := back.Token(LocalServer); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("error = %v, want ErrNoCredentials", err)
	}
}
