package cli

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// archiveMembers lists what an archive holds, with each member's mode.
func archiveMembers(t *testing.T, path string) map[string]os.FileMode {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()

	out := map[string]os.FileMode{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = os.FileMode(h.Mode).Perm()
	}
}

// backupTree stands up a control plane with a configuration directory beside
// it, and returns the two paths.
func backupTree(t *testing.T) (a *appliance, configDir string) {
	t.Helper()
	a = newAppliance(t)
	a.addUser("alice", "operator")

	configDir = filepath.Join(a.dir, "etc")
	if err := os.MkdirAll(filepath.Join(configDir, "pki"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The sealing key, and the two files that stop every node re-enrolling.
	for path, mode := range map[string]os.FileMode{
		"secret.key":              0o400,
		"server.toml":             0o644,
		"pki/agent-ca.crt":        0o644,
		"pki/agent-ca.crt.sealed": 0o600,
	} {
		if err := os.WriteFile(filepath.Join(configDir, path), []byte("contents of "+path), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(configDir, path), mode); err != nil {
			t.Fatal(err)
		}
	}
	return a, configDir
}

// R2-37. docs/specs/08-data-model.md §4 said `nodary backup create` captures
// the database and the key that unseals it; until this landed that sentence
// described nothing that runs, and the stated recovery story — "it is a single
// file" — left an operator to discover at restore time that every node had to
// re-enroll.
func TestBackupCapturesTheDatabaseAndTheKeyThatUnsealsIt(t *testing.T) {
	a, configDir := backupTree(t)
	dest := filepath.Join(t.TempDir(), "nodary-backup.tar.gz")
	if err := os.Chmod(filepath.Dir(dest), 0o700); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := a.run("backup", "create", "--out", dest, "--config-dir", configDir)
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	if strings.TrimSpace(stdout) != dest {
		t.Errorf("stdout should be the path alone, got %q", stdout)
	}

	held := archiveMembers(t, dest)
	for _, want := range []string{
		"backup.json", "nodary.db",
		"config/secret.key", "config/server.toml",
		"config/pki/agent-ca.crt", "config/pki/agent-ca.crt.sealed",
	} {
		if _, ok := held[want]; !ok {
			t.Errorf("the archive holds no %s: %v", want, held)
		}
	}

	// The archive itself is as sensitive as the key inside it.
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the archive is mode %04o, want 0600", mode)
	}

	// 08 §4 requires this said loudly wherever backup is documented, and the
	// output is where an operator actually reads it.
	for _, want := range []string{"secret.key", "as sensitive as"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the output does not warn about the key it just copied (%q):\n%s", want, stderr)
		}
	}
}

// The refusal 08 §4 names.
func TestBackupRefusesAWorldReadableDestination(t *testing.T) {
	a, configDir := backupTree(t)
	exposed := t.TempDir()
	if err := os.Chmod(exposed, 0o755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(exposed, "nodary-backup.tar.gz")

	code, _, stderr := a.run("backup", "create", "--out", dest, "--config-dir", configDir)
	if code == ExitOK {
		t.Fatalf("a world-readable destination was accepted:\n%s", stderr)
	}
	if !strings.Contains(stderr, "secret.key") {
		t.Errorf("the refusal does not say what is at stake:\n%s", stderr)
	}
	// And it names a way out rather than only saying no.
	if !strings.Contains(stderr, "install -d -m 0700") {
		t.Errorf("the refusal does not name the fix:\n%s", stderr)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Error("a refused backup still wrote a file")
	}
}

// A backup that silently replaced last night's would be worse than one that did
// not run.
func TestBackupNeverOverwrites(t *testing.T) {
	a, configDir := backupTree(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "nodary-backup.tar.gz")

	if code, _, stderr := a.run("backup", "create", "--out", dest, "--config-dir", configDir); code != ExitOK {
		t.Fatalf("the first backup: %d %s", code, stderr)
	}
	before, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, _ := a.run("backup", "create", "--out", dest, "--config-dir", configDir); code == ExitOK {
		t.Fatal("a second backup overwrote the first")
	}
	after, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("the existing archive was modified")
	}
}

// The round trip, which is the only thing that makes a backup a backup.
func TestARestoredBackupIsAWorkingControlPlane(t *testing.T) {
	a, configDir := backupTree(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "nodary-backup.tar.gz")
	if code, _, stderr := a.run("backup", "create", "--out", dest, "--config-dir", configDir); code != ExitOK {
		t.Fatalf("create: %d %s", code, stderr)
	}

	// Somewhere else entirely, as a rebuilt host would be.
	target := t.TempDir()
	restoredDB := filepath.Join(target, "nodary.db")
	restoredConfig := filepath.Join(target, "etc")

	code, _, stderr := run(t, "backup", "restore", "--from", dest,
		"--db", restoredDB, "--config-dir", restoredConfig)
	if code != ExitOK {
		t.Fatalf("restore: %d %s", code, stderr)
	}

	// The sealing key came back at 0400, not at whatever the umask said. A key
	// restored 0644 is a silent total compromise.
	info, err := os.Stat(filepath.Join(restoredConfig, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o400 {
		t.Errorf("secret.key restored as %04o, want 0400", mode)
	}

	// The database is not merely present: its chain verifies, which is the
	// assertion that would catch a torn copy of a live WAL database.
	code, _, stderr = run(t, "audit", "verify", "--db", restoredDB)
	if code != ExitOK {
		t.Fatalf("the restored chain does not verify: %d %s", code, stderr)
	}
	// And the user who existed at backup time is still there.
	code, stdout, _ := run(t, "user", "list", "--db", restoredDB)
	if code != ExitOK || !strings.Contains(stdout, "alice") {
		t.Errorf("the restored database has lost its users: %d %q", code, stdout)
	}

	// Restoring again refuses rather than mixing two moments together.
	if code, _, stderr := run(t, "backup", "restore", "--from", dest,
		"--db", restoredDB, "--config-dir", restoredConfig); code == ExitOK {
		t.Errorf("restoring over an existing installation was allowed:\n%s", stderr)
	}
}

// A database without its key restores into a control plane that starts and
// cannot read its own secrets, and finds out weeks later at a TOTP prompt. It
// is caught before anything is written instead.
func TestRestoreRefusesAnArchiveWithNoSealingKey(t *testing.T) {
	a, configDir := backupTree(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "nodary-backup.tar.gz")
	if code, _, stderr := a.run("backup", "create", "--out", dest, "--config-dir", configDir); code != ExitOK {
		t.Fatalf("create: %d %s", code, stderr)
	}

	// Rebuilt without the key, the way a hand-rolled "just tar the database"
	// would be.
	stripped := filepath.Join(dir, "stripped.tar.gz")
	stripKey(t, dest, stripped)

	target := t.TempDir()
	code, _, stderr := run(t, "backup", "restore", "--from", stripped,
		"--db", filepath.Join(target, "nodary.db"), "--config-dir", filepath.Join(target, "etc"))
	if code == ExitOK {
		t.Fatal("an archive with no sealing key was restored")
	}
	if !strings.Contains(stderr, "sealed under it") {
		t.Errorf("the refusal does not explain what would break:\n%s", stderr)
	}
	if _, err := os.Stat(filepath.Join(target, "nodary.db")); err == nil {
		t.Error("the refused restore still wrote the database")
	}
}

func stripKey(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	gzr, err := gzip.NewReader(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	gzw := gzip.NewWriter(out)
	tw := tar.NewWriter(gzw)

	tr := tar.NewReader(gzr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == "config/secret.key" {
			continue
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(tw, tr); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
}
