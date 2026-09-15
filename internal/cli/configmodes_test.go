package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/paths"
)

// readableByOthers is every file `server install` leaves under /etc/nodary that
// group or world may read, and why each one is safe there.
//
// An allowlist rather than a rule about names, for the reason
// internal/install/secrets_test.go gives about ExecStart=: "does this file hold
// a credential" is a judgment the next person should have to make deliberately.
// The two that matter were 0640 through every release so far — and gateway.env
// is *chowned to the service account*, so its group is the account the data
// plane runs as, and presenting that key to 127.0.0.1:4000 reaches LiteLLM
// directly, past nodary's allowlist, quota and metering.
var readableByOthers = map[string]string{
	"server.toml":             "addresses and paths; the service account reads it, and it names no credential",
	"litellm.env":             "a digest-pinned image reference, which is public by construction",
	"pki/agent-ca.crt":        "a certificate, which every node is handed at enrollment",
	"pki/server.crt":          "a certificate, which every client is shown at connection",
	"components.json":         "what was placed on this host, with digests; an inventory, not a secret",
	"advisories.toml":         "signed published content, meaningless to withhold",
	"advisories.toml.minisig": "the signature over it",
}

// stagedConfigDir runs an offline `server install` into a temporary tree and
// returns the configuration directory it wrote.
func stagedConfigDir(t *testing.T) string {
	t.Helper()
	a := newAppliance(t)
	dir := filepath.Join(a.dir, "etc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runWithStdin(t, "", "server", "install",
		"--root", a.dir, "--offline", "--db", a.db, "--secret-key", a.key,
		"--config", filepath.Join(dir, "server.toml"),
		"--user", "", "--skip-preflight", "--bind", "127.0.0.1:18443")
	if code != ExitOK {
		t.Fatalf("server install: exit %d, %s", code, stderr)
	}
	return dir
}

// dev/specs/08-data-model.md §4. The LiteLLM master key cannot be sealed the
// way TOTP seeds and the agent CA are — LiteLLM reads a plain YAML file and has
// no way to consume a sealed value — so the file mode is the whole control, and
// a test is the only thing that keeps a mode from drifting back.
func TestNoFileTheInstallWritesLeaksACredentialToItsGroup(t *testing.T) {
	dir := stagedConfigDir(t)

	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		// --root prefixes the default paths too, so the staged tree carries
		// /etc/nodary and /etc/systemd underneath this one. Unit files and the
		// layout are not this test's subject.
		if strings.HasPrefix(rel, "systemd"+string(filepath.Separator)) ||
			strings.HasPrefix(rel, "nodary"+string(filepath.Separator)) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o077 == 0 {
			return nil
		}
		if _, ok := readableByOthers[rel]; !ok {
			t.Errorf("%s is mode %04o, so group or world can read it. Write it 0600, or say "+
				"in readableByOthers why it is safe to publish.", rel, info.Mode().Perm())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// And the two that hold the key are named, so a future writer that creates one
// of them at a looser mode fails here even if the walk above is narrowed.
func TestTheMasterKeyFilesAre0600(t *testing.T) {
	dir := stagedConfigDir(t)
	for _, name := range []string{"gateway.env", "litellm.yaml"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != paths.ModeMasterKey {
			t.Errorf("%s is %04o, want %04o", name, got, paths.ModeMasterKey)
		}
	}
}

// A host installed by an earlier release has files at the mode that release
// gave them, and neither writer rewrites a file whose content has not moved —
// so tightening has to be unconditional or it never reaches an existing install.
func TestAReinstallTightensFilesAnOlderReleaseLeftOpen(t *testing.T) {
	dir := stagedConfigDir(t)
	for _, name := range []string{"gateway.env", "litellm.yaml"} {
		if err := os.Chmod(filepath.Join(dir, name), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	e := env{stdout: os.Stderr, stderr: os.Stderr}
	restrictConfigSecrets(e, dir)

	for _, name := range []string{"gateway.env", "litellm.yaml"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != paths.ModeMasterKey {
			t.Errorf("%s stayed %04o; a re-run must put the mode back", name, got)
		}
	}
}
