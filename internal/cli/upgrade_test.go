package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/components"
)

// upgradeTree stages a host that was installed by some earlier release: an
// /opt tree pointing at a version that is not this one, a litellm.env holding
// a superseded image, and an ownership record whose containerd digest has
// moved. Returns the --root prefix.
func upgradeTree(t *testing.T, release, image, containerdSHA string) string {
	t.Helper()
	root := t.TempDir()
	conf := filepath.Join(root, "etc", "nodary")
	if err := os.MkdirAll(filepath.Join(root, "opt", "nodary", release), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(conf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(release, filepath.Join(root, "opt", "nodary", "current")); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(conf, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("litellm.env", "NODARY_LITELLM_IMAGE="+image+"\n")
	record, err := json.Marshal(components.Ownership{
		NodaryVersion: release,
		Components: []components.Owned{{
			Component: "containerd", Version: "2.0.0",
			Path: "/usr/local/bin/containerd", SHA256: containerdSHA, Placed: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	write(components.OwnershipFile, string(record))
	return root
}

// manifestSHA is what this build pins for a component on the host platform.
func manifestSHA(t *testing.T, name string) string {
	t.Helper()
	m, err := components.Load()
	if err != nil {
		t.Fatal(err)
	}
	plat := resolvePlatform("host")
	for _, c := range m.Components {
		if c.Name == name {
			return c.Platforms[plat].SHA256
		}
	}
	t.Fatalf("the manifest pins no %s for %s", name, plat)
	return ""
}

// R5-15. `upgrade --check` answers one question — which pins move, and to what
// — without a session, a ceremony or a byte written. Every row here is a real
// comparison against host state: an operator who cannot see the diff before
// running an upgrade has no way to tell a CVE response from a no-op.
func TestUpgradeCheckNamesEveryPinThatMoves(t *testing.T) {
	root := upgradeTree(t, "0.0.1-ancient", "ghcr.io/berriai/litellm@sha256:"+strings.Repeat("a", 64),
		strings.Repeat("b", 64))

	code, stdout, stderr := run(t, "upgrade", "--check", "--root", root, "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	var got struct {
		Version string `json:"version"`
		Moves   []move `json:"moves"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("%v: %s", err, stdout)
	}
	if got.Version != buildinfo.Version {
		t.Errorf("version = %q, want %q", got.Version, buildinfo.Version)
	}

	by := map[string]move{}
	for _, w := range got.Moves {
		by[w.What] = w
	}
	for _, what := range []string{"nodary", "litellm", "containerd"} {
		w, ok := by[what]
		if !ok {
			t.Fatalf("no move for %s: %+v", what, got.Moves)
		}
		if w.From == "" || w.To == "" || w.From == w.To {
			t.Errorf("%s: from %q to %q", what, w.From, w.To)
		}
	}
	if from := by["nodary"].From; from != "0.0.1-ancient" {
		t.Errorf("nodary moves from %q, want the version `current` points at", from)
	}
	// The digest, not the version alone: a component can be rebuilt under a
	// name that did not move, and the digest is the thing an advisory names.
	if to := by["containerd"].To; !strings.Contains(to, manifestSHA(t, "containerd")[:12]) {
		t.Errorf("containerd moves to %q, which names no digest", to)
	}

	// An image the manifest pins but this host never placed is not a move: it
	// is pulled by the runtime at unit start, and the environment file above is
	// where its pin actually lives.
	for _, w := range got.Moves {
		if w.What == "vllm" || w.What == "grafana" {
			t.Errorf("%s is an image and has no file on this host to move", w.What)
		}
	}
}

// A host already at this release has nothing to move, and must say so rather
// than report a busy no-op an operator would run.
func TestUpgradeCheckIsSilentWhenNothingMoved(t *testing.T) {
	m, err := components.Load()
	if err != nil {
		t.Fatal(err)
	}
	image, err := imageFor(m, "litellm", resolvePlatform("host"))
	if err != nil {
		t.Fatal(err)
	}
	root := upgradeTree(t, buildinfo.Version, image, manifestSHA(t, "containerd"))

	code, stdout, stderr := run(t, "upgrade", "--check", "--root", root)
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "nothing to move") {
		t.Errorf("stdout = %q", stdout)
	}
}

// The reason this verb exists: a release that moves the LiteLLM digest has to
// reach /etc/nodary/litellm.env, because that is the only place the running
// container's image is named. And it must reach nothing else in that
// directory — litellm.yaml is `gateway sync`'s file, and rendering a fresh one
// here would replace a control plane's routes with the empty model_list a
// first install starts from.
func TestUpgradeRepinsLiteLLMAndLeavesItsRoutesAlone(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "operator")

	root := upgradeTree(t, "0.0.1-ancient",
		"ghcr.io/berriai/litellm@sha256:"+strings.Repeat("a", 64), strings.Repeat("b", 64))
	conf := filepath.Join(root, "etc", "nodary")
	routes := "model_list:\n  - model_name: gemma\n"
	if err := os.WriteFile(filepath.Join(conf, "litellm.yaml"), []byte(routes), 0o640); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := run(t, "upgrade", "--root", root, "--offline", "--user", "",
		"--db", a.db, "--secret-key", a.key, "--credentials", a.creds,
		"--justify", "CVE-2026-0000 in the data plane", "--yes")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s\n%s", code, stderr, stdout)
	}

	m, err := components.Load()
	if err != nil {
		t.Fatal(err)
	}
	want, err := imageFor(m, "litellm", resolvePlatform("host"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(conf, "litellm.env"))
	if err != nil {
		t.Fatal(err)
	}
	if got := trimEnvValue(string(body), "NODARY_LITELLM_IMAGE"); got != want {
		t.Errorf("litellm.env pins %q, want %q", got, want)
	}
	if got, _ := os.ReadFile(filepath.Join(conf, "litellm.yaml")); string(got) != routes {
		t.Errorf("litellm.yaml was rewritten:\n%s", got)
	}

	// `current` follows the release this binary is, which is what every unit's
	// ExecStart resolves through.
	if got := installedRelease(filepath.Join(root, "opt", "nodary")); got != buildinfo.Version {
		t.Errorf("current points at %q, want %q", got, buildinfo.Version)
	}

	// R5-15: the pre-upgrade backup is taken automatically and named in the
	// output. An upgrade that cannot be undone is one nobody runs.
	backup := ""
	for _, line := range strings.Split(stdout, "\n") {
		for _, f := range strings.Fields(line) {
			if strings.Contains(f, "pre-upgrade-") && strings.HasSuffix(f, ".tar.gz") {
				backup = f
			}
		}
	}
	if backup == "" {
		t.Fatalf("no backup named in the output:\n%s", stdout)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Errorf("the named backup is not there: %v", err)
	}
	held := archiveMembers(t, backup)
	if _, ok := held["nodary.db"]; !ok {
		t.Errorf("the pre-upgrade backup holds no database: %v", held)
	}
}

// --to would have to fetch a release, and verifying one needs a release signing
// key that does not exist yet. Refused by name, with the path that does work:
// an upgrade that silently downloaded something unverified is the failure 01 §2
// has no override flag for.
func TestUpgradeRefusesToFetchAReleaseItCannotVerify(t *testing.T) {
	code, _, stderr := run(t, "upgrade", "--to", "9.9.9", "--check")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "install.sh") {
		t.Errorf("the refusal does not name the path that works: %q", stderr)
	}
}

// A pin file nobody can read is not a pin that did not move. Guessing either
// way answers "is this host exposed" from a file that was never opened, which
// is the one thing this verb must not do.
func TestUpgradeCheckRefusesToGuessFromAnUnreadablePin(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads anything, so there is no unreadable file to make")
	}
	root := upgradeTree(t, "0.0.1-ancient", "ghcr.io/berriai/litellm@sha256:"+strings.Repeat("a", 64),
		strings.Repeat("b", 64))
	if err := os.Chmod(filepath.Join(root, "etc", "nodary", components.OwnershipFile), 0o000); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := run(t, "upgrade", "--check", "--root", root)
	if code != ExitFailure {
		t.Fatalf("exit = %d, want %d\n%s", code, ExitFailure, stdout)
	}
	if !strings.Contains(stderr, components.OwnershipFile) {
		t.Errorf("the failure does not name the file: %q", stderr)
	}
}
