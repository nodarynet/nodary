package cli

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nodarynet/nodary/internal/components"
)

// TestTheMirrorHoldsWhatANodeNeeds is the one assertion that stops a silent,
// remote failure.
//
// docs/specs/01-install.md §3: only the control-plane host ever contacts an
// upstream source, and every GPU host bootstraps from this cache over mTLS. So
// the mirror must hold the **node** set. Filling it with the server's own
// components instead leaves the control plane looking perfectly healthy and
// `node install` stopping on a machine with no internet — a different machine,
// hours later, with nothing on the control plane to suggest why.
func TestTheMirrorHoldsWhatANodeNeeds(t *testing.T) {
	m, err := components.Load()
	if err != nil {
		t.Fatal(err)
	}
	want, err := mirrorComponents(m, "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(want) == 0 {
		t.Fatal("the mirror would be empty; no node could bootstrap from this control plane")
	}

	names := make([]string, 0, len(want))
	for _, c := range want {
		names = append(names, c.Name)
		if !c.HasRole(components.RoleNode) {
			t.Errorf("%s is in the mirror and is not a node component", c.Name)
		}
		// An image is pulled from a registry by digest, by the runtime, with
		// different credentials. Staging one into a file cache stages nothing.
		if c.Kind == components.KindImage {
			t.Errorf("%s is an image; it cannot be staged into the mirror", c.Name)
		}
	}

	// Without these a node has nothing to run a model in, so their absence is
	// the failure this test exists for rather than a detail of the manifest.
	for _, needed := range []string{"containerd", "runc", "cni-plugins", "nerdctl"} {
		if !slices.Contains(names, needed) {
			t.Errorf("the mirror would not hold %s; a node cannot run a deployment without it", needed)
		}
	}
	// And not the server's own stack, which is what it would hold if the role
	// were ever "corrected" to RoleServer.
	for _, wrong := range []string{"litellm", "grafana", "prometheus"} {
		if slices.Contains(names, wrong) {
			t.Errorf("the mirror holds %s, a server component; the mirror is what *nodes* fetch", wrong)
		}
	}
}

// TestOfflineInstallContactsNothing covers the flag an operator installing from
// a bundle needs, and that every test here relies on.
func TestOfflineInstallContactsNothing(t *testing.T) {
	a := newAppliance(t)
	code, _, stderr := runWithStdin(t, "", "server", "install",
		"--root", a.dir, "--offline", "--db", a.db, "--secret-key", a.key,
		"--config", filepath.Join(a.dir, "server.toml"),
		"--user", "", "--skip-preflight", "--bind", "127.0.0.1:18443")
	if code != ExitOK {
		t.Fatalf("server install --offline: exit %d, %s", code, stderr)
	}
	entries, err := os.ReadDir(filepath.Join(a.dir, "var", "lib", "nodary", "dist"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("--offline fetched %d artifact(s); it must contact nothing", len(entries))
	}
}
