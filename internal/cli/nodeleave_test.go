package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/agent"
)

// enrolledTree writes what enrollment leaves on a node: agent.toml and the
// certificate and key it names. Under a --root prefix, so the teardown can be
// run for real without a node to run it on.
func enrolledTree(t *testing.T, models string) (root string, conf, cert, key string) {
	t.Helper()
	root = t.TempDir()
	dir := filepath.Join(root, "etc", "nodary")
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0o750); err != nil {
		t.Fatal(err)
	}
	conf = filepath.Join(dir, "agent.toml")
	cert, key = filepath.Join(pki, "node.crt"), filepath.Join(pki, "node.key")
	for _, p := range []string{cert, key} {
		if err := os.WriteFile(p, []byte("material"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	body := agent.RenderConfig(agent.Config{
		Server: "https://127.0.0.1:8443", Name: "fractal",
		CAFingerprint: "sha256:" + strings.Repeat("a", 64),
		Certificate:   cert, Key: key, ModelsDir: models,
	})
	if err := os.WriteFile(conf, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return root, conf, cert, key
}

// R4-06 / docs/specs/12-node-guardrails.md §5: leaving destroys the
// credentials that made this machine a node. Anything short of that is a host
// that can still be told what to run.
func TestNodeLeaveDestroysTheCredentials(t *testing.T) {
	root, conf, cert, key := enrolledTree(t, t.TempDir())

	code, stdout, stderr := run(t, "node", "leave", "--root", root, "--yes")
	if code != ExitOK {
		t.Fatalf("node leave: exit %d: %s\n%s", code, stderr, stdout)
	}
	for _, p := range []string{conf, cert, key} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived the teardown: %v", p, err)
		}
	}
	// The half it cannot do has to be named, or an operator believes the
	// fleet was told and the node's certificate stays valid.
	if !strings.Contains(stderr, "nodary node revoke fractal") {
		t.Errorf("leaving does not name the server-side half: %s", stderr)
	}
}

// Weights are the expensive thing on the disk and are kept unless asked for,
// the same split uninstall draws.
func TestNodeLeaveKeepsWeightsUnlessAsked(t *testing.T) {
	models := t.TempDir()
	weights := filepath.Join(models, "hub", "models--acme--tiny")
	if err := os.MkdirAll(weights, 0o755); err != nil {
		t.Fatal(err)
	}
	root, _, _, _ := enrolledTree(t, models)

	if code, _, stderr := run(t, "node", "leave", "--root", root, "--yes"); code != ExitOK {
		t.Fatalf("node leave: exit %d: %s", code, stderr)
	}
	if _, err := os.Stat(weights); err != nil {
		t.Errorf("leaving deleted weights nobody asked it to: %v", err)
	}

	// Asked for, they go — and the flag has to be able to find them, which
	// means reading models_dir out of agent.toml before removing it.
	root2, _, _, _ := enrolledTree(t, models)
	if code, _, stderr := run(t, "node", "leave", "--root", root2, "--yes", "--purge-models"); code != ExitOK {
		t.Fatalf("node leave --purge-models: exit %d: %s", code, stderr)
	}
	if _, err := os.Stat(weights); !os.IsNotExist(err) {
		t.Errorf("--purge-models left the weights behind: %v", err)
	}
}

// A host that was never enrolled has nothing to leave, and saying so beats
// reporting a successful teardown of nothing.
func TestNodeLeaveOnAHostThatNeverJoined(t *testing.T) {
	code, _, stderr := run(t, "node", "leave", "--root", t.TempDir(), "--yes")
	if code == ExitOK {
		t.Fatal("leaving succeeded on a host that never enrolled")
	}
	if !strings.Contains(stderr, "not enrolled") {
		t.Errorf("stderr = %q, want it to say this host is not a node", stderr)
	}
}

// Destroying credentials is not something to do on a typo, so it asks first
// and a refusal changes nothing.
func TestNodeLeaveAsksBeforeDestroyingAnything(t *testing.T) {
	root, conf, _, _ := enrolledTree(t, t.TempDir())

	code, _, stderr := runWithStdin(t, "n\n", "node", "leave", "--root", root)
	if code != ExitOK {
		t.Fatalf("declining should not be an error: exit %d: %s", code, stderr)
	}
	if _, err := os.Stat(conf); err != nil {
		t.Errorf("declining still destroyed the credentials: %v", err)
	}
	if !strings.Contains(stderr, "nothing was changed") {
		t.Errorf("stderr = %q, want it to say nothing happened", stderr)
	}
}
