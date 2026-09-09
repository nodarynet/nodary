package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/agent"
)

// TestModelRegisterTurnsPlacedWeightsIntoAServedRoute.
//
// The step that was a shell script this repository ships and no install
// places. Everything after "the weights are on disk" is arithmetic — digest
// each file, hash the list, find the pinned image, name a model, a deployment
// and a route — and an operator was expected to do all of it in TOML by hand,
// where every mistake surfaces minutes later inside a container.
func TestModelRegisterTurnsPlacedWeightsIntoAServedRoute(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")

	models := t.TempDir()
	dir := filepath.Join(models, "hub", "models--acme--tiny")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"config.json": `{"architectures":["Tiny"]}`, "model.safetensors": "tensors",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	code, stdout, stderr := a.run("model", "register", "acme/tiny",
		"--node", "fractal", "--models-dir", models, "--port", "8001",
		"--yes", "--justify", "first model")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}

	// The manifest travels with the weights, and nothing installed made one.
	manifest, err := os.ReadFile(filepath.Join(dir, agent.ManifestName))
	if err != nil {
		t.Fatalf("no manifest was written: %v", err)
	}
	entries, err := agent.ParseManifest(manifest)
	if err != nil {
		t.Fatalf("the manifest it wrote does not parse: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("manifest lists %d files, want 2: %s", len(entries), manifest)
	}

	for _, want := range []string{"+ model acme/tiny", "+ deployment tiny-fractal", "+ route tiny"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not report %q:\n%s", want, stdout)
		}
	}
	// The route name is what a client sends as `model`, and it is not the model
	// id — a fleet that is working perfectly answers 404 to the wrong one.
	if !strings.Contains(stderr, `ask for it as "tiny"`) {
		t.Errorf("the name clients use is not stated:\n%s", stderr)
	}

	// The catalog holds the manifest digest, not the manifest: the weights
	// carry the list and the control plane carries the one digest that makes
	// the list checkable.
	_, show, _ := a.run("config", "show", "--format", "json")
	if !strings.Contains(show, `"manifest_sha256"`) || strings.Contains(show, `"manifest_sha256": ""`) {
		t.Errorf("the catalog entry carries no manifest digest:\n%s", show)
	}
	if !strings.Contains(show, "vllm/vllm-openai@sha256:") {
		t.Errorf("the deployment does not pin an image by digest:\n%s", show)
	}
}
