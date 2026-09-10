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

	a.addUser("alice", "operator")
	code, stdout, stderr := a.run("model", "register", "acme/tiny",
		"--node", "fractal", "--models-dir", models, "--port", "8001",
		"--grant", "alice", "--yes", "--justify", "first model")
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

	// The grant rides along, because a route nobody may call is not a served
	// route: docs/specs/06-gateway.md §2 denies by default.
	for _, want := range []string{"+ model acme/tiny", "+ deployment tiny-fractal",
		"+ route tiny", "+ grant alice → tiny"} {
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

// TestModelRegisterRemoteNeedsAManifestButNoWeightsOnDisk is the other half
// of R4-33: registering `source: remote` succeeds with no weights on this
// machine at all — nothing here downloads anything, the manifest is what
// makes the resulting catalog entry checkable once an agent does.
func TestModelRegisterRemoteNeedsAManifestButNoWeightsOnDisk(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")

	manifest := filepath.Join(t.TempDir(), "nodary-manifest.sha256")
	body := strings.Repeat("a", 64) + "  config.json\n" + strings.Repeat("b", 64) + "  model.safetensors\n"
	if err := os.WriteFile(manifest, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := a.run("model", "register", "acme/tiny",
		"--source", "remote", "--manifest", manifest,
		"--node", "fractal", "--yes", "--justify", "remote model")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "2 file(s) named") {
		t.Errorf("did not report what the manifest named:\n%s", stdout)
	}
	for _, want := range []string{"+ model acme/tiny", "+ deployment tiny-fractal", "+ route tiny"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not report %q:\n%s", want, stdout)
		}
	}

	_, show, _ := a.run("config", "show", "--format", "json")
	if !strings.Contains(show, `"source": "remote"`) {
		t.Errorf("the catalog entry is not source: remote:\n%s", show)
	}
	if !strings.Contains(show, `"manifest_body"`) {
		t.Errorf("the manifest's content was not carried into the snapshot:\n%s", show)
	}
}

func TestModelRegisterRemoteRefusesWithNoManifest(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")

	code, _, stderr := a.run("model", "register", "acme/tiny",
		"--source", "remote", "--node", "fractal", "--yes", "--justify", "x")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d: %s", code, ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "--manifest is required") {
		t.Errorf("did not say why it refused:\n%s", stderr)
	}
}

func TestModelRegisterRefusesAnUnknownSource(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")

	code, _, stderr := a.run("model", "register", "acme/tiny",
		"--source", "sneakernet", "--node", "fractal", "--yes", "--justify", "x")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d: %s", code, ExitUsage, stderr)
	}
	if !strings.Contains(stderr, `"sneakernet"`) {
		t.Errorf("did not name the bad value:\n%s", stderr)
	}
}
