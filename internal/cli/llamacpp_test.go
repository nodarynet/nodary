package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/agent"
)

// The operator path for llama.cpp, end to end: weights placed by hand as a
// single GGUF, registered against the backend, and the pinned image resolved
// from the component manifest rather than typed.
//
// R6-02 kept llama.cpp out because it needs `[backend.extra]`, and a descriptor
// embedded whose features are unimplemented is a backend the binary claims to
// support and cannot run. This is what proves the claim is now true.
func TestRegisteringAGGUFAgainstLlamaCpp(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")

	// `single-file`, so the model directory is the flattened id rather than
	// the HuggingFace cache layout.
	models := t.TempDir()
	dir := filepath.Join(models, "acme--tiny")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tiny-q4_k_m.gguf"), []byte("GGUF, allegedly"), 0o644); err != nil {
		t.Fatal(err)
	}

	a.addUser("alice", "operator")
	code, stdout, stderr := a.run("model", "register", "acme/tiny",
		"--node", "fractal", "--models-dir", models, "--port", "8001",
		"--backend", "llama-cpp",
		"--grant", "alice", "--yes", "--justify", "a GGUF on the shelf")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}

	// The manifest travels with the weights, listing the one file.
	manifest, err := os.ReadFile(filepath.Join(dir, agent.ManifestName))
	if err != nil {
		t.Fatalf("no manifest was written: %v", err)
	}
	entries, err := agent.ParseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Path != "tiny-q4_k_m.gguf" {
		t.Fatalf("manifest = %+v, want the one GGUF", entries)
	}

	_ = stdout

	// And the image is the project's own, resolved from components.json by
	// digest — not a tag somebody can move. Read out of the document the verb
	// writes, with -o, which is where it actually lands.
	doc := filepath.Join(t.TempDir(), "register.toml")
	if code, _, stderr := a.run("model", "register", "acme/tiny",
		"--node", "fractal", "--models-dir", models, "--port", "8002",
		"--backend", "llama-cpp", "-o", doc,
		"--yes", "--justify", "reading the document"); code != ExitOK {
		t.Fatalf("register -o: %d %s", code, stderr)
	}
	written, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), "ghcr.io/ggml-org/llama.cpp@sha256:") {
		t.Errorf("the document does not pin the project's own image by digest:\n%s", written)
	}
	if !strings.Contains(string(written), `artifact = "single-file"`) {
		t.Errorf("the document does not record the backend's own layout:\n%s", written)
	}

	// The name the agent resolves for the argv, from the manifest this command
	// just wrote. Without it llama.cpp is handed `-m /models`, a directory.
	got, err := agent.SingleFileName(models, "acme/tiny")
	if err != nil {
		t.Fatalf("the weights cannot be named: %v", err)
	}
	if got != "tiny-q4_k_m.gguf" {
		t.Errorf("SingleFileName = %q", got)
	}
}

// The artifact kind is the backend's to declare, not a flag and not a constant.
// It was hardcoded to `hf-cache`, so `--backend llama-cpp` looked for a
// HuggingFace cache a GGUF is not in and then stamped a kind config.Apply
// refuses — the one path an operator would actually take, broken in two places
// at once.
func TestTheWeightsLayoutFollowsTheBackend(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")

	// A GGUF placed where the single-file layout puts it.
	models := t.TempDir()
	dir := filepath.Join(models, "acme--tiny")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tiny.gguf"), []byte("GGUF"), 0o644); err != nil {
		t.Fatal(err)
	}

	// vLLM declares `hf-cache`, so it looks somewhere else and says so rather
	// than registering a model whose weights nothing will find.
	code, _, stderr := a.run("model", "register", "acme/tiny",
		"--node", "fractal", "--models-dir", models, "--port", "8001",
		"--backend", "vllm",
		"--grant", "alice", "--yes", "--justify", "the wrong backend for these weights")
	if code == ExitOK {
		t.Fatal("vLLM accepted weights laid out for llama.cpp")
	}
	if !strings.Contains(stderr, filepath.Join("hub", "models--acme--tiny")) {
		t.Errorf("the refusal does not name where vLLM looked: %s", stderr)
	}

	// The same directory, the backend that declares that layout: accepted.
	if code, _, stderr := a.run("model", "register", "acme/tiny",
		"--node", "fractal", "--models-dir", models, "--port", "8001",
		"--backend", "llama-cpp",
		"--grant", "alice", "--yes", "--justify", "the right one"); code != ExitOK {
		t.Fatalf("llama-cpp refused weights in its own layout: %d %s", code, stderr)
	}
}

// A backend nobody has a descriptor for is refused before anything is digested,
// naming the flag rather than failing later inside config.Apply.
func TestRegisteringAgainstAnUnknownBackendIsRefused(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("fractal")
	a.addUser("alice", "operator")

	code, _, stderr := a.run("model", "register", "acme/tiny",
		"--node", "fractal", "--models-dir", t.TempDir(), "--port", "8001",
		// Not a real backend's name: one that is embedded later stops being
		// unknown and quietly takes this refusal with it.
		"--backend", "no-such-backend",
		"--grant", "alice", "--yes", "--justify", "a backend this build has not got")
	if code == ExitOK {
		t.Fatal("an unknown backend was accepted")
	}
	if !strings.Contains(stderr, "no-such-backend") {
		t.Errorf("the refusal does not name the backend: %s", stderr)
	}
}
