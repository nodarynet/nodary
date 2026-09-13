package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
)

// stageSingleFile places a `single-file` model and returns the models root and
// the manifest's own digest.
func stageSingleFile(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir, err := ModelDir(root, "single-file", "acme/tiny")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var manifest strings.Builder
	for _, name := range sortedNames(files) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(files[name]), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(files[name]))
		manifest.WriteString(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	}
	body := []byte(manifest.String())
	if err := os.WriteFile(filepath.Join(dir, ManifestName), body, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return root, hex.EncodeToString(sum[:])
}

func sortedNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Deterministic, so a multi-file manifest lists the same order every run.
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func llamaDeployment() api.DesiredDeployment {
	return api.DesiredDeployment{
		ID: "dep_llama", Model: "acme/tiny", Backend: "llama-cpp",
		Image:  "ghcr.io/ggml-org/llama.cpp@sha256:" + strings.Repeat("a", 64),
		GPUs:   []int{0},
		Params: json.RawMessage(`{"max_context":4096,"gpu_layers":33,"host":"0.0.0.0"}`),
		Port:   8001, Network: api.IsolatedNetwork, State: "ready",
	}
}

func singleFileDoc(d api.DesiredDeployment, digest string) api.Desired {
	return api.Desired{
		Rev: 7, Node: "gpu-01", Deployments: []api.DesiredDeployment{d},
		Staging: []api.DesiredStaging{{Model: "acme/tiny", Source: "local",
			Layout: "single-file", ManifestSHA256: digest, ExpectBytes: 40}},
	}
}

// The gap that would have made the descriptor useless. `inContainer` was the
// mount path for every layout but `hf-cache`, so llama.cpp would have been told
// `-m /models` — a directory — and failed at start with a message about the
// file format, a long way from the cause. Only the manifest knows the weights'
// own name.
func TestASingleFileDeploymentNamesTheWeightsAndNotTheirDirectory(t *testing.T) {
	root, digest := stageSingleFile(t, map[string]string{"tiny-q4_k_m.gguf": "GGUF, allegedly"})

	p, err := Build(singleFileDoc(llamaDeployment(), digest),
		PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Refused) != 0 {
		t.Fatalf("refused %+v", p.Refused)
	}
	if len(p.Units) != 1 {
		t.Fatalf("units = %d, want one: %+v", len(p.Units), p.Stage)
	}
	if got := p.Stage[0].File; got != "tiny-q4_k_m.gguf" {
		t.Errorf("stage names %q, want the file the manifest lists", got)
	}

	var args string
	for _, v := range p.Units[0].Env {
		if v.Key == "NODARY_ARGS" {
			args = v.Value
		}
	}
	if !strings.Contains(args, "-m /models/tiny-q4_k_m.gguf") {
		t.Errorf("argv = %q, want the weights file under the mount path", args)
	}
	// Through [backend.extra], which is the whole reason llama.cpp could not
	// be embedded before.
	if !strings.Contains(args, "-ngl 33") {
		t.Errorf("argv = %q, want gpu_layers rendered", args)
	}
}

// The manifest is a few lines of text beside hundreds of gigabytes of weights,
// so `--no-verify` — which exists to skip re-reading the bytes — still resolves
// the name. Otherwise `agent plan` could never render a llama.cpp argv at all.
func TestTheWeightsNameIsResolvedEvenWithoutVerification(t *testing.T) {
	root, digest := stageSingleFile(t, map[string]string{"tiny-q4_k_m.gguf": "GGUF, allegedly"})

	p, err := Build(singleFileDoc(llamaDeployment(), digest),
		PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: false})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Stage[0].File; got != "tiny-q4_k_m.gguf" {
		t.Errorf("file = %q under --no-verify; the manifest is cheap to read", got)
	}
	if p.Stage[0].State != "unverified" {
		t.Errorf("state = %q, want unverified: the bytes were not read", p.Stage[0].State)
	}
}

// A layout called `single-file` holding three files is a contradiction, and the
// one case that really produces it — a sharded GGUF — is a convention this
// build does not invent. Refused, with the deployment saying why, rather than
// picking one and serving the wrong weights in silence.
func TestAShardedSingleFileModelIsRefusedRatherThanGuessedAt(t *testing.T) {
	root, digest := stageSingleFile(t, map[string]string{
		"tiny-00001-of-00002.gguf": "shard one",
		"tiny-00002-of-00002.gguf": "shard two",
	})

	p, err := Build(singleFileDoc(llamaDeployment(), digest),
		PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Units) != 0 {
		t.Fatalf("built a unit for a model it cannot name: %+v", p.Units)
	}
	if len(p.Refused) != 1 {
		t.Fatalf("refused %+v, want one", p.Refused)
	}
	if !strings.Contains(p.Refused[0].Reason, ManifestName) {
		t.Errorf("reason = %q, want it to point at the manifest", p.Refused[0].Reason)
	}
}

// The name lands in NODARY_ARGS, which the unit expands unquoted so systemd
// splits it on whitespace — the same reason extra_args refuses a space rather
// than escaping it.
func TestWeightsNamedWithASpaceAreRefused(t *testing.T) {
	root, _ := stageSingleFile(t, map[string]string{"my model.gguf": "GGUF, allegedly"})
	if _, err := SingleFileName(root, "acme/tiny"); err == nil {
		t.Fatal("a weights name with a space was accepted")
	} else if !strings.Contains(err.Error(), "whitespace") {
		t.Errorf("error = %v, want it to name the problem", err)
	}
}
