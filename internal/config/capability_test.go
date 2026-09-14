package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/config"
)

// R6-04/R6-05, docs/specs/04-backends.md §7: capabilities are enforced at
// enable time, not discovered at crash time.
//
// This is the spec's own table, driven. "Enable time" means here, in the
// applier — the agent refuses a deployment it cannot render too, but a minute
// later and on a GPU host, so what an operator sees is a change that was
// accepted and then did not happen.
func TestTheValidationTableIsWhatSection7Says(t *testing.T) {
	for _, c := range []struct {
		what   string
		models []config.Model
		dep    config.Deployment
		says   []string
	}{
		{
			what: "tensor parallelism on a backend that has none",
			models: []config.Model{{ID: "acme/gguf", Backend: "llama-cpp",
				Source: "local", Artifact: "single-file"}},
			dep: config.Deployment{ID: "dep_one", ModelID: "acme/gguf", NodeName: "gpu-01",
				Backend: "llama-cpp", GPUs: []int{0}, Port: 8001,
				Params: `{"tensor_parallel": 4}`},
			// It names what the backend does have, out of the descriptor
			// rather than out of a table in nodary's code.
			says: []string{"llama-cpp", "tensor parallel", "tensor_split"},
		},
		{
			what: "a quantization the backend cannot load",
			models: []config.Model{{ID: "acme/gguf", Backend: "llama-cpp",
				Source: "local", Artifact: "single-file"}},
			dep: config.Deployment{ID: "dep_one", ModelID: "acme/gguf", NodeName: "gpu-01",
				Backend: "llama-cpp", GPUs: []int{0}, Port: 8001,
				Params: `{"quantization": "awq"}`},
			says: []string{"llama-cpp", "awq", "gguf"},
		},
		{
			what: "a model staged in a layout its backend cannot read",
			models: []config.Model{{ID: "acme/gguf", Backend: "vllm",
				Source: "local", Artifact: "single-file"}},
			dep: config.Deployment{ID: "dep_one", ModelID: "acme/gguf", NodeName: "gpu-01",
				Backend: "vllm", GPUs: []int{0}, Port: 8001},
			says: []string{"acme/gguf", "single-file", "hf-cache"},
		},
		{
			what: "parallelism beyond the cards assigned",
			models: []config.Model{{ID: "acme/tiny", Backend: "vllm",
				Source: "local", Artifact: "hf-cache"}},
			dep: config.Deployment{ID: "dep_one", ModelID: "acme/tiny", NodeName: "gpu-01",
				Backend: "vllm", GPUs: []int{0, 1}, Port: 8001,
				Params: `{"tensor_parallel": 4}`},
			says: []string{"4", "2", "dep_one"},
		},
	} {
		t.Run(c.what, func(t *testing.T) {
			err := applierFor(t, c.models...)(c.dep)
			if err == nil {
				t.Fatal("applied, and the container would have failed at start instead")
			}
			// Recognizable as a bad document on both front ends. An unwrapped
			// refusal is a 500 with the message withheld, and a refusal that
			// names an operator's own mistake and then withholds it has told
			// them nothing.
			if !errors.Is(err, config.ErrInvalid) {
				t.Errorf("err = %v, want it recognizable as a bad document", err)
			}
			for _, want := range c.says {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not name %q: %v", want, err)
				}
			}
		})
	}
}

// 1 is not parallelism, it is the absence of it. Refusing it would make a
// document that spells out its defaults unportable between backends for no
// difference in what actually runs.
func TestADegreeOfOneIsNotParallelism(t *testing.T) {
	apply := applierFor(t, config.Model{ID: "acme/gguf", Backend: "llama-cpp",
		Source: "local", Artifact: "single-file"})
	if err := apply(config.Deployment{ID: "dep_one", ModelID: "acme/gguf", NodeName: "gpu-01",
		Backend: "llama-cpp", GPUs: []int{0}, Port: 8001,
		Params: `{"tensor_parallel": 1}`}); err != nil {
		t.Errorf("tensor_parallel 1 on a backend without tensor parallelism: %v", err)
	}
}

// The check is a gate, not a wall: what the descriptor declares, applies.
func TestWhatTheBackendDeclaresIsAccepted(t *testing.T) {
	apply := applier(t)
	if err := apply(config.Deployment{ID: "dep_one", ModelID: "acme/tiny", NodeName: "gpu-01",
		Backend: "vllm", GPUs: []int{0, 1}, Port: 8001,
		Params: `{"tensor_parallel": 2, "quantization": "awq"}`}); err != nil {
		t.Errorf("vllm declares tensor_parallel and awq, and both were refused: %v", err)
	}
}

// An unknown backend is left alone, for the reason checkArtifact gives: R6 owns
// which backends exist, and refusing here would make the applier a second place
// that decides.
func TestAnUnknownBackendIsNotJudgedHere(t *testing.T) {
	apply := applierFor(t, config.Model{ID: "acme/tiny", Backend: "mystery", Source: "local"})
	if err := apply(config.Deployment{ID: "dep_one", ModelID: "acme/tiny", NodeName: "gpu-01",
		Backend: "mystery", GPUs: []int{0}, Port: 8001,
		Params: `{"tensor_parallel": 8}`}); err != nil {
		t.Errorf("an unknown backend was judged against capabilities it never declared: %v", err)
	}
}
