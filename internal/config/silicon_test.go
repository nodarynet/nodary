package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/config"
)

// R6-16: a backend placed on silicon its descriptor does not declare is
// refused, here, by name.
//
// In the applier and not only on the node, which is dev/specs/04-backends.md
// §7's rule for every check of this shape: the agent refuses it too, but a
// minute later and on a GPU host, so what an operator would otherwise see is a
// change that was accepted and then did not happen.
func TestABackendIsRefusedOnSiliconItDoesNotDeclare(t *testing.T) {
	apply := applierFor(t, config.Model{ID: "acme/tiny", Backend: "vllm",
		Source: "local", Artifact: "hf-cache"})
	err := apply(config.Deployment{ID: "dep_one", ModelID: "acme/tiny", NodeName: "gpu-amd",
		Backend: "vllm", GPUs: []int{0}, Port: 8001})
	if err == nil {
		t.Fatal("vLLM was placed on a Radeon, and no vLLM image for one exists")
	}
	if !errors.Is(err, config.ErrInvalid) {
		t.Errorf("err = %v, want it recognizable as a bad document", err)
	}
	// The vendor by name, the node by name, and what the backend does run on —
	// the three things an operator needs to pick a different one.
	for _, want := range []string{"vllm", "amd", "gpu-amd", "nvidia"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

// The other half, and the point of the matrix: the cross-vendor backend is
// accepted on the same node.
func TestTheCrossVendorBackendIsAcceptedOnTheSameNode(t *testing.T) {
	apply := applierFor(t, config.Model{ID: "acme/gguf", Backend: "llama-cpp",
		Source: "local", Artifact: "single-file"})
	if err := apply(config.Deployment{ID: "dep_one", ModelID: "acme/gguf", NodeName: "gpu-amd",
		Backend: "llama-cpp", GPUs: []int{0}, Port: 8001}); err != nil {
		t.Errorf("llama.cpp declares amd and was refused on an AMD node: %v", err)
	}
}

// A node that enrolled and has never reported offers nothing, and a check with
// no input is not a refusal. The applier already refuses an unknown node with a
// better sentence, and inventing a vendor here would refuse every deployment
// written before its node first checked in.
func TestANodeThatHasOfferedNothingIsNotJudgedOnSilicon(t *testing.T) {
	apply := applierFor(t, config.Model{ID: "acme/tiny", Backend: "vllm",
		Source: "local", Artifact: "hf-cache"})
	if err := apply(config.Deployment{ID: "dep_one", ModelID: "acme/tiny", NodeName: "gpu-new",
		Backend: "vllm", GPUs: []int{0}, Port: 8001}); err != nil {
		t.Errorf("a node that has offered nothing was judged on its silicon: %v", err)
	}
}
