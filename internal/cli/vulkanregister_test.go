package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/components"
)

// TestAnAMDNodeGetsTheVulkanImage is the whole slice through the verb an
// operator actually types, against the manifest this binary actually ships.
//
// Everything else about the vendor axis is either a unit test on a fixture
// manifest or a table on gpuFlag. Neither can say whether a real `model
// register` against a real AMD node lands the Vulkan digest in the document
// that gets applied — which is the only claim that matters, and the one that
// breaks if any link resolves against the control plane instead of the node.
func TestAnAMDNodeGetsTheVulkanImage(t *testing.T) {
	m, err := components.Load()
	if err != nil {
		t.Fatal(err)
	}
	cuda, err := imageFor(m, "llama-cpp", "linux/amd64", "nvidia")
	if err != nil {
		t.Fatal(err)
	}
	vulkan, err := imageFor(m, "llama-cpp", "linux/amd64", "amd")
	if err != nil {
		t.Fatalf("this release pins no amd llama-cpp image: %v", err)
	}
	if cuda == vulkan {
		t.Fatal("the two builds are the same digest; nothing below can tell them apart")
	}

	a := newAppliance(t)
	a.enrolledAs("cuda-01", "linux", "amd64", offerOf("nvidia"))
	a.enrolledAs("vulkan-01", "linux", "amd64", offerOf("amd"))
	// vLLM has no Vulkan build and is not going to grow one, so an AMD node
	// registering against it is refused rather than handed the CUDA image.
	a.addUser("alice", "operator")

	models := t.TempDir()
	dir := filepath.Join(models, "acme--tiny")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tiny-q4_k_m.gguf"), []byte("GGUF, allegedly"), 0o644); err != nil {
		t.Fatal(err)
	}
	// vLLM declares hf-cache, so the same model has to be on the shelf in that
	// shape too — otherwise the vendor refusal below never runs, because the
	// weights check comes first and would be what refused.
	hf := filepath.Join(models, "hub", "models--acme--tiny")
	if err := os.MkdirAll(hf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hf, "config.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	register := func(node, backend, out string) (int, string) {
		t.Helper()
		code, _, stderr := a.run("model", "register", "acme/tiny",
			"--node", node, "--models-dir", models, "--backend", backend,
			"-o", out, "--yes", "--justify", "which image does this node get")
		return code, stderr
	}

	for _, tc := range []struct{ node, want, notWant string }{
		{"vulkan-01", vulkan, cuda},
		{"cuda-01", cuda, vulkan},
	} {
		doc := filepath.Join(t.TempDir(), tc.node+".toml")
		if code, stderr := register(tc.node, "llama-cpp", doc); code != ExitOK {
			t.Fatalf("%s: exit %d: %s", tc.node, code, stderr)
		}
		written, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(written), tc.want) {
			t.Errorf("%s: the document does not pin %s:\n%s", tc.node, tc.want, written)
		}
		if strings.Contains(string(written), tc.notWant) {
			t.Errorf("%s: the document pins the other vendor's image", tc.node)
		}
	}

	// The refusal an AMD node meets on every other backend. It has to name the
	// vendor and read as an answer, because it is one: there is no Vulkan vLLM
	// to configure, and an operator sent looking for a setting will not find it.
	code, stderr := register("vulkan-01", "vllm", filepath.Join(t.TempDir(), "no.toml"))
	if code == ExitOK {
		t.Fatal("vllm registered on an AMD node; there is no Vulkan build of it")
	}
	for _, want := range []string{"amd", "NVIDIA-only", "--image"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not say %q: %s", want, stderr)
		}
	}
}
