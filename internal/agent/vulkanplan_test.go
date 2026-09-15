package agent

import (
	"strings"
	"testing"
)

// TestAnAMDNodePlansADeviceNodeAndNotCDI is the node half of the slice, driven
// through Build rather than through gpuFlag.
//
// gpuFlag's own table proves the argument; this proves the *plan* carries it —
// that a deployment on an AMD card is not refused somewhere upstream by a check
// written when every card was NVIDIA, and that what lands in the env file
// systemd reads is the device argument and nothing else.
//
// **It is llama.cpp, and it was vLLM until R6-16.** The original fixture put a
// vLLM deployment on a Radeon, which reads fine as a test of the device
// argument and is not a thing that can run: `vllm/vllm-openai` publishes no
// AMD image and the descriptor now says so. That the fixture had to change is
// the check working — a deployment nobody could have deployed was the shape
// this test was proving the plan would build.
func TestAnAMDNodePlansADeviceNodeAndNotCDI(t *testing.T) {
	root, digest := stageSingleFile(t, map[string]string{"tiny-q4_k_m.gguf": "GGUF, allegedly"})
	doc := singleFileDoc(llamaDeployment(), digest)

	// A host with an AMD card and an NVIDIA CDI specification present, which is
	// the mixed box this fleet actually develops on: the toolkit's answer must
	// not decide how a Radeon is reached.
	p, err := Build(doc, PlanOptions{
		ModelsDir: root, Verify: true,
		Present:    []GPU{{Index: 0, Vendor: VendorAMD, Render: "/dev/dri/renderD128"}},
		CDIDevices: []string{"nvidia.com/gpu=all"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Refused) != 0 {
		t.Fatalf("a deployment on an AMD card was refused: %+v", p.Refused)
	}
	if len(p.Units) != 1 {
		t.Fatalf("units = %d, want 1", len(p.Units))
	}

	env := string(p.Units[0].RenderEnv())
	if !strings.Contains(env, "NODARY_GPUS=--device /dev/dri/renderD128\n") {
		t.Errorf("the env file does not hand over the card's own device node:\n%s", env)
	}
	// The failure that would otherwise be invisible until the container starts
	// and finds no GPU: the CDI specification is NVIDIA's and says nothing
	// about this card.
	if strings.Contains(env, "--gpus") {
		t.Errorf("an AMD card was reached through CDI:\n%s", env)
	}

	// And the same document on an NVIDIA card still goes the old way, because
	// this is a second path and not a replacement.
	p, err = Build(doc, PlanOptions{
		ModelsDir: root, Verify: true,
		Present:    []GPU{{Index: 0, Vendor: VendorNVIDIA}},
		CDIDevices: []string{"nvidia.com/gpu=0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Units) != 1 {
		t.Fatalf("units = %d after the nvidia build: %+v", len(p.Units), p.Refused)
	}
	if env := string(p.Units[0].RenderEnv()); !strings.Contains(env, "NODARY_GPUS=--gpus device=0\n") {
		t.Errorf("the NVIDIA path changed:\n%s", env)
	}
}

// R6-16's node half. The applier refuses this and with the better message, in
// front of the operator who typed it — but a hand-edited document reaches a
// node without passing through that verb, and the alternative to refusing here
// is a container that starts, finds no device it understands and exits with a
// message about CUDA that names nothing an operator can act on.
func TestABackendIsRefusedOnSiliconItDoesNotDeclare(t *testing.T) {
	root, digest := stage(t, map[string]string{"config.json": "{}"})
	d := deployment()
	d.GPUs = []int{0}
	doc := desired(d)
	doc.Staging[0].ManifestSHA256 = digest

	p, err := Build(doc, PlanOptions{
		ModelsDir: root, Verify: true,
		Present: []GPU{{Index: 0, Vendor: VendorAMD, Render: "/dev/dri/renderD128"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Units) != 0 {
		t.Fatalf("vLLM was planned onto a Radeon: %+v", p.Units)
	}
	if len(p.Refused) != 1 {
		t.Fatalf("refused %d, want the one deployment: %+v", len(p.Refused), p.Refused)
	}
	// The vendor it was placed on and the silicon the backend declares, so the
	// reason is in the message rather than in a document somewhere else.
	for _, want := range []string{"vllm", "amd", "nvidia"} {
		if !strings.Contains(p.Refused[0].Reason, want) {
			t.Errorf("the refusal does not name %q: %s", want, p.Refused[0].Reason)
		}
	}
	// And the weights are still staged: the placement is wrong, the download
	// that already happened is not, and re-staging it would be minutes of
	// work undone by a typo in one field.
	if len(p.Stage) != 1 || p.Stage[0].State != StateStaged {
		t.Errorf("a refused placement unstaged the weights: %+v", p.Stage)
	}
}
