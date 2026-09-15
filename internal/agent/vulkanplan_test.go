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
func TestAnAMDNodePlansADeviceNodeAndNotCDI(t *testing.T) {
	root, digest := stage(t, map[string]string{"config.json": "{}"})
	d := deployment()
	d.GPUs = []int{0}
	doc := desired(d)
	doc.Staging[0].ManifestSHA256 = digest

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
