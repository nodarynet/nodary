package preflight

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// amdHost builds a /sys/class/drm tree with one AMD card and points the
// enumerator at it.
func amdHost(t *testing.T, vendorID, name string) {
	t.Helper()
	root := t.TempDir()
	dev := filepath.Join(root, "card0", "device")
	if err := os.MkdirAll(dev, 0o755); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"vendor": vendorID, "product_name": name, "mem_info_vram_total": "34359738368",
	} {
		if err := os.WriteFile(filepath.Join(dev, k), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := DRMRoot
	DRMRoot = root
	t.Cleanup(func() { DRMRoot = old })
}

// **The property R4-42 exists for.** Two of these checks are hard failures for
// a node, so before this an AMD host was refused enrollment for the absence of
// a driver it is not supposed to have — and the operator's only reading was
// that their machine was broken.
func TestAnAMDHostIsNotAFailedNVIDIAHost(t *testing.T) {
	amdHost(t, "0x1002", "AMD Instinct MI300X")

	r := Run(context.Background(), Options{
		Role: RoleNode, ModelsDir: "/", DataDir: "/",
		// The host has no NVIDIA anything, which is the ordinary case for it.
		run: fakeRun(nil, "nvidia-smi", "getenforce"),
	})

	for _, name := range []string{"nvidia driver", "gpus", "ram per gpu", "free vram"} {
		got := find(t, r, name)
		if got.Level == LevelFail {
			t.Errorf("%s failed on a host whose GPUs are not NVIDIA: %s", name, got.Detail)
		}
		if got.Level == LevelOK {
			t.Errorf("%s reported ok without checking anything: %s", name, got.Detail)
		}
	}

	// The enumeration is still reported: "does this host have GPUs" has an
	// answer here, and it is not "no".
	gpus := find(t, r, "gpus")
	if !strings.Contains(gpus.Detail, "MI300X") {
		t.Errorf("the card the kernel can see is not named: %s", gpus.Detail)
	}
	if !strings.Contains(gpus.Detail, "amd") {
		t.Errorf("the vendor is not named: %s", gpus.Detail)
	}
	// And the operator is told nodary cannot use it yet, rather than left to
	// infer that from a green tick.
	if !strings.Contains(gpus.Detail, "R6-13") {
		t.Errorf("nothing says nodary cannot place work on it yet: %s", gpus.Detail)
	}
}

// R6a §5's row that changes the shape of the install: CDI is how a GPU reaches
// a container on NVIDIA. `--device /dev/dri/renderD*` needs no toolkit at all,
// so requiring one would refuse a node over a package it must not install.
func TestTheContainerToolkitIsNotRequiredForAnotherVendor(t *testing.T) {
	amdHost(t, "0x1002", "AMD Instinct MI300X")

	got := checkContainerToolkit(context.Background(),
		Options{Role: RoleNode, run: fakeRun(nil, "nvidia-smi")})
	if got.Level == LevelFail {
		t.Errorf("an AMD host was failed for having no NVIDIA container toolkit: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "/dev/dri") {
		t.Errorf("the detail does not say how a card reaches a container instead: %s", got.Detail)
	}
}

// A host with no GPUs at all is still a failed node. The vendor question must
// not turn "there is nothing here" into a pass.
func TestAHostWithNoGPUsAtAllStillFails(t *testing.T) {
	root := t.TempDir()
	old := DRMRoot
	DRMRoot = root
	t.Cleanup(func() { DRMRoot = old })

	r := Run(context.Background(), Options{
		Role: RoleNode, ModelsDir: "/", DataDir: "/",
		run: fakeRun(nil, "nvidia-smi", "getenforce"),
	})
	for _, name := range []string{"nvidia driver", "gpus"} {
		if got := find(t, r, name); got.Level != LevelFail {
			t.Errorf("%s = %s on a host with no GPU of any vendor: %s", name, got.Level, got.Detail)
		}
	}
}

// NVIDIA is deliberately absent from the sysfs map: its driver answers, and on
// WSL2 it is the only thing that does. A card counted from both would be
// enumerated twice.
func TestNVIDIAIsLeftToItsOwnDriver(t *testing.T) {
	amdHost(t, "0x10de", "NVIDIA GeForce RTX 5090")
	if cards := DRMCards(); len(cards) != 0 {
		t.Errorf("the sysfs walk claimed an NVIDIA card: %+v", cards)
	}
}

// An Intel card publishes no product_name, and a card with no model string is
// still a card.
func TestAnIntelCardWithNoProductNameIsStillReported(t *testing.T) {
	root := t.TempDir()
	dev := filepath.Join(root, "card0", "device")
	if err := os.MkdirAll(dev, 0o755); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"vendor": "0x8086", "device": "0x0bd5"} {
		if err := os.WriteFile(filepath.Join(dev, k), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := DRMRoot
	DRMRoot = root
	t.Cleanup(func() { DRMRoot = old })

	cards := DRMCards()
	if len(cards) != 1 || cards[0].Vendor != VendorIntel {
		t.Fatalf("cards = %+v, want one intel card", cards)
	}
	if !strings.Contains(cards[0].Name, "0x0bd5") {
		t.Errorf("name = %q, want the PCI device id when there is no model string", cards[0].Name)
	}
}

// A host with an NVIDIA card and an integrated AMD one still needs the toolkit:
// the NVIDIA card is how it serves, and CDI is how that card reaches a
// container. Keyed on the driver answering rather than on sysfs alone, which is
// what makes this case come out right.
func TestAMixedHostStillNeedsTheToolkit(t *testing.T) {
	amdHost(t, "0x1002", "AMD Radeon Graphics")

	// nvidia-smi answers: there is an NVIDIA card here too.
	got := checkContainerToolkit(context.Background(), Options{
		Role: RoleNode,
		run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return []byte("0\n"), nil
		},
	})
	// Asserted on the *reason* rather than on the level, so this runs the same
	// on a machine that happens to have the toolkit installed and one that does
	// not. An earlier version skipped itself on the former, which is every
	// developer machine with an NVIDIA GPU — it proved nothing where it most
	// needed to, and an injection that skipped the toolkit for every mixed host
	// went uncaught.
	if strings.Contains(got.Detail, "/dev/dri") {
		t.Errorf("a host with an NVIDIA card was excused the toolkit because it also has "+
			"an AMD one: %s — %s", got.Level, got.Detail)
	}
	if got.Level == LevelSkip {
		t.Errorf("the toolkit was skipped on a host whose NVIDIA driver answers: %s", got.Detail)
	}
}
