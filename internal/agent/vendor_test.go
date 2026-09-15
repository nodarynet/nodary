package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nodarynet/nodary/internal/preflight"
)

// drmFixture builds a /sys/class/drm tree. cards is card name -> attributes.
func drmFixture(t *testing.T, cards map[string]map[string]string) {
	t.Helper()
	root := t.TempDir()
	for name, attrs := range cards {
		dev := filepath.Join(root, name, "device")
		if err := os.MkdirAll(dev, 0o755); err != nil {
			t.Fatal(err)
		}
		for k, v := range attrs {
			if err := os.WriteFile(filepath.Join(dev, k), []byte(v+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	old := preflight.DRMRoot
	preflight.DRMRoot = root
	t.Cleanup(func() { preflight.DRMRoot = old })
}

func TestTheSysfsWalkFindsAMDAndIntelAndLeavesNVIDIAToItsDriver(t *testing.T) {
	drmFixture(t, map[string]map[string]string{
		// 24 GiB, named by the driver.
		"card0": {"vendor": "0x1002", "device": "0x744c",
			"product_name": "Radeon RX 7900 XTX", "mem_info_vram_total": "25757220864"},
		// i915 publishes no product_name.
		"card1": {"vendor": "0x8086", "device": "0x56a0"},
		// probeGPUs already reported this one. Counting it here would offer the
		// same card twice under two indices.
		"card2": {"vendor": "0x10de", "device": "0x2b85", "product_name": "NVIDIA GeForce RTX 5090"},
		// A connector on card0, not a card.
		"card0-DP-1": {"vendor": "0x1002"},
	})

	got := probeDRM(0)
	if len(got) != 2 {
		t.Fatalf("want two cards, got %d: %+v", len(got), got)
	}
	if got[0].Vendor != VendorAMD || got[0].Name != "Radeon RX 7900 XTX" {
		t.Errorf("amd card wrong: %+v", got[0])
	}
	// Bytes in sysfs, MiB in the offer.
	if got[0].MemoryMiB != 24564 {
		t.Errorf("want 24564 MiB, got %d", got[0].MemoryMiB)
	}
	if got[1].Vendor != VendorIntel || got[1].Name != "INTEL 0x56a0" {
		t.Errorf("intel card wrong: %+v", got[1])
	}
}

// The index is this node's only handle on a card: the offer names it, the plan
// checks it, and the unit's argv renders it. Two enumerators both starting at
// zero would hand two cards the same one.
func TestSysfsCardsAreNumberedAfterTheDriversOwn(t *testing.T) {
	drmFixture(t, map[string]map[string]string{
		"card0": {"vendor": "0x1002", "device": "0x744c"},
		"card1": {"vendor": "0x1002", "device": "0x744c"},
	})
	got := probeDRM(2)
	if len(got) != 2 || got[0].Index != 2 || got[1].Index != 3 {
		t.Fatalf("want indices 2 and 3, got %+v", got)
	}
}

// WSL2 is the platform this fleet has been proved against and it has no cards
// under /sys/class/drm at all. An enumerator that reported something here would
// be inventing hardware.
func TestASysfsWithNoCardsEnumeratesNothing(t *testing.T) {
	drmFixture(t, map[string]map[string]string{})
	if got := probeDRM(0); len(got) != 0 {
		t.Fatalf("want nothing, got %+v", got)
	}
}

// docs/specs/02-enrollment.md §3 gates restating an offer behind certificate
// expiry, so an offer written before this field existed is the offer those
// nodes keep. It has to keep working, and it was nvidia.
func TestAnOfferWithNoVendorReadsAsNVIDIA(t *testing.T) {
	var o Offer
	if err := json.Unmarshal([]byte(
		`{"gpus":[{"index":0,"name":"NVIDIA GeForce RTX 5090","memory_mib":32607,"uuid":"GPU-abc"}],
		  "max_deployments":1,"backends":["vllm"]}`), &o); err != nil {
		t.Fatal(err)
	}
	if got := o.GPUs[0].VendorName(); got != VendorNVIDIA {
		t.Fatalf("an offer from before the field says %q, not nvidia", got)
	}
	// And the field itself stays empty: the offer is what the node put on the
	// table and nothing here rewrites it.
	if o.GPUs[0].Vendor != "" {
		t.Errorf("the stored offer was rewritten: %q", o.GPUs[0].Vendor)
	}
}

// The zero value of the field is the default, so a card this build enumerated
// must say so explicitly — otherwise an AMD card that lost its vendor somewhere
// would read as nvidia and be handed a CDI flag.
func TestAnEnumeratedCardCarriesItsVendorExplicitly(t *testing.T) {
	drmFixture(t, map[string]map[string]string{
		"card0": {"vendor": "0x1002", "device": "0x744c"},
	})
	raw, err := json.Marshal(probeDRM(0)[0])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["vendor"] != VendorAMD {
		t.Fatalf("the offer does not carry the vendor: %s", raw)
	}
}

// The enumerators are wired in series or the second one is dead code. Only the
// presence is asserted: whether nvidia-smi answers on the machine running this
// test is not something the test gets to decide.
func TestLocalInventoryCarriesTheCardsOnlySysfsCanSee(t *testing.T) {
	drmFixture(t, map[string]map[string]string{
		"card0": {"vendor": "0x1002", "device": "0x744c", "product_name": "Radeon RX 7900 XTX"},
	})
	var found bool
	for _, g := range LocalInventory(context.Background()).GPUs {
		if g.Vendor == VendorAMD && g.Name == "Radeon RX 7900 XTX" {
			found = true
		}
	}
	if !found {
		t.Fatal("the sysfs enumerator is not reached from LocalInventory")
	}
}
