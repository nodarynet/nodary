package install

import (
	"slices"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/dataplane"
)

// A seam with one value is a seam nobody has driven. This drives it with a
// second, synthetic plane — R3-18 brings a real one — so that the day Bifrost
// arrives, "the installer writes the selected plane's unit" is already known to
// be true rather than assumed from a refactor that never changed an answer.
func TestTheServerUnitsFollowTheSelectedPlane(t *testing.T) {
	other := dataplane.Plane{
		Name: "other", Unit: "nodary-other.service",
		UnitBody: "# Written by nodary. Edits are overwritten.\n[Service]\nExecStart=/bin/true\n",
	}

	units := Units("server", other)
	if _, ok := units[other.Unit]; !ok {
		t.Errorf("the selected plane's unit is not written: %v", slices.Sorted(keysOf(units)))
	}
	if body := units[other.Unit]; body != other.UnitBody {
		t.Errorf("the unit written is not the plane's:\n%s", body)
	}
	if _, ok := units[dataplane.LiteLLM.Unit]; ok {
		t.Error("the unselected plane's unit is written too; a host would run both")
	}
	// Everything else is the same set: choosing a data plane changes the data
	// plane, not whether the control plane has a prune timer.
	for _, want := range []string{"containerd.service", "nodary-server.service",
		"nodary-gateway.service", "nodary-gateway-sync.timer"} {
		if _, ok := units[want]; !ok {
			t.Errorf("%s is missing when a plane is selected", want)
		}
	}

	// A zero plane means what an absent `data_plane` key means. An Options
	// built by something that has no opinion — a node install, a test — must
	// still produce a working control plane rather than one with no data plane
	// at all.
	if _, ok := Units("server", dataplane.Plane{})[dataplane.LiteLLM.Unit]; !ok {
		t.Error("a zero plane wrote no data-plane unit; it must mean the default")
	}

	// A node runs no data plane whichever one the control plane selected.
	for name := range Units("node", other) {
		if strings.Contains(name, "other") {
			t.Errorf("a node was given the data plane's unit: %s", name)
		}
	}
}

func keysOf(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}
