package api_test

import (
	"net/http"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/fleet"
)

// R4-11, dev/specs/03-agent.md §4: an agent outside the supported range stops
// reconciling, keeps running what is up, and reports `incompatible`.
//
// The control plane used to refuse the heartbeat outright, and the consequence
// was the opposite of reporting: the node went `stale` sixty seconds later, so
// from here an incompatible agent and an unplugged machine were the same
// picture. An operator halfway through a rollout needs to see which nodes have
// not caught up, which means those nodes have to stay visible.
func TestAnAgentOutsideTheProtocolRangeStaysVisibleAndSaysWhy(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")

	// First a good heartbeat, so there is an inventory on record to protect.
	if status, raw := n.call(t, f, http.MethodPost, "/agent/status", api.StatusReport{
		Protocol: api.Protocol, AgentVersion: "0.0.1",
		Inventory: api.Inventory{Arch: "amd64", OS: "linux", DriverVersion: "570.00"},
	}); status != http.StatusOK {
		t.Fatalf("status: %d %s", status, raw)
	}

	// Then one from a version this build does not know.
	status, raw := n.call(t, f, http.MethodPost, "/agent/status", api.StatusReport{
		Protocol: api.ProtocolMax + 1, AgentVersion: "9.9.9",
		Inventory: api.Inventory{Arch: "loong64", OS: "plan9"},
	})
	if status != http.StatusOK {
		t.Fatalf("an incompatible agent was refused (%d): %s", status, raw)
	}

	_, body := f.do(http.MethodGet, "/nodes/gpu-01", f.admin, nil, nil)
	if body["incompatible"] != true {
		t.Errorf("incompatible = %v, want true: %v", body["incompatible"], body)
	}
	// It checked in, so it is not stale. Those are different problems and the
	// whole point of accepting the heartbeat is that they stop looking alike.
	if body["stale"] == true {
		t.Error("an agent that just checked in is reported stale")
	}
	if body["protocol"] != float64(api.ProtocolMax+1) {
		t.Errorf("protocol = %v, want what the agent said", body["protocol"])
	}
	if body["agent_version"] != "9.9.9" {
		t.Errorf("agent_version = %v, want what the agent said", body["agent_version"])
	}
	// And nothing was read out of a document whose shape this build does not
	// know. The inventory is the one from the version it could read.
	if body["os"] != "linux" || body["arch"] != "amd64" {
		t.Errorf("os/arch = %v/%v, want the last report this build could actually read",
			body["os"], body["arch"])
	}
}

// The column answers "what does that node speak". It was filled with this
// build's own constant, so every node in the fleet reported as current —
// including one that sent no protocol field at all, which is an agent old
// enough that saying so is the point.
func TestTheRecordedProtocolIsTheAgentsOwn(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")
	if status, raw := n.call(t, f, http.MethodPost, "/agent/status", api.StatusReport{
		AgentVersion: "0.0.1", Inventory: api.Inventory{Arch: "amd64", OS: "linux"},
	}); status != http.StatusOK {
		t.Fatalf("status: %d %s", status, raw)
	}
	_, body := f.do(http.MethodGet, "/nodes/gpu-01", f.admin, nil, nil)
	if body["protocol"] != float64(0) {
		t.Errorf("protocol = %v, want 0: the agent named none", body["protocol"])
	}
	// An agent too old to send one is not incompatible — it is the agent an
	// operator most needs to keep seeing in order to upgrade it.
	if body["incompatible"] == true {
		t.Error("an agent that named no protocol was called incompatible")
	}
}

// The desired-state document advertises the range, because comparing against
// one number would have every node in a fleet stop reconciling the moment the
// control plane was upgraded to a version that still accepts them.
func TestTheDesiredDocumentAdvertisesTheSupportedRange(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")
	doc := n.desired(t, f, "")
	if doc.ProtocolMin != fleet.ProtocolMin || doc.ProtocolMax != fleet.ProtocolMax {
		t.Errorf("range = %d-%d, want %d-%d",
			doc.ProtocolMin, doc.ProtocolMax, fleet.ProtocolMin, fleet.ProtocolMax)
	}
	if doc.ProtocolMax < doc.ProtocolMin {
		t.Error("the advertised range is empty, so no agent can ever be compatible")
	}
}
