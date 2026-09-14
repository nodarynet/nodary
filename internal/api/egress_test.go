package api_test

import (
	"net/http"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
)

// R2-26 / R4-29 end to end: docs/specs/03-agent.md §5's assertion runs inside a
// deployment's network namespace on the node, and until this it reached that
// node's journal and stopped there — so the one place an assessor looks knew
// nothing about the control the whole boundary rests on. The endpoint is a read
// of what the node reported, not a probe run from here.
func TestANodesEgressVerdictsAreServedFromWhatItReported(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")
	f.place("gpu-01", "dep_one", 0)
	f.place("gpu-01", "dep_two", 1)

	if status, raw := n.call(t, f, http.MethodPost, "/agent/status", api.StatusReport{
		Protocol: api.Protocol, AgentVersion: "0.0.0-test",
		Inventory: api.Inventory{Arch: "amd64", OS: "linux"},
		Deployments: []api.StatusUnit{
			{ID: "dep_one", State: "ready", Health: "healthy", Egress: "compliant"},
			{ID: "dep_two", State: "ready", Health: "healthy",
				Egress: "non-compliant", EgressReason: "dns: resolved example.com"},
		},
	}); status != http.StatusOK {
		t.Fatalf("status: %d %s", status, raw)
	}

	status, body := f.do(http.MethodGet, "/nodes/gpu-01/verify-egress", f.admin, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("verify-egress: %d %v", status, body)
	}
	// One leaking deployment is the node's verdict, whatever sits beside it.
	if body["state"] != "non-compliant" {
		t.Errorf("node state = %v, want non-compliant: dep_two has a way off the box", body["state"])
	}
	deployments, _ := body["deployments"].([]any)
	if len(deployments) != 2 {
		t.Fatalf("deployments = %v, want both", body["deployments"])
	}
	byID := map[string]map[string]any{}
	for _, d := range deployments {
		m, _ := d.(map[string]any)
		id, _ := m["deployment_id"].(string)
		byID[id] = m
	}
	if got := byID["dep_one"]["state"]; got != "compliant" {
		t.Errorf("dep_one = %v, want compliant", got)
	}
	// The reason travels with the verdict: "non-compliant" alone tells an
	// operator to go and look, and this tells them what to look at.
	if got := byID["dep_two"]["reason"]; got != "dns: resolved example.com" {
		t.Errorf("dep_two reason = %v, want what the node found", got)
	}
	if byID["dep_two"]["checked_at"] == "" {
		t.Error("no checked_at: a verdict with no time on it says nothing about the machine now")
	}
}

// Nothing has run, so nothing has been probed — which is neither compliant nor
// a failure. An endpoint answering "compliant" for a node that has asserted
// nothing would be the worst possible wrong answer here.
func TestANodeThatHasAssertedNothingSaysSo(t *testing.T) {
	f := newFixture(t)
	f.join("gpu-01")
	f.place("gpu-01", "dep_one", 0)

	status, body := f.do(http.MethodGet, "/nodes/gpu-01/verify-egress", f.admin, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("verify-egress: %d %v", status, body)
	}
	if body["state"] != "" {
		t.Errorf("state = %v, want the empty verdict for a node that has probed nothing", body["state"])
	}
	if body["stale"] != true {
		t.Errorf("stale = %v; a node that has never checked in is stale, and a verdict is "+
			"only as fresh as the node reporting it", body["stale"])
	}
}

func TestVerifyEgressOnANodeThatDoesNotExistIs404(t *testing.T) {
	f := newFixture(t)
	status, body := f.do(http.MethodGet, "/nodes/nowhere/verify-egress", f.admin, nil, nil)
	if status != http.StatusNotFound {
		t.Errorf("status = %d, want 404: %v", status, body)
	}
}
