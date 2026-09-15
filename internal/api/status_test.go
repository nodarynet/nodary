package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/observed"
)

// Waiting for approval has to be visible, and the only thing that makes it
// visible is that the node keeps checking in throughout.
func TestAPendingNodeCanStillHeartbeat(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")
	if status, raw := n.call(t, f, http.MethodPost, "/agent/status", api.StatusReport{
		Protocol: api.Protocol, AgentVersion: "0.0.0-test",
		Inventory: api.Inventory{Arch: "amd64", OS: "linux"},
	}); status != http.StatusOK {
		t.Fatalf("a pending node cannot heartbeat: %d %s", status, raw)
	}
	if len(n.desired(t, f, "").Deployments) != 0 {
		t.Error("heartbeating earned a pending node work")
	}
}

// R4-15 end to end over the wire: a node refuses part of its document and
// the reason reaches the control plane's own view of that node, where
// `nodary node show` reads it. Every hop between Build and the database is a
// field copied from one struct to the next, which is exactly the shape that
// looks wired and turns out never to have carried anything.
func TestARefusalReportedByANodeIsVisibleAgainstIt(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")
	f.place("gpu-01", "dep_one", 0)
	if status, body := f.do(http.MethodPost, "/nodes/gpu-01/approve", f.admin, nil,
		map[string]string{api.HeaderJustify: "the node in the rack we ordered"}); status != http.StatusOK {
		t.Fatalf("approve: %d %v", status, body)
	}

	if status, raw := n.call(t, f, http.MethodPost, "/agent/status", api.StatusReport{
		Protocol: api.Protocol, AgentVersion: "0.0.0-test", Rev: 4,
		Inventory: api.Inventory{Arch: "amd64", OS: "linux"},
		Refused: []api.StatusRefusal{{
			Deployment: "dep_one", Reason: "GPU 3 is not on this node's offer"}},
	}); status != http.StatusOK {
		t.Fatalf("status: %d %s", status, raw)
	}

	_, body := f.do(http.MethodGet, "/nodes/gpu-01", f.admin, nil, nil)
	refusals, _ := body["refusals"].([]any)
	if len(refusals) != 1 {
		t.Fatalf("refusals = %v, want the one the node reported", body["refusals"])
	}
	got, _ := refusals[0].(map[string]any)
	if got["reason"] != "GPU 3 is not on this node's offer" {
		t.Errorf("reason = %v, want what the node said", got["reason"])
	}
	if got["rev"] != float64(4) {
		t.Errorf("rev = %v, want the revision it was computed against", got["rev"])
	}
}

func TestTheHeartbeatIsObservedStateAndNotAudited(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")

	before := f.auditRecords(t)
	status, raw := n.call(t, f, http.MethodPost, "/agent/status", api.StatusReport{
		Protocol: api.Protocol, AgentVersion: "9.9.9",
		Inventory: api.Inventory{Arch: "amd64", OS: "linux", DriverVersion: "999.00",
			GPUs: json.RawMessage(`[{"index":0,"name":"test"}]`)},
	})
	if status != http.StatusOK {
		t.Fatalf("status: %d %s", status, raw)
	}
	if after := f.auditRecords(t); after != before {
		t.Errorf("the heartbeat wrote %d audit records; dev/plans/R4a-agent-protocol.md §4 says none",
			after-before)
	}

	_, body := f.do(http.MethodGet, "/nodes/gpu-01", f.admin, nil, nil)
	if body["stale"] != false {
		t.Errorf("stale = %v just after a heartbeat", body["stale"])
	}
	_, listed := f.do(http.MethodGet, "/nodes", f.admin, nil, nil)
	nodes, _ := listed["nodes"].([]any)
	first, _ := nodes[0].(map[string]any)
	if first["agent_version"] != "9.9.9" {
		t.Errorf("agent_version = %v, want what the node reported", first["agent_version"])
	}
}

// auditRecords counts the chain, so a test can assert that something wrote to
// it — or, here, that something did not.
func (f *fixture) auditRecords(t *testing.T) int64 {
	t.Helper()
	res, err := audit.VerifyDB(context.Background(), f.db)
	if err != nil {
		t.Fatal(err)
	}
	return res.Records
}

// R4-16 over the wire. The verdict is carried on its own field and stored with
// its own kind, and every hop between Reconcile and `nodary node show` is a
// field copied from one struct to the next — the shape that looks wired and
// turns out never to have carried anything. The two verdicts read alike and
// mean opposite things about whether a model is answering requests, so an
// out-of-policy row arriving as a refusal would be worse than it not arriving.
func TestAnOutOfPolicyVerdictCrossesTheWireAsItsOwnKind(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")
	f.place("gpu-01", "dep_one", 0)
	f.place("gpu-01", "dep_two", 1)
	if status, body := f.do(http.MethodPost, "/nodes/gpu-01/approve", f.admin, nil,
		map[string]string{api.HeaderJustify: "the node in the rack we ordered"}); status != http.StatusOK {
		t.Fatalf("approve: %d %v", status, body)
	}

	if status, raw := n.call(t, f, http.MethodPost, "/agent/status", api.StatusReport{
		Protocol: api.Protocol, AgentVersion: "0.0.0-test", Rev: 4,
		Inventory: api.Inventory{Arch: "amd64", OS: "linux"},
		Refused: []api.StatusRefusal{{
			Deployment: "dep_one", Reason: "GPU 3 is not on this node's offer"}},
		OutOfPolicy: []api.StatusRefusal{{
			Deployment: "dep_two", Reason: "node.toml caps max_vram_fraction at 0.5"}},
	}); status != http.StatusOK {
		t.Fatalf("status: %d %s", status, raw)
	}

	_, body := f.do(http.MethodGet, "/nodes/gpu-01", f.admin, nil, nil)
	refusals, _ := body["refusals"].([]any)
	if len(refusals) != 2 {
		t.Fatalf("refusals = %v, want both verdicts", body["refusals"])
	}
	kinds := map[string]string{}
	for _, r := range refusals {
		got, _ := r.(map[string]any)
		id, _ := got["deployment_id"].(string)
		kind, _ := got["kind"].(string)
		kinds[id] = kind
	}
	if kinds["dep_one"] != observed.KindRefused {
		t.Errorf("dep_one is %q, want %q", kinds["dep_one"], observed.KindRefused)
	}
	if kinds["dep_two"] != observed.KindOutOfPolicy {
		t.Errorf("dep_two is %q, want %q", kinds["dep_two"], observed.KindOutOfPolicy)
	}
}
