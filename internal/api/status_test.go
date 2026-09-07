package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/audit"
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
		t.Errorf("the heartbeat wrote %d audit records; docs/plans/R4a-agent-protocol.md §4 says none",
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
