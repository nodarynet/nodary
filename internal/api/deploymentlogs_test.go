package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
)

// R2-29. dev/specs/11-failure-modes.md §2 already has the agent capture the
// last hundred lines when a deployment fails; what did not exist was a way to
// read them by deployment id, without first knowing which node it landed on.
func TestAFailedDeploymentsCapturedLogIsServedByID(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")
	f.place("gpu-01", "dep_one", 0)
	f.place("gpu-01", "dep_two", 1)

	const captured = "systemd stopped restarting it after repeated failures\n" +
		"ValueError: Bfloat16 is only supported on GPUs with compute capability of at least 8.0"

	if status, raw := n.call(t, f, http.MethodPost, "/agent/status", api.StatusReport{
		Protocol: api.Protocol, AgentVersion: "0.0.0-test",
		Inventory: api.Inventory{Arch: "amd64", OS: "linux"},
		Deployments: []api.StatusUnit{
			{ID: "dep_one", State: "failed", Health: "unknown", Error: captured},
			{ID: "dep_two", State: "ready", Health: "healthy"},
		},
	}); status != http.StatusOK {
		t.Fatalf("status: %d %s", status, raw)
	}

	status, body := f.do(http.MethodGet, "/deployments/dep_one/logs", f.admin, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("logs: %d %v", status, body)
	}
	if body["lines"] != captured {
		t.Errorf("lines = %q, want what the node captured", body["lines"])
	}
	// The node is named, because an operator who wants more than the tail has
	// to know which machine to go to — and this endpoint is explicit that it
	// serves what was captured rather than what the container is printing now.
	if body["node"] != "gpu-01" {
		t.Errorf("node = %v, want the machine it ran on", body["node"])
	}
	if body["state"] != "failed" {
		t.Errorf("state = %v, want failed", body["state"])
	}
	if body["captured_at"] == "" || body["captured_at"] == nil {
		t.Errorf("nothing says when: %v", body)
	}

	// A deployment that has not failed has nothing captured, and that is an
	// answer rather than an error: the capture happens on failure, so an empty
	// string here means "it has not failed", not "the log was lost".
	status, body = f.do(http.MethodGet, "/deployments/dep_two/logs", f.admin, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("logs for a healthy deployment: %d %v", status, body)
	}
	if body["lines"] != "" {
		t.Errorf("lines = %q, want nothing captured for a healthy deployment", body["lines"])
	}
	if body["state"] != "ready" {
		t.Errorf("state = %v, want ready", body["state"])
	}
}

// Not a 500 with the message withheld, and not an empty success that leaves a
// caller believing a deployment exists and is quiet.
func TestLogsForADeploymentThatDoesNotExistAreA404(t *testing.T) {
	f := newFixture(t)
	status, body := f.do(http.MethodGet, "/deployments/dep_nope/logs", f.admin, nil, nil)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %v", status, body)
	}
	if !strings.Contains(asText(t, body), "dep_nope") {
		t.Errorf("the refusal does not name what was asked for: %v", body)
	}
}
