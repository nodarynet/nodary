package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/audit"
)

// R4-10: a node's events become records in the control plane's chain.
//
// dev/specs/03-agent.md §1 calls this endpoint "audit records and lifecycle
// events generated on the node", and that is what it has to be — a security
// event that only ever reaches the node's own journal is one an assessor cannot
// see and a compromised node can erase.
func TestANodesEventsBecomeRecordsInTheChain(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")

	status, raw := n.call(t, f, http.MethodPost, "/agent/events", api.EventBatch{
		Events: []api.NodeEvent{
			{ID: "ev_1", At: "2026-09-14T04:12:00.000Z", Action: "node.egress_non_compliant",
				Target: "tiny-gpu-01", Detail: map[string]any{"reason": "reached 1.1.1.1:443"}},
			{ID: "ev_2", At: "2026-09-14T04:31:00.000Z", Action: "node.deployment_failed",
				Target: "tiny-gpu-01", Detail: map[string]any{"reason": "the image is not pinned"}},
		},
	})
	if status != http.StatusOK {
		t.Fatalf("events: %d %s", status, raw)
	}
	var out struct {
		Accepted int `json:"accepted"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Accepted != 2 {
		t.Fatalf("accepted %d of 2", out.Accepted)
	}

	// The family, minus enrollment's own `node.enroll` — this node joined a
	// moment ago and that record is correctly there.
	all, err := audit.List(t.Context(), f.db, audit.Filter{Action: "node."})
	if err != nil {
		t.Fatal(err)
	}
	var records []audit.Record
	for _, rec := range all {
		if rec.Action == "node.egress_non_compliant" || rec.Action == "node.deployment_failed" {
			records = append(records, rec)
		}
	}
	if len(records) != 2 {
		t.Fatalf("%d of the node's events reached the chain, want 2:\n%s", len(records), toJSON(all))
	}
	for _, rec := range records {
		// The node is the actor, because it is: nobody asked for a deployment
		// to fail, and attributing it to the administrator who last touched the
		// model would put somebody's name on a thing they did not do.
		if rec.Actor.ID != "gpu-01" || rec.Actor.Method != "node" {
			t.Errorf("actor = %+v, want the node", rec.Actor)
		}
		if rec.Target == nil || rec.Target.ID != "tiny-gpu-01" {
			t.Errorf("target = %+v, want the deployment", rec.Target)
		}
		// Two clocks, kept apart. The record's own timestamp is when the
		// control plane wrote it; node_time is when the thing happened. A node
		// unreachable for an hour delivers an hour-old event, and collapsing
		// them would put the wrong time on it.
		if rec.Detail["node_time"] == nil || rec.Detail["event_id"] == nil {
			t.Errorf("detail = %v, want the node's clock and the event id", rec.Detail)
		}
		if rec.TS.Format(audit.TimeFormat) == rec.Detail["node_time"] {
			t.Error("the record's timestamp and the node's clock are the same value")
		}
	}
	if !strings.Contains(toJSON(records), "reached 1.1.1.1:443") {
		t.Errorf("the reason did not reach the chain:\n%s", toJSON(records))
	}
}

// A node may write events about itself and nothing else.
//
// The action vocabulary is what an operator filters the chain by, so a node
// that could choose any action could write `user.delete` into it — a record
// indistinguishable from an administrator deleting an account.
func TestANodeCannotWriteAnActionOutsideItsOwnVocabulary(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")

	for _, action := range []string{"user.delete", "config.apply", "", "  ", "nodeish.thing"} {
		status, raw := n.call(t, f, http.MethodPost, "/agent/events", api.EventBatch{
			Events: []api.NodeEvent{{ID: "ev_x", At: "2026-09-14T04:12:00.000Z", Action: action}},
		})
		if status != http.StatusBadRequest {
			t.Errorf("action %q: %d %s, want a refusal", action, status, raw)
		}
	}
	records, err := audit.List(t.Context(), f.db, audit.Filter{Action: "user.delete"})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Errorf("a node wrote %d records under an action that is not its own", len(records))
	}
}

// An unenrolled caller cannot write to the chain at all.
func TestEventsRequireANodeCertificate(t *testing.T) {
	f := newFixture(t)
	code, doc := f.do(http.MethodPost, "/agent/events", f.admin,
		api.EventBatch{Events: []api.NodeEvent{{Action: "node.thing"}}}, nil)
	if code != http.StatusUnauthorized {
		t.Errorf("an administrator's token wrote node events: %d %v", code, doc)
	}
}
