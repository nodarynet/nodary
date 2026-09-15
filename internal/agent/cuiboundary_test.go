package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// canaryPrompt is a string no part of nodary would ever produce, standing in
// for what a backend printed. What it is standing in for matters: the unit's
// ExecStart is `nerdctl run`, so the journal this is planted in is the
// container's own stdout, and nothing in nodary constrains what goes into it.
const canaryPrompt = "CANARY-e3b0c442-the-contract-value-is-4.2M-do-not-disclose"

// R4-45, and the pair of assertions is the point.
//
// dev/adr/0006-cui-boundary-and-fips.md makes "nodary records that a request
// happened, never what it said" structural rather than documentary, and its
// existing enforcement drives the canary through the *gateway*. A deployment
// that fails is a different path: dev/specs/11-failure-modes.md §2 has the
// agent capture the last hundred journal lines, and until this they went to
// two places at once.
//
// The two sinks are not equally serious and the test says so. An operator
// needs the log, so `deployment.last_error` keeps it — bounded, and overwritten
// by the next failure. The audit chain must not have it: a record cannot be
// retracted, and dev/specs/13-evidence.md exports a segment of the chain to an
// assessor.
func TestAContainersOutputReachesTheOperatorAndNeverTheChain(t *testing.T) {
	h, f := newFakeHost(t)
	f.failed["nodary-model@d1.service"] = true
	f.journal = "INFO: Received request chatcmpl-7: prompt: '" + canaryPrompt + "'\n" +
		"RuntimeError: CUDA out of memory"
	d := &Daemon{Host: h, events: NewEvents("")}
	u := Unit{Deployment: "d1"}

	state, reason, logs := d.observedState(context.Background(), u, Status{Health: "unknown"})
	if state != "failed" {
		t.Fatalf("state = %q, want failed", state)
	}

	// The operator's copy. Without it an operator debugging a crash has the
	// sentence nodary wrote and nothing the container said, which is the half
	// that names the cause.
	if !strings.Contains(failureText(reason, logs), canaryPrompt) {
		t.Errorf("last_error lost the container's output; 11 §2 asks for the last 100 lines")
	}
	// And nodary's own sentence carries none of it, because that is what the
	// chain is about to be given.
	if strings.Contains(reason, canaryPrompt) {
		t.Errorf("the reason carries the container's output: %q", reason)
	}

	d.noteChange("d1", "ready", "", 0, EgressVerdict{})
	d.noteChange("d1", state, reason, len(logs), EgressVerdict{})
	events := d.events.Take(time.Now())
	if len(events) != 1 || events[0].Action != "node.deployment_failed" {
		t.Fatalf("the failure emitted %v", actions(events))
	}

	// Every byte of the event, the way R3-15 searches every byte of the
	// database: a field added later that happened to carry the detail would
	// otherwise pass a test that only checked `reason`.
	raw, err := json.Marshal(events[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), canaryPrompt) {
		t.Errorf("the container's output reached the audit chain. "+
			"dev/adr/0006-cui-boundary-and-fips.md makes \"never what it said\" structural, "+
			"and a chain record cannot be retracted:\n%s", raw)
	}

	// The fact survives even though the content does not: an assessor reading
	// the chain can still tell a log was captured, and where to get it.
	if events[0].Detail["captured_log_bytes"] != len(logs) {
		t.Errorf("the event does not record that a log exists: %+v", events[0].Detail)
	}
}
