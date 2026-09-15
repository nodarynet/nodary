package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/api"
)

func ev(action string) api.NodeEvent {
	return api.NodeEvent{ID: eventID(), At: "2026-09-14T00:00:00.000Z", Action: action}
}

func actions(evs []api.NodeEvent) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.Action
	}
	return out
}

// Nothing leaves the queue until the control plane has taken it.
//
// An event dropped because a request timed out is an event that never reaches
// the chain, and the chain is the thing being kept.
func TestEventsAreHeldUntilTheyAreAccepted(t *testing.T) {
	q := NewEvents(filepath.Join(t.TempDir(), "events.ndjson"))
	for _, a := range []string{"node.a", "node.b", "node.c"} {
		q.Add(ev(a))
	}

	batch := q.Take(time.Now())
	if got := actions(batch); len(got) != 3 {
		t.Fatalf("Take = %v, want three", got)
	}
	// Taken and not delivered: the same three are still there.
	if got := actions(q.Take(time.Now())); len(got) != 3 {
		t.Errorf("an undelivered batch was forgotten: %v", got)
	}

	// A partial acceptance removes exactly what was accepted.
	q.Delivered(2)
	if got := actions(q.Take(time.Now())); len(got) != 1 || got[0] != "node.c" {
		t.Errorf("after accepting two of three: %v, want [node.c]", got)
	}
}

// dev/specs/11-failure-modes.md §1: the oldest events spill to disk.
func TestTheOldestEventsSpillToDiskAndComeBack(t *testing.T) {
	spill := filepath.Join(t.TempDir(), "events.ndjson")
	q := NewEvents(spill)
	for i := 0; i < eventsInMemory+10; i++ {
		q.Add(ev("node.e"))
	}
	if _, err := os.Stat(spill); err != nil {
		t.Fatalf("nothing spilled: %v", err)
	}

	// Everything comes back: the ten oldest from disk, ahead of what is still
	// in memory, and none of it lost.
	total := 0
	for range 20 {
		batch := q.Take(time.Now())
		if len(batch) == 0 {
			break
		}
		total += len(batch)
		q.Delivered(len(batch))
	}
	if total != eventsInMemory+10 {
		t.Errorf("delivered %d events, queued %d", total, eventsInMemory+10)
	}
}

// The bound is the point. A buffer that grows until the disk is full takes the
// staged weights with it, and a node that cannot stage is a node that cannot
// serve.
//
// **And the drop is itself recorded**, which is what keeps a gap in the chain
// from reading as a quiet period.
func TestAFullBufferDropsEventsAndSaysSo(t *testing.T) {
	spill := filepath.Join(t.TempDir(), "events.ndjson")
	// A buffer that is already over its limit: nothing more can be written.
	if err := os.WriteFile(spill, []byte(strings.Repeat("x", eventsSpillBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	q := NewEvents(spill)
	for i := 0; i < eventsInMemory+5; i++ {
		q.Add(ev("node.e"))
	}

	batch := q.Take(time.Now())
	if len(batch) == 0 {
		t.Fatal("nothing queued")
	}
	first := batch[0]
	if first.Action != "node.events_dropped" {
		t.Fatalf("the first event is %q, want the drop that displaced the rest", first.Action)
	}
	if got, _ := first.Detail["count"].(int); got != 5 {
		t.Errorf("the drop records count = %v, want 5", first.Detail["count"])
	}
	// Reported once. A counter that kept reporting the same drop would fill the
	// chain with the news that the chain is missing something.
	q.Delivered(len(batch))
	for _, e := range q.Take(time.Now()) {
		if e.Action == "node.events_dropped" {
			t.Error("the same drop was reported twice")
		}
	}
}

// A deployment's state is on every heartbeat; an event is for when it moves.
//
// A chain carrying the same line four times a minute is a chain nobody reads,
// and the transition is the thing a report of the current state cannot show at
// all: failed at 04:12, recovered at 04:19, failed again at 04:31 looks exactly
// like failed all along.
func TestEventsAreEmittedOnAChangeAndNotOnEveryReport(t *testing.T) {
	d := &Daemon{events: NewEvents("")}

	// The first sighting of a deployment is not a change. A restarted agent
	// would otherwise write an event for everything already running.
	d.noteChange("dep_a", "ready", "", 0, EgressVerdict{State: "compliant"})
	if got := d.events.Take(time.Now()); len(got) != 0 {
		t.Errorf("the first report of a deployment emitted %v", actions(got))
	}

	// Holding steady says nothing.
	d.noteChange("dep_a", "ready", "", 0, EgressVerdict{State: "compliant"})
	if got := d.events.Take(time.Now()); len(got) != 0 {
		t.Errorf("an unchanged report emitted %v", actions(got))
	}

	// A breach, and then its clearing. Both directions: a breach that cleared
	// is the half an assessor needs, because it says the control was not in
	// force for a window and when.
	d.noteChange("dep_a", "ready", "", 0, EgressVerdict{State: "non-compliant", Reason: "reached 1.1.1.1:443"})
	got := d.events.Take(time.Now())
	if len(got) != 1 || got[0].Action != "node.egress_non_compliant" {
		t.Fatalf("a breach emitted %v", actions(got))
	}
	if got[0].Target != "dep_a" || !strings.Contains(got[0].Detail["reason"].(string), "1.1.1.1") {
		t.Errorf("the event does not carry what happened: %+v", got[0])
	}
	d.events.Delivered(len(got))

	d.noteChange("dep_a", "ready", "", 0, EgressVerdict{State: "compliant"})
	if got := actions(d.events.Take(time.Now())); len(got) != 1 || got[0] != "node.egress_compliant" {
		t.Errorf("the breach clearing emitted %v", got)
	}
	d.events.Delivered(1)

	// A failure carries its reason, and recovering from one says nothing —
	// the recovery shows as the next state on the heartbeat.
	d.noteChange("dep_a", "failed", "the image is not pinned", 0, EgressVerdict{State: "compliant"})
	got = d.events.Take(time.Now())
	if len(got) != 1 || got[0].Action != "node.deployment_failed" {
		t.Fatalf("a failure emitted %v", actions(got))
	}
	if got[0].Detail["reason"] != "the image is not pinned" || got[0].Detail["from"] != "ready" {
		t.Errorf("the event does not say what happened or what it was: %+v", got[0].Detail)
	}
}
