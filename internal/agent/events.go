package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/nodarynet/nodary/internal/api"
)

// Events generated on this node, on their way into the control plane's audit
// chain (docs/specs/03-agent.md §1, R4-10).
//
// **A heartbeat carries state and an event carries what happened**, and the
// difference is what the chain is for. `nodary node show` can say a deployment
// is failed; only an event says it failed at 04:12 because the image was not
// pinned, recovered at 04:19, and failed again at 04:31. A node's egress
// assertion going from compliant to breached and back leaves no trace at all in
// a report of the current verdict — and docs/specs/11-failure-modes.md §3 calls
// that a critical alert.
//
// **Bounded, and the bound is visible.** 11 §1 makes the overflow a named
// failure mode: the oldest events spill to disk, and if the disk buffer fills
// the drop is itself recorded. So the queue can lose events and cannot lose the
// fact that it did — which is the property that keeps a gap in the chain from
// reading as a quiet period.
const (
	// eventsInMemory is small: this is a queue drained every fifteen seconds,
	// not a buffer for an outage. The spill file is what covers an outage.
	eventsInMemory = 256
	// eventsSpillBytes bounds the file. A node that cannot reach its control
	// plane for a week must not fill the disk the weights are staged on.
	eventsSpillBytes = 4 << 20
	// eventsPerPost bounds one request, so a node coming back from an outage
	// does not hand the control plane a single enormous transaction.
	eventsPerPost = 64
)

// Events is the node's queue.
type Events struct {
	mu sync.Mutex
	// queue is oldest-first. Delivery takes from the front.
	queue []api.NodeEvent
	// spill is where overflow goes. Empty disables it, which is what a test and
	// `agent plan` use — neither has a node directory to write into.
	spill string
	// dropped counts events no buffer had room for. It is reported as an event
	// of its own rather than as a number on the heartbeat, because the drop is
	// a thing that happened at a time and belongs in the chain beside what it
	// displaced.
	dropped int
}

func NewEvents(spill string) *Events { return &Events{spill: spill} }

// Add queues one event, spilling the oldest to disk if the queue is full.
func (e *Events) Add(ev api.NodeEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.queue = append(e.queue, ev)
	for len(e.queue) > eventsInMemory {
		oldest := e.queue[0]
		e.queue = e.queue[1:]
		if err := e.spillOne(oldest); err != nil {
			e.dropped++
		}
	}
}

// spillOne appends to the disk buffer, refusing once it is full.
//
// The refusal is the whole point of a bound: a file that grows until the disk
// is full takes the model weights with it, and a node that cannot stage is a
// node that cannot serve.
func (e *Events) spillOne(ev api.NodeEvent) error {
	if e.spill == "" {
		return fmt.Errorf("no spill file is configured")
	}
	if fi, err := os.Stat(e.spill); err == nil && fi.Size() >= eventsSpillBytes {
		return fmt.Errorf("the event buffer is full at %d bytes", fi.Size())
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(e.spill, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// Take returns the next batch to deliver, without removing it.
//
// Nothing is removed until the control plane has accepted it: an event dropped
// because a request timed out is an event that never reaches the chain, and the
// chain is the thing being kept.
func (e *Events) Take(now time.Time) []api.NodeEvent {
	e.mu.Lock()
	defer e.mu.Unlock()

	// The drop is reported before what is left, because it is older than
	// anything still queued — it is the reason some of it is missing.
	if e.dropped > 0 {
		dropped := e.dropped
		e.dropped = 0
		e.queue = append([]api.NodeEvent{{
			At:     now.UTC().Format(api.EventTimeFormat),
			Action: "node.events_dropped",
			Detail: map[string]any{"count": dropped, "limit_bytes": eventsSpillBytes},
		}}, e.queue...)
	}
	e.refill()
	if len(e.queue) > eventsPerPost {
		return append([]api.NodeEvent(nil), e.queue[:eventsPerPost]...)
	}
	return append([]api.NodeEvent(nil), e.queue...)
}

// Delivered removes the batch the control plane accepted.
func (e *Events) Delivered(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if n > len(e.queue) {
		n = len(e.queue)
	}
	e.queue = e.queue[n:]
}

// refill reads the spill file back once the queue has room, oldest first.
//
// The whole file at once, because it is bounded and because reading it in parts
// would mean tracking a position in it — a second piece of state to keep
// correct across a restart, for a file that fits in memory by construction.
func (e *Events) refill() {
	if e.spill == "" || len(e.queue) >= eventsInMemory {
		return
	}
	f, err := os.Open(e.spill)
	if err != nil {
		return
	}
	var buffered []api.NodeEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var ev api.NodeEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err == nil {
			buffered = append(buffered, ev)
		}
	}
	f.Close()
	if len(buffered) == 0 {
		return
	}
	// Removed only once it is in hand. A crash between the two re-delivers
	// events, which the chain shows as duplicates; the other order loses them,
	// which it cannot show at all.
	if err := os.Remove(e.spill); err != nil {
		return
	}
	e.queue = append(buffered, e.queue...)
}
