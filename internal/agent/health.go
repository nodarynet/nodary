package agent

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// HealthInterval and UnhealthyAfter are docs/specs/03-agent.md §7: the agent
// polls each deployment's health endpoint every 10s, and three consecutive
// failures mark it unhealthy.
//
// Three and not one: a model server under load drops a probe occasionally, and
// a single miss that removed a deployment from its route would make the fleet
// less available than no health checking at all.
const (
	HealthInterval = 10 * time.Second
	UnhealthyAfter = 3
)

// probeTimeout is shorter than the interval, so a hung endpoint produces a
// failure rather than a poller that never comes back round.
const probeTimeout = 5 * time.Second

// Health tracks consecutive failures per deployment.
//
// The count is the state, and it lives here rather than in the control plane
// because it is about this node's last thirty seconds. A restart of the agent
// starts the count again, which is correct: the agent has not observed three
// failures, and asserting one it did not see would remove a serving deployment
// from its route.
type Health struct {
	mu     sync.Mutex
	misses map[string]int
	client *http.Client
}

// NewHealth returns a tracker that probes over loopback.
//
// docs/specs/03-agent.md §5 publishes a deployment's port on 127.0.0.1 only, so
// this is the only address that can reach it — and a probe that succeeded from
// anywhere else would mean the isolation had failed.
func NewHealth() *Health {
	return &Health{misses: map[string]int{}, client: &http.Client{Timeout: probeTimeout}}
}

// Status is one deployment's health as this node sees it.
type Status struct {
	Deployment string `json:"deployment"`
	// Health is the vocabulary 0006_fleet.sql's CHECK accepts.
	Health string `json:"health"`
	Misses int    `json:"misses"`
	Error  string `json:"error,omitempty"`
}

// Poll probes every unit once and returns what it found.
//
// It reports and does not act. docs/specs/03-agent.md §7 splits the two: the
// agent marks a deployment unhealthy, "the control plane removes it from its
// route, and Restart=always handles recovery". A route is fleet state — another
// node may hold the last ready replica — so a node that withdrew itself would
// be deciding on information it does not have.
func (h *Health) Poll(ctx context.Context, units []Unit) []Status {
	out := make([]Status, 0, len(units))
	live := map[string]bool{}
	for _, u := range units {
		live[u.Deployment] = true
		out = append(out, h.probe(ctx, u))
	}

	// Forget deployments that are gone, so a node that has been up for months
	// does not accumulate a counter per deployment it ever ran.
	h.mu.Lock()
	for id := range h.misses {
		if !live[id] {
			delete(h.misses, id)
		}
	}
	h.mu.Unlock()
	return out
}

func (h *Health) probe(ctx context.Context, u Unit) Status {
	s := Status{Deployment: u.Deployment}
	url := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(u.HostPort)) + u.Probe.Health

	err := h.get(ctx, url)
	h.mu.Lock()
	defer h.mu.Unlock()
	if err == nil {
		delete(h.misses, u.Deployment)
		s.Health = "healthy"
		return s
	}

	h.misses[u.Deployment]++
	s.Misses = h.misses[u.Deployment]
	s.Error = err.Error()
	// Below the threshold it is `unknown`, not `healthy`: reporting healthy
	// after a failed probe would be asserting something this node just watched
	// fail, and reporting unhealthy on the first miss is what the threshold
	// exists to avoid.
	s.Health = "unknown"
	if s.Misses >= UnhealthyAfter {
		s.Health = "unhealthy"
	}
	return s
}

func (h *Health) get(ctx context.Context, url string) error {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("health returned %s", resp.Status)
	}
	return nil
}
