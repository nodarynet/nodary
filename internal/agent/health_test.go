package agent

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
)

// serveHealth runs a health endpoint on loopback and returns its port plus a
// switch to make it start failing.
func serveHealth(t *testing.T) (int, *atomic.Bool) {
	t.Helper()
	var down atomic.Bool
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port, &down
}

func healthUnit(port int) Unit {
	return Unit{Deployment: "dep_one", HostPort: port,
		Probe: Probe{Health: "/health", Ready: "/health", ReadyTimeoutS: 60}}
}

// docs/specs/03-agent.md §7: three consecutive failures mark it unhealthy.
// Three and not one, because a model server under load drops a probe
// occasionally and a single miss that pulled it from its route would make the
// fleet less available than no health checking at all.
func TestThreeConsecutiveFailuresMarkADeploymentUnhealthy(t *testing.T) {
	port, down := serveHealth(t)
	h := NewHealth()
	units := []Unit{healthUnit(port)}
	ctx := context.Background()

	if got := h.Poll(ctx, units); got[0].Health != "healthy" {
		t.Fatalf("health = %+v, want healthy", got[0])
	}

	down.Store(true)
	for i, want := range []string{"unknown", "unknown", "unhealthy"} {
		got := h.Poll(ctx, units)[0]
		if got.Health != want {
			t.Errorf("failure %d: health = %q, want %q", i+1, got.Health, want)
		}
		if got.Misses != i+1 {
			t.Errorf("failure %d: misses = %d", i+1, got.Misses)
		}
	}

	// A single success clears it. Recovery must not need three good probes: the
	// deployment is serving again, and every extra probe is time it spends out
	// of its route for no reason.
	down.Store(false)
	got := h.Poll(ctx, units)[0]
	if got.Health != "healthy" || got.Misses != 0 {
		t.Errorf("after recovery = %+v, want healthy with no misses", got)
	}
}

// Below the threshold it is `unknown`, never `healthy`. Reporting healthy after
// a probe this node just watched fail would be asserting something it saw not
// happen.
func TestAFailedProbeIsNeverReportedAsHealthy(t *testing.T) {
	// A port with nothing on it: connection refused, which is the common shape
	// of a deployment that has not finished starting.
	h := NewHealth()
	got := h.Poll(context.Background(), []Unit{healthUnit(1)})[0]
	if got.Health == "healthy" {
		t.Errorf("health = %+v, want anything but healthy", got)
	}
	if got.Error == "" {
		t.Error("a failed probe reported no reason")
	}
}

// A node that has been up for months must not accumulate a counter for every
// deployment it ever ran.
func TestCountersAreForgottenWhenADeploymentGoes(t *testing.T) {
	h := NewHealth()
	ctx := context.Background()
	h.Poll(ctx, []Unit{healthUnit(1)})
	h.Poll(ctx, []Unit{healthUnit(1)})

	h.mu.Lock()
	before := len(h.misses)
	h.mu.Unlock()
	if before != 1 {
		t.Fatalf("misses = %d, want the one deployment", before)
	}

	h.Poll(ctx, nil)
	h.mu.Lock()
	after := len(h.misses)
	h.mu.Unlock()
	if after != 0 {
		t.Errorf("misses = %d after the deployment went, want 0", after)
	}
}

// The probe goes to loopback and nowhere else: docs/specs/03-agent.md §5
// publishes a deployment's port on 127.0.0.1 only, so a probe that reached a
// deployment by any other address would mean the isolation had failed.
func TestTheProbeOnlyEverAsksLoopback(t *testing.T) {
	var asked atomic.Value
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Store(r.Host + r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})}
	go srv.Serve(ln)
	defer srv.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	NewHealth().Poll(context.Background(), []Unit{healthUnit(port)})

	want := "127.0.0.1:" + strconv.Itoa(port) + "/health"
	if got, _ := asked.Load().(string); got != want {
		t.Errorf("probed %q, want %q — the health path comes from the descriptor", got, want)
	}
}
