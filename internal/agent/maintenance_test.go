package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/api"
)

func windowed(w string) NodeConfig {
	c := NodeConfig{}
	c.Window.Maintenance = w
	return c
}

func at(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestMaintenanceOpen(t *testing.T) {
	for _, c := range []struct {
		name   string
		window string
		when   string
		open   bool
	}{
		// 2026-09-12 is a Saturday; 2026-09-13 a Sunday.
		{"inside", "sat 02:00-06:00 UTC", "2026-09-12T03:00:00Z", true},
		{"on the opening minute", "sat 02:00-06:00 UTC", "2026-09-12T02:00:00Z", true},
		{"on the closing minute", "sat 02:00-06:00 UTC", "2026-09-12T06:00:00Z", false},
		{"a minute early", "sat 02:00-06:00 UTC", "2026-09-12T01:59:00Z", false},
		{"the right hour, the wrong day", "sat 02:00-06:00 UTC", "2026-09-13T03:00:00Z", false},

		// An absent window is never open: a node that asked for nothing to be
		// stopped on a schedule must not get the most disruptive reading.
		{"no window at all", "", "2026-09-12T03:00:00Z", false},

		// "sat 22:00-02:00" is Saturday evening and the small hours of Sunday.
		{"wrapping, before midnight", "sat 22:00-02:00 UTC", "2026-09-12T23:30:00Z", true},
		{"wrapping, after midnight", "sat 22:00-02:00 UTC", "2026-09-13T01:30:00Z", true},
		{"wrapping, the gap between", "sat 22:00-02:00 UTC", "2026-09-13T03:00:00Z", false},
		{"wrapping, Saturday morning is outside", "sat 22:00-02:00 UTC", "2026-09-12T09:00:00Z", false},

		// The window is the node's local Saturday, not the agent's UTC one.
		// 2026-09-13T01:00Z is Saturday 20:00 in EST.
		{"a zone that is not UTC", "sat 19:00-23:00 EST", "2026-09-13T01:00:00Z", true},
		{"the same instant is outside the UTC window", "sat 19:00-23:00 UTC", "2026-09-13T01:00:00Z", false},

		// Refused at load, so it can only be reached by a hand-built struct.
		// Closed rather than a guessed zone.
		{"an unresolvable zone", "sat 02:00-06:00 PST", "2026-09-12T03:00:00Z", false},
		{"a malformed window", "whenever", "2026-09-12T03:00:00Z", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := windowed(c.window).MaintenanceOpen(at(t, c.when)); got != c.open {
				t.Errorf("MaintenanceOpen(%s) with %q = %t, want %t", c.when, c.window, got, c.open)
			}
		})
	}
}

// Measured: Go's zone database resolves EST, CET and MST and does not resolve
// PST or AEST. Half the abbreviations somebody reaches for first are not zones,
// and without this check they parse, validate, advertise, and then match no
// minute of any week.
func TestAWindowNamingAZoneThisHostCannotResolveIsRefused(t *testing.T) {
	for _, c := range []struct{ window, mentions string }{
		{"sat 02:00-06:00 PST", "not a time zone"},
		{"sat 02:00-02:00 UTC", "same minute"},
		{"someday 02:00-06:00 UTC", "sat 02:00-06:00 UTC"},
	} {
		err := checkMaintenance(c.window)
		if err == nil {
			t.Errorf("%q was accepted", c.window)
			continue
		}
		if !strings.Contains(err.Error(), c.mentions) {
			t.Errorf("%q: refusal does not say %q: %v", c.window, c.mentions, err)
		}
	}
	if err := checkMaintenance("sat 02:00-06:00 UTC"); err != nil {
		t.Errorf("a good window was refused: %v", err)
	}
}

// dev/specs/12-node-guardrails.md §3's second half. A deployment a node.toml
// edit invalidated waits "for the control plane to withdraw it, **or for the
// next maintenance window**" — and until now there was no such window, so it
// waited forever: the node restated the verdict every minute about something it
// went on running, and the only way to act on it was from the far end.
func TestAnOutOfPolicyDeploymentIsStoppedWhenTheWindowOpens(t *testing.T) {
	h, f := newFakeHost(t)
	running := UnitName("dep_one")
	f.active[running] = true

	p := Plan{Rev: 9, Node: "gpu-01", MaintenanceOpen: true,
		Units: []Unit{}, Stage: []Stage{}, Refused: []Refusal{},
		OutOfPolicy: []Refusal{{Deployment: "dep_one",
			Reason: "node.toml caps max_vram_fraction at 0.5 and this asks for 0.9"}}}

	r := Reconcile(context.Background(), p, h)

	if len(r.Stopped) != 1 || r.Stopped[0] != running {
		t.Errorf("stopped %v, want the out-of-policy unit once the window is open", r.Stopped)
	}
	// Still reported as the verdict it is: an operator reading the heartbeat
	// needs to know it stopped *because* it was out of policy.
	if len(r.OutOfPolicy) != 1 || r.OutOfPolicy[0].Deployment != "dep_one" {
		t.Errorf("out of policy = %+v, want the deployment named", r.OutOfPolicy)
	}
}

// The window governs this one action and nothing else. An open window must not
// become a second reason to stop something that is perfectly in policy.
func TestAnOpenWindowStopsNothingThatIsInPolicy(t *testing.T) {
	h, f := newFakeHost(t)
	fine := UnitName("dep_fine")
	f.active[fine] = true

	p := Plan{Rev: 9, Node: "gpu-01", MaintenanceOpen: true,
		Units: []Unit{{Deployment: "dep_fine"}}, Stage: []Stage{},
		Refused: []Refusal{}, OutOfPolicy: []Refusal{}}

	if r := Reconcile(context.Background(), p, h); len(r.Stopped) != 0 {
		t.Errorf("an open window stopped %v", r.Stopped)
	}
}

// Build is what reads the clock, so the plan carries a decision rather than
// Reconcile carrying a dependency on the time of day.
func TestBuildRecordsWhetherTheWindowIsOpen(t *testing.T) {
	for _, c := range []struct {
		when string
		open bool
	}{
		{"2026-09-12T03:00:00Z", true},  // Saturday, inside
		{"2026-09-12T09:00:00Z", false}, // Saturday, outside
	} {
		p, err := Build(api.Desired{Rev: 1, Node: "gpu-01"}, PlanOptions{
			ModelsDir: t.TempDir(), ConfigDir: t.TempDir(),
			Node: windowed("sat 02:00-06:00 UTC"), Now: at(t, c.when),
		})
		if err != nil {
			t.Fatal(err)
		}
		if p.MaintenanceOpen != c.open {
			t.Errorf("at %s, MaintenanceOpen = %t, want %t", c.when, p.MaintenanceOpen, c.open)
		}
	}

	// The safety-critical end of the same path. A node that declared no window
	// asked for nothing to be stopped on a schedule, so no clock ever opens
	// one — this is what keeps every node.toml written before this change
	// behaving exactly as it did.
	p, err := Build(api.Desired{Rev: 1, Node: "gpu-01"}, PlanOptions{
		ModelsDir: t.TempDir(), ConfigDir: t.TempDir(),
		Node: NodeConfig{}, Now: at(t, "2026-09-12T03:00:00Z"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.MaintenanceOpen {
		t.Error("a node with no maintenance window was given an open one")
	}
}
