package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Host is everything the reconcile loop does that is not a decision.
//
// Two function fields rather than an interface, because two is the whole
// boundary: internal/agent/plan.go put every decidable part in Build, so what
// is left is running a command and making one HTTP request. An interface with a
// method per operation would be an abstraction over a surface that has two
// functions in it (docs/plans/R4c-reconcile.md §1).
type Host struct {
	// Run executes a command and returns its combined output.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// UserScope drives `systemctl --user`. Production is always the system
	// manager; a test uses the user manager because it can start a unit without
	// being root.
	UserScope bool
	// UnitDir is where nodary-model@.service is written.
	UnitDir string
	// ConfigDir is where the environment files go, and what the template's
	// EnvironmentFile= is rendered against.
	ConfigDir string
}

// RealHost runs commands with os/exec.
func RealHost(unitDir, configDir string) Host {
	return Host{Run: runCommand, UnitDir: unitDir, ConfigDir: configDir}
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// systemctl builds the argument list for this host's manager.
func (h Host) systemctl(ctx context.Context, args ...string) ([]byte, error) {
	if h.UserScope {
		args = append([]string{"--user"}, args...)
	}
	return h.Run(ctx, "systemctl", args...)
}

// Report is what one reconcile did, in the shape the heartbeat sends.
type Report struct {
	Rev     int64            `json:"rev"`
	Units   []UnitOutcome    `json:"units"`
	Stopped []string         `json:"stopped"`
	Stage   []StagingOutcome `json:"stage"`
	Refused []Refusal        `json:"refused"`
	Errors  []string         `json:"errors"`
}

// UnitOutcome is one deployment after the loop ran.
type UnitOutcome struct {
	Deployment string `json:"deployment"`
	// State is the deployment vocabulary of 0006_fleet.sql, not systemd's.
	State string `json:"state"`
	// Action is what this iteration did, and is empty when it did nothing —
	// which is the normal case for a converged node.
	Action string `json:"action,omitempty"`
	Error  string `json:"error,omitempty"`
}

type StagingOutcome struct {
	Model  string `json:"model"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// Reconcile converges the host onto the plan and reports what it observed.
//
// docs/specs/03-agent.md §3: every iteration is idempotent and converges, and
// the agent never assumes it caused the current state — it observes and
// corrects. The fixed ordering holds: weights are staged before a unit starts
// (Build refuses a deployment whose weights are corrupt, and this skips one
// whose weights are absent), and a unit is stopped before anything about it is
// forgotten.
func Reconcile(ctx context.Context, p Plan, h Host) Report {
	r := Report{Rev: p.Rev, Units: []UnitOutcome{}, Stopped: []string{},
		Stage: []StagingOutcome{}, Refused: p.Refused, Errors: []string{}}
	for _, s := range p.Stage {
		r.Stage = append(r.Stage, StagingOutcome{Model: s.Model, State: s.State, Reason: s.Reason})
	}
	if r.Refused == nil {
		r.Refused = []Refusal{}
	}

	// The template first: an instance cannot start without it, and a change to
	// it needs a reload before anything reads it.
	if changed, err := EnsureUnitTemplate(h.UnitDir, h.ConfigDir); err != nil {
		r.Errors = append(r.Errors, err.Error())
		return r
	} else if changed {
		if out, err := h.systemctl(ctx, "daemon-reload"); err != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("daemon-reload: %v: %s", err, tail(out)))
			return r
		}
	}

	staged := map[string]string{}
	for _, s := range p.Stage {
		staged[s.Model] = s.State
	}

	wanted := map[string]bool{}
	for _, u := range p.Units {
		wanted[UnitName(u.Deployment)] = true
		r.Units = append(r.Units, reconcileUnit(ctx, u, staged, h))
	}

	// Stop what the plan no longer names. Scoped to nodary-model@* and nothing
	// else: a node is rarely only a nodary node
	// (docs/specs/12-node-guardrails.md), and an agent that stopped anything it
	// did not recognise on a machine somebody else also uses is the most
	// destructive thing this codebase could do.
	running, err := h.runningInstances(ctx)
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
		return r
	}
	for _, name := range running {
		if wanted[name] {
			continue
		}
		if out, err := h.systemctl(ctx, "stop", name); err != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("stopping %s: %v: %s", name, err, tail(out)))
			continue
		}
		r.Stopped = append(r.Stopped, name)
	}
	sort.Strings(r.Stopped)
	return r
}

// reconcileUnit brings one deployment to where the plan wants it.
func reconcileUnit(ctx context.Context, u Unit, staged map[string]string, h Host) UnitOutcome {
	out := UnitOutcome{Deployment: u.Deployment}

	// Weights before the unit — docs/specs/03-agent.md §3's first ordering
	// rule. Build already refused a deployment whose weights are corrupt; this
	// is the case where they are simply not there yet, which is not an error
	// and must not start a container that would fail obscurely.
	if state := staged[u.ModelID]; state != StateStaged {
		out.State, out.Action = "staging", "waiting for weights"
		return out
	}

	changed, err := writeEnvFile(u)
	if err != nil {
		out.State, out.Error = "failed", err.Error()
		return out
	}

	active := h.isActive(ctx, UnitName(u.Deployment))
	switch {
	case changed && active:
		// The env file moved under a running deployment, so it is running the
		// wrong thing. This is the only path that restarts something healthy,
		// which is why writeEnvFile compares before it writes.
		out.Action = "restarted: its configuration changed"
		if o, err := h.systemctl(ctx, "restart", UnitName(u.Deployment)); err != nil {
			out.State, out.Error = "failed", fmt.Sprintf("%v: %s", err, tail(o))
			return out
		}
	case !active:
		out.Action = "started"
		if o, err := h.systemctl(ctx, "start", UnitName(u.Deployment)); err != nil {
			out.State, out.Error = "failed", fmt.Sprintf("%v: %s", err, tail(o))
			return out
		}
	}

	out.State = "starting"
	if h.isActive(ctx, UnitName(u.Deployment)) {
		// `active` means the process is up. Whether it can serve is health's
		// question, and R4-20 answers it separately — a model server is active
		// for minutes before it is ready.
		out.State = "ready"
	}
	return out
}

// writeEnvFile writes the unit's environment file and reports whether it
// differed from what was already there.
//
// Comparing before writing is the whole of docs/plans/R4c-reconcile.md §2: the
// failure mode of getting it wrong is not a wasted write, it is a model server
// restarting every fifteen seconds forever and dropping in-flight requests each
// time.
func writeEnvFile(u Unit) (changed bool, err error) {
	want := u.RenderEnv()
	switch existing, err := os.ReadFile(u.EnvPath); {
	case err == nil && bytes.Equal(existing, want):
		return false, nil
	case err != nil && !os.IsNotExist(err):
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(u.EnvPath), 0o755); err != nil {
		return false, err
	}
	// 0640: it names an image and a model path, not a secret, but it is not
	// something every user on the box needs to read either.
	if err := os.WriteFile(u.EnvPath, want, 0o640); err != nil {
		return false, fmt.Errorf("writing %s: %w", u.EnvPath, err)
	}
	return true, nil
}

// isActive asks systemd rather than remembering what it started.
//
// docs/specs/03-agent.md §3: the agent never assumes it caused the current
// state. A unit that died between iterations, or that an operator stopped by
// hand, has to be observed rather than inferred.
func (h Host) isActive(ctx context.Context, unit string) bool {
	// `is-active` exits non-zero for anything but active, so the output is what
	// is read and the error is expected.
	out, _ := h.systemctl(ctx, "is-active", unit)
	return strings.TrimSpace(string(out)) == "active"
}

// runningInstances lists the nodary-model@ units systemd currently knows about.
func (h Host) runningInstances(ctx context.Context) ([]string, error) {
	out, err := h.systemctl(ctx, "list-units", "--no-legend", "--no-pager",
		"--plain", "--state=active", "nodary-model@*.service")
	if err != nil {
		return nil, fmt.Errorf("listing nodary units: %v: %s", err, tail(out))
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "nodary-model@") {
			continue
		}
		names = append(names, fields[0])
	}
	return names, nil
}

// LogTail is the last n lines of a unit's log, for a deployment that failed.
// docs/specs/11-failure-modes.md §2 wants the last 100.
func (h Host) LogTail(ctx context.Context, unit string, n int) string {
	args := []string{"-u", unit, "-n", fmt.Sprint(n), "--no-pager", "--output=cat"}
	if h.UserScope {
		args = append([]string{"--user"}, args...)
	}
	out, err := h.Run(ctx, "journalctl", args...)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// tail bounds command output that goes into a report. An error message is
// evidence; a megabyte of one is a denial of service against the heartbeat.
func tail(out []byte) string {
	const max = 2048
	s := strings.TrimSpace(string(out))
	if len(s) > max {
		return s[len(s)-max:]
	}
	return s
}
