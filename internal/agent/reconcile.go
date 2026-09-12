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
	// Asserted remembers the egress verdict reached for each deployment since it
	// was last started.
	//
	// It exists because the assertion used to run once, immediately after
	// `systemctl start` — at a moment when the container **cannot** exist yet,
	// since ExecStart is `nerdctl run` and it may still be pulling. Every first
	// start therefore recorded `inconclusive: no such object`, and nothing ever
	// looked again. A control that always reports inconclusive is one people
	// learn to skip, which is the opposite of what R4-29 is for.
	//
	// A map on the Host rather than a return value: the daemon holds one Host
	// across reconciles, so this is where "since it was last started" can live
	// without threading state through every caller.
	Asserted map[string]string
	// Self is this binary's path. The egress probe runs it inside a
	// deployment's network namespace, so the agent and the assertion are
	// versioned together and the probe needs nothing from the model's image.
	// Empty disables the post-start assertion, which is what a test that is not
	// exercising it wants.
	Self string
}

// RealHost runs commands with os/exec.
func RealHost(unitDir, configDir string) Host {
	self, _ := os.Executable()
	return Host{Run: runCommand, UnitDir: unitDir, ConfigDir: configDir, Self: self,
		Asserted: map[string]string{}}
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
	// RestartDone is deployments `nodary model restart` (R4-36) asked for and
	// this run actually cycled, reported back so the control plane can stop
	// asking (internal/observed.Heartbeat consumes it, the same shape
	// Plan.ResetDone already uses).
	RestartDone []string `json:"restart_done,omitempty"`
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
	// Egress is docs/specs/03-agent.md §5's verdict, filled when this iteration
	// started the deployment. R4-29: it runs after every start.
	Egress *EgressVerdict `json:"egress,omitempty"`
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

	force := map[string]bool{}
	for _, id := range p.Restart {
		force[id] = true
	}

	wanted := map[string]bool{}
	for _, u := range p.Units {
		wanted[UnitName(u.Deployment)] = true
		outcome, restarted := reconcileUnit(ctx, u, staged, h, force[u.Deployment])
		r.Units = append(r.Units, outcome)
		if restarted {
			r.RestartDone = append(r.RestartDone, u.Deployment)
		}
	}

	// Stop what the plan no longer names. Scoped to nodary-model@* and nothing
	// else: a node is rarely only a nodary node
	// (docs/specs/12-node-guardrails.md), and an agent that stopped anything it
	// did not recognize on a machine somebody else also uses is the most
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

// reconcileUnit brings one deployment to where the plan wants it, and reports
// whether a restart forced by `nodary model restart` (R4-36) actually landed
// this cycle, so the caller knows whether to ack the request.
func reconcileUnit(ctx context.Context, u Unit, staged map[string]string, h Host, forced bool) (UnitOutcome, bool) {
	out := UnitOutcome{Deployment: u.Deployment}

	// Weights before the unit — docs/specs/03-agent.md §3's first ordering
	// rule. Build already refused a deployment whose weights are corrupt; this
	// is the case where they are simply not there yet, which is not an error
	// and must not start a container that would fail obscurely.
	if state := staged[u.ModelID]; state != StateStaged {
		out.State, out.Action = "staging", "waiting for weights"
		return out, false
	}

	changed, err := writeEnvFile(u)
	if err != nil {
		out.State, out.Error = "failed", err.Error()
		return out, false
	}

	state := h.activeState(ctx, UnitName(u.Deployment))
	active := state == "active"
	switch {
	// R4-21: systemd has restarted this five times inside the start limit
	// (unit.go) and given up. Reported and left alone — an agent that
	// started it again every reconcile would be grinding against a failure
	// on a sixty-second loop, which is what
	// docs/specs/12-node-guardrails.md §1 rejects for refusals and is no
	// better here. `nodary model restart` is the explicit unstick, below.
	case state == "failed" && !forced:
		out.State = "failed"
		out.Error = "systemd stopped restarting it after repeated failures; " +
			"`nodary model restart` tries again"
		return out, false

	case (changed || forced) && active:
		// The env file moved under a running deployment, so it is running the
		// wrong thing — or nothing moved and an operator asked for a cycle
		// anyway (`nodary model restart`). Either is the only path that
		// restarts something healthy, which is why writeEnvFile compares
		// before it writes.
		out.Action = "restarted: its configuration changed"
		if forced && !changed {
			out.Action = "restarted: requested by an operator"
		}
		if o, err := h.systemctl(ctx, "restart", UnitName(u.Deployment)); err != nil {
			out.State, out.Error = "failed", fmt.Sprintf("%v: %s", err, tail(o))
			return out, false
		}
	case !active:
		// A failed unit only reaches here when an operator asked for it
		// (forced). systemd refuses `start` on one that hit its start limit —
		// "start request repeated too quickly" — until the failure is
		// cleared, so clearing it is part of honoring the request rather
		// than a separate act.
		if state == "failed" {
			if o, err := h.systemctl(ctx, "reset-failed", UnitName(u.Deployment)); err != nil {
				out.State, out.Error = "failed", fmt.Sprintf("clearing the previous failure: %v: %s", err, tail(o))
				return out, false
			}
		}
		out.Action = "started"
		if o, err := h.systemctl(ctx, "start", UnitName(u.Deployment)); err != nil {
			out.State, out.Error = "failed", fmt.Sprintf("%v: %s", err, tail(o))
			return out, false
		}
	}

	// `starting`, never `ready`. `active` means the process is up, and whether
	// it can serve is health's question — R4-20 answers it separately, and a
	// model server is active for minutes before it is ready. This said `ready`
	// while nerdctl was still pulling the image, so the reconcile that had just
	// started a deployment reported it as serving.
	out.State = "starting"
	if !h.isActive(ctx, UnitName(u.Deployment)) {
		out.State = "stopped"
	}

	// R4-29: the assertion runs after every start, not only on demand.
	//
	// **Until it reaches an answer, not once.** A start is the trigger and the
	// container is not there yet when it fires, so a single attempt records
	// `inconclusive` every time and never revisits it. Retried while the
	// verdict is inconclusive and the unit is up; once conclusive it is
	// remembered and not re-probed, because re-checking a converged deployment
	// every fifteen seconds would put three network operations per deployment
	// into the loop for a namespace nothing has touched. `nodary node
	// verify-egress` is how an operator asks again.
	if out.Action != "" {
		// A new start needs a new answer; whatever was concluded about the
		// previous container says nothing about this one.
		delete(h.Asserted, u.Deployment)
	}
	if h.Self != "" && out.State != "failed" && out.State != "stopped" &&
		!conclusive(h.Asserted[u.Deployment]) {
		if v, err := VerifyEgress(ctx, h, u.Deployment, h.Self); err == nil {
			out.Egress = &v
		} else {
			// Recorded rather than swallowed: an assertion that could not run
			// has not passed, and the whole value of this control is that it
			// says so.
			out.Egress = &EgressVerdict{Deployment: u.Deployment,
				State: Inconclusive, Reason: err.Error()}
		}
		if h.Asserted != nil {
			h.Asserted[u.Deployment] = out.Egress.State
		}
	}
	// Every earlier return above is a failure or a no-op for restart's
	// purposes and already returned false; reaching here means whatever this
	// cycle needed to do to the unit succeeded, so a forced restart is done.
	return out, forced
}

// conclusive reports whether an egress verdict is one worth keeping.
//
// Inconclusive is not: it is the honest answer to "the assertion could not
// run", and the whole point of recording it is that somebody looks again.
func conclusive(state string) bool {
	return state != "" && state != Inconclusive
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

// activeState is systemd's own word for what this unit is doing: `active`,
// `failed`, `inactive`, `activating`, and the rest of `systemctl is-active`'s
// vocabulary.
//
// docs/specs/03-agent.md §3: the agent never assumes it caused the current
// state. A unit that died between iterations, or that an operator stopped by
// hand, has to be observed rather than inferred.
//
// **`failed` and `inactive` are different facts and the difference is the
// whole of R4-21.** A unit systemd stopped cleanly should be started again by
// the next reconcile; one that burned its restart budget (the start limit in
// unit.go) has already been restarted five times and starting it a sixth is
// grinding against a failure rather than reporting it. This used to compare
// the word against "active" and throw the rest away, so both arrived as
// "stopped" and a crash-loop was indistinguishable from a clean stop.
func (h Host) activeState(ctx context.Context, unit string) string {
	// `is-active` exits non-zero for anything but active, so the output is what
	// is read and the error is expected.
	out, _ := h.systemctl(ctx, "is-active", unit)
	return strings.TrimSpace(string(out))
}

func (h Host) isActive(ctx context.Context, unit string) bool {
	return h.activeState(ctx, unit) == "active"
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

// RunningDeployments is the deployment ids with a live unit.
//
// Exported because `nodary doctor` asserts egress against exactly the set the
// reconcile loop would: a diagnostic that checked a different set from the one
// the agent manages would be answering a different question.
func RunningDeployments(ctx context.Context, h Host) ([]string, error) {
	units, err := h.runningInstances(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(units))
	for _, u := range units {
		id := strings.TrimSuffix(strings.TrimPrefix(u, "nodary-model@"), ".service")
		if id != "" {
			out = append(out, id)
		}
	}
	return out, nil
}
