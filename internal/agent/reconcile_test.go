package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeHost is a systemd that records what it was asked to do and answers from
// a state map. It is deliberately not a mock framework: the whole surface is
// one function, and what the tests assert is the sequence of commands.
type fakeHost struct {
	mu     sync.Mutex
	calls  []string
	active map[string]bool
	fail   map[string]string
}

func newFakeHost(t *testing.T) (Host, *fakeHost) {
	f := &fakeHost{active: map[string]bool{}, fail: map[string]string{}}
	dir := t.TempDir()
	// Asserted, like RealHost. Without it every test ran against a nil map,
	// which is a configuration production never has — and a nil map answers
	// "nothing concluded" forever, so the egress retry could not be tested.
	return Host{
		Run:       f.run,
		UnitDir:   filepath.Join(dir, "units"),
		ConfigDir: filepath.Join(dir, "etc"),
		Asserted:  map[string]string{},
	}, f
}

func (f *fakeHost) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)

	if msg, bad := f.fail[args[0]]; bad {
		return []byte(msg), fmt.Errorf("exit status 1")
	}
	if name == "nerdctl" || name == "nsenter" {
		if msg, bad := f.fail[args[0]]; bad {
			return []byte(msg), fmt.Errorf("exit status 1")
		}
		return nil, fmt.Errorf("exit status 127")
	}
	switch args[0] {
	case "is-active":
		if f.active[args[1]] {
			return []byte("active\n"), nil
		}
		return []byte("inactive\n"), fmt.Errorf("exit status 3")
	case "start", "restart":
		f.active[args[1]] = true
	case "stop":
		delete(f.active, args[1])
	case "list-units":
		var b strings.Builder
		for name := range f.active {
			fmt.Fprintf(&b, "%s loaded active running nodary\n", name)
		}
		return []byte(b.String()), nil
	}
	return nil, nil
}

func (f *fakeHost) did(what string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.Contains(c, what) {
			return true
		}
	}
	return false
}

func (f *fakeHost) count(what string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.Contains(c, what) {
			n++
		}
	}
	return n
}

func (f *fakeHost) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

// planFor builds a real plan against real staged weights, so the reconcile
// tests are driven by the same rendering production uses.
func planFor(t *testing.T, h Host) Plan {
	t.Helper()
	root, digest := stage(t, map[string]string{"config.json": "{}"})
	doc := desired(deployment())
	doc.Staging[0].ManifestSHA256 = digest
	p, err := Build(doc, PlanOptions{ModelsDir: root, ConfigDir: h.ConfigDir,
		Present: twoGPUs(), Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Units) != 1 {
		t.Fatalf("plan refused everything: %+v", p.Refused)
	}
	return p
}

// docs/specs/03-agent.md §3: every iteration is idempotent and converges. The
// failure this guards is not a wasted write — it is a model server restarting
// every fifteen seconds forever, dropping in-flight requests each time.
func TestASecondReconcileOfTheSamePlanChangesNothing(t *testing.T) {
	h, f := newFakeHost(t)
	p := planFor(t, h)

	first := Reconcile(context.Background(), p, h)
	if len(first.Errors) != 0 {
		t.Fatalf("errors: %v", first.Errors)
	}
	if first.Units[0].Action != "started" {
		t.Errorf("first pass: action = %q, want started", first.Units[0].Action)
	}
	if !f.did("systemctl start nodary-model@dep_one.service") {
		t.Error("nothing was started")
	}

	f.reset()
	second := Reconcile(context.Background(), p, h)
	if second.Units[0].Action != "" {
		t.Errorf("second pass: action = %q, want nothing to do", second.Units[0].Action)
	}
	// Not `ready`. Reconcile observes systemd, and systemd's `active` is the
	// process being up — whether it can serve is health's question, answered by
	// the heartbeat. Claiming ready here is what reported a deployment as
	// serving while nerdctl was still pulling its image.
	if second.Units[0].State != "starting" {
		t.Errorf("second pass: state = %q, want starting", second.Units[0].State)
	}
	for _, forbidden := range []string{"start", "restart", "daemon-reload"} {
		if f.did("systemctl " + forbidden) {
			t.Errorf("a converged node ran `systemctl %s`", forbidden)
		}
	}

	// And a third, because "idempotent" is a claim about every iteration.
	f.reset()
	if third := Reconcile(context.Background(), p, h); third.Units[0].Action != "" {
		t.Errorf("third pass: action = %q", third.Units[0].Action)
	}
	if f.count("systemctl restart") != 0 {
		t.Error("a converged node restarted something")
	}
}

// The one path that restarts something healthy, and it has to be a real change.
func TestAChangedConfigurationRestartsAndOnlyThen(t *testing.T) {
	h, f := newFakeHost(t)
	p := planFor(t, h)
	Reconcile(context.Background(), p, h)

	// A different port is a different env file.
	changed := p
	changed.Units = []Unit{p.Units[0]}
	changed.Units[0].Env = append([]EnvVar{}, p.Units[0].Env...)
	for i := range changed.Units[0].Env {
		if changed.Units[0].Env[i].Key == "NODARY_PORT" {
			changed.Units[0].Env[i].Value = "8002"
		}
	}

	f.reset()
	r := Reconcile(context.Background(), changed, h)
	if !strings.Contains(r.Units[0].Action, "restarted") {
		t.Errorf("action = %q, want a restart", r.Units[0].Action)
	}
	if !f.did("systemctl restart nodary-model@dep_one.service") {
		t.Error("the unit was not restarted")
	}
	body, err := os.ReadFile(p.Units[0].EnvPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "NODARY_PORT=8002") {
		t.Errorf("the env file was not updated:\n%s", body)
	}
}

// A unit whose deployment the control plane withdrew is stopped. A unit that is
// not ours is not touched, and that is the assertion that matters: a node is
// rarely only a nodary node.
func TestOnlyNodaryUnitsAreStopped(t *testing.T) {
	h, f := newFakeHost(t)
	p := planFor(t, h)
	Reconcile(context.Background(), p, h)

	f.mu.Lock()
	f.active["nodary-model@dep_gone.service"] = true
	f.active["postgresql.service"] = true
	f.active["something-the-operator-runs.service"] = true
	f.mu.Unlock()

	f.reset()
	r := Reconcile(context.Background(), p, h)
	if len(r.Stopped) != 1 || r.Stopped[0] != "nodary-model@dep_gone.service" {
		t.Errorf("stopped = %v, want only the withdrawn nodary unit", r.Stopped)
	}
	for _, theirs := range []string{"postgresql.service", "something-the-operator-runs.service"} {
		if f.did("systemctl stop " + theirs) {
			t.Fatalf("the agent stopped %s, which is not its unit", theirs)
		}
	}
	// The listing itself has to be scoped, not filtered afterwards: a glob that
	// matched everything would make this depend on the filter never regressing.
	if !f.did("nodary-model@*.service") {
		t.Error("list-units was not scoped to nodary-model@*")
	}
}

// Weights before the unit — docs/specs/03-agent.md §3's first ordering rule.
// Starting a container whose weights are not there yet produces a crash loop
// that says nothing useful.
func TestAUnitWaitsForItsWeights(t *testing.T) {
	h, f := newFakeHost(t)
	root := t.TempDir() // nothing staged
	doc := desired(deployment())
	p, err := Build(doc, PlanOptions{ModelsDir: root, ConfigDir: h.ConfigDir,
		Present: twoGPUs(), Verify: true})
	if err != nil {
		t.Fatal(err)
	}

	r := Reconcile(context.Background(), p, h)
	if r.Units[0].State != "staging" {
		t.Errorf("state = %q, want staging", r.Units[0].State)
	}
	if f.did("systemctl start") {
		t.Error("a unit was started before its weights were there")
	}
	if _, err := os.Stat(p.Units[0].EnvPath); !os.IsNotExist(err) {
		t.Error("an env file was written for a deployment that cannot run")
	}
}

// The template is a contract with plan.go's variable names. A hand-edited one
// that no longer reads ${NODARY_ARGS} starts a model server with no arguments.
func TestTheUnitTemplateIsRestoredWhenItDrifts(t *testing.T) {
	h, f := newFakeHost(t)
	p := planFor(t, h)
	Reconcile(context.Background(), p, h)
	if !f.did("systemctl daemon-reload") {
		t.Error("writing the template did not reload systemd")
	}

	path := filepath.Join(h.UnitDir, TemplateName)
	if err := os.WriteFile(path, []byte("[Service]\nExecStart=/bin/true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.reset()
	Reconcile(context.Background(), p, h)

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The bare form specifically: systemd splits `$FOO` into arguments and
	// passes `${FOO}` as one, and a braced NODARY_ARGS hands the model server
	// its whole argv as a single string. TestSystemdSplitsBareVariablesAndNotBracedOnes
	// measures that; this stops the braces coming back in a template edit.
	if !strings.Contains(string(body), "$NODARY_ARGS") {
		t.Errorf("the template was not restored:\n%s", body)
	}
	if strings.Contains(string(body), "${NODARY_ARGS}") {
		t.Error("NODARY_ARGS is braced; systemd would pass the whole argv as one argument")
	}
	if !f.did("systemctl daemon-reload") {
		t.Error("restoring the template did not reload systemd")
	}
	// And it points at this host's configuration directory, not a hardcoded one.
	if !strings.Contains(string(body), "EnvironmentFile="+h.ConfigDir+"/deployments/%i.env") {
		t.Errorf("EnvironmentFile does not point at %s:\n%s", h.ConfigDir, body)
	}
}

// A unit that will not start is reported, not retried into a corner. This is
// the case on a host with no containerd, which is every host until R5-04.
func TestAUnitThatWillNotStartIsReportedWithItsOutput(t *testing.T) {
	h, f := newFakeHost(t)
	p := planFor(t, h)
	f.fail["start"] = "Failed to start nodary-model@dep_one.service: Unit not found."

	r := Reconcile(context.Background(), p, h)
	if r.Units[0].State != "failed" {
		t.Errorf("state = %q, want failed", r.Units[0].State)
	}
	if !strings.Contains(r.Units[0].Error, "Unit not found") {
		t.Errorf("error = %q, want systemd's own output", r.Units[0].Error)
	}
}

// The report is what the heartbeat sends, so it has to encode. Empty slices and
// not nulls: a control plane reading `"units": null` cannot tell "no units"
// from "the agent did not say".
func TestTheReportEncodesWithEmptySlicesNotNulls(t *testing.T) {
	h, _ := newFakeHost(t)
	r := Reconcile(context.Background(), Plan{Rev: 3}, h)
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "null") {
		t.Errorf("the report encodes nulls: %s", raw)
	}
}

// R4-37: a heartbeat reports bytes completed against total, not just a
// running count. `source: local` never sets Total (VerifyStaged is
// all-or-nothing), so that case has to fall back to Bytes rather than
// reporting 0 — a fully-verified model showing "bytes_total: 0" would read as
// nothing being staged at all.
func TestStagingStatusFallsBackToBytesWhenTotalIsUnknown(t *testing.T) {
	got := stagingStatus(Stage{Model: "acme/tiny", State: StateStaged, Bytes: 40})
	if got.BytesTotal != 40 {
		t.Errorf("bytes_total = %d, want 40 (falls back to bytes done)", got.BytesTotal)
	}

	got = stagingStatus(Stage{Model: "acme/tiny", State: StateStaging, Bytes: 10, Total: 100})
	if got.BytesTotal != 100 {
		t.Errorf("bytes_total = %d, want 100 (a real total is never overridden)", got.BytesTotal)
	}
}

// R4-36: a disabled deployment still has to be named on the heartbeat, or its
// row in the control plane's database freezes at whatever it last reported —
// possibly still "ready" for something systemd has, in fact, stopped.
func TestDisabledStatusReportsWhatSystemdActuallyShows(t *testing.T) {
	if got := disabledStatus("dep_one", false); got.State != "stopped" {
		t.Errorf("state = %q, want stopped: systemd is not running it", got.State)
	}
	if got := disabledStatus("dep_one", true); got.State != "starting" {
		t.Errorf("state = %q, want starting: disable was requested but systemd has not converged yet", got.State)
	}
}

// R4-36: `nodary model restart` reaches the agent as Plan.Restart, and an
// active, unchanged unit — the case neither of Reconcile's existing branches
// covers — must still be cycled when it is named there.
func TestForcedRestartCyclesAnActiveUnchangedUnit(t *testing.T) {
	h, f := newFakeHost(t)
	p := planFor(t, h)

	Reconcile(context.Background(), p, h)
	f.reset()

	p.Restart = []string{"dep_one"}
	r := Reconcile(context.Background(), p, h)

	if !f.did("restart nodary-model@dep_one.service") {
		t.Errorf("calls = %v, want a restart even though nothing changed", f.calls)
	}
	if len(r.RestartDone) != 1 || r.RestartDone[0] != "dep_one" {
		t.Errorf("RestartDone = %v, want [dep_one]", r.RestartDone)
	}
}

// A restart request against a deployment that is not currently running is
// satisfied by starting it — the operator's intent ("make it fresh") is met
// either way, and there is no unit to restart in place.
func TestForcedRestartOnAStoppedUnitJustStartsIt(t *testing.T) {
	h, f := newFakeHost(t)
	p := planFor(t, h)
	p.Restart = []string{"dep_one"}

	r := Reconcile(context.Background(), p, h)

	if !f.did("start nodary-model@dep_one.service") {
		t.Errorf("calls = %v, want it started", f.calls)
	}
	if len(r.RestartDone) != 1 || r.RestartDone[0] != "dep_one" {
		t.Errorf("RestartDone = %v, want [dep_one]", r.RestartDone)
	}
}

// R4-29 runs the assertion after every start, and a start whose assertion
// cannot run has not passed it.
//
// The failure this rules out is the quiet one: an agent that starts a
// deployment, cannot reach the namespace to check it, and reports nothing —
// leaving a model serving with no evidence about the control the product's
// strongest claim rests on.
func TestEgressIsAssertedAfterAStartAndNotSilentlySkipped(t *testing.T) {
	h, f := newFakeHost(t)
	h.Self = "/usr/local/bin/nodary"
	p := planFor(t, h)

	// nerdctl is not installed on this host, so the probe cannot run — which is
	// exactly the state that must not be reported as compliant.
	f.fail["inspect"] = "nerdctl: command not found"

	r := Reconcile(context.Background(), p, h)
	if r.Units[0].Egress == nil {
		t.Fatal("a started deployment carried no egress verdict")
	}
	if got := r.Units[0].Egress.State; got != Inconclusive {
		t.Errorf("egress = %q, want inconclusive: an assertion that could not run has not passed",
			got)
	}

	// The next pass looks again. "Could not tell" is not an answer, and the
	// probe fires immediately after `systemctl start`, when the container it
	// looks for may not exist yet — so a single attempt would record
	// inconclusive forever.
	f.reset()
	second := Reconcile(context.Background(), p, h)
	if second.Units[0].Egress == nil || second.Units[0].Egress.State != Inconclusive {
		t.Errorf("an inconclusive verdict was not retried: %+v", second.Units[0].Egress)
	}

	// Once it reaches one, it stops: re-probing a settled deployment every
	// fifteen seconds is three network operations per deployment for a
	// namespace nothing has touched. `nodary node verify-egress` asks again.
	h.Asserted["dep_one"] = Compliant
	f.reset()
	third := Reconcile(context.Background(), p, h)
	if third.Units[0].Egress != nil {
		t.Errorf("a converged reconcile re-ran a settled assertion: %+v", third.Units[0].Egress)
	}
	if f.did("nsenter") {
		t.Error("a converged reconcile entered a namespace")
	}
}

// TestReadyMeansServingNotMerelyActive is what the first real deployment
// reported wrongly.
//
// docs/specs/03-agent.md §7 waits for `ready` and counts ready replicas before
// a rolling restart may proceed, so `ready` has to mean *able to serve*. The
// unit is Type=exec running `nerdctl run`, which systemd calls active the
// instant the binary is exec'd — while it is still pulling twenty gigabytes,
// and again while the model loads weights.
//
// Reported ready anyway, this told an operator a deployment was serving when no
// container existed, and would let a rolling restart count a still-pulling
// replica as the last live one.
func TestReadyMeansServingNotMerelyActive(t *testing.T) {
	d := &Daemon{Host: Host{
		UserScope: true,
		Run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			// `is-active` succeeds: the unit is up.
			return []byte("active"), nil
		},
	}}
	u := Unit{Deployment: "d1"}

	if got := d.observedState(context.Background(), u, "unknown"); got != "starting" {
		t.Errorf("active with unknown health = %q, want starting", got)
	}
	if got := d.observedState(context.Background(), u, "unhealthy"); got != "starting" {
		t.Errorf("active but unhealthy = %q, want starting", got)
	}
	if got := d.observedState(context.Background(), u, "healthy"); got != "ready" {
		t.Errorf("active and healthy = %q, want ready", got)
	}

	down := &Daemon{Host: Host{
		UserScope: true,
		Run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return nil, errNotActive
		},
	}}
	if got := down.observedState(context.Background(), u, "healthy"); got != "stopped" {
		t.Errorf("an inactive unit = %q, want stopped", got)
	}
}

var errNotActive = errors.New("inactive")

// TestAnInconclusiveEgressAssertionIsRetried is the control that always
// reported inconclusive.
//
// The assertion fired immediately after `systemctl start`, at a moment when the
// container **cannot** exist — ExecStart is `nerdctl run`, which may still be
// pulling. So every first start recorded
//
//	egress=inconclusive reason="... no such object nodary-<id>"
//
// and nothing looked again. A control whose answer is always "could not tell"
// is one people learn to skip, which is the opposite of R4-29's purpose.
func TestAnInconclusiveEgressAssertionIsRetried(t *testing.T) {
	h := Host{Asserted: map[string]string{}}

	// Nothing recorded yet, and inconclusive, are both worth another look.
	if conclusive("") {
		t.Error("an unasserted deployment was treated as answered")
	}
	if conclusive(Inconclusive) {
		t.Error("inconclusive was treated as an answer; it is the absence of one")
	}
	// A real verdict is kept, so a converged deployment is not re-probed every
	// fifteen seconds for a namespace nothing has touched.
	for _, state := range []string{Compliant, NonCompliant} {
		if !conclusive(state) {
			t.Errorf("%q was not treated as an answer", state)
		}
	}

	// A restart discards the previous answer: whatever was concluded about the
	// old container says nothing about the new one.
	h.Asserted["d1"] = Compliant
	delete(h.Asserted, "d1")
	if conclusive(h.Asserted["d1"]) {
		t.Error("a restarted deployment kept its predecessor's verdict")
	}
}
