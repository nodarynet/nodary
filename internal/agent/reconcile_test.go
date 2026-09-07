package agent

import (
	"context"
	"encoding/json"
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
	return Host{
		Run:       f.run,
		UnitDir:   filepath.Join(dir, "units"),
		ConfigDir: filepath.Join(dir, "etc"),
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
	if second.Units[0].State != "ready" {
		t.Errorf("second pass: state = %q, want ready", second.Units[0].State)
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
