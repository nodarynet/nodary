package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
)

func ptrFloat(f float64) *float64 { return &f }
func ptrInt(n int) *int           { return &n }

// withGuardrails builds one document against one node.toml.
func withGuardrails(t *testing.T, c NodeConfig, deps ...api.DesiredDeployment) Plan {
	t.Helper()
	root, digest := stage(t, map[string]string{"config.json": "{}"})
	doc := desired(deps...)
	doc.Staging[0].ManifestSHA256 = digest

	p, err := Build(doc, PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true, Node: c})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// R4-14, docs/specs/12-node-guardrails.md §1. The limits were parsed, validated
// and advertised, and nothing evaluated the desired-state document against
// them: a control plane could place a backend the node excluded, a VRAM
// fraction above its ceiling, or more deployments than it said it would take,
// and the node ran all of it.
func TestBuildRefusesAPlacementOutsideNodeToml(t *testing.T) {
	vllmOnly := NodeConfig{Allow: Allow{Backends: []string{"sglang"}}}
	capped := NodeConfig{Limits: Limits{MaxVRAMFraction: ptrFloat(0.5)}}

	greedy := deployment()
	greedy.Params = json.RawMessage(`{"tensor_parallel":2,"gpu_memory_fraction":0.9}`)
	modest := deployment()
	modest.Params = json.RawMessage(`{"tensor_parallel":2,"gpu_memory_fraction":0.4}`)

	for _, tc := range []struct {
		what string
		node NodeConfig
		dep  api.DesiredDeployment
		want string // empty means the placement is allowed
	}{
		{"a backend the node excludes", vllmOnly, deployment(), "allows backends"},
		{"a backend the node allows",
			NodeConfig{Allow: Allow{Backends: []string{"vllm"}}}, deployment(), ""},
		// An empty list is a real answer and is not an absent one. TOML tells
		// them apart, LoadNodeConfig keeps them apart, and so does this.
		{"a node offering no backends at all",
			NodeConfig{Allow: Allow{Backends: []string{}}}, deployment(), "allows backends"},
		{"a VRAM fraction above the ceiling", capped, greedy, "max_vram_fraction"},
		{"a VRAM fraction under the ceiling", capped, modest, ""},
		{"no ceiling set", NodeConfig{}, greedy, ""},
		// The ceiling is a limit on what may be asked for, so a deployment that
		// asks for nothing in particular is not outside it.
		{"a deployment naming no fraction", capped, deployment(), ""},
	} {
		p := withGuardrails(t, tc.node, tc.dep)
		switch {
		case tc.want == "":
			if len(p.OutOfPolicy) != 0 {
				t.Errorf("%s: %+v, want the placement allowed", tc.what, p.OutOfPolicy)
			}
			if len(p.Units) != 1 {
				t.Errorf("%s: units = %d, want one", tc.what, len(p.Units))
			}
		default:
			if len(p.OutOfPolicy) != 1 {
				t.Errorf("%s: out of policy %+v, want one", tc.what, p.OutOfPolicy)
				continue
			}
			if !strings.Contains(p.OutOfPolicy[0].Reason, tc.want) {
				t.Errorf("%s: reason = %q, want it to name %q",
					tc.what, p.OutOfPolicy[0].Reason, tc.want)
			}
			// A guardrail verdict is not a refusal. Build cannot know whether
			// the placement is running, and 12 §3 turns on exactly that.
			if len(p.Refused) != 0 {
				t.Errorf("%s: also refused %+v", tc.what, p.Refused)
			}
			if len(p.Units) != 0 {
				t.Errorf("%s: built a unit for it anyway", tc.what)
			}
		}
	}
}

// max_deployments counts what the plan accepted, in the document's own order —
// which is deployment id, because internal/config reads `ORDER BY id`. Stable
// between cycles is the property that matters: an operator who fixes the wrong
// one because the cap moved has been given a moving target.
func TestMaxDeploymentsCapsThePlanInAStableOrder(t *testing.T) {
	first, second, third := deployment(), deployment(), deployment()
	first.ID, second.ID, third.ID = "dep_a", "dep_b", "dep_c"
	second.Port, third.Port = 8002, 8003
	second.GPUs, third.GPUs = []int{0}, []int{1}
	first.GPUs = []int{0, 1}

	node := NodeConfig{Limits: Limits{MaxDeployments: ptrInt(2)}}
	for range 3 {
		p := withGuardrails(t, node, first, second, third)
		if len(p.Units) != 2 {
			t.Fatalf("units = %d, want the cap of two: %+v", len(p.Units), p.OutOfPolicy)
		}
		if len(p.OutOfPolicy) != 1 || p.OutOfPolicy[0].Deployment != "dep_c" {
			t.Fatalf("out of policy = %+v, want the last by id", p.OutOfPolicy)
		}
		if !strings.Contains(p.OutOfPolicy[0].Reason, "max_deployments") {
			t.Errorf("reason = %q", p.OutOfPolicy[0].Reason)
		}
	}
}

// gpu_indices is deliberately not re-checked here: Advertise narrows the offer
// and Daemon.reconcile passes that narrowed set as Present, so unitFor already
// refuses a card the node withheld. This pins the division — a withheld GPU is
// a *refusal*, because the node cannot run it, not a guardrail verdict about
// something it will not.
func TestAWithheldGPUIsARefusalAndNotAGuardrailVerdict(t *testing.T) {
	c := NodeConfig{Limits: Limits{GPUIndices: []int{0}}}
	offer, _ := c.Advertise(twoGPUs(), []string{"vllm"})
	if len(offer.GPUs) != 1 {
		t.Fatalf("the offer holds %d GPUs, want the one on offer", len(offer.GPUs))
	}

	root, digest := stage(t, map[string]string{"config.json": "{}"})
	doc := desired(deployment()) // binds GPUs 0 and 1
	doc.Staging[0].ManifestSHA256 = digest

	p, err := Build(doc, PlanOptions{ModelsDir: root, Present: offer.GPUs, Verify: true, Node: c})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Refused) != 1 {
		t.Fatalf("refused %+v, want one", p.Refused)
	}
	if len(p.OutOfPolicy) != 0 {
		t.Errorf("also reported out of policy %+v; the offer already answered this", p.OutOfPolicy)
	}
}

// A node.toml with nothing in it offers the whole machine, which is the right
// default for a dedicated GPU host and what an absent file means.
func TestAnEmptyNodeConfigRefusesNothing(t *testing.T) {
	p := withGuardrails(t, NodeConfig{}, deployment())
	if len(p.OutOfPolicy) != 0 {
		t.Errorf("out of policy %+v on a node with no limits", p.OutOfPolicy)
	}
	if len(p.Units) != 1 {
		t.Errorf("units = %d, want one", len(p.Units))
	}
}

// R4-16, docs/specs/12-node-guardrails.md §3. **A guardrail nobody dares touch
// is not a guardrail.**
//
// This is the half Build cannot decide. A guardrail verdict produces no Unit,
// and Reconcile's stop loop stops every nodary-model@ instance the plan does
// not name — so enforcing guardrails without this would mean that editing
// node.toml terminated a model mid-request. An operator who learns that once
// never edits the file again, and the rails become decorative.
func TestAGuardrailNarrowedUnderARunningDeploymentDoesNotKillIt(t *testing.T) {
	h, f := newFakeHost(t)
	running := UnitName("dep_one")
	f.active[running] = true

	p := Plan{Rev: 9, Node: "gpu-01",
		Units: []Unit{}, Stage: []Stage{}, Refused: []Refusal{},
		OutOfPolicy: []Refusal{{Deployment: "dep_one",
			Reason: "node.toml caps max_vram_fraction at 0.5 and this asks for 0.9"}}}

	r := Reconcile(context.Background(), p, h)

	if len(r.Stopped) != 0 {
		t.Errorf("stopped %v; 12 §3 forbids killing a deployment a guardrail narrowed under", r.Stopped)
	}
	if !f.active[running] {
		t.Error("the unit is no longer active")
	}
	if len(r.OutOfPolicy) != 1 || r.OutOfPolicy[0].Deployment != "dep_one" {
		t.Errorf("out of policy = %+v, want the running deployment", r.OutOfPolicy)
	}
	// And it is not also a refusal: a refusal says nothing is running, and
	// something is.
	if len(r.Refused) != 0 {
		t.Errorf("refused %+v", r.Refused)
	}
}

// The other half of the same decision. Nothing is serving, so there is nothing
// to protect — and reporting it as `out_of_policy` would tell an operator a
// model is running outside its limits when none is.
func TestAnOutOfPolicyPlacementThatNeverStartedIsARefusal(t *testing.T) {
	h, f := newFakeHost(t)

	p := Plan{Rev: 9, Node: "gpu-01",
		Units: []Unit{}, Stage: []Stage{}, Refused: []Refusal{},
		OutOfPolicy: []Refusal{{Deployment: "dep_one",
			Reason: "node.toml allows backends [sglang] and this asks for \"vllm\""}}}

	r := Reconcile(context.Background(), p, h)

	if len(r.Refused) != 1 || r.Refused[0].Deployment != "dep_one" {
		t.Errorf("refused = %+v, want the placement that never started", r.Refused)
	}
	if len(r.OutOfPolicy) != 0 {
		t.Errorf("out of policy %+v for something that is not running", r.OutOfPolicy)
	}
	// And it was never started, which is the point of refusing it.
	for _, c := range f.calls {
		if strings.Contains(c, "start "+UnitName("dep_one")) {
			t.Errorf("started a placement node.toml excludes: %q", c)
		}
	}
}

// A deployment that leaves the document entirely is still stopped. The
// out-of-policy path protects what a guardrail narrowed under, and must not
// become a way for anything absent from the plan to survive.
func TestOutOfPolicyDoesNotProtectADeploymentTheDocumentDropped(t *testing.T) {
	h, f := newFakeHost(t)
	gone := UnitName("dep_gone")
	f.active[gone] = true
	f.active[UnitName("dep_one")] = true

	p := Plan{Rev: 9, Node: "gpu-01",
		Units: []Unit{}, Stage: []Stage{}, Refused: []Refusal{},
		OutOfPolicy: []Refusal{{Deployment: "dep_one", Reason: "node.toml caps max_deployments at 0"}}}

	r := Reconcile(context.Background(), p, h)

	if len(r.Stopped) != 1 || r.Stopped[0] != gone {
		t.Errorf("stopped = %v, want only the deployment the document dropped", r.Stopped)
	}
	if f.active[gone] {
		t.Error("a deployment absent from the plan is still running")
	}
}
