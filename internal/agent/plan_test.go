package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
)

func desired(d ...api.DesiredDeployment) api.Desired {
	return api.Desired{
		Rev: 7, Node: "gpu-01", Deployments: d,
		Staging: []api.DesiredStaging{{Model: "acme/tiny", Source: "local",
			Layout: "hf-cache", ExpectBytes: 40}},
	}
}

func deployment() api.DesiredDeployment {
	return api.DesiredDeployment{
		ID: "dep_one", Model: "acme/tiny", Backend: "vllm",
		Image:     "registry.internal/vllm@sha256:" + strings.Repeat("a", 64),
		GPUs:      []int{0, 1},
		Params:    json.RawMessage(`{"tensor_parallel":2,"max_context":131072}`),
		ExtraArgs: json.RawMessage(`["--enable-prefix-caching"]`),
		Port:      8001, Network: api.IsolatedNetwork, State: "ready",
	}
}

func twoGPUs() []GPU { return []GPU{{Index: 0}, {Index: 1}} }

// The slice's whole deliverable: one document in, one env file's exact contents
// out, with nothing touched on the host.
func TestOneDocumentRendersOneUnit(t *testing.T) {
	root, digest := stage(t, map[string]string{"config.json": "{}"})
	doc := desired(deployment())
	doc.Staging[0].ManifestSHA256 = digest

	p, err := Build(doc, PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Refused) != 0 {
		t.Fatalf("refused %+v", p.Refused)
	}
	if len(p.Units) != 1 {
		t.Fatalf("units = %d, want 1", len(p.Units))
	}
	if p.Stage[0].State != StateStaged {
		t.Errorf("staging = %+v, want staged", p.Stage[0])
	}

	u := p.Units[0]
	if u.Service != "nodary-model@dep_one.service" {
		t.Errorf("service = %q", u.Service)
	}
	if !strings.HasSuffix(u.EnvPath, "/deployments/dep_one.env") {
		t.Errorf("env path = %q, want docs/specs/03-agent.md §6's location", u.EnvPath)
	}
	if u.Probe.Health != "/health" || u.Probe.ReadyTimeoutS != 1800 {
		t.Errorf("probe = %+v, want it filled from the descriptor", u.Probe)
	}

	want := map[string]string{
		// The model path is the container's side of the bind mount, not the
		// host's: the argv runs inside the container.
		"NODARY_ARGS": "--model=/root/.cache/huggingface/hub/models--acme--tiny " +
			"--max-model-len=131072 --tensor-parallel-size=2 --enable-prefix-caching",
		"NODARY_CONTAINER_PORT": "8000",
		"NODARY_GPUS":           "0,1",
		"NODARY_IMAGE":          "registry.internal/vllm@sha256:" + strings.Repeat("a", 64),
		"NODARY_MODELS_DIR":     root,
		"NODARY_MOUNT_PATH":     "/root/.cache/huggingface",
		"NODARY_NETWORK":        api.IsolatedNetwork,
		"NODARY_PORT":           "8001",
	}
	got := map[string]string{}
	for _, v := range u.Env {
		got[v.Key] = v.Value
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s =\n  %q\nwant\n  %q", k, got[k], w)
		}
	}
	if len(got) != len(want) {
		// A variable the unit template does not reference is a setting that
		// looks applied and is not.
		t.Errorf("env has %d variables, want exactly the %d the template reads: %v",
			len(got), len(want), u.Env)
	}
}

// The env file is compared against what is on disk to decide whether to
// restart. A rendering that varied between runs would rewrite it every
// reconcile and restart a serving model for no reason at all.
func TestTheEnvFileRendersIdentically(t *testing.T) {
	root, digest := stage(t, map[string]string{"config.json": "{}"})
	doc := desired(deployment())
	doc.Staging[0].ManifestSHA256 = digest

	var first string
	for i := 0; i < 25; i++ {
		p, err := Build(doc, PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true})
		if err != nil {
			t.Fatal(err)
		}
		got := string(p.Units[0].RenderEnv())
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("the env file changed between renders:\n%s\n---\n%s", first, got)
		}
	}
	if !strings.Contains(first, "NODARY_PORT=8001\n") {
		t.Errorf("env file does not read as systemd expects:\n%s", first)
	}
}

// Every reason a node declines work. A refusal is a normal outcome
// (docs/specs/03-agent.md §2) — it is reported, and nothing is half-applied.
func TestWhatANodeRefusesAndWhy(t *testing.T) {
	root, digest := stage(t, map[string]string{"config.json": "{}"})

	for _, tc := range []struct {
		what   string
		mutate func(*api.DesiredDeployment)
		want   string
	}{
		{"a backend this build does not have",
			func(d *api.DesiredDeployment) { d.Backend = "tensorrt-llm" }, "not one this build has"},
		{"no pinned image",
			func(d *api.DesiredDeployment) { d.Image = "" }, "no image is pinned"},
		{"no GPU assigned",
			func(d *api.DesiredDeployment) { d.GPUs = nil }, "no GPU is assigned"},
		{"a GPU that is not on offer",
			func(d *api.DesiredDeployment) { d.GPUs = []int{3} }, "GPU 3 is not on this node's offer"},
		{"no host port",
			func(d *api.DesiredDeployment) { d.Port = 0 }, "no host port"},
		{"a model not in the staging list",
			func(d *api.DesiredDeployment) { d.Model = "acme/other" }, "not in this node's staging list"},
		// 04 §3 puts anything outside the canonical set in extra_args. Guessing
		// a flag produces a container that fails at start for a reason nobody
		// can trace back to here, so the deployment is refused instead.
		{"a parameter the backend does not take",
			func(d *api.DesiredDeployment) {
				d.Backend = "sglang"
				d.Params = json.RawMessage(`{"gpu_memory_fraction":0.9}`)
			}, "does not take gpu_memory_fraction"},
		// The unit template expands ${NODARY_ARGS} unquoted, so systemd splits
		// it on whitespace and no quoting we invent would survive.
		{"an extra arg with whitespace in it",
			func(d *api.DesiredDeployment) {
				d.ExtraArgs = json.RawMessage(`["--flag=a b"]`)
			}, "contains whitespace"},
		{"params that are not an object",
			func(d *api.DesiredDeployment) { d.Params = json.RawMessage(`"nope"`) }, "not an object"},
	} {
		d := deployment()
		tc.mutate(&d)
		doc := desired(d)
		doc.Staging[0].ManifestSHA256 = digest

		p, err := Build(doc, PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true})
		if err != nil {
			t.Fatalf("%s: %v", tc.what, err)
		}
		if len(p.Refused) != 1 {
			t.Errorf("%s: refused %+v, want one refusal", tc.what, p.Refused)
			continue
		}
		if !strings.Contains(p.Refused[0].Reason, tc.want) {
			t.Errorf("%s: reason = %q, want it to mention %q", tc.what, p.Refused[0].Reason, tc.want)
		}
		if len(p.Units) != 0 {
			t.Errorf("%s: a refused deployment still produced a unit", tc.what)
		}
	}
}

// Corrupt weights refuse the deployment rather than starting a container that
// will fail obscurely. docs/specs/11-failure-modes.md §2: it refuses to start,
// and the state is terminal until an explicit restage.
func TestCorruptWeightsRefuseTheDeployment(t *testing.T) {
	root, _ := stage(t, map[string]string{"config.json": "{}"})
	doc := desired(deployment())
	doc.Staging[0].ManifestSHA256 = strings.Repeat("f", 64) // not what is on disk

	p, err := Build(doc, PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Stage[0].State != StateCorrupt {
		t.Fatalf("staging = %+v, want corrupt", p.Stage[0])
	}
	if len(p.Refused) != 1 || !strings.Contains(p.Refused[0].Reason, "corrupt") {
		t.Errorf("refused = %+v, want the deployment refused for corrupt weights", p.Refused)
	}
}

// Remote staging is R4-33 and is not in this release. A node that cannot stage
// says which path it is missing rather than sitting silently at `absent`.
func TestRemoteStagingSaysItIsNotImplemented(t *testing.T) {
	doc := desired()
	doc.Staging[0].Source = "remote"
	p, err := Build(doc, PlanOptions{ModelsDir: t.TempDir(), Present: twoGPUs(), Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Stage[0].Reason, "R4-33") {
		t.Errorf("reason = %q, want the task number", p.Stage[0].Reason)
	}
}

// An empty document is a plan with nothing in it, not an error. That is what a
// pending node receives, and what a drained node receives.
func TestAnEmptyDocumentPlansNothing(t *testing.T) {
	p, err := Build(api.Desired{Rev: 3, Node: "gpu-01"}, PlanOptions{ModelsDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Units) != 0 || len(p.Stage) != 0 || len(p.Refused) != 0 {
		t.Errorf("plan = %+v, want nothing to do", p)
	}
	if p.Rev != 3 || p.Node != "gpu-01" {
		t.Errorf("plan = %+v, want it to carry the revision and the node", p)
	}
}
