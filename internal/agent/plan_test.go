package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/backend"
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
	// VerifyStaged's byte count used to be computed and then dropped: Stage
	// carried no field for it, so every heartbeat reported 0 regardless of
	// what was actually staged — `nodary node show` showed "0 B" for a model
	// that was, in fact, fully verified.
	if p.Stage[0].Bytes != int64(len("{}")) {
		t.Errorf("stage bytes = %d, want %d", p.Stage[0].Bytes, len("{}"))
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
		// host's: the argv runs inside the container. Positional, not
		// `--model=`: `vllm serve` takes the model as its first argument and
		// removed the flag, and the descriptor renders `{v}` for it.
		"NODARY_ARGS": "/root/.cache/huggingface/hub/models--acme--tiny " +
			"--max-model-len=131072 --tensor-parallel-size=2 --enable-prefix-caching",
		"NODARY_CONTAINER_PORT": "8000",
		"NODARY_GPUS":           "device=0,1",
		// Empty and still present. The template reads `$NODARY_ENV`, and a
		// variable the env file omits is one systemd expands to nothing —
		// which works, and leaves the file a different shape per deployment.
		"NODARY_ENV":        "",
		"NODARY_IMAGE":      "registry.internal/vllm@sha256:" + strings.Repeat("a", 64),
		"NODARY_MODELS_DIR": root,
		"NODARY_MOUNT_PATH": "/root/.cache/huggingface",
		"NODARY_NETWORK":    api.IsolatedNetwork,
		"NODARY_PORT":       "8001",
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

// TestTheGPUFlagFollowsWhatTheHostDeclares is the failure that killed the first
// real deployment.
//
// nerdctl resolves `--gpus device=0` to the CDI device `nvidia.com/gpu=0`. On
// WSL2 that device does not exist — there is no /dev/nvidia0, only /dev/dxg, so
// `nvidia-ctk cdi generate` emits a single device named `all` — and every start
// died in a restart loop with "unresolvable CDI devices nvidia.com/gpu=0" on a
// host where `nerdctl run --gpus all` works.
func TestTheGPUFlagFollowsWhatTheHostDeclares(t *testing.T) {
	one := map[int]bool{0: true}
	two := map[int]bool{0: true, 1: true}

	for _, tc := range []struct {
		name     string
		assigned []int
		offered  map[int]bool
		cdi      []string
		want     string
		wantErr  string
	}{
		{"indexed devices are used when they exist", []int{0}, two,
			[]string{"nvidia.com/gpu=0", "nvidia.com/gpu=1", "nvidia.com/gpu=all"}, "device=0", ""},
		{"several indices", []int{0, 1}, two,
			[]string{"nvidia.com/gpu=0", "nvidia.com/gpu=1"}, "device=0,1", ""},
		// The WSL2 case: `all` is the only device, and the node offers exactly
		// the one card being assigned, so `all` is not a widening.
		{"all is equivalent on a single-GPU host", []int{0}, one,
			[]string{"nvidia.com/gpu=all"}, "all", ""},
		// The case that must not silently widen: `all` would hand this
		// deployment a card it was not assigned.
		{"a subset of a multi-GPU host is refused", []int{0}, two,
			[]string{"nvidia.com/gpu=all"}, "", "subset"},
		{"a device nothing declares is named", []int{3}, map[int]bool{3: true},
			[]string{"nvidia.com/gpu=0"}, "", "none of them names"},
		// nvidia-ctk could not be asked. The indexed form stands: preflight
		// already refuses a node with no toolkit, and guessing `all` here would
		// be exactly the widening this refuses above.
		{"an unknown specification changes nothing", []int{0}, one, nil, "device=0", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := gpuFlag(tc.assigned, tc.offered, tc.cdi)
			switch {
			case tc.wantErr != "":
				if err == nil {
					t.Fatalf("got %q, want a refusal mentioning %q", got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("the refusal does not say why: %v", err)
				}
			case err != nil:
				t.Fatalf("unexpected refusal: %v", err)
			case got != tc.want:
				t.Errorf("--gpus %q, want %q", got, tc.want)
			}
		})
	}
}

// TestADeploymentCarriesItsEnvironment is the gap that stopped the first real
// model.
//
// A backend is configured by arguments *and* by environment, and only the first
// was expressible. On WSL2 vLLM refuses to start — `RuntimeError: UVA is not
// available` — and both published fixes, `VLLM_WSL2_ENABLE_PIN_MEMORY=1` and
// `VLLM_USE_V2_MODEL_RUNNER=0`, are environment variables with no command-line
// form. No deployment could be made to run on a platform 01 §8 supports.
func TestADeploymentCarriesItsEnvironment(t *testing.T) {
	got, err := envFlags(backend.Backend{}, false,
		[]byte(`{"VLLM_WSL2_ENABLE_PIN_MEMORY":"1","HF_HUB_OFFLINE":"1"}`))
	if err != nil {
		t.Fatal(err)
	}
	// Sorted, because this goes into a unit's environment file and a set that
	// reordered between reconciles would restart a serving model for nothing.
	if want := "-e HF_HUB_OFFLINE=1 -e VLLM_WSL2_ENABLE_PIN_MEMORY=1"; got != want {
		t.Errorf("env = %q, want %q", got, want)
	}

	// Absent is empty, not `-e`: the template expands it unquoted, and a stray
	// flag with no argument would make nerdctl consume the image reference.
	if got, err := envFlags(backend.Backend{}, false, nil); err != nil || got != "" {
		t.Errorf("no env rendered %q, %v; want empty", got, err)
	}
	if got, err := envFlags(backend.Backend{}, false, []byte(`{}`)); err != nil || got != "" {
		t.Errorf("an empty object rendered %q, %v; want empty", got, err)
	}

	// Whitespace is refused rather than escaped — the same rule extra_args
	// follows, and for the same reason: systemd splits this on whitespace and
	// no quoting convention invented here would survive it.
	if _, err := envFlags(backend.Backend{}, false, []byte(`{"A":"one two"}`)); err == nil {
		t.Error("a value with whitespace was accepted")
	}
	if _, err := envFlags(backend.Backend{}, false, []byte(`{"A B":"1"}`)); err == nil {
		t.Error("a name with whitespace was accepted")
	}
	if _, err := envFlags(backend.Backend{}, false, []byte(`{"A":1}`)); err == nil {
		t.Error("a non-string value was accepted")
	}
}

// TestADescriptorsWSL2EnvironmentAppliesOnlyThere is the toggle-versus-detect
// question, answered by detecting.
//
// "vLLM will not start on WSL2 without this variable" is a fact about vLLM, not
// about nodary or about one operator's deployment, so it lives in the
// descriptor — docs/specs/04-backends.md §1's argument for descriptors rather
// than plugins. A fleet with both WSL2 and native nodes then works without
// anybody remembering which is which, and a native host is not handed a
// variable that means nothing there.
func TestADescriptorsWSL2EnvironmentAppliesOnlyThere(t *testing.T) {
	b := backend.Backend{
		Env:     map[string]string{"ALWAYS": "1"},
		EnvWSL2: map[string]string{"VLLM_WSL2_ENABLE_PIN_MEMORY": "1"},
	}

	native, err := envFlags(b, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if native != "-e ALWAYS=1" {
		t.Errorf("on a native host: %q, want only the unconditional entry", native)
	}

	wsl, err := envFlags(b, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if wsl != "-e ALWAYS=1 -e VLLM_WSL2_ENABLE_PIN_MEMORY=1" {
		t.Errorf("on WSL2: %q", wsl)
	}

	// The deployment wins. Without this the fallback for a host the
	// descriptor's default does not fix would be unreachable — which is the
	// whole reason an operator would be setting it.
	over, err := envFlags(b, true, []byte(`{"VLLM_WSL2_ENABLE_PIN_MEMORY":"0","VLLM_USE_V2_MODEL_RUNNER":"0"}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := "-e ALWAYS=1 -e VLLM_USE_V2_MODEL_RUNNER=0 -e VLLM_WSL2_ENABLE_PIN_MEMORY=0"; over != want {
		t.Errorf("the deployment did not override the descriptor:\n got %q\nwant %q", over, want)
	}
}
