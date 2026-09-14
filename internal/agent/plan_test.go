package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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

// R4-36: `nodary model disable` reaches the agent as State: "disabled" on the
// deployment. Build must not render a Unit for it — no GPU/backend/staged
// check either, since none of that matters for something that will not run —
// while its model stays verified and staged, since disable leaves weights in
// place (docs/specs/05-catalog.md §4).
func TestBuildSkipsAUnitForADisabledDeployment(t *testing.T) {
	root, digest := stage(t, map[string]string{"config.json": "{}"})
	dep := deployment()
	dep.State = "disabled"
	doc := desired(dep)
	doc.Staging[0].ManifestSHA256 = digest

	p, err := Build(doc, PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Units) != 0 {
		t.Errorf("units = %+v, want none: a disabled deployment must not run", p.Units)
	}
	if len(p.Refused) != 0 {
		t.Errorf("refused = %+v, want none: disabled is not a refusal", p.Refused)
	}
	if len(p.Disabled) != 1 || p.Disabled[0] != "dep_one" {
		t.Errorf("disabled = %v, want [dep_one]", p.Disabled)
	}
	if len(p.Stage) != 1 || p.Stage[0].State != StateStaged {
		t.Errorf("stage = %+v, want the model still verified and staged", p.Stage)
	}
}

// R4-36: doc.Restart is a request Build only carries forward for a real
// agent — opt.Downloads is nil only for a one-shot `agent plan` preview, and
// a preview must restart nothing any more than it deletes anything (Reset's
// own guard, mirrored here).
func TestBuildCarriesRestartOnlyForARealAgent(t *testing.T) {
	root, digest := stage(t, map[string]string{"config.json": "{}"})
	doc := desired(deployment())
	doc.Staging[0].ManifestSHA256 = digest
	doc.Restart = []string{"dep_one"}

	p, err := Build(doc, PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Restart) != 0 {
		t.Errorf("Restart = %v, want none: a preview (no Downloader) must not restart anything", p.Restart)
	}

	dl, _ := stagingDownloader(t)
	p, err = Build(doc, PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true, Downloads: dl})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Restart) != 1 || p.Restart[0] != "dep_one" {
		t.Errorf("Restart = %v, want [dep_one]", p.Restart)
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
// TestRemoteStagingWithNoDownloaderSaysWhy is `agent plan` against a remote
// model: R4-33 is built, but a one-shot preview never constructs a
// Downloader (see PlanOptions.Downloads's comment), and a node that cannot
// stage should say which path it is missing rather than silently doing
// nothing. Downloader.Status itself — a Downloads that is set — is
// remote_test.go's.
func TestRemoteStagingWithNoDownloaderSaysWhy(t *testing.T) {
	doc := desired()
	doc.Staging[0].Source = "remote"
	p, err := Build(doc, PlanOptions{ModelsDir: t.TempDir(), Present: twoGPUs(), Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Stage[0].Reason, "agent plan") {
		t.Errorf("reason = %q, want it to name why nothing started", p.Stage[0].Reason)
	}
}

// TestBuildAppliesAReset_Restage is the restage shape: the model is still in
// doc.Staging (a deployment wants it), the Downloader's cache says corrupt
// from an earlier attempt, and doc.Reset asks for it to be cleared. Build
// should discard the stale cache entry and let staging start over, within
// the same call — not wait for a second reconcile cycle.
func TestBuildAppliesAReset_Restage(t *testing.T) {
	srv, manifest := remoteFixture(t, map[string]string{"config.json": `{"model_type":"tiny"}`})
	defer srv.Close()
	digest := sha256.Sum256([]byte(manifest))

	doc := desired()
	doc.Staging[0].Source = "remote"
	doc.Staging[0].ManifestBody = manifest
	doc.Staging[0].ManifestSHA256 = hex.EncodeToString(digest[:])
	doc.Reset = []api.DesiredReset{{Model: "acme/tiny", Layout: "hf-cache"}}

	root := t.TempDir()
	dir, _ := ModelDir(root, "hf-cache", "acme/tiny")
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	// The verdict a previous attempt left behind. It is terminal, so nothing
	// revisits it until doc.Reset clears it — which is the whole point.
	(&progress{path: progressPath(dir)}).set(StateCorrupt, 0, 0, "a previous attempt failed")

	dl, f := stagingDownloader(t)
	dl.BaseURL = srv.URL

	p, err := Build(doc, PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true, Downloads: dl})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ResetDone) != 1 || p.ResetDone[0] != "acme/tiny" {
		t.Errorf("ResetDone = %v, want [acme/tiny]", p.ResetDone)
	}
	if p.Stage[0].State == StateCorrupt {
		t.Errorf("staging = %+v, want the stale corrupt cache entry cleared", p.Stage[0])
	}

	// And the retry is actually under way: Reset cleared the verdict, and the
	// same Build call started a fresh staging unit rather than leaving the
	// model to wait for the next reconcile.
	if !f.did("systemd-run") {
		t.Error("Reset cleared the stale verdict but no new staging unit was started")
	}
}

// TestBuildAppliesAReset_Unstage is the unstage shape: nothing in doc.Staging
// or doc.Deployments names the model at all — the deployment was already
// removed — but doc.Reset still asks for its weights back. Build should
// delete them even though nothing wants them staged.
func TestBuildAppliesAReset_Unstage(t *testing.T) {
	root, _ := stage(t, map[string]string{"config.json": "{}"})
	dir, err := ModelDir(root, "hf-cache", "acme/tiny")
	if err != nil {
		t.Fatal(err)
	}

	doc := api.Desired{Rev: 7, Node: "gpu-01",
		Reset: []api.DesiredReset{{Model: "acme/tiny", Layout: "hf-cache"}}}
	dl, _ := stagingDownloader(t)

	p, err := Build(doc, PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true, Downloads: dl})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ResetDone) != 1 || p.ResetDone[0] != "acme/tiny" {
		t.Errorf("ResetDone = %v, want [acme/tiny]", p.ResetDone)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("weights at %s were not removed", dir)
	}
	if len(p.Stage) != 0 {
		t.Errorf("Stage = %+v, want empty: nothing in doc.Staging names this model", p.Stage)
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

// plan builds one document against two staged GPUs, which is what most of the
// tests above do by hand.
func plan(t *testing.T, deps ...api.DesiredDeployment) Plan {
	t.Helper()
	root, digest := stage(t, map[string]string{"config.json": "{}"})
	doc := desired(deps...)
	doc.Staging[0].ManifestSHA256 = digest
	p, err := Build(doc, PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// R4-23, docs/specs/03-agent.md §7: "the control plane guarantees no two
// deployments on a node claim the same index, and the agent double-checks
// before starting."
//
// The control plane's guarantee is a unique index (0006_fleet.sql), so this is
// defense in depth — which is the point: 11 §2 makes two deployments on one
// card a named failure mode, and a node that trusted the document would start
// both and make each of them slow rather than making one of them refuse.
func TestANodeRefusesASecondClaimOnOneCard(t *testing.T) {
	first, second := deployment(), deployment()
	first.ID, second.ID = "dep_a", "dep_b"
	first.GPUs, second.GPUs = []int{0, 1}, []int{1}
	second.Port = 8002

	p := plan(t, first, second)
	if len(p.Units) != 1 || p.Units[0].Deployment != "dep_a" {
		t.Fatalf("units = %+v, want only the first claimant", p.Units)
	}
	if len(p.Refused) != 1 || p.Refused[0].Deployment != "dep_b" {
		t.Fatalf("refused = %+v, want dep_b", p.Refused)
	}
	// It names the card and the holder, because neither is guessable from the
	// document the node was handed.
	for _, want := range []string{"1", "dep_a"} {
		if !strings.Contains(p.Refused[0].Reason, want) {
			t.Errorf("the reason does not name %s: %q", want, p.Refused[0].Reason)
		}
	}

	// Stable across cycles: config.Read orders deployments by id, so the same
	// one wins every time. A loser that alternated would be started and
	// stopped forever, and an operator fixing "the one that is refused" would
	// be chasing a moving target.
	for range 3 {
		again := plan(t, first, second)
		if len(again.Refused) != 1 || again.Refused[0].Deployment != "dep_b" {
			t.Fatalf("a later cycle refused %+v instead", again.Refused)
		}
	}
}

// A deployment that cannot run for some other reason must not hold a card away
// from one that can: the claim is taken after the unit renders, not before.
func TestAnImpossibleDeploymentHoldsNoCard(t *testing.T) {
	broken, good := deployment(), deployment()
	broken.ID, good.ID = "dep_a", "dep_b"
	broken.Image = "" // a node runs pinned digests and does not choose one
	broken.GPUs, good.GPUs = []int{0}, []int{0}
	good.Port = 8002

	p := plan(t, broken, good)
	if len(p.Units) != 1 || p.Units[0].Deployment != "dep_b" {
		t.Fatalf("units = %+v, want dep_b to have GPU 0 after dep_a could not use it", p.Units)
	}
	if len(p.Refused) != 1 || p.Refused[0].Deployment != "dep_a" {
		t.Fatalf("refused = %+v, want only the one with no image", p.Refused)
	}
	if strings.Contains(p.Refused[0].Reason, "claimed") {
		t.Errorf("dep_a was refused for a conflict rather than for its own problem: %q",
			p.Refused[0].Reason)
	}
}

// planOn builds one document with an explicit measured inventory and an
// explicit offer, which is the pair R4-25 turns on.
func planOn(t *testing.T, detected, offered []GPU, deps ...api.DesiredDeployment) Plan {
	t.Helper()
	root, digest := stage(t, map[string]string{"config.json": "{}"})
	doc := desired(deps...)
	doc.Staging[0].ManifestSHA256 = digest
	p, err := Build(doc, PlanOptions{
		ModelsDir: root, Present: offered, Detected: detected, Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// R4-25, docs/specs/11-failure-modes.md §2: "GPU falls off the bus — agent
// reports; affected deployments marked `failed`; node flagged. **Never
// auto-rebooted**."
func TestADeploymentOnACardThatLeftTheBusIsFailed(t *testing.T) {
	d := deployment()
	d.GPUs = []int{0, 1}

	// The driver reports one card where the deployment was given two.
	p := planOn(t, []GPU{{Index: 0}}, []GPU{{Index: 0}}, d)
	if len(p.Units) != 0 {
		t.Errorf("built a unit on a card that is not there: %+v", p.Units)
	}
	if len(p.Failed) != 1 || p.Failed[0].Deployment != "dep_one" {
		t.Fatalf("failed = %+v, want dep_one", p.Failed)
	}
	// The message has to say which card went and what is left: one card off the
	// bus and a driver that stopped enumerating altogether are different
	// problems with different next steps.
	for _, want := range []string{"1", "GPU 0"} {
		if !strings.Contains(p.Failed[0].Reason, want) {
			t.Errorf("the reason does not name %s: %q", want, p.Failed[0].Reason)
		}
	}
	// Not a refusal: a refusal says the configuration is wrong, and this
	// configuration is right — the hardware is not.
	if len(p.Refused) != 0 {
		t.Errorf("also refused: %+v", p.Refused)
	}
}

// The same absence from the offer, the opposite fact. A card node.toml excludes
// is a decision somebody made on this machine and can unmake by editing a file;
// reporting it as hardware failure would send an operator to `dmesg` for a
// line they wrote themselves.
func TestACardNodeTomlExcludedIsNotAHardwareFailure(t *testing.T) {
	d := deployment()
	d.GPUs = []int{1}

	// Both cards are on the bus; the node offers only the first.
	p := planOn(t, []GPU{{Index: 0}, {Index: 1}}, []GPU{{Index: 0}}, d)
	if len(p.Failed) != 0 {
		t.Errorf("a card that is present was reported as gone: %+v", p.Failed)
	}
	if len(p.Refused) != 1 || !strings.Contains(p.Refused[0].Reason, "offer") {
		t.Fatalf("refused = %+v, want one refusal about the offer", p.Refused)
	}
}

// `agent plan` measures nothing, and a caller that did not measure must not be
// read as having measured no GPUs — that would report every deployment on the
// node as failed hardware.
func TestAPlanThatMeasuredNothingClaimsNoFailure(t *testing.T) {
	p := plan(t, deployment())
	if len(p.Failed) != 0 {
		t.Errorf("failed = %+v, want none: nothing was measured", p.Failed)
	}
	if len(p.Units) != 1 {
		t.Errorf("units = %d, want the deployment planned as usual", len(p.Units))
	}
}

const acmeDescriptor = `[backend]
name           = "acme-serve"
api            = "openai"
weights_layout = "hf-cache"
mount_path     = "/weights"
container_port = 9000
image_default  = "acme/serve:1"

[backend.capabilities]
tensor_parallel = false
expert_parallel = false
quantization    = ["awq"]
lora            = false
cpu_offload     = false

[backend.args]
model_path = "--model={v}"
port       = "--port={v}"

[backend.gpu]
mechanism = "device-flag"

[backend.probe]
health          = "/healthz"
ready           = "/healthz"
ready_timeout_s = 300
`

// R6-07: a node runs a backend that is not compiled into it, because the
// control plane sent the descriptor. There is no other channel — 03 §1 gives
// it no way to push, and a file placed on each node by hand would be a second
// copy of one fact.
func TestANodeRunsADescriptorItWasSent(t *testing.T) {
	root, digest := stage(t, map[string]string{"config.json": "{}"})
	doc := desired(deployment())
	doc.Staging[0].ManifestSHA256 = digest
	doc.Deployments[0].Backend = "acme-serve"
	// acme names neither max_context nor tensor_parallel, and a parameter the
	// descriptor does not name is dropped and the deployment refused (R6-03) —
	// which is itself proof the sent descriptor is the one in force.
	doc.Deployments[0].Params = json.RawMessage(`{}`)
	doc.Backends = []api.DesiredBackend{{Name: "acme-serve", Source: acmeDescriptor}}

	p, err := Build(doc, PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Units) != 1 {
		t.Fatalf("units = %d, refusals %+v: the sent descriptor was not used",
			len(p.Units), p.Refused)
	}
	env := envOf(p.Units[0])
	// The descriptor's own vocabulary, not a built-in's: `--model=` is acme's
	// spelling, and the mount path and container port are its too.
	if !strings.Contains(env["NODARY_ARGS"], "--model=") {
		t.Errorf("args = %q, want the sent descriptor's own spelling", env["NODARY_ARGS"])
	}
	if env["NODARY_CONTAINER_PORT"] != "9000" {
		t.Errorf("container port = %q, want the descriptor's 9000", env["NODARY_CONTAINER_PORT"])
	}
	if env["NODARY_MOUNT_PATH"] != "/weights" {
		t.Errorf("mount path = %q, want the descriptor's /weights", env["NODARY_MOUNT_PATH"])
	}
}

func envOf(u Unit) map[string]string {
	out := map[string]string{}
	for _, kv := range u.Env {
		out[kv.Key] = kv.Value
	}
	return out
}

// A built-in may not be redefined. The applier refuses registering one, and
// this is the same rule held on the far side of the wire: a node that accepted
// a redefinition would be one host in a fleet quietly running a different vLLM.
func TestASentDescriptorMayNotShadowABuiltIn(t *testing.T) {
	root, digest := stage(t, map[string]string{"config.json": "{}"})
	doc := desired(deployment())
	doc.Staging[0].ManifestSHA256 = digest
	doc.Backends = []api.DesiredBackend{{Name: "vllm",
		Source: strings.Replace(acmeDescriptor,
			`name           = "acme-serve"`, `name           = "vllm"`, 1)}}

	p, err := Build(doc, PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Units) != 1 {
		t.Fatalf("units = %d, want the deployment still planned", len(p.Units))
	}
	if got := envOf(p.Units[0])["NODARY_CONTAINER_PORT"]; got != "8000" {
		t.Errorf("container port = %q, want the built-in vLLM's 8000 — a sent descriptor "+
			"redefined a backend compiled into this agent", got)
	}
}

// A descriptor that does not parse affects the deployments that name it and
// nothing else. Failing the whole plan would stop the node reconciling
// anything, including what is already serving.
func TestAnUnreadableSentDescriptorDoesNotStopTheNode(t *testing.T) {
	root, digest := stage(t, map[string]string{"config.json": "{}"})
	doc := desired(deployment())
	doc.Staging[0].ManifestSHA256 = digest
	doc.Backends = []api.DesiredBackend{{Name: "acme-serve", Source: "this is not toml {{{"}}

	p, err := Build(doc, PlanOptions{ModelsDir: root, Present: twoGPUs(), Verify: true})
	if err != nil {
		t.Fatalf("a bad descriptor failed the whole plan: %v", err)
	}
	// The deployment on vllm is untouched; only one naming acme-serve would
	// have been refused.
	if len(p.Units) != 1 {
		t.Errorf("units = %d, want the unrelated deployment still planned", len(p.Units))
	}
}
