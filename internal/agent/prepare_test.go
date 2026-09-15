package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
)

// trtDescriptor is a backend that builds before it serves — the shape
// dev/specs/04-backends.md §6 gives TensorRT-LLM, minimal in every other
// respect so a test failure can only be about the phase.
const trtDescriptor = `[backend]
name           = "trt"
api            = "openai"
weights_layout = "engine-dir"
mount_path     = "/engine"
container_port = 8000
image_default  = "acme/trtllm-serve:1"

[backend.args]
model_path = "--model={v}"
port       = "--port={v}"

[backend.probe]
health          = "/health"
ready           = "/health"
ready_timeout_s = 1800

[backend.prepare]
required          = true
image             = "acme/trtllm-build:1"
command           = "trtllm-build --checkpoint_dir {src} --output_dir {out} --tp_size {tp}"
artifact          = "engine-dir"
gpu_arch_specific = true
timeout_s         = 21600
`

// stageEngine places a staged `engine-dir` model — the checkpoint a build
// reads. `weights_layout` describes a directory whose contents nodary does not
// interpret, which is what lets one value cover both the build's input and its
// output.
func stageEngine(t *testing.T) (root, digest string) {
	t.Helper()
	root = t.TempDir()
	dir, err := ModelDir(root, "engine-dir", "acme/tiny")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "checkpoint"
	if err := os.WriteFile(filepath.Join(dir, "rank0.safetensors"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	manifest := []byte(hex.EncodeToString(sum[:]) + "  rank0.safetensors\n")
	if err := os.WriteFile(filepath.Join(dir, ManifestName), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	md := sha256.Sum256(manifest)
	return root, hex.EncodeToString(md[:])
}

// trtDoc is a desired-state document placing one TensorRT-LLM-shaped
// deployment, with the descriptor carried the way R6-07 carries one.
func trtDoc(root, digest string) api.Desired {
	return api.Desired{
		Rev: 7, Node: "gpu-01",
		Backends: []api.DesiredBackend{{Name: "trt", Source: trtDescriptor}},
		Staging: []api.DesiredStaging{{Model: "acme/tiny", Source: "local",
			Layout: "engine-dir", ManifestSHA256: digest}},
		Deployments: []api.DesiredDeployment{{
			ID: "dep_trt", Model: "acme/tiny", Backend: "trt",
			Image: "acme/trtllm-serve@sha256:" + strings.Repeat("a", 64),
			GPUs:  []int{0, 1}, Params: json.RawMessage(`{"tensor_parallel":2}`),
			Port: 8001, Network: api.IsolatedNetwork, State: "ready",
		}},
	}
}

func a100s() []GPU {
	return []GPU{{Index: 0, Name: "NVIDIA A100-SXM4-80GB"}, {Index: 1, Name: "NVIDIA A100-SXM4-80GB"}}
}

// The phase exists at all: a backend that declares a build gets one, and the
// unit is pointed at what the build will produce rather than at the weights.
func TestABackendThatBuildsGetsAPreparePhase(t *testing.T) {
	root, digest := stageEngine(t)
	h, f := newFakeHost(t)
	h.Self = "/usr/local/bin/nodary"

	p, err := Build(trtDoc(root, digest), PlanOptions{ModelsDir: root, Present: a100s(),
		Verify: true, Builds: &Preparer{Host: h}, ConfigDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Refused) != 0 {
		t.Fatalf("refused %+v", p.Refused)
	}
	if len(p.Prepare) != 1 {
		t.Fatalf("prepare = %+v, want one entry", p.Prepare)
	}
	got := p.Prepare[0]
	if got.State != StatePreparing {
		t.Errorf("state = %q (%s), want %q", got.State, got.Reason, StatePreparing)
	}
	if got.Key == "" {
		t.Error("the artifact has no key, so nothing identifies what was built")
	}
	// The unit exists while the build runs — reconcileUnit is what holds it
	// back — and it must already name the directory the artifact will have.
	if len(p.Units) != 1 {
		t.Fatalf("units = %d, want 1", len(p.Units))
	}
	mount := envOf(p.Units[0])["NODARY_MODELS_DIR"]
	if mount != got.Dir {
		t.Errorf("the unit mounts %q, want the artifact at %q — a backend that builds serves "+
			"what it built, not what it read", mount, got.Dir)
	}
	if strings.Contains(mount, "hub") || mount == root {
		t.Errorf("the unit mounts the staged weights (%q) rather than the engine", mount)
	}

	// And a build was actually started, as a transient unit like staging.
	var started string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "systemd-run") && strings.Contains(c, "agent prepare") {
			started = c
		}
	}
	if started == "" {
		t.Fatalf("no build was started: %v", f.calls)
	}
	for _, want := range []string{"--collect", "Type=oneshot", "TimeoutStartSec=", got.Key} {
		if !strings.Contains(started, want) {
			t.Errorf("the unit is missing %q: %s", want, started)
		}
	}
}

// §4's ordering: stage, then prepare, then serve. A build reads the staged
// weights, so one that started before they arrived would fail on an empty
// directory and report it as a broken builder.
func TestNoBuildStartsBeforeTheWeightsAreStaged(t *testing.T) {
	root := t.TempDir() // nothing staged
	h, f := newFakeHost(t)
	h.Self = "/usr/local/bin/nodary"

	p, err := Build(trtDoc(root, strings.Repeat("b", 64)), PlanOptions{ModelsDir: root,
		Present: a100s(), Verify: true, Builds: &Preparer{Host: h}, ConfigDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Prepare) != 1 || p.Prepare[0].State != StateAbsent {
		t.Fatalf("prepare = %+v, want absent while the weights are not staged", p.Prepare)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "agent prepare") {
			t.Fatalf("a build started with no weights to read: %s", c)
		}
	}
}

// `agent plan` is a preview. It says what would be built and starts nothing,
// exactly as it neither downloads nor deletes.
func TestAPreviewStartsNoBuild(t *testing.T) {
	root, digest := stageEngine(t)
	p, err := Build(trtDoc(root, digest), PlanOptions{ModelsDir: root, Present: a100s(),
		Verify: true, ConfigDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Prepare) != 1 || p.Prepare[0].State != StateAbsent {
		t.Fatalf("prepare = %+v", p.Prepare)
	}
	if !strings.Contains(p.Prepare[0].Reason, "agent plan") {
		t.Errorf("the reason does not say which path is missing: %q", p.Prepare[0].Reason)
	}
	// It still says where the artifact would go, which is the question a
	// preview is being asked.
	if p.Prepare[0].Dir == "" || p.Prepare[0].Key == "" {
		t.Errorf("a preview reports no artifact at all: %+v", p.Prepare[0])
	}
}

// The key is what stops an engine compiled for one card being served on
// another. §6 spells the property "not portable across GPU models", so the
// model names are what it is keyed on.
func TestTheArtifactKeyFollowsWhatWouldChangeIt(t *testing.T) {
	root, digest := stageEngine(t)
	keyWith := func(mutate func(*api.Desired), gpus []GPU) string {
		t.Helper()
		doc := trtDoc(root, digest)
		if mutate != nil {
			mutate(&doc)
		}
		p, err := Build(doc, PlanOptions{ModelsDir: root, Present: gpus,
			Verify: true, ConfigDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Prepare) != 1 {
			t.Fatalf("prepare = %+v", p.Prepare)
		}
		return p.Prepare[0].Key
	}

	base := keyWith(nil, a100s())
	l40s := []GPU{{Index: 0, Name: "NVIDIA L40S"}, {Index: 1, Name: "NVIDIA L40S"}}

	if same := keyWith(nil, a100s()); same != base {
		t.Error("the same inputs produced two keys, so nothing would ever hit the cache")
	}
	if onL40S := keyWith(nil, l40s); onL40S == base {
		t.Error("an engine built on an A100 would be served on an L40S; gpu_arch_specific " +
			"says it is not portable and the key has to carry that")
	}
	// Different weights, same everything else.
	if other := keyWith(func(d *api.Desired) {
		d.Staging[0].ManifestSHA256 = strings.Repeat("c", 64)
	}, a100s()); other == base {
		t.Error("an engine built from one set of weights would be served for another")
	}
	// Different parallelism: an engine is compiled for a fixed rank count.
	if tp4 := keyWith(func(d *api.Desired) {
		d.Deployments[0].Params = json.RawMessage(`{"tensor_parallel":4}`)
	}, a100s()); tp4 == base {
		t.Error("an engine built for two ranks would be served for four")
	}
	// A portable artifact is not keyed on the card.
	portable := strings.Replace(trtDescriptor, "gpu_arch_specific = true",
		"gpu_arch_specific = false", 1)
	onA100 := keyWith(func(d *api.Desired) { d.Backends[0].Source = portable }, a100s())
	onL40S := keyWith(func(d *api.Desired) { d.Backends[0].Source = portable }, l40s)
	if onA100 != onL40S {
		t.Error("a backend that says its output is portable had it rebuilt per card anyway")
	}
}

// The gate, in the same place and the same shape as the one for weights: a
// server started against a half-written engine fails hours after the cause.
func TestAUnitWaitsForItsBuild(t *testing.T) {
	h, _ := newFakeHost(t)
	u := Unit{Deployment: "dep_trt", ModelID: "acme/tiny",
		EnvPath: filepath.Join(t.TempDir(), "dep_trt.env")}
	staged := map[string]string{"acme/tiny": StateStaged}

	for _, tc := range []struct {
		name         string
		built        Prepared
		wantState    string
		wantStartFor bool
	}{
		{"building", Prepared{Deployment: "dep_trt", State: StatePreparing}, "preparing", false},
		{"failed", Prepared{Deployment: "dep_trt", State: StateFailed,
			Reason: "the build failed: out of memory"}, "failed", false},
		{"built", Prepared{Deployment: "dep_trt", State: StatePrepared}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			built := map[string]Prepared{"dep_trt": tc.built}
			out, _ := reconcileUnit(context.Background(), u, staged, built, h, false)
			if !tc.wantStartFor {
				if out.State != tc.wantState {
					t.Fatalf("state = %q, want %q", out.State, tc.wantState)
				}
				if tc.wantState == "failed" && out.Error == "" {
					t.Error("a failed build reports no reason, so nothing says why")
				}
				return
			}
			// A finished build takes the gate out of the way; whatever happens
			// next is the ordinary unit path and not this test's business.
			if out.State == "preparing" {
				t.Fatalf("a finished build still held the unit back: %+v", out)
			}
		})
	}
}

// The marker, not the directory, is what says a build finished. A builder
// killed halfway leaves a directory full of partial output, and serving from
// it is the failure this phase exists to prevent.
func TestOnlyAMarkerMakesAnArtifactCount(t *testing.T) {
	root, digest := stageEngine(t)
	h, _ := newFakeHost(t)
	h.Self = "/usr/local/bin/nodary"
	opt := PlanOptions{ModelsDir: root, Present: a100s(), Verify: true,
		Builds: &Preparer{Host: h}, ConfigDir: t.TempDir()}

	p, err := Build(trtDoc(root, digest), opt)
	if err != nil {
		t.Fatal(err)
	}
	got := p.Prepare[0]

	// A directory that exists and no marker is still not prepared.
	if err := os.MkdirAll(got.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p, err = Build(trtDoc(root, digest), opt)
	if err != nil {
		t.Fatal(err)
	}
	if p.Prepare[0].State == StatePrepared {
		t.Fatal("a directory with no marker was served as a finished engine")
	}

	// The marker makes it one, and nothing is started again.
	modelDir, err := ModelDir(root, "engine-dir", "acme/tiny")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(preparedMarker(modelDir, got.Key), []byte(`{"key":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	h2, f2 := newFakeHost(t)
	h2.Self = "/usr/local/bin/nodary"
	opt.Builds = &Preparer{Host: h2}
	p, err = Build(trtDoc(root, digest), opt)
	if err != nil {
		t.Fatal(err)
	}
	if p.Prepare[0].State != StatePrepared {
		t.Fatalf("prepare = %+v, want prepared", p.Prepare[0])
	}
	for _, c := range f2.calls {
		if strings.Contains(c, "agent prepare") {
			t.Fatalf("a finished artifact was rebuilt: %s", c)
		}
	}
}

// The child: it runs the builder, and what it leaves behind is the whole of
// what the agent reads.
func TestTheBuildChildWritesAVerdict(t *testing.T) {
	setup := func(t *testing.T) (prepareRequest, string) {
		t.Helper()
		dir := t.TempDir()
		req := prepareRequest{
			Deployment: "dep_trt", Model: "acme/tiny", Key: "abc123",
			Image:  "acme/trtllm-build:1",
			Argv:   []string{"trtllm-build", "--output_dir", PrepareOutMount},
			SrcDir: filepath.Join(dir, "src"), OutDir: filepath.Join(dir, "out"),
			Marker:   filepath.Join(dir, "out.done.json"),
			Progress: filepath.Join(dir, "out.progress.json"),
			GPUs:     "device=0,1", TimeoutS: 60,
		}
		if err := os.MkdirAll(req.SrcDir, 0o755); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "request.json")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return req, path
	}

	t.Run("a build that works", func(t *testing.T) {
		req, path := setup(t)
		var ran []string
		out, err := RunPrepare(path, func(_ context.Context, name string, args ...string) ([]byte, error) {
			ran = append(ran, name+" "+strings.Join(args, " "))
			// The builder writes into the mount it was given, which on this
			// side of the bind is the scratch directory.
			return nil, os.WriteFile(filepath.Join(req.OutDir+".building", "engine"), []byte("e"), 0o644)
		})
		if err != nil {
			t.Fatal(err)
		}
		if out.State != StatePrepared {
			t.Fatalf("state = %q (%s)", out.State, out.Reason)
		}
		if len(ran) != 1 || !strings.Contains(ran[0], "acme/trtllm-build:1") {
			t.Fatalf("builder invocation = %v", ran)
		}
		// Read-only input, writable output, and the GPUs. An engine compiled
		// without the card is not an engine.
		for _, want := range []string{
			req.SrcDir + ":" + PrepareSrcMount + ":ro",
			":" + PrepareOutMount,
			"--gpus device=0,1",
		} {
			if !strings.Contains(ran[0], want) {
				t.Errorf("the builder was not given %q: %s", want, ran[0])
			}
		}
		if _, err := os.Stat(req.Marker); err != nil {
			t.Errorf("no marker: %v", err)
		}
		if _, err := os.Stat(filepath.Join(req.OutDir, "engine")); err != nil {
			t.Errorf("the artifact is not under its real name: %v", err)
		}
		if _, err := os.Stat(req.OutDir + ".building"); err == nil {
			t.Error("the scratch directory survived a finished build")
		}
	})

	t.Run("a build that fails", func(t *testing.T) {
		req, path := setup(t)
		out, err := RunPrepare(path, func(context.Context, string, ...string) ([]byte, error) {
			return []byte("CUDA error: out of memory"), fmt.Errorf("exit status 1")
		})
		if err != nil {
			t.Fatal(err)
		}
		if out.State != StateFailed {
			t.Fatalf("state = %q, want failed", out.State)
		}
		// 11 §2 wants the reason where an operator will meet it, which is the
		// deployment's last_error and not a container log on a GPU host.
		if !strings.Contains(out.Reason, "out of memory") {
			t.Errorf("the reason does not carry the build log: %q", out.Reason)
		}
		if _, err := os.Stat(req.Marker); err == nil {
			t.Error("a failed build left a marker, so it would be served")
		}
		if _, err := os.Stat(req.OutDir); err == nil {
			t.Error("a failed build left an artifact directory behind")
		}
		// And the verdict is on disk, so the next reconcile does not start six
		// more hours of the same failure.
		got, ok := readPrepareProgress(req.Progress)
		if !ok || got.State != StateFailed {
			t.Errorf("progress = %+v, %v", got, ok)
		}
	})
}
