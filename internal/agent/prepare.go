package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/backend"
)

// R6-06, dev/specs/04-backends.md §4: the lifecycle is stage → prepare →
// serve, not stage → serve.
//
// TensorRT-LLM is why. It compiles a per-GPU-architecture engine out of the
// staged weights before it can answer anything — hours of work producing a
// second artifact that itself has to be cached and verified. §4 calls omitting
// this phase "the standard mistake in 'just swap the image' plugin designs".
//
// **The same shape as staging, for the same reasons** (internal/agent/stageunit.go):
// a transient unit rather than work inside the agent process, a request file
// rather than flags, and a progress file rather than a mutex, because the
// parent and the child are different processes. A six-hour compile has no
// business running inside the long-lived root daemon that holds this node's
// mTLS key, and it must survive an agent restart without starting over.
//
// It runs on the **node** and not on the control plane, which is the opposite
// of a derived image (R6-09). A derived image is a container built once for a
// fleet; this is an engine compiled against the card it will serve from, and
// the control plane has no such card.

const (
	// StatePrepared is an artifact this node built and verified.
	StatePrepared = "prepared"
	// StatePreparing is a build running now.
	StatePreparing = "preparing"
	// StateFailed is a build that ran and did not produce one. Terminal until
	// something changes the key: a build that failed on the same inputs fails
	// the same way, and retrying it forever is six hours of GPU per cycle.
	StateFailed = "failed"
)

// Prepared is one deployment's build artifact and what has to happen to it.
type Prepared struct {
	Deployment string `json:"deployment"`
	Model      string `json:"model"`
	// Key is what identifies this artifact: see prepareKey. Reported so an
	// operator can tell a rebuild caused by a changed command from one caused
	// by a different card.
	Key    string `json:"key"`
	Dir    string `json:"dir"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// prepareKey is everything that would make the artifact different.
//
// Content-addressed like the rest of this product: the weights it was built
// from, the backend and builder image that built it, the exact argv, and — only
// when the descriptor says the output is not portable — the GPU models it was
// built on. A cache keyed on the deployment id instead would serve an engine
// compiled for an A100 on an L40S after a card swap, which is not an error
// anything reports; it is wrong numbers.
//
// The GPU *names* rather than a compute capability, because that is what the
// driver reports (internal/agent/inventory.go) and because §6 spells the
// property "not portable across GPU models".
func prepareKey(model, manifestSHA, backendName string, p backend.Prepare,
	argv []string, gpus []GPU) string {

	h := sha256.New()
	for _, part := range append([]string{model, manifestSHA, backendName, p.Image}, argv...) {
		// Length-prefixed, so that two different splits of the same bytes
		// cannot hash alike.
		fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	if p.GPUArchSpecific {
		var names []string
		for _, g := range gpus {
			if !containsString(names, g.Name) {
				names = append(names, g.Name)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(h, "%d:%s", len(n), n)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func containsString(all []string, want string) bool {
	for _, a := range all {
		if a == want {
			return true
		}
	}
	return false
}

// The artifact and its bookkeeping live beside the model directory, which is
// the convention `<dir>.staging.json` already set: nothing that looks at
// whether the model directory exists can mistake any of them for weights.
//
// Keyed within that directory rather than one path per model, so two
// deployments of one model with different parallelism — or on different cards —
// do not build into each other.
func preparedRoot(modelDir string) string        { return modelDir + ".prepared" }
func preparedDir(modelDir, key string) string    { return filepath.Join(preparedRoot(modelDir), key) }
func preparedMarker(modelDir, key string) string { return preparedDir(modelDir, key) + ".done.json" }
func prepareReqPath(modelDir, key string) string {
	return preparedDir(modelDir, key) + ".request.json"
}
func prepareProgressPath(modelDir, key string) string {
	return preparedDir(modelDir, key) + ".progress.json"
}

// prepareUnitName is one artifact's transient unit.
//
// Named by the key rather than the deployment: the key is what the build is
// *of*, so two deployments that would produce the same artifact wait on one
// unit instead of racing two builds into one directory.
func prepareUnitName(key string) string { return "nodary-prepare-" + key + ".service" }

// prepareRequest is everything the transient unit needs. A file rather than
// flags for the reason stageRequest is one: an argv is visible in `ps` to every
// local user for as long as the parent runs.
type prepareRequest struct {
	Deployment string   `json:"deployment"`
	Model      string   `json:"model"`
	Key        string   `json:"key"`
	Image      string   `json:"image"`
	Argv       []string `json:"argv"`
	// SrcDir and OutDir are the host paths. The container sees them at the
	// fixed mount points below, which is what Argv was rendered against.
	SrcDir   string `json:"src_dir"`
	OutDir   string `json:"out_dir"`
	Marker   string `json:"marker"`
	Progress string `json:"progress"`
	// RequestPath is where this file itself lives, so the unit's argv can name
	// it without the parent and the child computing the path twice.
	RequestPath string `json:"request_path"`
	GPUs        string `json:"gpus"`
	TimeoutS    int    `json:"timeout_s"`
}

// PrepareSrcMount and PrepareOutMount are where the build sees its input and
// its output, and they are fixed rather than taken from the descriptor.
//
// The command template is written by whoever wrote the descriptor and the host
// paths are chosen by nodary, so something has to be the stable thing the
// template refers to. Fixing them here means `{src}` and `{out}` mean the same
// two directories in every descriptor, and a build cannot be handed a path
// that happens to collide with something in its own image.
const (
	PrepareSrcMount = "/nodary/src"
	PrepareOutMount = "/nodary/out"
)

// marker is what a finished build leaves behind, and the only thing that makes
// an artifact directory count as one.
//
// A directory that exists is not evidence: a build killed halfway leaves one
// full of partial output, and serving from it is the failure this phase exists
// to prevent. So the child writes this file after the builder exits zero, and
// nothing else ever does.
type marker struct {
	Key        string `json:"key"`
	Model      string `json:"model"`
	Deployment string `json:"deployment"`
	FinishedAt string `json:"finished_at"`
}

// Preparer runs and tracks builds. One per agent, like Downloader.
type Preparer struct {
	Host Host
}

// Status is the verdict for one deployment's artifact, starting a build if
// nothing is already doing it.
//
// The order is the point: a finished artifact costs one stat, a running build
// costs one `systemctl is-active`, and only a deployment with neither reaches
// the branch that starts anything.
func (pr *Preparer) Status(req prepareRequest) Prepared {
	out := Prepared{Deployment: req.Deployment, Model: req.Model,
		Key: req.Key, Dir: req.OutDir}
	if _, err := os.Stat(req.Marker); err == nil {
		out.State = StatePrepared
		return out
	}
	ctx := context.Background()
	switch pr.Host.activeState(ctx, prepareUnitName(req.Key)) {
	case "active", "activating", "deactivating", "reloading":
		out.State = StatePreparing
		if have, ok := readPrepareProgress(req.Progress); ok && have.Reason != "" {
			out.Reason = have.Reason
		}
		return out
	}
	// Not running, no marker. Either it has never run, or it ran and failed —
	// and those are different outcomes, so the progress file is what tells
	// them apart rather than starting a six-hour build again to find out.
	if have, ok := readPrepareProgress(req.Progress); ok && have.State == StateFailed {
		out.State, out.Reason = StateFailed, have.Reason
		return out
	}
	if err := pr.start(ctx, req); err != nil {
		out.State, out.Reason = StateFailed, err.Error()
		return out
	}
	out.State = StatePreparing
	return out
}

// start launches the build's transient unit.
//
// No IP filter, unlike staging: a build pulls its image through containerd,
// which is not this unit's child, and reaches a package index that R6-09 will
// govern where it belongs. Filtering here would deny the enclave for a process
// that does no network work of its own, which reads as a control and is not
// one.
func (pr *Preparer) start(ctx context.Context, req prepareRequest) error {
	if pr.Host.Self == "" {
		return errors.New("this agent does not know its own path, so it cannot start a build")
	}
	if err := writePrepareRequest(req.RequestPath, req); err != nil {
		return err
	}
	args := []string{
		"--unit=" + prepareUnitName(req.Key),
		"--description=nodary prepare " + req.Model + " for " + req.Deployment,
		// Collected on exit, so the next reconcile finds a verdict on disk or a
		// clean slate rather than a failed unit object systemd-run refuses to
		// reuse. The verdict is the child's job precisely because --collect
		// takes the unit's own result away with it.
		"--collect",
		"--property=Type=oneshot",
		// The build is the long pole and systemd's default is 90 seconds.
		// Without this every prepare is killed as a start timeout and reported
		// as though the builder had crashed.
		fmt.Sprintf("--property=TimeoutStartSec=%d", req.TimeoutS+prepareGrace),
		"--", pr.Host.Self, "agent", "prepare", "--request", req.RequestPath,
	}
	if out, err := pr.Host.systemdRun(ctx, args...); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// prepareGrace is how much longer systemd waits than the build is allowed to
// run. The child enforces timeout_s itself and writes a reason; systemd killing
// it first would replace that reason with nothing.
const prepareGrace = 60

func writePrepareRequest(path string, req prepareRequest) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func readPrepareRequest(path string) (prepareRequest, error) {
	var req prepareRequest
	b, err := os.ReadFile(path)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(b, &req); err != nil {
		return req, fmt.Errorf("reading the prepare request: %w", err)
	}
	if req.Key == "" || req.OutDir == "" || len(req.Argv) == 0 {
		return req, errors.New("the prepare request names no artifact or no command")
	}
	return req, nil
}

func writePrepareProgress(path string, p Prepared) {
	b, err := json.Marshal(p)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func readPrepareProgress(path string) (Prepared, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Prepared{}, false
	}
	var p Prepared
	if err := json.Unmarshal(b, &p); err != nil || p.State == "" {
		return Prepared{}, false
	}
	return p, true
}

// RunPrepare builds one artifact and exits. This is the child:
// `nodary agent prepare --request <path>`, which is all the transient unit runs.
//
// Like RunStaging it returns its verdict rather than an error for a failed
// build: a build that fails is not an error in this program, it is a state with
// a reason, and the file it writes is where the agent reads it.
func RunPrepare(requestPath string, run func(context.Context, string, ...string) ([]byte, error)) (Prepared, error) {
	req, err := readPrepareRequest(requestPath)
	if err != nil {
		return Prepared{}, err
	}
	out := Prepared{Deployment: req.Deployment, Model: req.Model, Key: req.Key,
		Dir: req.OutDir, State: StatePreparing}
	writePrepareProgress(req.Progress, out)

	// Into a scratch directory, renamed on success. A builder killed at the
	// timeout has then written nothing that could be mistaken for an artifact,
	// which matters more here than anywhere else: the marker says an engine is
	// finished and the engine is what gets served.
	scratch := req.OutDir + ".building"
	_ = os.RemoveAll(scratch)
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		out.State, out.Reason = StateFailed, err.Error()
		writePrepareProgress(req.Progress, out)
		return out, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(req.TimeoutS)*time.Second)
	defer cancel()

	args := []string{"run", "--rm", "--gpus", req.GPUs,
		"-v", req.SrcDir + ":" + PrepareSrcMount + ":ro",
		"-v", scratch + ":" + PrepareOutMount,
		req.Image}
	args = append(args, req.Argv...)
	body, err := run(ctx, "/usr/local/bin/nerdctl", args...)
	if err != nil {
		_ = os.RemoveAll(scratch)
		out.State = StateFailed
		if ctx.Err() != nil {
			out.Reason = fmt.Sprintf("the build did not finish within %ds; "+
				"04 §4 bounds it and this one hit the bound", req.TimeoutS)
		} else {
			// The tail, not the whole log: 11 §2 wants the reason in the
			// deployment's last_error, and a build log is megabytes.
			out.Reason = fmt.Sprintf("the build failed: %v: %s", err, logTail(body))
		}
		writePrepareProgress(req.Progress, out)
		return out, nil
	}
	if err := os.RemoveAll(req.OutDir); err != nil {
		out.State, out.Reason = StateFailed, err.Error()
		writePrepareProgress(req.Progress, out)
		return out, nil
	}
	if err := os.Rename(scratch, req.OutDir); err != nil {
		out.State, out.Reason = StateFailed, err.Error()
		writePrepareProgress(req.Progress, out)
		return out, nil
	}
	// The marker last, after the artifact is in place under its real name.
	// Written in the other order, an agent that died between them would find a
	// marker for a directory that is not there.
	b, err := json.Marshal(marker{Key: req.Key, Model: req.Model,
		Deployment: req.Deployment, FinishedAt: time.Now().UTC().Format(time.RFC3339)})
	if err == nil {
		err = os.WriteFile(req.Marker, b, 0o644)
	}
	if err != nil {
		out.State, out.Reason = StateFailed, err.Error()
		writePrepareProgress(req.Progress, out)
		return out, nil
	}
	out.State, out.Reason = StatePrepared, ""
	writePrepareProgress(req.Progress, out)
	return out, nil
}

// logTail is the last few lines of a build log, which is what an operator
// needs and what a heartbeat can carry.
func logTail(body []byte) string {
	const max = 2000
	s := strings.TrimSpace(string(body))
	if len(s) > max {
		s = "…" + s[len(s)-max:]
	}
	return s
}

// planPrepare works out one deployment's artifact and starts the build if
// nothing is doing it — dev/specs/04-backends.md §4.
//
// **Weights first.** A build reads the staged weights, so a model that is
// still arriving has nothing to build from and this reports `absent` rather
// than starting a builder that would fail on an empty directory. That is
// §3's ordering rule — stage, then prepare, then serve — and it is enforced
// here rather than left to the builder to discover.
func planPrepare(d api.DesiredDeployment, desc backend.Descriptor, st Stage,
	manifestSHA string, present map[int]GPU, opt PlanOptions) Prepared {

	pr := *desc.Backend.Prepare
	out := Prepared{Deployment: d.ID, Model: d.Model}

	params := backend.Params{}
	if len(d.Params) > 0 {
		if err := json.Unmarshal(d.Params, &params); err != nil {
			out.State, out.Reason = StateFailed, fmt.Sprintf("params are not an object: %v", err)
			return out
		}
	}
	// The build is told the parallelism the server will use, because an engine
	// is compiled for a fixed number of ranks: one built for two cards cannot
	// be served on four, and finding that out at serve time is a container
	// that exits on a shape mismatch.
	tp := len(d.GPUs)
	if v, ok := params["tensor_parallel"]; ok {
		n, ok := jsonInt(v)
		if !ok {
			out.State, out.Reason = StateFailed,
				fmt.Sprintf("tensor_parallel is %v, which is not a whole number", v)
			return out
		}
		tp = n
	}

	// Rendered against the container's fixed mount points, never the host
	// paths: that is what makes the key the same on two nodes with different
	// models directories, which is the whole point of content-addressing it.
	argv, err := pr.Argv(PrepareSrcMount, PrepareOutMount, tp)
	if err != nil {
		out.State, out.Reason = StateFailed, unwrap(err)
		return out
	}

	var gpus []GPU
	for _, idx := range d.GPUs {
		if g, ok := present[idx]; ok {
			gpus = append(gpus, g)
		}
	}
	key := prepareKey(d.Model, manifestSHA, d.Backend, pr, argv, gpus)
	out.Key = key

	// The staged directory as Build already resolved it, rather than resolving
	// it a second time from the layout: two computations of one path is how
	// they come to disagree.
	srcDir := st.Dir
	if srcDir == "" {
		out.State, out.Reason = StateFailed, "this node has no staged directory for "+d.Model
		return out
	}
	out.Dir = preparedDir(srcDir, key)

	if st.State != StateStaged {
		// Not a failure: the weights are on their way. Reported so an operator
		// watching a deployment sees why the build has not started rather than
		// an empty prepare list.
		out.State, out.Reason = StateAbsent, "waiting for the weights this build reads"
		return out
	}
	if opt.Builds == nil {
		// `agent plan` is a preview. It says what the artifact would be and
		// starts nothing, exactly as it neither downloads nor deletes.
		out.State = StateAbsent
		out.Reason = "the build needs a running agent; `agent plan` never starts one"
		return out
	}

	// The builder reaches a card the same way the server will, because it is
	// the same card: TensorRT-LLM compiles against the architecture it is
	// handed (dev/specs/04-backends.md §4), so a build that got a different
	// device than the deployment would produce an engine for the wrong one.
	flag, err := gpuFlag(d.GPUs, present, opt.CDIDevices)
	if err != nil {
		out.State, out.Reason = StateFailed, err.Error()
		return out
	}
	return opt.Builds.Status(prepareRequest{
		Deployment: d.ID, Model: d.Model, Key: key,
		Image: pr.Image, Argv: argv,
		SrcDir:      srcDir,
		OutDir:      out.Dir,
		Marker:      preparedMarker(srcDir, key),
		Progress:    prepareProgressPath(srcDir, key),
		RequestPath: prepareReqPath(srcDir, key),
		GPUs:        flag,
		TimeoutS:    pr.TimeoutS,
	})
}

// unwrap drops a sentinel prefix so a reason reads as a sentence rather than
// as "invalid backend descriptor: invalid backend descriptor: …".
func unwrap(err error) string {
	s := err.Error()
	if _, rest, found := strings.Cut(s, ": "); found {
		return rest
	}
	return s
}

// jsonInt reads a whole number out of a decoded JSON value.
//
// `encoding/json` hands back float64 for every number, so 2 arrives as 2.0 and
// has to come back as "2": `--tp_size 2.000000` is a build that fails on its
// own argument.
func jsonInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if n != float64(int(n)) {
			return 0, false
		}
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}
