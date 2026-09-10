package agent

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/backend"
	"github.com/nodarynet/nodary/internal/paths"
)

// A Plan is what the agent would do, worked out without doing any of it.
//
// docs/specs/03-agent.md §3's loop is `desired → evaluate → observe → act`, and
// everything up to `act` is a pure function of a document, a models directory
// and what the driver reported. Keeping it that way is what lets the decisions
// be tested exhaustively without containerd, systemd or a GPU — and it is what
// `nodary agent plan` renders, so an operator can see what would happen before
// anything does.
//
// R4c holds the acting half. Nothing in this file writes a file, starts a unit
// or opens a socket.
type Plan struct {
	Rev   int64   `json:"rev"`
	Node  string  `json:"node"`
	Units []Unit  `json:"units"`
	Stage []Stage `json:"stage"`
	// Refused is a deployment the node will not run, with the reason. A refusal
	// is a normal outcome (docs/specs/03-agent.md §2) and is reported, not
	// retried.
	Refused []Refusal `json:"refused"`
	// ResetDone is models whose weights this run actually discarded in
	// response to doc.Reset (`nodary model restage`/`unstage`), reported
	// back on the next heartbeat so the control plane can stop asking
	// (internal/observed.Heartbeat consumes it).
	ResetDone []string `json:"reset_done,omitempty"`
	// Disabled is a deployment `nodary model disable` turned off
	// (docs/specs/05-catalog.md §4). No Unit is built for it — nothing about
	// GPUs, the backend or staged weights matters for something that will
	// not run — and Reconcile's existing "stop what is not wanted" loop
	// (internal/agent/reconcile.go) is what actually stops it, since it is
	// simply absent from Units.
	Disabled []string `json:"disabled,omitempty"`
	// Restart is deployment ids `nodary model restart` (R4-36) asked to be
	// cycled now — the request, not the outcome. Unlike Reset (filesystem
	// only, so Build can perform it directly) this needs `systemctl`, which
	// only Reconcile has, so Reconcile is what actually restarts them and
	// reports which ones landed as Report.RestartDone.
	Restart []string `json:"restart,omitempty"`
}

// Unit is one deployment rendered as everything systemd needs.
//
// docs/specs/03-agent.md §6: the agent writes only
// /etc/nodary/deployments/<id>.env and calls systemctl. It holds no supervision
// logic, so this struct is the whole of what it decides.
type Unit struct {
	Deployment string `json:"deployment"`
	ModelID    string `json:"model"`
	Service    string `json:"service"`
	EnvPath    string `json:"env_path"`
	// Env is the file's contents, as ordered key/value pairs. Ordered because
	// the file is compared against what is on disk to decide whether to
	// restart, and a map's iteration order would rewrite it every reconcile and
	// restart a serving model for no reason.
	Env []EnvVar `json:"env"`
	// Probe is where health is polled, filled from the backend descriptor.
	Probe    Probe `json:"probe"`
	GPUs     []int `json:"gpus"`
	HostPort int   `json:"host_port"`
}

type EnvVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Probe is what R4c polls: docs/specs/03-agent.md §7.
type Probe struct {
	Health        string `json:"health"`
	Ready         string `json:"ready"`
	ReadyTimeoutS int    `json:"ready_timeout_s"`
}

// Stage is one model's weights and what has to happen to them.
type Stage struct {
	Model  string `json:"model"`
	Source string `json:"source"`
	Dir    string `json:"dir"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// Bytes is progress: for `source: local` (VerifyStaged), all-or-nothing —
	// there is no partial state between "verified" and "not yet" for weights
	// already on disk, so it is 0 until State is StateStaged and then the full
	// count. For `source: remote` (Downloader, R4-33) it climbs while State is
	// StateStaging, against Total once Total is known — a HEAD request away,
	// not from anything the control plane has to be trusted to report
	// correctly.
	Bytes int64 `json:"bytes,omitempty"`
	// Total is 0 when unknown — a local verdict never sets it (Bytes already
	// means "the whole thing" once staged) and a remote download that has not
	// finished its HEAD requests yet has nothing to report.
	Total int64 `json:"total,omitempty"`
}

type Refusal struct {
	Deployment string `json:"deployment"`
	Reason     string `json:"reason"`
}

// PlanOptions are what the node knows that the document does not.
type PlanOptions struct {
	ModelsDir string
	// ConfigDir is where the environment files go. It is a parameter so a test
	// can drive real systemd against a temporary tree; production always passes
	// paths.ConfigDir.
	ConfigDir string
	// Present is what the driver reported, already narrowed to the offer.
	Present []GPU
	// Verify runs the manifest check. It is a parameter because reading every
	// byte of a large model is minutes of disk, and `nodary agent plan` should
	// be able to answer without doing it.
	Verify bool
	// WSL2 says whether this host runs under WSL2, so a descriptor's
	// host-conditional environment can be applied. A parameter rather than a
	// probe inside Build, so a test can render both hosts.
	WSL2 bool
	// CDIDevices are the device names the host's CDI specification declares,
	// as `nvidia-ctk cdi list` reports them. Nil means it could not be asked.
	//
	// It is here because the runtime resolves `--gpus device=0` to the CDI
	// device `nvidia.com/gpu=0`, and whether that device exists is a property
	// of the host rather than of the deployment. See gpuFlag.
	CDIDevices []string
	// Downloads runs `source: remote` staging. Nil in every caller except
	// Daemon.reconcile — `agent plan` passes none, deliberately: a one-shot
	// preview command must never be what starts a download that outlives it.
	Downloads *Downloader
}

// Build turns one desired-state document into a plan.
//
// Refusals here are about what this node *cannot* do — an unknown backend, a
// GPU that is not on offer, a deployment with no image. They are not the
// guardrail evaluation of docs/specs/12-node-guardrails.md, which is R4-14 and
// is not in the MVP: a limit in node.toml narrows what is *offered* (R4-13) and
// this build does not additionally refuse work the control plane placed within
// that offer.
func Build(doc api.Desired, opt PlanOptions) (Plan, error) {
	if opt.ConfigDir == "" {
		opt.ConfigDir = paths.ConfigDir
	}
	p := Plan{Rev: doc.Rev, Node: doc.Node,
		Units: []Unit{}, Stage: []Stage{}, Refused: []Refusal{}, Disabled: []string{}}

	descriptors, err := backend.Builtins()
	if err != nil {
		return Plan{}, err
	}
	offered := map[int]bool{}
	for _, g := range opt.Present {
		offered[g.Index] = true
	}

	// Reset runs before staging is evaluated, so a restage's deletion is
	// visible to this same cycle's VerifyStaged/Downloads.Status call rather
	// than costing an extra ~60s round trip. Guarded the same way remote
	// staging itself is: a one-shot preview (opt.Downloads == nil) must
	// never delete anything, and neither should a plan that never read the
	// manifest in the first place.
	if opt.Verify && opt.Downloads != nil {
		for _, r := range doc.Reset {
			dir, err := ModelDir(opt.ModelsDir, r.Layout, r.Model)
			if err != nil {
				continue
			}
			if opt.Downloads.Reset(r.Model, dir) {
				p.ResetDone = append(p.ResetDone, r.Model)
			}
		}
	}

	// Restart is a request, not an outcome: cycling a unit needs systemctl,
	// which only Reconcile has, so Build only carries the request forward.
	// Guarded the same way Reset is — opt.Downloads is nil only for a
	// one-shot `agent plan` preview, and a preview must restart nothing any
	// more than it deletes anything.
	if opt.Downloads != nil {
		p.Restart = append(p.Restart, doc.Restart...)
	}

	// Staging first, and the order is not cosmetic: docs/specs/03-agent.md §3
	// fixes it — weights are staged before a deployment is prepared, and a
	// deployment is prepared before its unit starts.
	byModel := map[string]Stage{}
	for _, s := range doc.Staging {
		st := Stage{Model: s.Model, Source: s.Source, State: StateAbsent}
		dir, err := ModelDir(opt.ModelsDir, s.Layout, s.Model)
		if err != nil {
			st.State, st.Reason = StateCorrupt, err.Error()
			byModel[s.Model] = st
			continue
		}
		st.Dir = dir
		switch {
		case !opt.Verify:
			// Applies to remote as much as local: a preview must not start a
			// download any more than it re-reads bytes it already has.
			st.State, st.Reason = "unverified", "the manifest was not read; run without --no-verify to check it"
		case s.Source == "local":
			v := VerifyStaged(opt.ModelsDir, s.Layout, s.Model, s.ManifestSHA256)
			st.State, st.Reason, st.Bytes = v.State, v.Reason, v.Bytes
		case opt.Downloads == nil:
			// R4-33's download itself needs a long-lived Downloader to poll
			// across reconcile cycles, which `agent plan` — a one-shot preview
			// — deliberately never constructs. Named rather than silently
			// skipped, so a node that cannot stage says which path it is
			// missing.
			st.Reason = "remote staging needs a running agent; `agent plan` never starts a download"
		default:
			// Already staged from an earlier run — including one this same
			// process finished before a restart — costs one read, not a
			// network round trip: VerifyStaged answers that without the
			// Downloader ever being asked.
			if v := VerifyStaged(opt.ModelsDir, s.Layout, s.Model, s.ManifestSHA256); v.State == StateStaged {
				st.State, st.Bytes, st.Total, st.Reason = v.State, v.Bytes, v.Bytes, v.Reason
			} else {
				got := opt.Downloads.Status(s.Model, s.ManifestBody, s.ManifestSHA256, dir)
				st.State, st.Bytes, st.Total, st.Reason = got.State, got.Bytes, got.Total, got.Reason
			}
		}
		byModel[s.Model] = st
	}
	for _, m := range sortedStageKeys(byModel) {
		p.Stage = append(p.Stage, byModel[m])
	}

	for _, d := range doc.Deployments {
		if d.State == "disabled" {
			p.Disabled = append(p.Disabled, d.ID)
			continue
		}
		u, err := unitFor(d, descriptors, offered, byModel, opt)
		if err != nil {
			p.Refused = append(p.Refused, Refusal{Deployment: d.ID, Reason: err.Error()})
			continue
		}
		p.Units = append(p.Units, u)
	}
	return p, nil
}

// unitFor renders one deployment, or says why it cannot be rendered.
func unitFor(d api.DesiredDeployment, descriptors map[string]backend.Descriptor,
	offered map[int]bool, staged map[string]Stage, opt PlanOptions) (Unit, error) {
	desc, ok := descriptors[d.Backend]
	if !ok {
		return Unit{}, fmt.Errorf("backend %q is not one this build has (%s)",
			d.Backend, strings.Join(backend.Names(descriptors), ", "))
	}
	if d.Image == "" {
		return Unit{}, fmt.Errorf("no image is pinned; a node runs pinned digests and does not choose one")
	}
	if d.Port <= 0 {
		return Unit{}, fmt.Errorf("no host port is assigned")
	}
	if len(d.GPUs) == 0 {
		return Unit{}, fmt.Errorf("no GPU is assigned; docs/specs/03-agent.md §7 makes assignment explicit, always")
	}
	// The node's own check of what the control plane assigned. R4-23 makes this
	// a hard refusal, and it deliberately does not test for /dev/nvidia<index>:
	// a WSL2 host has no such device and nvidia-smi still reports the card.
	for _, idx := range d.GPUs {
		if !offered[idx] {
			return Unit{}, fmt.Errorf("GPU %d is not on this node's offer", idx)
		}
	}

	gpus, err := gpuFlag(d.GPUs, offered, opt.CDIDevices)
	if err != nil {
		return Unit{}, err
	}
	env, err := envFlags(desc.Backend, opt.WSL2, d.Env)
	if err != nil {
		return Unit{}, err
	}

	st, ok := staged[d.Model]
	if !ok {
		return Unit{}, fmt.Errorf("model %q is not in this node's staging list", d.Model)
	}
	if st.State == StateCorrupt {
		return Unit{}, fmt.Errorf("weights are corrupt: %s", st.Reason)
	}

	params := backend.Params{}
	if len(d.Params) > 0 {
		if err := json.Unmarshal(d.Params, &params); err != nil {
			return Unit{}, fmt.Errorf("params are not an object: %v", err)
		}
	}
	var extra []string
	if len(d.ExtraArgs) > 0 {
		if err := json.Unmarshal(d.ExtraArgs, &extra); err != nil {
			return Unit{}, fmt.Errorf("extra_args is not a list of strings: %v", err)
		}
	}
	// The model path as the *container* sees it: the weights are bind-mounted
	// at the descriptor's mount_path, so the argv must name that side.
	inContainer := desc.Backend.MountPath
	if desc.Backend.WeightsLayout == "hf-cache" {
		inContainer = filepath.Join(desc.Backend.MountPath,
			"hub", "models--"+strings.ReplaceAll(d.Model, "/", "--"))
	}
	for _, a := range extra {
		// Refused, not escaped. The unit template expands ${NODARY_ARGS}
		// unquoted so systemd splits it on whitespace, and no quoting
		// convention we invent here would survive that. Silently collapsing the
		// space would start a container with an argument the operator did not
		// write.
		if strings.ContainsAny(a, " \t\n") {
			return Unit{}, fmt.Errorf(
				"extra_args %q contains whitespace, which the unit's EnvironmentFile cannot carry", a)
		}
	}
	args, dropped, err := desc.Args(inContainer, params, extra)
	if err != nil {
		return Unit{}, err
	}
	if len(dropped) > 0 {
		// Dropped rather than guessed (04 §3), and said out loud: a parameter
		// that silently vanished is a deployment running with settings the
		// operator believes are in force.
		return Unit{}, fmt.Errorf("%s does not take %s; move them to extra_args",
			d.Backend, strings.Join(dropped, ", "))
	}

	network := d.Network
	if network == "" {
		network = api.IsolatedNetwork
	}
	return Unit{
		Deployment: d.ID,
		ModelID:    d.Model,
		Service:    UnitName(d.ID),
		EnvPath:    filepath.Join(opt.ConfigDir, "deployments", d.ID+".env"),
		GPUs:       d.GPUs,
		HostPort:   d.Port,
		Probe: Probe{Health: desc.Backend.Probe.Health, Ready: desc.Backend.Probe.Ready,
			ReadyTimeoutS: desc.Backend.Probe.ReadyTimeoutS},
		// The names are the unit template's, docs/specs/03-agent.md §6, and
		// nothing else may appear here: a variable the template does not
		// reference is a setting that looks applied and is not.
		Env: []EnvVar{
			{"NODARY_ARGS", strings.Join(args, " ")},
			{"NODARY_CONTAINER_PORT", strconv.Itoa(desc.Backend.ContainerPort)},
			// The whole `--gpus` value, not just the indices: what the runtime
			// accepts depends on what the host's CDI specification declares.
			{"NODARY_GPUS", gpus},
			// `-e KEY=VALUE` pairs, or empty. Unbraced in the template so
			// systemd splits it, the same mechanism NODARY_ARGS uses.
			{"NODARY_ENV", env},
			{"NODARY_IMAGE", d.Image},
			{"NODARY_MODELS_DIR", opt.ModelsDir},
			{"NODARY_MOUNT_PATH", desc.Backend.MountPath},
			{"NODARY_NETWORK", network},
			{"NODARY_PORT", strconv.Itoa(d.Port)},
		},
	}, nil
}

// RenderEnv is the file docs/specs/03-agent.md §6's EnvironmentFile= reads.
//
// systemd's parser is not a shell: a value is taken literally to end of line,
// so nothing here is quoted or escaped. Values that could contain whitespace —
// NODARY_ARGS is the only one — are joined by shellJoin, which refuses rather
// than escapes.
func (u Unit) RenderEnv() []byte {
	var b strings.Builder
	b.WriteString("# Written by nodary. Edits are overwritten on the next reconcile.\n")
	fmt.Fprintf(&b, "# Deployment %s — docs/specs/03-agent.md §6\n", u.Deployment)
	for _, v := range u.Env {
		fmt.Fprintf(&b, "%s=%s\n", v.Key, v.Value)
	}
	return []byte(b.String())
}

// joinIndices renders a GPU set for the runtime's device flag.
func joinIndices(in []int) string {
	out := make([]string, len(in))
	for i, n := range in {
		out[i] = strconv.Itoa(n)
	}
	return strings.Join(out, ",")
}

func sortedStageKeys(m map[string]Stage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// gpuFlag is the value the unit passes to `--gpus`.
//
// **The runtime resolves `device=0` to the CDI device `nvidia.com/gpu=0`, and
// on WSL2 no such device exists.** There is no /dev/nvidia0 there — the only
// node is /dev/dxg — so `nvidia-ctk cdi generate` emits a single device named
// `all`, and every deployment died in a restart loop with
//
//	CDI device injection failed: unresolvable CDI devices nvidia.com/gpu=0
//
// on a host where `nerdctl run --gpus all` works perfectly. docs/specs/03-agent.md
// §7's note that a WSL2 host has no per-GPU device node was written about the
// *assignment check*; this is the same fact reaching the argv.
//
// So: use the indexed form when the host declares indexed devices, and fall
// back to `all` only when it is genuinely equivalent — every GPU the node
// offers is assigned to this deployment. **A subset is refused rather than
// widened**, because 03 §7 makes assignment explicit and handing a container
// three cards when it was given one is not a degraded mode, it is a different
// deployment.
//
// An empty device list means nvidia-ctk could not be asked. The indexed form is
// then used unchanged: preflight already refuses a node with no toolkit, and
// guessing `all` on a host whose specification nobody read would be the
// widening this function exists to prevent.
func gpuFlag(assigned []int, offered map[int]bool, cdi []string) (string, error) {
	indexed := "device=" + joinIndices(assigned)
	if len(cdi) == 0 {
		return indexed, nil
	}

	have := map[string]bool{}
	for _, name := range cdi {
		// `nvidia.com/gpu=0` — the part after the last `=` is the device.
		if i := strings.LastIndex(name, "="); i >= 0 {
			have[name[i+1:]] = true
		}
	}
	everyIndexed := true
	for _, idx := range assigned {
		if !have[strconv.Itoa(idx)] {
			everyIndexed = false
			break
		}
	}
	if everyIndexed {
		return indexed, nil
	}
	if !have["all"] {
		return "", fmt.Errorf("this host's CDI specification declares %v, and none of them "+
			"names the assigned GPU(s) %v; `nvidia-ctk cdi generate` writes it", cdi, assigned)
	}
	if len(assigned) != len(offered) {
		return "", fmt.Errorf("this host's CDI specification declares only `all`, so a subset "+
			"cannot be assigned: %d of %d GPU(s) were requested. On WSL2 there is no per-GPU "+
			"device node for nvidia-ctk to name", len(assigned), len(offered))
	}
	return "all", nil
}

// envFlags renders a deployment's environment as `-e KEY=VALUE` pairs.
//
// A backend is configured by arguments *and* by environment, and only the first
// was expressible. The case that proved it: on WSL2 vLLM refuses to start with
// `RuntimeError: UVA is not available`, and both published fixes —
// `VLLM_WSL2_ENABLE_PIN_MEMORY=1` and `VLLM_USE_V2_MODEL_RUNNER=0` — are
// environment variables with no command-line form. No deployment could be made
// to run on a platform docs/specs/01-install.md §8 supports.
//
// Sorted, because the result goes into a unit's environment file and a set that
// reordered between reconciles would rewrite the file and restart a serving
// model for no reason — the same rule the argv follows.
//
// Whitespace is refused rather than escaped, for the reason extra_args gives:
// the template expands this unquoted so systemd splits it, and no quoting
// convention invented here would survive that.
func envFlags(b backend.Backend, wsl2 bool, raw json.RawMessage) (string, error) {
	env := map[string]string{}
	// Descriptor first, host-conditional second, deployment last: **the
	// deployment wins.** A descriptor says what a backend needs in general and
	// an operator says what this deployment needs here, and the specific one
	// has to be able to override the general — otherwise the fallback for a
	// host the descriptor's default does not fix is unreachable.
	for _, from := range []map[string]string{b.Env, wslOnly(b.EnvWSL2, wsl2)} {
		for k, v := range from {
			env[k] = v
		}
	}
	if len(raw) > 0 {
		var own map[string]string
		if err := json.Unmarshal(raw, &own); err != nil {
			return "", fmt.Errorf("env is not an object of strings: %v", err)
		}
		for k, v := range own {
			env[k] = v
		}
	}
	if len(env) == 0 {
		return "", nil
	}
	names := make([]string, 0, len(env))
	for k := range env {
		names = append(names, k)
	}
	sort.Strings(names)

	var out []string
	for _, k := range names {
		if k == "" || strings.ContainsAny(k, " \t\n=") {
			return "", fmt.Errorf("env name %q is not usable in an environment file", k)
		}
		if strings.ContainsAny(env[k], " \t\n") {
			return "", fmt.Errorf(
				"env %s contains whitespace, which the unit's EnvironmentFile cannot carry", k)
		}
		out = append(out, "-e", k+"="+env[k])
	}
	return strings.Join(out, " "), nil
}

// wslOnly returns m when this host is WSL2, and nothing otherwise.
func wslOnly(m map[string]string, wsl2 bool) map[string]string {
	if !wsl2 {
		return nil
	}
	return m
}

// IsWSL2 reports whether this host runs under WSL2, for a caller building a
// PlanOptions.
func IsWSL2() bool { return isWSL() }
