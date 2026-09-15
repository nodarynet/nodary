package agent

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/backend"
	"github.com/nodarynet/nodary/internal/paths"
)

// A Plan is what the agent would do, worked out without doing any of it.
//
// dev/specs/03-agent.md §3's loop is `desired → evaluate → observe → act`, and
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
	// is a normal outcome (dev/specs/03-agent.md §2) and is reported, not
	// retried.
	Refused []Refusal `json:"refused"`
	// ResetDone is models whose weights this run actually discarded in
	// response to doc.Reset (`nodary model restage`/`unstage`), reported
	// back on the next heartbeat so the control plane can stop asking
	// (internal/observed.Heartbeat consumes it).
	ResetDone []string `json:"reset_done,omitempty"`
	// Disabled is a deployment `nodary model disable` turned off
	// (dev/specs/05-catalog.md §4). No Unit is built for it — nothing about
	// GPUs, the backend or staged weights matters for something that will
	// not run — and Reconcile's existing "stop what is not wanted" loop
	// (internal/agent/reconcile.go) is what actually stops it, since it is
	// simply absent from Units.
	Disabled []string `json:"disabled,omitempty"`
	// OutOfPolicy is a deployment the control plane placed that node.toml
	// narrows out (dev/specs/12-node-guardrails.md §1).
	//
	// Separate from Refused because the outcome turns on something Build
	// cannot see. 12 §3 requires that a guardrail narrowed under a *running*
	// deployment reports `out_of_policy` and does **not** kill it — editing a
	// config file must never terminate a serving model, or it is a guardrail
	// nobody dares touch. Only Reconcile knows what is running, so Build states
	// the verdict and Reconcile decides between refusing a placement that never
	// started and leaving alone one that did.
	OutOfPolicy []Refusal `json:"out_of_policy,omitempty"`
	// Prepare is the build each deployment needs before it can serve
	// (dev/specs/04-backends.md §4). Empty for every backend that serves what
	// was staged, which is all of them but TensorRT-LLM.
	Prepare []Prepared `json:"prepare,omitempty"`
	// Restart is deployment ids `nodary model restart` (R4-36) asked to be
	// cycled now — the request, not the outcome. Unlike Reset (filesystem
	// only, so Build can perform it directly) this needs `systemctl`, which
	// only Reconcile has, so Reconcile is what actually restarts them and
	// reports which ones landed as Report.RestartDone.
	Restart []string `json:"restart,omitempty"`
	// Failed is a deployment whose hardware has gone: a GPU it was assigned is
	// no longer on the bus (R4-25, dev/specs/11-failure-modes.md §2).
	//
	// Its own list rather than a Refusal, because the outcome is different in
	// the one way that matters to an operator. A refusal says "this never
	// started and the configuration is why"; this says "this was running on a
	// card that is gone", which is a hardware failure reported as `failed`
	// against the deployment with the missing card named — and **never** as a
	// reboot. A node that reboots itself to clear a GPU fault is a node that
	// comes back with an encrypted root waiting at a console nobody is at
	// (dev/specs/03-agent.md's reboot safety).
	Failed []Refusal `json:"failed,omitempty"`
	// MaintenanceOpen says whether node.toml's window is open at the moment
	// this plan was built. Decided here rather than in Reconcile so the plan
	// stays a complete description of what should happen, and so one clock
	// read covers the whole cycle.
	MaintenanceOpen bool `json:"maintenance_open,omitempty"`
}

// Unit is one deployment rendered as everything systemd needs.
//
// dev/specs/03-agent.md §6: the agent writes only
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

// Probe is what R4c polls: dev/specs/03-agent.md §7.
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
	// File is the weights' own name, for a `single-file` layout and empty for
	// every other. llama.cpp is told `-m <file>`, and only the manifest knows
	// which file that is (SingleFileName).
	File  string `json:"file,omitempty"`
	Bytes int64  `json:"bytes,omitempty"`
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
	// Detected is what the driver reported *before* node.toml narrowed it.
	//
	// The two together are how a card that node.toml excluded is told from one
	// that is no longer there, which are the same absence from Present and
	// opposite facts: the first is a decision somebody made on this machine,
	// the second is dev/specs/11-failure-modes.md §2's "GPU falls off the
	// bus". Nil means the caller did not measure — `agent plan` against a
	// hand-written document — and the check is skipped rather than declaring
	// every card missing.
	Detected []GPU
	// Node is /etc/nodary/node.toml, evaluated against the document before
	// anything is reconciled (dev/specs/12-node-guardrails.md §1). The zero
	// value offers the whole machine, which is what an absent file means.
	Node NodeConfig
	// Now is the clock the maintenance window is read against. The zero value
	// means time.Now(); it is a parameter so a test can stand at 3am on a
	// Saturday without waiting for one.
	Now time.Time
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
	// Builds runs the prepare phase (R6-06). Nil for the same reason
	// Downloads is: `agent plan` is a preview and must not start a six-hour
	// compile any more than it starts a download.
	Builds *Preparer
}

// Build turns one desired-state document into a plan.
//
// Two kinds of verdict come out of it, and they are not the same thing.
// Refused is what this node *cannot* do — an unknown backend, a GPU that is not
// on offer, a deployment with no image. OutOfPolicy is what node.toml says it
// *will* not do (R4-14, dev/specs/12-node-guardrails.md §1), which is a
// decision an operator made on this machine and can unmake by editing a file.
// Keeping them apart is what lets 12 §3 hold: a placement that is out of policy
// and already serving is left alone, and one that is merely impossible never
// was serving.
func Build(doc api.Desired, opt PlanOptions) (Plan, error) {
	if opt.ConfigDir == "" {
		opt.ConfigDir = paths.ConfigDir
	}
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	p := Plan{Rev: doc.Rev, Node: doc.Node, Units: []Unit{}, Stage: []Stage{},
		Refused: []Refusal{}, OutOfPolicy: []Refusal{}, Disabled: []string{},
		MaintenanceOpen: opt.Node.MaintenanceOpen(opt.Now)}
	// Nil rather than empty: a caller that did not measure must not be read as
	// having measured nothing. See PlanOptions.Detected.
	var detected map[int]bool
	if len(opt.Detected) > 0 {
		detected = map[int]bool{}
		for _, g := range opt.Detected {
			detected[g.Index] = true
		}
	}

	descriptors, err := backend.Builtins()
	if err != nil {
		return Plan{}, err
	}
	// The registered descriptors the control plane sent for this node's own
	// deployments (R6-07). Merged rather than replacing: a built-in cannot be
	// shadowed, which the applier already refuses at registration — this is
	// the same rule held on the far side of the wire, because a node that
	// accepted a redefinition would be one host in a fleet quietly running a
	// different vLLM.
	//
	// A descriptor that does not parse is *dropped*, not fatal. It affects the
	// deployments that name it and nothing else, and unitFor already refuses a
	// deployment whose backend it cannot find, with a reason that names the
	// backend — which is what an operator needs. Failing the whole plan would
	// stop a node from reconciling anything, including what is serving.
	for _, b := range doc.Backends {
		if _, builtin := descriptors[b.Name]; builtin {
			continue
		}
		d, err := backend.Parse([]byte(b.Source))
		if err != nil || d.Backend.Name != b.Name {
			continue
		}
		// A derive carries only its name, its parent and its recipe, so
		// without this it would reach unitFor with no vocabulary, no layout
		// and no probe — refused as if it were misconfigured rather than
		// serving as the backend it inherits.
		if d, err = backend.Resolve(d); err != nil {
			continue
		}
		descriptors[b.Name] = d
	}
	present := map[int]GPU{}
	for _, g := range opt.Present {
		present[g.Index] = g
	}
	// GPU index -> the deployment this plan has already given it to.
	claims := map[int]string{}

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

	// Staging first, and the order is not cosmetic: dev/specs/03-agent.md §3
	// fixes it — weights are staged before a deployment is prepared, and a
	// deployment is prepared before its unit starts.
	byModel := map[string]Stage{}
	// The digest each model was staged against. It is in the document rather
	// than in Stage, and the prepare key needs it: an engine built from one
	// set of weights must not be served for another.
	shaByModel := map[string]string{}
	for _, s := range doc.Staging {
		shaByModel[s.Model] = s.ManifestSHA256
	}
	for _, s := range doc.Staging {
		st := Stage{Model: s.Model, Source: s.Source, State: StateAbsent}
		dir, err := ModelDir(opt.ModelsDir, s.Layout, s.Model)
		if err != nil {
			st.State, st.Reason = StateCorrupt, err.Error()
			byModel[s.Model] = st
			continue
		}
		st.Dir = dir
		if s.Layout == "single-file" {
			// Regardless of Verify: the manifest is a text file, and without
			// its one entry unitFor has no argv to render. A failure here is
			// not a staging verdict — the weights may be perfectly fine — so
			// it leaves File empty and lets unitFor refuse the deployment with
			// a reason about the argv rather than about the bytes.
			st.File, _ = SingleFileName(opt.ModelsDir, s.Model)
		}
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
		// Before the guardrails, because a card that is gone is not a decision
		// node.toml made and not something an operator can unmake by editing a
		// file. Reported as a failure of the deployment rather than as a
		// refusal of the placement: the configuration is correct and the
		// hardware is not.
		if gone := missing(detected, d.GPUs); len(gone) > 0 {
			p.Failed = append(p.Failed, Refusal{Deployment: d.ID,
				Reason: fmt.Sprintf("GPU %s %s assigned to this deployment and no longer on this "+
					"host's bus; the driver reports %s. Nothing is rebooted to clear it "+
					"(dev/specs/11-failure-modes.md §2)",
					joinIndices(gone), plural(gone), presentList(opt.Detected))})
			continue
		}
		// Before unitFor, so a placement node.toml will not have is not first
		// reported as an impossibility. `len(p.Units)` rather than the loop
		// index is what max_deployments counts: something refused for another
		// reason occupies no slot.
		if reason := opt.Node.outsideLimits(d, len(p.Units)); reason != "" {
			p.OutOfPolicy = append(p.OutOfPolicy, Refusal{Deployment: d.ID, Reason: reason})
			continue
		}
		// The prepare phase, between staging and the unit
		// (dev/specs/04-backends.md §4). It produces the directory the unit
		// will serve from, so it is worked out before unitFor rather than
		// after: for a backend that builds, the model path *is* the artifact.
		var prep *Prepared
		if desc, known := descriptors[d.Backend]; known && desc.Backend.Prepare != nil {
			got := planPrepare(d, desc, byModel[d.Model], shaByModel[d.Model], present, opt)
			p.Prepare = append(p.Prepare, got)
			prep = &got
		}
		u, err := unitFor(d, descriptors, present, byModel, prep, opt)
		if err != nil {
			p.Refused = append(p.Refused, Refusal{Deployment: d.ID, Reason: err.Error()})
			continue
		}
		// R4-23: dev/specs/03-agent.md §7 — "the control plane guarantees no
		// two deployments on a node claim the same index, and the agent
		// double-checks before starting."
		//
		// After unitFor, so a deployment that cannot run for some other reason
		// does not hold a card away from one that can. First claimant wins, and
		// that is stable rather than arbitrary: config.Read orders deployments
		// by id, so the same one wins every cycle and the loser is not started
		// and stopped alternately forever.
		if holder := claimedBy(claims, d.GPUs); holder != "" {
			p.Refused = append(p.Refused, Refusal{Deployment: d.ID,
				Reason: fmt.Sprintf("GPU %s on this node %s already claimed by deployment %q; "+
					"11 §2 makes two deployments on one card a failure mode, and starting this "+
					"would make both of them slow rather than one of them wrong",
					joinIndices(overlap(claims, d.GPUs)), plural(overlap(claims, d.GPUs)), holder)})
			continue
		}
		for _, idx := range d.GPUs {
			claims[idx] = d.ID
		}
		p.Units = append(p.Units, u)
	}
	return p, nil
}

// claimedBy names the deployment already holding any of these indices.
func claimedBy(claims map[int]string, want []int) string {
	for _, idx := range want {
		if held, ok := claims[idx]; ok {
			return held
		}
	}
	return ""
}

// overlap is the indices already claimed, for the message.
func overlap(claims map[int]string, want []int) []int {
	var out []int
	for _, idx := range want {
		if _, ok := claims[idx]; ok {
			out = append(out, idx)
		}
	}
	return out
}

func plural(idx []int) string {
	if len(idx) == 1 {
		return "is"
	}
	return "are"
}

// unitFor renders one deployment, or says why it cannot be rendered.
func unitFor(d api.DesiredDeployment, descriptors map[string]backend.Descriptor,
	present map[int]GPU, staged map[string]Stage, prep *Prepared, opt PlanOptions) (Unit, error) {
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
		return Unit{}, fmt.Errorf("no GPU is assigned; dev/specs/03-agent.md §7 makes assignment explicit, always")
	}
	// The node's own check of what the control plane assigned. R4-23 makes this
	// a hard refusal, and it deliberately does not test for /dev/nvidia<index>:
	// a WSL2 host has no such device and nvidia-smi still reports the card.
	for _, idx := range d.GPUs {
		if _, ok := present[idx]; !ok {
			return Unit{}, fmt.Errorf("GPU %d is not on this node's offer", idx)
		}
	}

	gpus, err := gpuFlag(d.GPUs, present, opt.CDIDevices)
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
	switch desc.Backend.WeightsLayout {
	case "hf-cache":
		inContainer = filepath.Join(desc.Backend.MountPath,
			"hub", "models--"+strings.ReplaceAll(d.Model, "/", "--"))
	case "single-file":
		// The file, not the directory it sits in. A backend that takes
		// `-m /models` starts, reads a directory where it expected weights,
		// and fails with a message about the file format — which is a long way
		// from the missing manifest entry that actually caused it.
		if staged[d.Model].File == "" {
			return Unit{}, fmt.Errorf("the %s layout needs the weights' own name and %s does not "+
				"give one; check %s beside them", desc.Backend.WeightsLayout, d.Model, ManifestName)
		}
		inContainer = filepath.Join(desc.Backend.MountPath, staged[d.Model].File)
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
	// A parameter the *build* consumed is not one the server dropped. An
	// engine is compiled for a fixed rank count, so `tensor_parallel` reaches
	// TensorRT-LLM through trtllm-build and may never appear in the serving
	// argv at all — and refusing it here would leave no way to build a
	// two-rank engine.
	if desc.Backend.Prepare != nil {
		dropped = without(dropped, desc.Backend.Prepare.Consumes())
	}
	if len(dropped) > 0 {
		// Dropped rather than guessed (04 §3), and said out loud: a parameter
		// that silently vanished is a deployment running with settings the
		// operator believes are in force.
		return Unit{}, fmt.Errorf("%s does not take %s; move them to extra_args",
			d.Backend, strings.Join(dropped, ", "))
	}

	// What gets bind-mounted at mount_path. For a backend that builds, it is
	// the artifact and not the weights: the weights were the build's input and
	// the server has no use for them. The unit is still rendered while the
	// build runs — reconcileUnit is what holds it back, the same way it holds
	// back a deployment whose weights are still arriving — so the path has to
	// be the one the artifact will have, not the one it has now.
	hostMount := opt.ModelsDir
	if prep != nil {
		if prep.Dir == "" {
			return Unit{}, fmt.Errorf("%s builds before it serves and this node worked out no "+
				"artifact directory: %s", d.Backend, prep.Reason)
		}
		hostMount = prep.Dir
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
		// The names are the unit template's, dev/specs/03-agent.md §6, and
		// nothing else may appear here: a variable the template does not
		// reference is a setting that looks applied and is not.
		Env: []EnvVar{
			{"NODARY_ARGS", strings.Join(args, " ")},
			{"NODARY_CONTAINER_PORT", strconv.Itoa(desc.Backend.ContainerPort)},
			// The whole device argument, flag included: the flag itself is
			// `--gpus` on NVIDIA and `--device` on everything else, and its
			// value depends on what the host's CDI specification declares.
			// Unbraced in the template so systemd splits it — see gpuFlag.
			{"NODARY_GPUS", gpus},
			// `-e KEY=VALUE` pairs, or empty. Unbraced in the template so
			// systemd splits it, the same mechanism NODARY_ARGS uses.
			{"NODARY_ENV", env},
			{"NODARY_IMAGE", d.Image},
			{"NODARY_MODELS_DIR", hostMount},
			{"NODARY_MOUNT_PATH", desc.Backend.MountPath},
			{"NODARY_NETWORK", network},
			{"NODARY_PORT", strconv.Itoa(d.Port)},
		},
	}, nil
}

// RenderEnv is the file dev/specs/03-agent.md §6's EnvironmentFile= reads.
//
// systemd's parser is not a shell: a value is taken literally to end of line,
// so nothing here is quoted or escaped. Values that could contain whitespace —
// NODARY_ARGS is the only one — are joined by shellJoin, which refuses rather
// than escapes.
// Image is what this unit will run.
//
// Read out of the env file rather than stored a second time on the Unit: the
// env file is what systemd expands into `nerdctl run`, so a copy beside it is
// a second answer that can disagree with the one that actually starts.
func (u Unit) Image() string {
	for _, v := range u.Env {
		if v.Key == "NODARY_IMAGE" {
			return v.Value
		}
	}
	return ""
}

func (u Unit) RenderEnv() []byte {
	var b strings.Builder
	b.WriteString("# Written by nodary. Edits are overwritten on the next reconcile.\n")
	fmt.Fprintf(&b, "# Deployment %s — dev/specs/03-agent.md §6\n", u.Deployment)
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

// gpuFlag is the whole device argument the unit passes to `nerdctl run`, flag
// and value.
//
// **The flag is not a constant, which is why the value is not one either.**
// `--gpus device=0` reaches a card through the CDI specification nvidia-ctk
// writes; the same llama.cpp descriptor on an AMD card reaches it with
// `--device /dev/dri/renderD128` and no toolkit at all. Same backend, same
// deployment, different argument — decided by the vendor of the silicon, which
// the node offered and an administrator approved
// (dev/plans/R6a-a-second-gpu-vendor.md §2). So the unit template holds
// `$NODARY_GPUS` unbraced and no literal flag, and this function renders both.
//
// The NVIDIA half below is unchanged and is the older and harder of the two:
//
// **The runtime resolves `device=0` to the CDI device `nvidia.com/gpu=0`, and
// on WSL2 no such device exists.** There is no /dev/nvidia0 there — the only
// node is /dev/dxg — so `nvidia-ctk cdi generate` emits a single device named
// `all`, and every deployment died in a restart loop with
//
//	CDI device injection failed: unresolvable CDI devices nvidia.com/gpu=0
//
// on a host where `nerdctl run --gpus all` works perfectly. dev/specs/03-agent.md
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
func gpuFlag(assigned []int, present map[int]GPU, cdi []string) (string, error) {
	// Every assigned card, one vendor. A mixed assignment has no right answer
	// — one container gets one device argument — and `model register` already
	// refuses to write one, but a hand-edited document reaches here without
	// passing through that verb (dev/plans/R6a-a-second-gpu-vendor.md §9).
	vendors := map[string]bool{}
	for _, idx := range assigned {
		vendors[present[idx].VendorName()] = true
	}
	if len(vendors) > 1 {
		names := make([]string, 0, len(vendors))
		for v := range vendors {
			names = append(names, v)
		}
		sort.Strings(names)
		return "", fmt.Errorf("GPUs %v are %s cards and one container is handed one device "+
			"argument; split this into a deployment per vendor", assigned, strings.Join(names, " and "))
	}
	if !vendors[VendorNVIDIA] {
		// **No toolkit, no CDI, and nothing to enumerate against.** The device
		// node is the whole mechanism here, which is less machinery than the
		// NVIDIA path rather than more (R6a §5). What it does need and CDI does
		// not is for the container's user to be able to *open* the node, which
		// depends on the group that owns it and varies by distribution — the
		// AMD equivalent of the CDI trap R4-23a found, and it will not show up
		// until this runs on real hardware.
		//
		// ponytail: no --group-add. Add it when a real AMD node shows the
		// container cannot open a node it was handed.
		var args []string
		for _, idx := range assigned {
			g := present[idx]
			if g.Render == "" {
				return "", fmt.Errorf("GPU %d is a %s card and the kernel publishes no render "+
					"node for it under /sys/class/drm; there is nothing to hand a container",
					idx, g.VendorName())
			}
			args = append(args, "--device", g.Render)
		}
		return strings.Join(args, " "), nil
	}

	indexed := "--gpus device=" + joinIndices(assigned)
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
	if len(assigned) != len(present) {
		return "", fmt.Errorf("this host's CDI specification declares only `all`, so a subset "+
			"cannot be assigned: %d of %d GPU(s) were requested. On WSL2 there is no per-GPU "+
			"device node for nvidia-ctk to name", len(assigned), len(present))
	}
	return "--gpus all", nil
}

// envFlags renders a deployment's environment as `-e KEY=VALUE` pairs.
//
// A backend is configured by arguments *and* by environment, and only the first
// was expressible. The case that proved it: on WSL2 vLLM refuses to start with
// `RuntimeError: UVA is not available`, and both published fixes —
// `VLLM_WSL2_ENABLE_PIN_MEMORY=1` and `VLLM_USE_V2_MODEL_RUNNER=0` — are
// environment variables with no command-line form. No deployment could be made
// to run on a platform dev/specs/01-install.md §8 supports.
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

// missing is the assigned indices the driver no longer reports.
//
// A nil map means nothing was measured, which is not the same as measuring
// nothing: see PlanOptions.Detected.
func missing(detected map[int]bool, assigned []int) []int {
	if detected == nil {
		return nil
	}
	var out []int
	for _, idx := range assigned {
		if !detected[idx] {
			out = append(out, idx)
		}
	}
	return out
}

// presentList renders what the driver does report, for the message. An operator
// reading "GPU 2 is gone" needs to know whether one card fell off or the driver
// stopped enumerating altogether.
func presentList(gpus []GPU) string {
	if len(gpus) == 0 {
		return "no GPU at all"
	}
	idx := make([]int, 0, len(gpus))
	for _, g := range gpus {
		idx = append(idx, g.Index)
	}
	return "GPU " + joinIndices(idx)
}

// without is `all` less every element of `some`.
func without(all, some []string) []string {
	var out []string
	for _, a := range all {
		if !containsString(some, a) {
			out = append(out, a)
		}
	}
	return out
}
