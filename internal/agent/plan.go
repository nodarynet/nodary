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
	// Verdict is only filled for `source: local`, which verifies from the
	// manifest that travels with the weights. Remote staging is R4-33 and is
	// not in the MVP (docs/plans/mvp.md §5.4).
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
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
		Units: []Unit{}, Stage: []Stage{}, Refused: []Refusal{}}

	descriptors, err := backend.Builtins()
	if err != nil {
		return Plan{}, err
	}
	offered := map[int]bool{}
	for _, g := range opt.Present {
		offered[g.Index] = true
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
		case s.Source != "local":
			// R4-33. Named rather than silently skipped, so a node that cannot
			// stage says which path it is missing.
			st.Reason = "remote staging is not implemented in this release (R4-33); register the model as source = \"local\""
		case !opt.Verify:
			st.State, st.Reason = "unverified", "the manifest was not read; run without --no-verify to check it"
		default:
			v := VerifyStaged(opt.ModelsDir, s.Layout, s.Model, s.ManifestSHA256)
			st.State, st.Reason = v.State, v.Reason
		}
		byModel[s.Model] = st
	}
	for _, m := range sortedStageKeys(byModel) {
		p.Stage = append(p.Stage, byModel[m])
	}

	for _, d := range doc.Deployments {
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
			// Comma-separated with no spaces: the unit template puts this
			// inside `--gpus '"device=${NODARY_GPUS}"'`, and the runtime parses
			// the list itself.
			{"NODARY_GPUS", joinIndices(d.GPUs)},
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
