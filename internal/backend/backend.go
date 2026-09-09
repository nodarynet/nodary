// Package backend is the model-server descriptor: what varies between vLLM,
// SGLang and the rest, expressed as data.
//
// docs/specs/04-backends.md §1 rejects a plugin base class for two reasons, and
// this package is the second one made real: model servers differ in their
// argument vocabulary, their weight layout and their probe, and all three are
// expressible declaratively. Nothing here executes anything a descriptor says —
// it produces an argv and a mount path, and the agent runs them.
//
// The first reason is why the built-ins are compiled in rather than read from
// disk: the install path is a signed binary, and a directory of descriptors the
// binary trusts without the signature covering them is the hole the signature
// was closing. Operator-added descriptors are R6-07 and are audited on
// registration.
package backend

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed descriptors/*.toml
var builtinFS embed.FS

// ErrInvalid is a descriptor that does not parse or does not hold together.
var ErrInvalid = errors.New("invalid backend descriptor")

// ErrUnknown is a backend nothing has registered.
var ErrUnknown = errors.New("unknown backend")

// Descriptor is docs/specs/04-backends.md §6.
//
// `prepare` and `derive` are absent. They are R6-06 and R6-08, and a field
// parsed but not honoured is worse than one that is refused: an operator who
// writes `[backend.prepare]` and sees it accepted believes a build step will
// run. Unknown keys are rejected, so writing one is an error today and becomes
// a feature later without the intervening lie.
type Descriptor struct {
	Backend Backend `toml:"backend"`
}

type Backend struct {
	Name          string            `toml:"name"`
	API           string            `toml:"api"`
	WeightsLayout string            `toml:"weights_layout"`
	MountPath     string            `toml:"mount_path"`
	ContainerPort int               `toml:"container_port"`
	ImageDefault  string            `toml:"image_default"`
	Capabilities  Capabilities      `toml:"capabilities"`
	Args          map[string]string `toml:"args"`
	GPU           GPU               `toml:"gpu"`
	Probe         Probe             `toml:"probe"`
	Metrics       Metrics           `toml:"metrics"`
}

type Capabilities struct {
	TensorParallel bool     `toml:"tensor_parallel"`
	ExpertParallel bool     `toml:"expert_parallel"`
	Quantization   []string `toml:"quantization"`
	LoRA           bool     `toml:"lora"`
	CPUOffload     bool     `toml:"cpu_offload"`
}

type GPU struct {
	Mechanism string `toml:"mechanism"`
}

type Probe struct {
	Health        string `toml:"health"`
	Ready         string `toml:"ready"`
	ReadyTimeoutS int    `toml:"ready_timeout_s"`
}

type Metrics struct {
	Path string `toml:"path"`
}

// Closed vocabularies. Each is a value the agent or the gateway switches on, so
// an unrecognized one is a descriptor that would be silently mishandled.
var (
	apis     = []string{"openai", "triton", "custom"}
	layouts  = []string{"hf-cache", "single-file", "engine-dir"}
	gpuModes = []string{"device-flag", "cuda-visible-devices"}
)

// Parse reads one descriptor.
//
// Unknown keys are refused, as everywhere else nodary reads a file a human
// wrote. Here it does double duty: it is also what makes the absence of
// `[backend.prepare]` honest rather than silent.
func Parse(body []byte) (Descriptor, error) {
	var d Descriptor
	md, err := toml.Decode(string(body), &d)
	if err != nil {
		return Descriptor{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if u := md.Undecoded(); len(u) > 0 {
		keys := make([]string, len(u))
		for i, k := range u {
			keys[i] = k.String()
		}
		sort.Strings(keys)
		return Descriptor{}, fmt.Errorf("%w: unknown keys %s", ErrInvalid, strings.Join(keys, ", "))
	}
	return d, d.Validate()
}

// Validate refuses a descriptor that would fail later and less clearly.
func (d Descriptor) Validate() error {
	b := d.Backend
	switch {
	case strings.TrimSpace(b.Name) == "":
		return fmt.Errorf("%w: name is required", ErrInvalid)
	case !contains(apis, b.API):
		return fmt.Errorf("%w: %s: api must be one of %s", ErrInvalid, b.Name, strings.Join(apis, ", "))
	case !contains(layouts, b.WeightsLayout):
		return fmt.Errorf("%w: %s: weights_layout must be one of %s",
			ErrInvalid, b.Name, strings.Join(layouts, ", "))
	case b.MountPath == "" && b.WeightsLayout != "engine-dir":
		return fmt.Errorf("%w: %s: mount_path is required — the weights have to appear somewhere in the container",
			ErrInvalid, b.Name)
	case b.ContainerPort <= 0 || b.ContainerPort > 65535:
		return fmt.Errorf("%w: %s: container_port %d is not a port", ErrInvalid, b.Name, b.ContainerPort)
	case !contains(gpuModes, b.GPU.Mechanism):
		return fmt.Errorf("%w: %s: gpu.mechanism must be one of %s",
			ErrInvalid, b.Name, strings.Join(gpuModes, ", "))
	case b.Probe.Health == "" || b.Probe.Ready == "":
		// Without both, a deployment can never be marked healthy or ready, so
		// it would sit `starting` forever and nothing would say why.
		return fmt.Errorf("%w: %s: probe.health and probe.ready are both required", ErrInvalid, b.Name)
	case b.Probe.ReadyTimeoutS <= 0:
		return fmt.Errorf("%w: %s: probe.ready_timeout_s must be positive — 11 §2 marks a deployment failed at it",
			ErrInvalid, b.Name)
	case b.Args["model_path"] == "":
		// Every other canonical parameter is optional; this one is how the
		// server is told what to serve.
		return fmt.Errorf("%w: %s: args.model_path is required", ErrInvalid, b.Name)
	}
	for canonical, tmpl := range b.Args {
		if !strings.Contains(tmpl, "{v}") {
			return fmt.Errorf("%w: %s: args.%s = %q has no {v} to substitute",
				ErrInvalid, b.Name, canonical, tmpl)
		}
	}
	return nil
}

// Builtins are the descriptors compiled into this binary, by name.
//
// vLLM and SGLang. llama.cpp needs `[backend.extra]` and TensorRT-LLM needs
// `[backend.prepare]`, and both are R6 — a descriptor embedded here whose
// features are unimplemented would be a backend the binary claims to support
// and cannot run.
func Builtins() (map[string]Descriptor, error) {
	entries, err := fs.ReadDir(builtinFS, "descriptors")
	if err != nil {
		return nil, err
	}
	out := make(map[string]Descriptor, len(entries))
	for _, e := range entries {
		body, err := fs.ReadFile(builtinFS, "descriptors/"+e.Name())
		if err != nil {
			return nil, err
		}
		d, err := Parse(body)
		if err != nil {
			return nil, fmt.Errorf("built-in %s: %w", e.Name(), err)
		}
		if _, dup := out[d.Backend.Name]; dup {
			return nil, fmt.Errorf("%w: two built-ins are named %q", ErrInvalid, d.Backend.Name)
		}
		out[d.Backend.Name] = d
	}
	return out, nil
}

// Get returns one built-in descriptor.
func Get(name string) (Descriptor, error) {
	all, err := Builtins()
	if err != nil {
		return Descriptor{}, err
	}
	d, ok := all[name]
	if !ok {
		return Descriptor{}, fmt.Errorf("%w %q (this build has %s)",
			ErrUnknown, name, strings.Join(Names(all), ", "))
	}
	return d, nil
}

// Names lists a descriptor set, sorted.
func Names(all map[string]Descriptor) []string {
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Params are the canonical parameters of docs/specs/04-backends.md §3.
//
// Held as decoded JSON rather than a struct because the desired-state document
// carries them as one object and the set is the descriptor's business, not this
// type's: a struct here would have to grow a field for every canonical
// parameter, which is the normalization treadmill §3 exists to avoid.
type Params map[string]any

// Args renders the argv for one deployment.
//
// Order is fixed and alphabetical by canonical name, with model_path first and
// extra_args last. A stable order is not cosmetic: the rendered command goes
// into a unit's environment file, and a set that reordered between reconciles
// would rewrite the file and restart a serving model for no reason.
//
// A parameter the descriptor does not name is **dropped, not passed through**.
// docs/specs/04-backends.md §3 is explicit that anything outside the canonical
// set belongs in extra_args, and silently inventing `--max-context=…` for a
// backend that spells it differently produces a container that fails at start
// with an error nobody can trace back to here.
func (d Descriptor) Args(modelPath string, p Params, extra []string) ([]string, []string, error) {
	b := d.Backend
	args := []string{render(b.Args["model_path"], modelPath)}

	var dropped []string
	for _, name := range sortedKeys(p) {
		if name == "model_path" {
			// The caller supplies the path; a document that also set it would
			// otherwise silently win or silently lose.
			dropped = append(dropped, name)
			continue
		}
		tmpl, ok := b.Args[name]
		if !ok {
			dropped = append(dropped, name)
			continue
		}
		v, err := scalar(p[name])
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %s: %s: %v", ErrInvalid, b.Name, name, err)
		}
		args = append(args, render(tmpl, v))
	}
	// Verbatim, and appended after the translated set. The control plane does
	// not interpret these and says so (04 §3).
	args = append(args, extra...)
	return args, dropped, nil
}

// render substitutes {v}. A template may hold a space — llama.cpp's `-m {v}` —
// so the result is split into separate argv elements rather than left as one.
func render(tmpl, v string) string { return strings.ReplaceAll(tmpl, "{v}", v) }

// scalar is how a canonical parameter becomes a command-line value.
//
// JSON numbers arrive as float64, and 2 must render as "2" and not "2.000000":
// `--tensor-parallel-size=2.000000` is a container that will not start.
func scalar(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case bool:
		return strconv.FormatBool(t), nil
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10), nil
		}
		return strconv.FormatFloat(t, 'g', -1, 64), nil
	case int:
		return strconv.Itoa(t), nil
	case int64:
		return strconv.FormatInt(t, 10), nil
	case json.Number:
		return t.String(), nil
	}
	return "", fmt.Errorf("%T is not a value a command line can carry", v)
}

func sortedKeys(p Params) []string {
	out := make([]string, 0, len(p))
	for k := range p {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(all []string, want string) bool { return slices.Contains(all, want) }
