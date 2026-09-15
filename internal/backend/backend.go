// Package backend is the model-server descriptor: what varies between vLLM,
// SGLang and the rest, expressed as data.
//
// dev/specs/04-backends.md §1 rejects a plugin base class for two reasons, and
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
	"regexp"
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

// ErrUnsupported is a deployment asking a backend for something it has said it
// cannot do. Separate from ErrInvalid because the descriptor is fine and the
// request is not, and the two reach an operator as different sentences.
var ErrUnsupported = errors.New("the backend does not support this")

// ErrUnknown is a backend nothing has registered.
var ErrUnknown = errors.New("unknown backend")

// The json tags are the same words as the toml ones, deliberately.
// `--format json` is a schema a script reads (dev/specs/10-cli.md §4), and
// untagged fields come back as Go names — `TensorParallel` rather than
// `tensor_parallel` — which an operator has no way to connect to the key they
// write in a descriptor. Safe to add because a descriptor is not in a
// revision's hash preimage: a deployment stores its backend's *name*, and a
// registered descriptor is stored as the TOML bytes themselves.
//
// Descriptor is dev/specs/04-backends.md §6.
//
// `derive` is R6-08 and is now a feature rather than a refused key — the
// promise `prepare` was kept to before R6-06, kept here too: it was refused
// while it did nothing, so no operator ever wrote one and saw it accepted
// believing an image would be built.
type Descriptor struct {
	Backend Backend `json:"backend" toml:"backend"`
}

type Backend struct {
	Name          string `json:"name" toml:"name"`
	API           string `json:"api" toml:"api"`
	WeightsLayout string `json:"weights_layout" toml:"weights_layout"`
	MountPath     string `json:"mount_path" toml:"mount_path"`
	ContainerPort int    `json:"container_port" toml:"container_port"`
	ImageDefault  string `json:"image_default" toml:"image_default"`
	// Command is what the image needs before the rendered arguments, for an
	// image that declares no default command of its own.
	//
	// **Measured, not anticipated.** `lmsysorg/sglang`'s entrypoint is
	// /opt/nvidia/nvidia_entrypoint.sh with no Cmd, and that script ends in
	// `exec "$@"` -- so an argv of flags and no program exits immediately with
	// `exec: --: invalid option`. vLLM's entrypoint is `vllm serve` and
	// llama.cpp's is /app/llama-server, which is why neither ever needed one.
	//
	// Empty for both of those, and empty is the right default: an image that
	// knows how to start itself must not have a command put in front of it.
	//
	// Split on whitespace and placed ahead of the argv, never through a shell --
	// Prepare.Command's rule, for Prepare.Command's reason.
	Command string `json:"command,omitempty" toml:"command"`
	// Silicon is the GPU vendors this backend runs on, in internal/preflight's
	// vocabulary: nvidia, amd, intel.
	//
	// **In the descriptor rather than in a table in the CLI**, which is
	// dev/specs/04-backends.md §1's argument applied to one more fact: which
	// silicon a backend runs on varies between backends and is expressible as
	// data, so it is data the backend declares. It is also what makes §9's
	// "register your own descriptor" an answer rather than a brush-off — a site
	// that pins its own SGLang-on-ROCm image can say the descriptor runs on
	// `amd` and be offered it, which it could not if the matrix lived in a
	// switch statement here.
	//
	// **Required, and an empty list is not "runs anywhere."** A descriptor
	// written before this field existed would otherwise claim Vulkan, which is
	// exactly how a CUDA-only backend gets placed on a Radeon — the refusal
	// R6-13 already gives at the image, reintroduced one layer up where it is
	// the operator's own descriptor saying it.
	Silicon      []string          `json:"silicon" toml:"silicon"`
	Capabilities Capabilities      `json:"capabilities" toml:"capabilities"`
	Args         map[string]string `json:"args" toml:"args"`
	// Extra is backend-specific options surfaced as named ones
	// (dev/specs/04-backends.md §6): llama.cpp's `gpu_layers = "-ngl {v}"`
	// has no equivalent anywhere else, and there is no canonical parameter for
	// it because there is nothing to be canonical about.
	//
	// A second table rather than more rows in Args, because the difference is
	// the point. A name in Args is one nodary *translates* — the same
	// `max_context` reaches vLLM as `--max-model-len` and SGLang as
	// `--context-length`, and a document written against one backend means the
	// same thing against another. A name here is one nodary merely *passes*,
	// and moving the deployment to a different backend is expected to refuse
	// rather than to quietly mean something else.
	//
	// It is still named, unlike extra_args: an operator writes
	// `gpu_layers: 33` and the descriptor knows the spelling, so a typo is
	// refused instead of reaching the container as an argument nobody wrote.
	Extra map[string]string `json:"extra" toml:"extra"`
	// Env is applied to every container this backend runs.
	Env map[string]string `json:"env" toml:"env"`
	// EnvWSL2 is applied only on a WSL2 host.
	//
	// Backend knowledge belongs in the descriptor, which is
	// dev/specs/04-backends.md §1's whole argument for descriptors rather than
	// plugins — and "vLLM will not start on WSL2 without this variable" is
	// exactly that: a fact about vLLM, not about nodary or about one operator's
	// deployment. Putting it here means a fleet with both WSL2 and native nodes
	// works without anybody remembering which is which.
	//
	// One condition, not a condition engine. A second one can generalise this;
	// inventing the general form for a single case would be a mechanism nobody
	// has exercised.
	EnvWSL2 map[string]string `json:"env_wsl2" toml:"env_wsl2"`
	Probe   Probe             `json:"probe" toml:"probe"`
	Metrics Metrics           `json:"metrics" toml:"metrics"`
	// Prepare is nil for a backend that serves what was staged. R6-06.
	Prepare *Prepare `json:"prepare,omitempty" toml:"prepare"`
	// Inherits names the built-in this descriptor varies. Non-empty makes this
	// a derive (R6-08, dev/specs/04-backends.md §5), which is validated
	// instead of the ordinary form rather than in addition to it.
	Inherits string `json:"inherits,omitempty" toml:"inherits"`
	// Derive is the recipe. Present exactly when Inherits is.
	Derive *Derive `json:"derive,omitempty" toml:"derive"`
}

type Capabilities struct {
	TensorParallel bool     `json:"tensor_parallel" toml:"tensor_parallel"`
	ExpertParallel bool     `json:"expert_parallel" toml:"expert_parallel"`
	Quantization   []string `json:"quantization" toml:"quantization"`
	LoRA           bool     `json:"lora" toml:"lora"`
	CPUOffload     bool     `json:"cpu_offload" toml:"cpu_offload"`
}

type Probe struct {
	Health        string `json:"health" toml:"health"`
	Ready         string `json:"ready" toml:"ready"`
	ReadyTimeoutS int    `json:"ready_timeout_s" toml:"ready_timeout_s"`
}

type Metrics struct {
	Path string `json:"path" toml:"path"`
}

// Prepare is dev/specs/04-backends.md §4: the lifecycle is stage → prepare →
// serve, not stage → serve.
//
// Absent from every descriptor nodary ships. It was written for TensorRT-LLM
// 0.x, which compiled a per-GPU-architecture engine from the staged weights
// before it could answer anything — hours of work producing a second artifact
// that itself had to be cached and verified. 1.x compiles in-process and
// needed none, and that backend is no longer shipped at all; the phase stays
// because an operator's own descriptor (§9) can declare one. §4 calls omitting this phase "the standard
// mistake in 'just swap the image' plugin designs" — the interface looks
// sufficient until the first backend that needs a build step.
//
// A pointer, unlike every other table here, because absence is a fact this one
// has to state. A zero-valued Prepare and a backend that declares no prepare
// are different things, and a bool beside the struct saying which would be a
// second place for the same fact to be written.
type Prepare struct {
	// Required is true or the table is refused. A prepare that is not
	// required is one nothing would ever decide to run — there is no second
	// input that would settle it — so the honest way to say a backend needs
	// no build step is to write no table at all. It is spelled rather than
	// assumed because §6 spells it, and a descriptor an operator copies from
	// the spec has to parse.
	Required bool `json:"required" toml:"required"`
	// Image is the builder, which is not the serving image: TensorRT-LLM
	// builds in the full NGC container and serves from a smaller one.
	Image string `json:"image" toml:"image"`
	// Command is the build, as an argv template over {src}, {out} and {tp}.
	// Not a shell: it is split on whitespace and handed to the container, so
	// there is no interpolation, no redirection and nothing to quote.
	Command string `json:"command" toml:"command"`
	// Artifact is the weights_layout the output *becomes*, which is why it is
	// drawn from the same closed vocabulary. A backend whose weights_layout is
	// `engine-dir` reads what its own prepare produced.
	Artifact string `json:"artifact" toml:"artifact"`
	// GPUArchSpecific says the output is not portable across GPU models, so a
	// cached artifact built on one architecture may not be served on another.
	// Declared by the backend rather than discovered, because discovering it
	// means serving from a wrong engine once to find out.
	GPUArchSpecific bool `json:"gpu_arch_specific" toml:"gpu_arch_specific"`
	// TimeoutS bounds the build. Positive for the same reason
	// probe.ready_timeout_s is: without it a wedged build is indistinguishable
	// from a slow one, forever.
	TimeoutS int `json:"timeout_s" toml:"timeout_s"`
}

// prepareVars are the substitutions Command may use. A placeholder outside
// this set would reach the builder literally, as an argument nobody wrote.
var prepareVars = []string{"{src}", "{out}", "{tp}"}

// placeholder finds {...} so an unknown one can be named rather than passed on.
var placeholder = regexp.MustCompile(`\{[a-z_]+\}`)

// Consumes are the canonical parameters this build reads rather than the
// server.
//
// A backend that compiles an engine is configured in two places at once, and
// the split is not the operator's to make: a parameter the build substitutes is
// not one the server is then given, and without this a document that set it
// would be refused as a parameter the backend does not take — true of the
// *server* and false of the backend, leaving no way to configure the build.
//
// **The motivating example was wrong and is recorded here rather than quietly
// dropped.** This said `tensor_parallel` is baked into a TensorRT-LLM engine at
// build time so `trtllm-serve` may not take it as a flag at all. That describes
// 0.x, which served an engine directory. In 1.x — the release R6-02 pins —
// `trtllm-serve` parses `--tp_size` itself and compiles in-process, so
// TensorRT-LLM declares no prepare at all and consumes nothing. The mechanism
// is still right for any backend whose build genuinely swallows a parameter;
// what it lacks today is a user, and saying so is better than leaving a comment
// asserting something false about the one backend it names.
//
// Derived from the command rather than declared separately, so a descriptor
// cannot claim to consume something it never substitutes.
func (p Prepare) Consumes() []string {
	var out []string
	if strings.Contains(p.Command, "{tp}") {
		out = append(out, "tensor_parallel")
	}
	return out
}

// Argv renders the build command.
//
// Split on whitespace after substitution, like Args: the result is an argv
// handed to a container, so `--output_dir {out}` has to become two elements.
// A path holding whitespace is refused rather than quoted, for the reason
// extra_args already is — there is no quoting convention that survives being
// split again downstream.
func (p Prepare) Argv(src, out string, tensorParallel int) ([]string, error) {
	for what, v := range map[string]string{"{src}": src, "{out}": out} {
		if v == "" {
			return nil, fmt.Errorf("%w: prepare needs a path for %s", ErrInvalid, what)
		}
		if strings.ContainsAny(v, " \t\n") {
			return nil, fmt.Errorf("%w: the prepare path %q for %s holds whitespace, and the "+
				"command is split on it", ErrInvalid, v, what)
		}
	}
	if tensorParallel < 1 {
		tensorParallel = 1
	}
	cmd := strings.NewReplacer(
		"{src}", src, "{out}", out, "{tp}", strconv.Itoa(tensorParallel),
	).Replace(p.Command)
	return strings.Fields(cmd), nil
}

// Closed vocabularies. Each is a value the agent or the gateway switches on, so
// an unrecognized one is a descriptor that would be silently mishandled.
var (
	apis    = []string{"openai", "triton", "custom"}
	layouts = []string{"hf-cache", "single-file", "engine-dir"}
)

// Parse reads one descriptor.
//
// Unknown keys are refused, as everywhere else nodary reads a file a human
// wrote — which is what let `[backend.derive]` be added later without any
// descriptor having silently carried one in the meantime.
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
		// **Removed, not unknown.** `[backend.gpu] mechanism` was in this
		// schema and in dev/specs/04-backends.md §6 with two legal values,
		// and R6-07 made writing a descriptor a road operators are meant to
		// take — so somebody has copied it. "unknown keys" reads as a typo in
		// a word they can see is spelled right, which sends them looking for
		// the mistake instead of at the sentence that would explain it.
		for _, k := range keys {
			if k == "backend.gpu.mechanism" || k == "backend.gpu" {
				return Descriptor{}, fmt.Errorf("%w: [backend.gpu] was removed: the flag that "+
					"reaches a card follows the node's GPU vendor, not the backend — the same "+
					"descriptor is `--gpus device=0` on NVIDIA and `--device /dev/dri/renderD128` "+
					"on AMD. Delete the table", ErrInvalid)
			}
		}
		return Descriptor{}, fmt.Errorf("%w: unknown keys %s", ErrInvalid, strings.Join(keys, ", "))
	}
	return d, d.Validate()
}

// Validate refuses a descriptor that would fail later and less clearly.
func (d Descriptor) Validate() error {
	b := d.Backend
	if strings.TrimSpace(b.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalid)
	}
	// A derive carries a name, an `inherits` and a recipe. Everything the
	// ordinary form requires below is something it inherits, so it is validated
	// instead of this rather than as well.
	if b.Inherits != "" || b.Derive != nil {
		return d.validateDerive()
	}
	switch {
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
	case b.Probe.Health == "" || b.Probe.Ready == "":
		// Without both, a deployment can never be marked healthy or ready, so
		// it would sit `starting` forever and nothing would say why.
		return fmt.Errorf("%w: %s: probe.health and probe.ready are both required", ErrInvalid, b.Name)
	case b.Probe.ReadyTimeoutS <= 0:
		return fmt.Errorf("%w: %s: probe.ready_timeout_s must be positive — 11 §2 marks a deployment failed at it",
			ErrInvalid, b.Name)
	case strings.ContainsAny(b.Command, shellish):
		// A command is an argv, not a shell. A pipe or a redirection here would
		// reach the program as an argument instead of doing what it looks like,
		// which is derive.steps' rule and the same trap.
		return fmt.Errorf("%w: %s: command %q contains a shell metacharacter; it is an argv, "+
			"not a shell", ErrInvalid, b.Name, b.Command)
	case len(b.Silicon) == 0:
		return fmt.Errorf("%w: %s: silicon is required — name the GPU vendors this backend "+
			"runs on (%s); an omitted list would mean \"any card\", which is how a CUDA-only "+
			"backend gets placed on a Radeon", ErrInvalid, b.Name, strings.Join(silicon, ", "))
	case b.Args["model_path"] == "":
		// Every other canonical parameter is optional; this one is how the
		// server is told what to serve.
		return fmt.Errorf("%w: %s: args.model_path is required", ErrInvalid, b.Name)
	}
	for i, v := range b.Silicon {
		if !contains(silicon, v) {
			return fmt.Errorf("%w: %s: silicon %q is not one of %s",
				ErrInvalid, b.Name, v, strings.Join(silicon, ", "))
		}
		// A repeat is a descriptor somebody edited twice, and it reaches an
		// operator as a duplicate in every list this is printed into.
		if contains(b.Silicon[:i], v) {
			return fmt.Errorf("%w: %s: silicon names %s twice", ErrInvalid, b.Name, v)
		}
	}
	for canonical, tmpl := range b.Args {
		if !strings.Contains(tmpl, "{v}") {
			return fmt.Errorf("%w: %s: args.%s = %q has no {v} to substitute",
				ErrInvalid, b.Name, canonical, tmpl)
		}
	}
	for name, tmpl := range b.Extra {
		if !strings.Contains(tmpl, "{v}") {
			return fmt.Errorf("%w: %s: extra.%s = %q has no {v} to substitute",
				ErrInvalid, b.Name, name, tmpl)
		}
		// A name in both tables is a descriptor that cannot say which
		// translation it meant, and whichever Args happened to consult first
		// would become the answer. Refused rather than ordered.
		if _, both := b.Args[name]; both {
			return fmt.Errorf("%w: %s: %s is in both args and extra; a name is translated or "+
				"passed through, not both", ErrInvalid, b.Name, name)
		}
	}
	return b.Prepare.validate(b.Name, b.WeightsLayout)
}

// validate refuses a prepare table that would fail on a GPU host hours later.
//
// A nil receiver is the common case — most backends serve what was staged —
// and is deliberately not an error.
func (p *Prepare) validate(backend, layout string) error {
	if p == nil {
		return nil
	}
	switch {
	case !p.Required:
		// Nothing would ever decide to run an optional build: there is no
		// second input that settles it, so the phase would be declared and
		// never happen. Writing no table is how a backend says it needs none.
		return fmt.Errorf("%w: %s: prepare.required must be true — a prepare nothing would "+
			"run is a build step an operator believes in and never gets; omit [backend.prepare] "+
			"for a backend that serves what was staged", ErrInvalid, backend)
	case strings.TrimSpace(p.Image) == "":
		// The builder is not the server: TensorRT-LLM compiles in the full NGC
		// container and serves from a smaller one, so image_default cannot
		// stand in for this.
		return fmt.Errorf("%w: %s: prepare.image is required; the builder is not the "+
			"serving image", ErrInvalid, backend)
	case strings.TrimSpace(p.Command) == "":
		return fmt.Errorf("%w: %s: prepare.command is required", ErrInvalid, backend)
	case !strings.Contains(p.Command, "{src}"):
		return fmt.Errorf("%w: %s: prepare.command has no {src}, so the build would read no "+
			"weights", ErrInvalid, backend)
	case !strings.Contains(p.Command, "{out}"):
		// Worse than reading nothing: a build that writes somewhere nodary did
		// not choose succeeds, caches nothing, and runs again every reconcile.
		return fmt.Errorf("%w: %s: prepare.command has no {out}, so the build would write "+
			"outside the artifact directory and be rebuilt every cycle", ErrInvalid, backend)
	case !contains(layouts, p.Artifact):
		return fmt.Errorf("%w: %s: prepare.artifact must be one of %s — it is the layout the "+
			"output becomes", ErrInvalid, backend, strings.Join(layouts, ", "))
	case p.Artifact != layout:
		// The serving container reads weights_layout. A prepare producing
		// something else builds an artifact nothing is ever pointed at, and
		// the deployment serves the staged weights as though the build had
		// not happened — which is the failure this phase exists to prevent,
		// arrived at by a different road.
		return fmt.Errorf("%w: %s: prepare.artifact is %q but weights_layout is %q; the server "+
			"reads what the build wrote, so they name one thing",
			ErrInvalid, backend, p.Artifact, layout)
	case p.TimeoutS <= 0:
		return fmt.Errorf("%w: %s: prepare.timeout_s must be positive — a wedged build is "+
			"otherwise indistinguishable from a slow one, forever", ErrInvalid, backend)
	}
	for _, v := range placeholder.FindAllString(p.Command, -1) {
		if !contains(prepareVars, v) {
			return fmt.Errorf("%w: %s: prepare.command uses %s, which is not one of %s; it "+
				"would reach the builder as an argument nobody wrote",
				ErrInvalid, backend, v, strings.Join(prepareVars, " "))
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

// Params are the canonical parameters of dev/specs/04-backends.md §3.
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
// dev/specs/04-backends.md §3 is explicit that anything outside the canonical
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
			// Then a backend-specific one, if the descriptor names it. Checked
			// second so a canonical name can never be shadowed by a
			// pass-through of the same spelling — Validate refuses that case,
			// and this is the order that makes the refusal unnecessary rather
			// than merely enforced.
			tmpl, ok = b.Extra[name]
		}
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
