package backend

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The built-ins are compiled in, so a descriptor that does not hold together is
// a binary that cannot start a deployment and would not say so until a node
// tried. This is the one test that has to pass for the embed to be worth
// anything.
func TestTheBuiltInDescriptorsAreValid(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatalf("Builtins: %v", err)
	}
	if got := Names(all); !reflect.DeepEqual(got, []string{"llama-cpp", "sglang", "vllm"}) {
		t.Fatalf("built-ins = %v, want llama-cpp, sglang and vllm", got)
	}
	// TensorRT-LLM is still out, and for the reason llama.cpp was until
	// `[backend.extra]` landed: it needs `[backend.prepare]` (R6-06), and a
	// descriptor embedded whose features are unimplemented is a backend the
	// binary claims to support and cannot run.
	if _, err := Get("tensorrt-llm"); !errors.Is(err, ErrUnknown) {
		t.Errorf("Get(tensorrt-llm): error = %v, want ErrUnknown — it needs [backend.prepare]", err)
	}
}

// The whole claim of docs/specs/04-backends.md §3 is that the argument
// vocabulary is data. Two backends, one set of canonical parameters, two
// different command lines, and no branch anywhere that names a backend.
func TestOneParameterSetTranslatesThroughEachDescriptor(t *testing.T) {
	params := Params{}
	if err := json.Unmarshal([]byte(
		`{"tensor_parallel":2,"max_context":131072,"gpu_memory_fraction":0.92}`), &params); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		backend string
		want    []string
	}{
		{"vllm", []string{
			"/models/gemma",
			"--gpu-memory-utilization=0.92",
			"--max-model-len=131072",
			"--tensor-parallel-size=2",
			"--enable-prefix-caching",
		}},
		{"sglang", []string{
			"--model-path=/models/gemma",
			"--context-length=131072",
			"--tp-size=2",
			"--enable-prefix-caching",
		}},
	} {
		d, err := Get(tc.backend)
		if err != nil {
			t.Fatal(err)
		}
		got, dropped, err := d.Args("/models/gemma", params, []string{"--enable-prefix-caching"})
		if err != nil {
			t.Fatalf("%s: %v", tc.backend, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s argv =\n  %v\nwant\n  %v", tc.backend, got, tc.want)
		}
		// SGLang's descriptor has no gpu_memory_fraction, so it is dropped
		// rather than invented — 04 §3 puts anything outside the canonical set
		// in extra_args, and guessing a flag produces a container that fails at
		// start for a reason nobody can trace.
		if tc.backend == "sglang" && !reflect.DeepEqual(dropped, []string{"gpu_memory_fraction"}) {
			t.Errorf("sglang dropped %v, want gpu_memory_fraction reported", dropped)
		}
		if tc.backend == "vllm" && len(dropped) != 0 {
			t.Errorf("vllm dropped %v, want nothing", dropped)
		}
	}
}

// JSON has one number type and a command line has none. `2` arriving as
// float64 and rendering as "2.000000" is a container that will not start, and
// the failure would be a vLLM usage error a long way from here.
func TestNumbersRenderAsAValueACommandLineCanCarry(t *testing.T) {
	d, err := Get("vllm")
	if err != nil {
		t.Fatal(err)
	}
	params := Params{}
	if err := json.Unmarshal([]byte(`{"tensor_parallel":2,"gpu_memory_fraction":0.9}`), &params); err != nil {
		t.Fatal(err)
	}
	got, _, err := d.Args("/m", params, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--tensor-parallel-size=2", "--gpu-memory-utilization=0.9"} {
		if !containsString(got, want) {
			t.Errorf("argv = %v, want %s", got, want)
		}
	}
}

// The order is what a unit's environment file records. A set that reordered
// between reconciles would rewrite the file and restart a serving model for no
// reason at all.
func TestArgvOrderIsStable(t *testing.T) {
	d, err := Get("vllm")
	if err != nil {
		t.Fatal(err)
	}
	params := Params{"max_context": 4096, "dtype": "fp8", "tensor_parallel": 2, "served_name": "g"}
	first, _, err := d.Args("/m", params, []string{"--x"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, _, err := d.Args("/m", params, []string{"--x"})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("argv reordered between renders:\n  %v\n  %v", first, again)
		}
	}
	if first[0] != "/m" {
		t.Errorf("argv[0] = %q, want the model path first", first[0])
	}
	if first[len(first)-1] != "--x" {
		t.Errorf("argv[-1] = %q, want extra_args last and verbatim", first[len(first)-1])
	}
}

func TestParseRefusesWhatItShould(t *testing.T) {
	base := `
[backend]
name = "x"
api = "openai"
weights_layout = "hf-cache"
mount_path = "/m"
container_port = 8000
[backend.args]
model_path = "--model={v}"
[backend.gpu]
mechanism = "device-flag"
[backend.probe]
health = "/health"
ready = "/health"
ready_timeout_s = 60
`
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatalf("the minimal valid descriptor was refused: %v", err)
	}

	for _, tc := range []struct{ what, body string }{
		{"an unknown key", base + "\n[backend.nonsense]\nx = 1\n"},
		// The two R6 sections. They must be refused rather than accepted and
		// ignored: an operator who writes one and sees it accepted believes a
		// build step will run.
		{"a prepare section", base + "\n[backend.prepare]\nrequired = true\n"},
		{"a derive section", base + "\n[backend.derive]\nfrom = \"x@sha256:a\"\n"},
		{"an unknown api", strings.Replace(base, `api = "openai"`, `api = "grpc"`, 1)},
		{"an unknown layout", strings.Replace(base, `"hf-cache"`, `"tarball"`, 1)},
		{"no model_path", strings.Replace(base, `model_path = "--model={v}"`, `port = "--port={v}"`, 1)},
		{"a template with nothing to substitute", strings.Replace(base,
			`model_path = "--model={v}"`, `model_path = "--model"`, 1)},
		{"no ready timeout", strings.Replace(base, "ready_timeout_s = 60", "ready_timeout_s = 0", 1)},
		{"a port that is not a port", strings.Replace(base, "container_port = 8000", "container_port = 0", 1)},
	} {
		if _, err := Parse([]byte(tc.body)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: error = %v, want a refusal", tc.what, err)
		}
	}
}

func containsString(all []string, want string) bool {
	for _, s := range all {
		if s == want {
			return true
		}
	}
	return false
}

// trtPrepare is the TensorRT-LLM table from docs/specs/04-backends.md §6,
// under a descriptor minimal in every other respect so a refusal can only be
// about the phase.
func withPrepare(body string) string {
	return `[backend]
name           = "trt"
api            = "openai"
weights_layout = "engine-dir"
container_port = 8000
image_default  = "nvcr.io/nvidia/trtllm-serve:1"

[backend.args]
model_path = "--model={v}"

[backend.gpu]
mechanism = "device-flag"

[backend.probe]
health          = "/health"
ready           = "/health"
ready_timeout_s = 1800

[backend.prepare]
` + body
}

const trtPrepare = `required          = true
image             = "nvcr.io/nvidia/tensorrt-llm:1"
command           = "trtllm-build --checkpoint_dir {src} --output_dir {out} --tp_size {tp}"
artifact          = "engine-dir"
gpu_arch_specific = true
timeout_s         = 21600
`

// The spec's own example has to parse. It is what an operator copies.
func TestTheSpecsPrepareTableParses(t *testing.T) {
	d, err := Parse([]byte(withPrepare(trtPrepare)))
	if err != nil {
		t.Fatalf("§6's TensorRT-LLM table was refused: %v", err)
	}
	p := d.Backend.Prepare
	if p == nil {
		t.Fatal("the table parsed into nothing")
	}
	if !p.Required || !p.GPUArchSpecific || p.TimeoutS != 21600 || p.Artifact != "engine-dir" {
		t.Errorf("prepare = %+v", p)
	}
}

// A backend with no prepare is the common case and must stay free of it: a
// zero-valued Prepare would make every descriptor claim a build step.
func TestABackendWithNoPrepareTableHasNone(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range all {
		if d.Backend.Prepare != nil {
			t.Errorf("%s declares a prepare phase and should not", name)
		}
	}
}

// Every row is a build that would otherwise fail on a GPU host, hours in, with
// a message about something else.
func TestPrepareIsRefusedWhenItCouldNotWork(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"not required", strings.Replace(trtPrepare, "required          = true",
			"required          = false", 1), "required must be true"},
		{"no builder image", strings.Replace(trtPrepare,
			`image             = "nvcr.io/nvidia/tensorrt-llm:1"`, `image = ""`, 1),
			"image is required"},
		{"no command", strings.Replace(trtPrepare,
			`command           = "trtllm-build --checkpoint_dir {src} --output_dir {out} --tp_size {tp}"`,
			`command = ""`, 1), "command is required"},
		{"reads nothing", strings.Replace(trtPrepare, "--checkpoint_dir {src} ", "", 1),
			"no {src}"},
		{"writes nowhere", strings.Replace(trtPrepare, "--output_dir {out} ", "", 1),
			"no {out}"},
		{"unknown placeholder", strings.Replace(trtPrepare, "{tp}", "{threads}", 1),
			"{threads}"},
		{"artifact is not a layout", strings.Replace(trtPrepare,
			`artifact          = "engine-dir"`, `artifact = "engine"`, 1), "must be one of"},
		{"artifact disagrees with the layout", strings.Replace(trtPrepare,
			`artifact          = "engine-dir"`, `artifact = "hf-cache"`, 1), "name one thing"},
		{"no timeout", strings.Replace(trtPrepare, "timeout_s         = 21600",
			"timeout_s = 0", 1), "timeout_s must be positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(withPrepare(tc.body)))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want %q, got %v", tc.want, err)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("not ErrInvalid: %v", err)
			}
		})
	}
}

// The command is an argv, not a shell line: split after substitution, so
// `--output_dir {out}` becomes two elements and the builder sees a flag and a
// path rather than one string it cannot parse.
func TestThePrepareCommandRendersAsAnArgv(t *testing.T) {
	d, err := Parse([]byte(withPrepare(trtPrepare)))
	if err != nil {
		t.Fatal(err)
	}
	argv, err := d.Backend.Prepare.Argv("/w/src", "/w/out", 4)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"trtllm-build", "--checkpoint_dir", "/w/src", "--output_dir", "/w/out",
		"--tp_size", "4"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %q, want %q", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv = %q, want %q", argv, want)
		}
	}
	// Unset parallelism is one card, not zero: `--tp_size 0` is a build that
	// fails on an argument the operator never wrote.
	argv, err = d.Backend.Prepare.Argv("/w/src", "/w/out", 0)
	if err != nil {
		t.Fatal(err)
	}
	if argv[len(argv)-1] != "1" {
		t.Errorf("tp with no parallelism set = %q, want 1", argv[len(argv)-1])
	}
	// Refused rather than quoted, for the reason extra_args already is: the
	// argv is split again downstream and no quoting we invent survives it.
	if _, err := d.Backend.Prepare.Argv("/w/my weights", "/w/out", 1); err == nil {
		t.Error("a path holding whitespace was accepted into an argv that gets split")
	}
}
