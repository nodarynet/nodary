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
	if got := Names(all); !reflect.DeepEqual(got, []string{"sglang", "vllm"}) {
		t.Fatalf("built-ins = %v, want sglang and vllm", got)
	}
	if _, err := Get("llama-cpp"); !errors.Is(err, ErrUnknown) {
		t.Errorf("Get(llama-cpp): error = %v, want ErrUnknown — it needs [backend.extra], which is R6", err)
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
			"--model=/models/gemma",
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
	if first[0] != "--model=/m" {
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
