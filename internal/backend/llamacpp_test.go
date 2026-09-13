package backend

import (
	"strings"
	"testing"
)

// R6-02. llama.cpp is the third built-in, and the one that shows the descriptor
// format carries more than a vocabulary: a single GGUF rather than a
// HuggingFace cache, an option no other backend expresses, and a server that
// can run where there is no VRAM. vLLM and SGLang differ only in spelling, and
// two descriptors that differ only in spelling cannot demonstrate that anything
// but the spelling is data-driven.
func TestTheLlamaCppDescriptorRendersARunnableArgv(t *testing.T) {
	d, err := Get("llama-cpp")
	if err != nil {
		t.Fatal(err)
	}
	if d.Backend.WeightsLayout != "single-file" {
		t.Errorf("weights_layout = %q, want single-file — llama.cpp is handed a GGUF",
			d.Backend.WeightsLayout)
	}
	if !d.Backend.Capabilities.CPUOffload {
		t.Error("cpu_offload is false; serving where VRAM is short is the reason for this backend")
	}
	// `--tensor-split` divides layers by proportion and is not tensor
	// parallelism. Declaring it as such would let a document written for vLLM
	// move here and mean something else.
	if d.Backend.Capabilities.TensorParallel {
		t.Error("tensor_parallel is true; llama.cpp has --tensor-split, which is a different thing")
	}

	args, dropped, err := d.Args("/models/tiny.gguf", Params{
		"max_context": float64(4096), "port": float64(8080), "host": "0.0.0.0",
		"gpu_layers": float64(33),
	}, []string{"--metrics"})
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 0 {
		t.Errorf("dropped %v; every one of those is named by the descriptor", dropped)
	}
	// Joined with spaces into NODARY_ARGS and split again by systemd, so the
	// space-separated forms are argv pairs rather than one argument each.
	got := strings.Join(args, " ")
	for _, want := range []string{
		"-m /models/tiny.gguf", // the file, not its directory
		"-ngl 33",              // through [backend.extra]
		"-c 4096", "--port 8080", "--host 0.0.0.0",
		"--metrics", // extra_args, verbatim and last
	} {
		if !strings.Contains(got, want) {
			t.Errorf("argv %q does not carry %q", got, want)
		}
	}
	// model_path first, extra_args last: the order is fixed because the argv
	// goes into an environment file, and a set that reordered between
	// reconciles would restart a serving model for no reason.
	if !strings.HasPrefix(got, "-m /models/tiny.gguf") {
		t.Errorf("argv does not start with the model: %q", got)
	}
	if !strings.HasSuffix(got, "--metrics") {
		t.Errorf("extra_args is not last: %q", got)
	}
}

// R6-02's other half. `[backend.extra]` is a second table rather than more rows
// in args, because the difference is the point: a name in args is one nodary
// *translates* between backends, and a name here is one it merely passes. A
// descriptor that put a name in both could not say which it meant.
func TestExtraIsPassedThroughAndNeverShadowsACanonicalName(t *testing.T) {
	base := `
[backend]
name = "t"
api = "openai"
weights_layout = "single-file"
mount_path = "/models"
container_port = 8080
[backend.args]
model_path = "-m {v}"
max_context = "-c {v}"
[backend.extra]
%s
[backend.gpu]
mechanism = "device-flag"
[backend.probe]
health = "/health"
ready = "/health"
ready_timeout_s = 60
`
	if _, err := Parse([]byte(strings.Replace(base, "%s", `gpu_layers = "-ngl {v}"`, 1))); err != nil {
		t.Fatalf("a well-formed extra table was refused: %v", err)
	}

	// A name in both tables: whichever lookup ran first would become the
	// answer, which is a coin toss written as a descriptor.
	_, err := Parse([]byte(strings.Replace(base, "%s", `max_context = "--ctx {v}"`, 1)))
	if err == nil {
		t.Fatal("a name in both args and extra was accepted")
	}
	if !strings.Contains(err.Error(), "both args and extra") {
		t.Errorf("error = %v, want it to name the collision", err)
	}

	// The same {v} rule as args: a template with nothing to substitute is an
	// option whose value silently disappears.
	if _, err := Parse([]byte(strings.Replace(base, "%s", `gpu_layers = "-ngl"`, 1))); err == nil {
		t.Error("an extra template with no {v} was accepted")
	}
}

// A parameter no table names is still dropped and the deployment refused.
// Adding a second lookup must not turn "the descriptor does not know this" into
// "pass it along and hope".
func TestAnUnknownParameterIsStillDroppedWithExtraPresent(t *testing.T) {
	d, err := Get("llama-cpp")
	if err != nil {
		t.Fatal(err)
	}
	_, dropped, err := d.Args("/models/tiny.gguf", Params{"tensor_parallel": float64(4)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0] != "tensor_parallel" {
		t.Errorf("dropped = %v, want tensor_parallel — llama.cpp has no such option", dropped)
	}
}
