package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/backend"
)

// The listing is what an operator reads before writing `params`, so it has to
// carry the vocabulary rather than only the name.
func TestBackendListNamesWhatEachBackendUnderstands(t *testing.T) {
	code, out, stderr := run(t, "backend", "list", "--format", "json")
	if code != ExitOK {
		t.Fatalf("backend list: exit %d, %s", code, stderr)
	}
	var got struct {
		Backends []backend.Report `json:"backends"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(got.Backends) < 3 {
		t.Fatalf("want the three built-ins, got %d:\n%s", len(got.Backends), out)
	}
	by := map[string]backend.Report{}
	for _, b := range got.Backends {
		by[b.Name] = b
	}
	for _, name := range []string{"vllm", "sglang", "llama-cpp"} {
		if _, ok := by[name]; !ok {
			t.Errorf("%s is missing from the listing", name)
		}
	}
	// The keys are the words a descriptor and a document use, not Go field
	// names: an operator reading `TensorParallel` has no way to connect it to
	// the `tensor_parallel` they write.
	// The colon matters: `tensor_parallel` is also a *value* in vllm's params
	// list, so matching the bare word would pass even with the key renamed.
	for _, want := range []string{`"weights_layout":`, `"tensor_parallel":`, `"container_port":`} {
		if !strings.Contains(out, want) {
			t.Errorf("--format json does not carry the key %s — an operator reading a Go "+
				"field name cannot connect it to the key they write:\n%s", want, out)
		}
	}
	// Two lists, not one. A name in params is translated and means the same
	// thing against another backend; a name in extra is passed through and
	// does not (04 §3), and flattening them loses exactly that.
	llama := by["llama-cpp"]
	if !contains(llama.Extra, "gpu_layers") {
		t.Errorf("llama-cpp's extra = %v, want gpu_layers", llama.Extra)
	}
	if contains(llama.Args, "gpu_layers") {
		t.Error("a pass-through option is listed as a canonical parameter, which would tell " +
			"an operator it is portable to another backend")
	}
	if !contains(by["vllm"].Args, "max_context") {
		t.Errorf("vllm's params = %v, want max_context", by["vllm"].Args)
	}
}

func TestBackendShowRefusesAnUnknownName(t *testing.T) {
	code, _, stderr := run(t, "backend", "show", "nonesuch")
	if code == ExitOK {
		t.Fatal("an unknown backend was shown")
	}
	// It says what this build does have, because the next thing the operator
	// does is pick one.
	for _, want := range []string{"nonesuch", "vllm"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not name %q: %s", want, stderr)
		}
	}
}

// register and remove are named rather than falling through to "unknown
// subcommand": an operator who reads 04 §9 and types one should be told it is
// not in this release, not that it does not exist.
func TestBackendRegisterSaysItIsNotBuiltYet(t *testing.T) {
	for _, verb := range []string{"register", "remove"} {
		code, _, stderr := run(t, "backend", verb, "--file", "x.toml")
		if code == ExitOK {
			t.Fatalf("backend %s reported success", verb)
		}
		if !strings.Contains(stderr, "not implemented") {
			t.Errorf("backend %s: %s", verb, stderr)
		}
	}
}

func contains(all []string, want string) bool {
	for _, a := range all {
		if a == want {
			return true
		}
	}
	return false
}
