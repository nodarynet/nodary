package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/backend"
	"github.com/nodarynet/nodary/internal/config"
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

// A minimal descriptor that passes the schema, matching internal/config's
// fixture: what is under test is an operator's own file, not a built-in.
const acmeDescriptor = `[backend]
name           = "acme-serve"
api            = "openai"
weights_layout = "hf-cache"
mount_path     = "/weights"
container_port = 9000
image_default  = "acme/serve:1"

[backend.capabilities]
tensor_parallel = false
expert_parallel = false
quantization    = ["awq"]
lora            = false
cpu_offload     = false

[backend.args]
model_path = "--model={v}"
port       = "--port={v}"

[backend.probe]
health          = "/healthz"
ready           = "/healthz"
ready_timeout_s = 300
`

// descriptorFile writes a descriptor somewhere `backend register -f` can read it.
func (a *appliance) descriptorFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acme.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func (a *appliance) registerBackend(t *testing.T, body string) {
	t.Helper()
	code, _, stderr := a.run("backend", "register", "--file", a.descriptorFile(t, body),
		"--yes", "--justify", "test fixture")
	if code != ExitOK {
		t.Fatalf("backend register: exit %d: %s", code, stderr)
	}
}

// backendNames is what `backend list` reports, keyed by name.
func (a *appliance) backendNames(t *testing.T) map[string]backend.Report {
	t.Helper()
	code, out, stderr := a.run("backend", "list", "--format", "json")
	if code != ExitOK {
		t.Fatalf("backend list: exit %d: %s", code, stderr)
	}
	var got struct {
		Backends []backend.Report `json:"backends"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	by := map[string]backend.Report{}
	for _, b := range got.Backends {
		by[b.Name] = b
	}
	return by
}

// Registration is a configuration change, so it lands through the applier and
// shows up in the same listing the built-ins do — with `registered` as its
// source, which is the one thing an operator has to be able to tell apart.
func TestBackendRegisterPutsAnOperatorsDescriptorInTheCatalog(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerBackend(t, acmeDescriptor)

	by := a.backendNames(t)
	acme, ok := by["acme-serve"]
	if !ok {
		t.Fatalf("acme-serve is not in the listing: %v", by)
	}
	if acme.Source != backend.SourceRegistered {
		t.Errorf("source = %q, want %q — an operator cannot tell their own descriptor "+
			"from one this binary carries", acme.Source, backend.SourceRegistered)
	}
	if acme.SHA256 == "" {
		t.Error("a registered descriptor reports no digest, so nothing identifies which " +
			"bytes a node was sent")
	}
	if _, ok := by["vllm"]; !ok {
		t.Error("registering one descriptor lost the built-ins")
	}
	// The act is the ordinary configuration one — a second audit action for
	// the same write would be a second road into the catalog — and it carries
	// the descriptor's digest, which is 04 §9's actual requirement. The
	// revision holds the bytes; the record is what an assessor can query.
	code, out, stderr := a.run("audit", "list", "--format", "json")
	if code != ExitOK {
		t.Fatalf("audit list: exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, `"config.apply"`) {
		t.Errorf("registering a backend recorded no config.apply:\n%s", out)
	}
	if !strings.Contains(out, acme.SHA256) {
		t.Errorf("no audit record carries the descriptor's digest %s, so nothing an "+
			"assessor can query says which bytes were approved:\n%s", acme.SHA256, out)
	}
}

// The file is read on the machine holding it, so a typo refuses in front of
// the person who can fix it rather than as a 422 three hops later.
func TestBackendRegisterRefusesAFileThatIsNotADescriptor(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	path := a.descriptorFile(t, "[backend]\nname = \"acme-serve\"\napi = \"telepathy\"\n")
	code, _, stderr := a.run("backend", "register", "-f", path, "--yes", "--justify", "test")
	if code == ExitOK {
		t.Fatal("a descriptor that is not one was registered")
	}
	if !strings.Contains(stderr, path) {
		t.Errorf("the refusal does not name the file the operator has open: %s", stderr)
	}
	if _, ok := a.backendNames(t)["acme-serve"]; ok {
		t.Error("a descriptor that refused was registered anyway")
	}
}

// The removal goes back as the whole configuration with --prune, so the one
// thing that must be true is that nothing else goes with it.
func TestBackendRemoveTakesOneOutAndLeavesTheRestStanding(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerBackend(t, acmeDescriptor)
	a.registerModel(t, "Qwen/Qwen2.5-0.5B-Instruct", "gpu-01")

	code, _, stderr := a.run("backend", "remove", "acme-serve", "--yes", "--justify", "done with it")
	if code != ExitOK {
		t.Fatalf("backend remove: exit %d: %s", code, stderr)
	}
	if _, ok := a.backendNames(t)["acme-serve"]; ok {
		t.Error("acme-serve is still registered")
	}
	// The model, its deployment, its route and the node were in the document
	// only because it was read back whole, and --prune deletes whatever a
	// document does not name. If it reached any of them this is where an
	// operator would find out — otherwise it is after the fact, on a fleet.
	code, out, stderr := a.run("config", "show", "--format", "json")
	if code != ExitOK {
		t.Fatalf("config show: exit %d: %s", code, stderr)
	}
	var snap config.Snapshot
	if err := json.Unmarshal([]byte(out), &snap); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(snap.Backends) != 0 {
		t.Errorf("backends = %v, want none left", snap.Backends)
	}
	if len(snap.Models) != 1 || len(snap.Deployments) != 1 ||
		len(snap.Routes) != 1 || len(snap.Nodes) != 1 {
		t.Errorf("removing one backend pruned the configuration around it: "+
			"%d models, %d deployments, %d routes, %d nodes; want 1 of each",
			len(snap.Models), len(snap.Deployments), len(snap.Routes), len(snap.Nodes))
	}
}

// A node whose descriptor vanished cannot render an argv at all, so every
// deployment on that backend would fail at once for a reason naming neither
// this command nor this document. The refusal is the applier's, reached
// through this verb, so `config apply --prune` cannot walk around it.
func TestBackendRemoveRefusesOneStillServingSomething(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerBackend(t, acmeDescriptor)

	models := t.TempDir()
	dir := filepath.Join(models, "hub", "models--acme--tiny")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := a.run("model", "register", "acme/tiny", "--node", "gpu-01",
		"--backend", "acme-serve", "--image", "acme/serve:1", "--models-dir", models,
		"--port", "8001", "--yes", "--justify", "test fixture")
	if code != ExitOK {
		t.Fatalf("model register on a registered backend: exit %d: %s", code, stderr)
	}

	code, _, stderr = a.run("backend", "remove", "acme-serve", "--yes", "--justify", "test")
	if code == ExitOK {
		t.Fatal("a backend still serving a deployment was removed")
	}
	for _, want := range []string{"acme-serve", "still used"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not say %q: %s", want, stderr)
		}
	}
	if _, ok := a.backendNames(t)["acme-serve"]; !ok {
		t.Error("the refusal rolled nothing back: acme-serve is gone anyway")
	}
}

// Two ways to name nothing, and they need different next steps: one is a name
// that was never registered, the other is a name this binary carries and no
// catalog row exists for.
func TestBackendRemoveSaysWhichKindOfNothingItFound(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	for _, tc := range []struct{ name, want string }{
		{"vllm", "built into this binary"},
		{"nonesuch", "no registered backend"},
	} {
		code, _, stderr := a.run("backend", "remove", tc.name, "--yes", "--justify", "test")
		if code == ExitOK {
			t.Fatalf("backend remove %s reported success", tc.name)
		}
		if !strings.Contains(stderr, tc.want) {
			t.Errorf("backend remove %s: want %q, got %s", tc.name, tc.want, stderr)
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

// A backend and the last deployment using it have to be removable in one
// document. Checking "still used" beside the registrations meant the check ran
// before the deployment prune did, so the only way out of a custom backend was
// two applies in the right order — and the refusal said the deployment was
// there when the document plainly removed it.
func TestOneDocumentCanRetireABackendAndItsLastDeployment(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerBackend(t, acmeDescriptor)

	models := t.TempDir()
	dir := filepath.Join(models, "hub", "models--acme--tiny")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := a.run("model", "register", "acme/tiny", "--node", "gpu-01",
		"--backend", "acme-serve", "--image", "acme/serve:1", "--models-dir", models,
		"--port", "8001", "--yes", "--justify", "test fixture"); code != ExitOK {
		t.Fatalf("model register: exit %d: %s", code, stderr)
	}

	path := filepath.Join(t.TempDir(), "node-only.toml")
	if err := os.WriteFile(path,
		[]byte("[[node]]\nname = \"gpu-01\"\nstate = \"approved\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := a.run("config", "apply", "-f", path, "--prune",
		"--yes", "--justify", "retiring the backend and what it served")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, "- backend acme-serve") {
		t.Errorf("the change list does not retire the backend:\n%s", out)
	}
	if _, ok := a.backendNames(t)["acme-serve"]; ok {
		t.Error("acme-serve survived a document that does not name it")
	}
}

// The road an operator actually takes. `model register` creates a route as
// well as a deployment, so a backend that cannot be routed to is refused
// there — at the moment the route would come into being, naming it.
func TestRegisteringAModelOnABackendTheGatewayCannotProxyIsRefused(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerBackend(t, strings.Replace(acmeDescriptor,
		`api            = "openai"`, `api            = "triton"`, 1))

	models := t.TempDir()
	dir := filepath.Join(models, "hub", "models--acme--tiny")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := a.run("model", "register", "acme/tiny", "--node", "gpu-01",
		"--backend", "acme-serve", "--image", "acme/serve:1", "--models-dir", models,
		"--port", "8001", "--yes", "--justify", "test")
	if code == ExitOK {
		t.Fatal("a model was routed to a backend that does not speak OpenAI")
	}
	// It has to say which of the three things is wrong, because the operator
	// wrote all three: the descriptor's api, the backend, and the route.
	for _, want := range []string{"triton", "acme-serve", "openai"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not name %q: %s", want, stderr)
		}
	}
}
