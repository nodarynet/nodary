package agent

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func four() []GPU {
	return []GPU{
		{Index: 0, Name: "RTX 4090", MemoryMiB: 24564},
		{Index: 1, Name: "RTX 4090", MemoryMiB: 24564},
		{Index: 2, Name: "RTX 4090", MemoryMiB: 24564},
		{Index: 3, Name: "RTX 4090", MemoryMiB: 24564},
	}
}

// docs/specs/12-node-guardrails.md §4: a four-GPU host offering three appears as
// a three-GPU node. The narrowing happens on the node, so the control plane is
// never told about the fourth card and cannot place work on it.
func TestAFourGPUHostOfferingThreeIsAThreeGPUNode(t *testing.T) {
	c := mustLoad(t, `
[limits]
gpu_indices     = [1, 2, 3]
max_deployments = 2

[allow]
backends    = ["vllm"]
prepare_jobs = false
reboot       = false

[window]
maintenance = "sat 02:00-06:00 UTC"
`)
	offer, k := c.Advertise(four(), []string{"vllm", "sglang"})

	var got []int
	for _, g := range offer.GPUs {
		got = append(got, g.Index)
	}
	if !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Errorf("offered GPUs = %v, want 1, 2, 3 — GPU 0 drives the display", got)
	}
	if offer.MaxDeployments != 2 {
		t.Errorf("max_deployments = %d, want 2", offer.MaxDeployments)
	}
	if !reflect.DeepEqual(offer.Backends, []string{"vllm"}) {
		t.Errorf("backends = %v, want only the allowed one", offer.Backends)
	}
	if k.PrepareJobs || k.Reboot {
		t.Errorf("constraints = %+v, want prepare_jobs and reboot refused", k)
	}
	if k.Maintenance != "sat 02:00-06:00 UTC" {
		t.Errorf("maintenance = %q", k.Maintenance)
	}
}

// §2: a file with no [limits] offers the whole machine, and so does no file at
// all. That is the right default for a dedicated GPU host, so it has to be the
// zero value's meaning rather than something a caller remembers to arrange.
func TestAnAbsentFileOffersTheWholeMachine(t *testing.T) {
	for _, tc := range []struct {
		what string
		c    NodeConfig
	}{
		{"no file", mustLoadPath(t, filepath.Join(t.TempDir(), "absent.toml"))},
		{"an empty file", mustLoad(t, "")},
		{"comments only", mustLoad(t, "# nothing here\n")},
	} {
		offer, k := tc.c.Advertise(four(), []string{"vllm", "sglang"})
		if len(offer.GPUs) != 4 {
			t.Errorf("%s: offered %d GPUs, want all four", tc.what, len(offer.GPUs))
		}
		if offer.MaxDeployments != 4 {
			t.Errorf("%s: max_deployments = %d, want one per offered GPU", tc.what, offer.MaxDeployments)
		}
		if !reflect.DeepEqual(offer.Backends, []string{"vllm", "sglang"}) {
			t.Errorf("%s: backends = %v, want all of them", tc.what, offer.Backends)
		}
		if !k.PrepareJobs || !k.PackageInstall || !k.Reboot || k.MaxVRAMFraction != 1 {
			t.Errorf("%s: constraints = %+v, want everything permitted", tc.what, k)
		}
	}
}

// An empty list and an absent one are different answers, and TOML can tell them
// apart. Collapsing them would turn "offer nothing" into "offer everything",
// which is the wrong direction for a mistake to go.
func TestAnEmptyGPUListOffersNoGPUs(t *testing.T) {
	c := mustLoad(t, "[limits]\ngpu_indices = []\n")
	offer, _ := c.Advertise(four(), nil)
	if len(offer.GPUs) != 0 {
		t.Errorf("offered %v, want none", offer.GPUs)
	}
}

func TestNodeConfigRefusesWhatItShould(t *testing.T) {
	for _, tc := range []struct{ what, body string }{
		// The misspelling that matters: an operator who writes this and is not
		// told believes a GPU is withheld that is in fact on offer.
		{"a misspelt key", "[limits]\ngpu_indicies = [1]\n"},
		{"an unknown section", "[limit]\ngpu_indices = [1]\n"},
		{"a negative index", "[limits]\ngpu_indices = [-1]\n"},
		{"a repeated index", "[limits]\ngpu_indices = [1, 1]\n"},
		{"a fraction above one", "[limits]\nmax_vram_fraction = 1.5\n"},
		{"a fraction of zero", "[limits]\nmax_vram_fraction = 0\n"},
		{"a malformed window", `[window]` + "\n" + `maintenance = "saturday nights"` + "\n"},
		{"not TOML at all", "gpu_indices = [1"},
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "node.toml")
		if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadNodeConfig(path); !errors.Is(err, ErrBadConfig) {
			t.Errorf("%s: error = %v, want a refusal", tc.what, err)
		}
	}
}

func TestNodeConfigRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.toml")
	max := 2
	want := NodeConfig{}
	want.Limits.GPUIndices = []int{1, 2, 3}
	want.Limits.MaxDeployments = &max
	want.Window.Maintenance = "sat 02:00-06:00 UTC"

	if err := os.WriteFile(path, RenderNodeConfig(want), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadNodeConfig(path)
	if err != nil {
		t.Fatalf("LoadNodeConfig: %v", err)
	}
	if !reflect.DeepEqual(got.Limits.GPUIndices, want.Limits.GPUIndices) ||
		*got.Limits.MaxDeployments != max ||
		got.Window.Maintenance != want.Window.Maintenance {
		t.Errorf("round trip = %+v", got)
	}
}

func mustLoad(t *testing.T, body string) NodeConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "node.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return mustLoadPath(t, path)
}

func mustLoadPath(t *testing.T, path string) NodeConfig {
	t.Helper()
	c, err := LoadNodeConfig(path)
	if err != nil {
		t.Fatalf("LoadNodeConfig(%s): %v", path, err)
	}
	return c
}
