package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/components"
)

// offerOf is an offer as a node writes one, which is not what a placement can
// assume: the vendor is absent on every node enrolled before it existed.
func offerOf(gpus ...string) string {
	var b strings.Builder
	b.WriteString(`{"max_deployments":4,"gpus":[`)
	for i, vendor := range gpus {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"index":`)
		b.WriteString(string(rune('0' + i)))
		b.WriteString(`,"name":"card","memory_mib":8192`)
		if vendor != "" {
			b.WriteString(`,"vendor":"` + vendor + `"`)
		}
		b.WriteString(`}`)
	}
	b.WriteString(`]}`)
	return b.String()
}

func targetFor(t *testing.T, a *appliance, node string, gpus ...int) (string, string, bool, string) {
	t.Helper()
	var out, errb bytes.Buffer
	e := env{stdin: strings.NewReader(""), stdout: &out, stderr: &errb, defaultDB: a.db}
	plat, vendor, ok := nodeTarget(e, nil, a.db, node, gpus)
	return plat, vendor, ok, errb.String()
}

// TestTheImageIsResolvedForTheNodeNotTheControlPlane is the cost R6a §3 names:
// this is not a manifest change alone, it reaches into the register path.
//
// `model register` resolved against buildinfo.Platform() — the platform of
// whichever box the operator typed the command on. Every node's answer was the
// same until a fleet could hold two vendors, so that was right by accident, and
// it was already wrong for an arm64 node placed from an amd64 control plane.
// Both failures are silent in the same way: the document applies, the revision
// records, and an image that cannot run is pinned into it.
func TestTheImageIsResolvedForTheNodeNotTheControlPlane(t *testing.T) {
	a := newAppliance(t)
	a.enrolledAs("cuda-01", "linux", "amd64", offerOf("nvidia"))
	a.enrolledAs("vulkan-01", "linux", "amd64", offerOf("amd"))
	a.enrolledAs("jetson-01", "linux", "arm64", offerOf("nvidia"))
	// docs/specs/02-enrollment.md §3 gates restating an offer behind
	// certificate expiry, so a node that enrolled before the vendor existed
	// keeps an offer with none in it forever. Absent has to read as nvidia or
	// this release strands the fleet it shipped to.
	a.enrolledAs("legacy-01", "linux", "amd64", offerOf(""))

	for _, tc := range []struct {
		node, plat, vendor string
	}{
		{"cuda-01", "linux/amd64", "nvidia"},
		{"vulkan-01", "linux/amd64", "amd"},
		{"jetson-01", "linux/arm64", "nvidia"},
		{"legacy-01", "linux/amd64", "nvidia"},
	} {
		plat, vendor, ok, stderr := targetFor(t, a, tc.node, 0)
		if !ok {
			t.Fatalf("%s: refused: %s", tc.node, stderr)
		}
		if plat != tc.plat || vendor != tc.vendor {
			t.Errorf("%s: resolved %s/%s, want %s/%s", tc.node, plat, vendor, tc.plat, tc.vendor)
		}
	}

	// A node the control plane has never heard of is the applier's refusal to
	// give, not this one's — and `--out` writes a document with no fleet to ask
	// at all. Falling back to this machine is what every release before this
	// one did for every node.
	plat, vendor, ok, stderr := targetFor(t, a, "nosuchnode", 0)
	if !ok || plat != buildinfo.Platform() || vendor != "" {
		t.Errorf("an unknown node resolved %s/%s ok=%v: %s", plat, vendor, ok, stderr)
	}
}

// TestAMixedVendorPlacementIsRefused answers the one part of R6a §9 that has to
// be answered today.
//
// One deployment runs one image, so two vendors among the assigned cards has no
// right answer: either image is a container that cannot drive half the GPUs it
// was given. Resolving to the first one silently is how that becomes a runtime
// failure on the node instead of a sentence at the keyboard.
func TestAMixedVendorPlacementIsRefused(t *testing.T) {
	a := newAppliance(t)
	a.enrolledAs("mixed-01", "linux", "amd64", offerOf("nvidia", "amd"))

	if _, _, ok, _ := targetFor(t, a, "mixed-01", 0); !ok {
		t.Error("one nvidia card on a mixed host was refused; the vendors that matter are the assigned ones")
	}
	if _, _, ok, _ := targetFor(t, a, "mixed-01", 1); !ok {
		t.Error("one amd card on a mixed host was refused")
	}
	_, _, ok, stderr := targetFor(t, a, "mixed-01", 0, 1)
	if ok {
		t.Fatal("a placement spanning an nvidia and an amd card resolved to a single image")
	}
	for _, want := range []string{"amd and nvidia", "mixed-01", "0,1"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not name %q: %s", want, stderr)
		}
	}
}

// TestABackendWithNoBuildForThisVendorSaysSo is the message an operator meets
// on the hardware this slice exists for.
//
// vLLM, SGLang and TensorRT-LLM have no Vulkan build and are not going to grow
// one (R6a §8), so "no image for amd" is the true and final answer rather than
// a gap. It has to read as one, because the alternative reading — that
// something is misconfigured — sends somebody looking for a setting.
func TestABackendWithNoBuildForThisVendorSaysSo(t *testing.T) {
	m := &components.Manifest{Schema: components.SchemaVersion, Components: []components.Component{{
		Name: "llama-cpp", Version: "b4738", Kind: components.KindImage,
		Roles: []components.Role{components.RoleNode}, Group: components.GroupBackend,
		Platforms: map[string]components.Artifact{"linux/amd64": {
			Image:   "ghcr.io/ggml-org/llama.cpp@sha256:" + strings.Repeat("0", 64),
			Vendors: map[string]components.Artifact{"amd": {Image: "ghcr.io/ggml-org/llama.cpp@sha256:" + strings.Repeat("1", 64)}},
		}},
	}, {
		Name: "vllm", Version: "v0.28.0", Kind: components.KindImage,
		Roles: []components.Role{components.RoleNode}, Group: components.GroupBackend,
		Platforms: map[string]components.Artifact{"linux/amd64": {
			Image: "vllm/vllm-openai@sha256:" + strings.Repeat("2", 64),
		}},
	}}}

	// NVIDIA is the base entry, spelled by name at this seam because that is
	// where a detected machine meets a manifest that has never needed the word.
	got, err := imageFor(m, "llama-cpp", "linux/amd64", "nvidia")
	if err != nil || !strings.Contains(got, strings.Repeat("0", 64)) {
		t.Errorf("nvidia did not resolve to the base entry: %q %v", got, err)
	}
	got, err = imageFor(m, "llama-cpp", "linux/amd64", "amd")
	if err != nil || !strings.Contains(got, strings.Repeat("1", 64)) {
		t.Errorf("amd did not resolve to the override: %q %v", got, err)
	}

	_, err = imageFor(m, "vllm", "linux/amd64", "amd")
	if err == nil {
		t.Fatal("vllm resolved an image for amd; there is no Vulkan build of it to resolve")
	}
	if !strings.Contains(err.Error(), "amd") || !strings.Contains(err.Error(), "NVIDIA-only") {
		t.Errorf("the refusal reads as a gap rather than an answer: %v", err)
	}
}
