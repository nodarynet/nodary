package components

import (
	"strings"
	"testing"
)

// TestAVendorWithNoImagePinnedIsRefusedNotSubstituted is the whole point of the
// vendors map.
//
// The tempting fallback — no override, use the base — pins a CUDA image onto an
// AMD node. Nothing refuses that: the manifest is valid, `model register`
// succeeds, config.Apply succeeds, and the failure arrives on the node as a
// model server that cannot find CUDA, naming neither the vendor nor the image,
// on a machine the operator may have no shell on.
func TestAVendorWithNoImagePinnedIsRefusedNotSubstituted(t *testing.T) {
	base := Artifact{Image: "vllm/vllm-openai@sha256:" + zeros}

	// NVIDIA is spelled as the absent vendor, because the base entry *is* the
	// CUDA build. internal/cli/imageFor is what maps the name onto that.
	if got, ok := base.ForVendor(""); !ok || got.Image != base.Image {
		t.Errorf("the base entry did not answer for no vendor: %v %q", ok, got.Image)
	}
	if _, ok := base.ForVendor("amd"); ok {
		t.Error("a component with no vendors map answered for amd; every image in the " +
			"manifest is a CUDA build, so that is a CUDA image on a Radeon")
	}

	with := Artifact{Image: base.Image, Vendors: map[string]Artifact{
		"amd": {Image: "ghcr.io/ggml-org/llama.cpp@sha256:" + ones},
	}}
	got, ok := with.ForVendor("amd")
	if !ok || got.Image != with.Vendors["amd"].Image {
		t.Errorf("the amd override did not answer: %v %q", ok, got.Image)
	}
	if got, ok := with.ForVendor(""); !ok || got.Image != base.Image {
		t.Errorf("an override changed the base entry: %v %q", ok, got.Image)
	}
	if _, ok := with.ForVendor("intel"); ok {
		t.Error("an amd override answered for intel")
	}
}

// TestAVendorOverrideIsPinnedLikeAnyOtherArtifact holds the two ways a vendor
// map could quietly be worth less than the manifest it sits in.
//
// An override is what actually gets pulled on that hardware, so a tag there
// defeats digest pinning for exactly the hosts nobody has run yet — the ones
// with the least other evidence that anything is right. And a nested vendors
// map parses fine, is never read, and looks like a pin that is doing something.
func TestAVendorOverrideIsPinnedLikeAnyOtherArtifact(t *testing.T) {
	m := &Manifest{Schema: SchemaVersion, Components: []Component{{
		Name: "llama-cpp", Version: "b4738", Kind: KindImage,
		Roles: []Role{RoleNode}, Group: GroupBackend,
		Platforms: map[string]Artifact{"linux/amd64": {
			Image: "ghcr.io/ggml-org/llama.cpp@sha256:" + zeros,
			Vendors: map[string]Artifact{
				"amd": {Image: "ghcr.io/ggml-org/llama.cpp:server-vulkan-b4740"},
				"intel": {Image: "ghcr.io/ggml-org/llama.cpp@sha256:" + ones,
					Vendors: map[string]Artifact{"amd": {Image: "x"}}},
			},
		}},
	}}}
	errs := m.Validate()
	var tagged, nested bool
	for _, err := range errs {
		switch {
		case strings.Contains(err.Error(), "not digest-pinned") && strings.Contains(err.Error(), "amd"):
			tagged = true
		case strings.Contains(err.Error(), "its own vendors map"):
			nested = true
		}
	}
	if !tagged {
		t.Errorf("a tag in a vendor override validated: %v", errs)
	}
	if !nested {
		t.Errorf("a nested vendors map validated: %v", errs)
	}
}

const (
	zeros = "0000000000000000000000000000000000000000000000000000000000000000"
	ones  = "1111111111111111111111111111111111111111111111111111111111111111"
)
