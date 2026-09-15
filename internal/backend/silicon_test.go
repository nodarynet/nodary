package backend

import (
	"errors"
	"strings"
	"testing"
)

// silicon is the R6-16 field: which GPU vendors a backend runs on, declared by
// the backend rather than tabulated in nodary.
const siliconBase = `
[backend]
name = "x"
api = "openai"
weights_layout = "hf-cache"
mount_path = "/m"
container_port = 8000
silicon = ["nvidia", "amd"]
[backend.args]
model_path = "--model={v}"
[backend.probe]
health = "/health"
ready = "/health"
ready_timeout_s = 60
`

func TestADescriptorDeclaresTheSiliconItRunsOn(t *testing.T) {
	d, err := Parse([]byte(siliconBase))
	if err != nil {
		t.Fatal(err)
	}
	for vendor, want := range map[string]bool{
		"nvidia": true,
		"amd":    true,
		"intel":  false,
		// The empty vendor is nvidia — agent.GPU.VendorName's default and the
		// component manifest's base entry, which is what a GPU offered before
		// there was a vendor axis at all comes back as.
		"": true,
	} {
		if got := d.RunsOn(vendor); got != want {
			t.Errorf("RunsOn(%q) = %v, want %v", vendor, got, want)
		}
	}

	for _, tc := range []struct{ what, body string }{
		// The one that matters. A descriptor written before this field existed
		// parses cleanly and would otherwise claim every vendor, which is how a
		// CUDA-only backend gets placed on a Radeon.
		{"no silicon at all", strings.Replace(siliconBase, `silicon = ["nvidia", "amd"]`, "", 1)},
		{"an empty list", strings.Replace(siliconBase, `["nvidia", "amd"]`, `[]`, 1)},
		{"a vendor outside the vocabulary", strings.Replace(siliconBase, `"amd"`, `"rocm"`, 1)},
		{"a vendor named twice", strings.Replace(siliconBase, `"amd"`, `"nvidia"`, 1)},
	} {
		if _, err := Parse([]byte(tc.body)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: error = %v, want a refusal", tc.what, err)
		}
	}
}

// Every backend this build ships names its silicon, and names it truthfully
// against dev/plans/R6b-the-silicon-matrix.md §3 — which is the table an
// operator is offered from, so a descriptor that disagrees with it is the
// matrix being wrong rather than a preference.
func TestTheShippedDescriptorsDeclareTheMatrix(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		// No `rocm/vllm` and no `intel/vllm`: R6b §1 declines a third and a
		// fourth publisher, so upstream's CUDA-only image is the whole offer.
		"vllm": {"nvidia"},
		// ROCm tags exist and every one of them is Instinct. There is no RDNA
		// build, so on the card a small site owns this backend has no image.
		"sglang": {"nvidia"},
		// The cross-vendor one, which is the reason it is pinned.
		"llama-cpp": {"nvidia", "amd", "intel"},
	}
	if len(all) != len(want) {
		t.Errorf("this build ships %d descriptors and the matrix covers %d: %v",
			len(all), len(want), Names(all))
	}
	for name, vendors := range want {
		d, ok := all[name]
		if !ok {
			t.Errorf("%s is not a built-in", name)
			continue
		}
		if strings.Join(d.Backend.Silicon, ",") != strings.Join(vendors, ",") {
			t.Errorf("%s declares %v, and the matrix says %v", name, d.Backend.Silicon, vendors)
		}
	}
}

// A derive corrects an image; it does not move a backend onto silicon the
// backend cannot drive. It inherits the declaration instead.
func TestADeriveInheritsSiliconAndMayNotDeclareIt(t *testing.T) {
	body := `
[backend]
name = "vllm-fips"
inherits = "vllm"
[backend.derive]
from = "vllm/vllm-openai@sha256:` + strings.Repeat("b", 64) + `"
steps = ["pip install --no-cache-dir opencv-python-headless"]
timeout_s = 1800
`
	d, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := Resolve(d)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.RunsOn("nvidia") || resolved.RunsOn("amd") {
		t.Errorf("a derive of vllm declares %v; it inherits vllm's", resolved.Backend.Silicon)
	}

	claimed := strings.Replace(body, "[backend.derive]", "silicon = [\"amd\"]\n[backend.derive]", 1)
	if _, err := Parse([]byte(claimed)); !errors.Is(err, ErrInvalid) {
		t.Errorf("a derive claiming its own silicon was accepted: %v", err)
	}
}

// R6b §3's table, driven. One ordered preference list has to reproduce a
// per-vendor matrix exactly, or the matrix is written down in two places.
func TestTheOfferIsTheMatrix(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	reports := Reports(all)
	for _, c := range []struct {
		vendor    string
		offer     []string
		recommend string
	}{
		{"nvidia", []string{"llama-cpp", "sglang", "vllm"}, "sglang"},
		{"amd", []string{"llama-cpp"}, "llama-cpp"},
		{"intel", []string{"llama-cpp"}, "llama-cpp"},
		// A node that has offered nothing, and a GPU offered before there was
		// a vendor axis at all. Both are nvidia, everywhere else in the tree.
		{"", []string{"llama-cpp", "sglang", "vllm"}, "sglang"},
	} {
		offer, recommend := Offer(reports, c.vendor)
		if strings.Join(offer, ",") != strings.Join(c.offer, ",") {
			t.Errorf("%q offers %v, want %v", c.vendor, offer, c.offer)
		}
		if recommend != c.recommend {
			t.Errorf("%q recommends %q, want %q", c.vendor, recommend, c.recommend)
		}
	}
}

// A site's own descriptor is offered on the silicon it declares and is never
// recommended: this build has no basis for suggesting an image it has not
// tested, and a descriptor that could nominate itself would outrank the ones
// that were.
func TestARegisteredDescriptorIsOfferedAndNotRecommended(t *testing.T) {
	mine := Report{Name: "sglang-rocm", Source: SourceRegistered, Silicon: []string{"amd"}}
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	reports := append(Reports(all), mine)

	offer, recommend := Offer(reports, "amd")
	if strings.Join(offer, ",") != "llama-cpp,sglang-rocm" {
		t.Errorf("offer = %v, want the registered one beside llama-cpp", offer)
	}
	if recommend != "llama-cpp" {
		t.Errorf("recommend = %q, want the backend this build pins", recommend)
	}

	// And when nothing this build pins is eligible, there is an offer and no
	// recommendation — which is a different answer from having nothing.
	offer, recommend = Offer([]Report{mine}, "amd")
	if len(offer) != 1 || offer[0] != "sglang-rocm" {
		t.Errorf("offer = %v, want the one descriptor that runs there", offer)
	}
	if recommend != "" {
		t.Errorf("recommend = %q, want no suggestion at all", recommend)
	}
}
