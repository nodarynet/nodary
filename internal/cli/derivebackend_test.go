package cli

import (
	"strings"
	"testing"
)

// fipsDescriptor is docs/specs/04-backends.md §5's own example: the case
// derived images exist for.
const fipsDescriptor = `[backend]
name     = "vllm-fips"
inherits = "vllm"

[backend.derive]
from      = "vllm/vllm-openai@sha256:61fc8a896b0a4fbbbdc063bc4b0dbc25ce98e02b5050c24aeb7830ac02039b14"
steps     = ["pip install --no-cache-dir opencv-python-headless==4.12.0.88"]
index_url = "https://pypi.internal/simple"
timeout_s = 1800
`

// A derive on its own carries a name, a parent and a recipe — nothing else. If
// the parent is not resolved into it, every read gets a descriptor with no
// argument vocabulary, no weight layout and no probe, and a deployment on it is
// refused for the reasons of a backend that does not exist.
func TestARegisteredDeriveIsTheBackendItInherits(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerBackend(t, fipsDescriptor)

	by := a.backendNames(t)
	fips, ok := by["vllm-fips"]
	if !ok {
		t.Fatalf("vllm-fips is not in the listing: %v", by)
	}
	parent := by["vllm"]
	for _, c := range []struct{ what, want, have string }{
		{"api", parent.API, fips.API},
		{"weights_layout", parent.WeightsLayout, fips.WeightsLayout},
		{"mount_path", parent.MountPath, fips.MountPath},
		{"probe.health", parent.Probe.Health, fips.Probe.Health},
	} {
		if c.want == "" {
			t.Fatalf("the fixture is wrong: vllm reports no %s", c.what)
		}
		if c.have != c.want {
			t.Errorf("%s = %q, want vllm's %q", c.what, c.have, c.want)
		}
	}
	if len(fips.Args) != len(parent.Args) {
		t.Errorf("params = %v, want vllm's %v — a derive that translates a different "+
			"vocabulary is a different backend", fips.Args, parent.Args)
	}
	// Cleared rather than inherited: the image this backend serves is the one
	// its build produces, and naming the base would let a deployment start on
	// the uncorrected image — the failure the derive exists to prevent.
	if fips.ImageDefault != "" {
		t.Errorf("image = %q, want none; a derive that names its base can be deployed "+
			"without ever being built", fips.ImageDefault)
	}
	if fips.Recipe == nil {
		t.Error("the recipe is not reported, so nothing says what `backend build` would do")
	}
}

// The descriptor parses, so nothing downstream would call it malformed. It
// would simply be a row that resolves to nothing.
func TestADeriveOfAParentThisBuildHasNotGotIsRefused(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	src := strings.Replace(fipsDescriptor, `inherits = "vllm"`, `inherits = "vllm-ng"`, 1)
	code, _, stderr := a.run("backend", "register", "--file", a.descriptorFile(t, src),
		"--yes", "--justify", "test")
	if code == ExitOK {
		t.Fatal("a derive of a backend this build has not got was registered")
	}
	if !strings.Contains(stderr, "vllm-ng") {
		t.Errorf("the refusal does not name the parent that is missing: %s", stderr)
	}
	if _, ok := a.backendNames(t)["vllm-fips"]; ok {
		t.Error("a descriptor that refused was registered anyway")
	}
}
