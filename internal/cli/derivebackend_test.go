package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/derive"
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

// stubBuild makes `backend build` produce a fixed result without a container
// runtime, and reports what it was asked to build.
//
// The export is left a real code path: buildRuntime answers `nerdctl save` by
// writing a file, so the tar that reaches the mirror cache is one the test can
// look at rather than one nothing checks.
type stubbed struct {
	asked  derive.Options
	dist   string
	saved  []string
	failed string
	// savedTo is the path `nerdctl save -o` was pointed at, and destSeen
	// whether the name the mirror serves already existed while it ran. A node
	// fetching a half-written tar gets a `nerdctl load` failure with nothing
	// to say about the cause, so the export must not write under that name.
	savedTo  []string
	destSeen bool
	dest     string
}

func stubBuild(t *testing.T, digest string) *stubbed {
	t.Helper()
	st := &stubbed{dist: t.TempDir()}
	prevBuild, prevRun := buildDerive, buildRuntime
	buildDerive = func(_ context.Context, o derive.Options) (derive.Result, error) {
		st.asked = o
		return derive.Result{Image: o.Tag, Digest: digest, Steps: 1,
			Reached: []string{"pypi.internal:443"}}, nil
	}
	buildRuntime = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 2 && args[0] == "save" && args[1] == "-o" {
			if st.failed != "" {
				return []byte(st.failed), errors.New("exit status 1")
			}
			if st.dest != "" {
				if _, err := os.Stat(st.dest); err == nil {
					st.destSeen = true
				}
			}
			st.saved = append(st.saved, args[len(args)-1])
			st.savedTo = append(st.savedTo, args[2])
			return nil, os.WriteFile(args[2], []byte("a tar of "+args[len(args)-1]), 0o600)
		}
		return nil, nil
	}
	t.Cleanup(func() { buildDerive, buildRuntime = prevBuild, prevRun })
	return st
}

func (a *appliance) buildWith(t *testing.T, st *stubbed, verb, justify string) (int, string) {
	t.Helper()
	code, _, stderr := a.run("backend", verb, "vllm-fips", "--dist", st.dist,
		"--yes", "--justify", justify)
	return code, stderr
}

const builtDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// §5's actual requirement: the inputs pinned, the output pinned, and the person
// who asked for it named. That record is what turns "someone ran pip install on
// a GPU box" into an artifact with provenance.
func TestBackendBuildRecordsWhatItProduced(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerBackend(t, fipsDescriptor)
	st := stubBuild(t, builtDigest)

	code, stderr := a.buildWith(t, st, "build", "FIPS: stock opencv aborts at import")
	if code != ExitOK {
		t.Fatalf("backend build: exit %d: %s", code, stderr)
	}
	if st.asked.Descriptor.Backend.Derive == nil {
		t.Fatal("the build was handed a descriptor with no recipe")
	}

	code, out, stderr := a.run("audit", "list", "--format", "json")
	if code != ExitOK {
		t.Fatalf("audit list: exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, `"backend.build"`) {
		t.Errorf("the build recorded no backend.build action:\n%s", out)
	}
	fips := a.backendNames(t)["vllm-fips"]
	for _, want := range []struct{ what, value string }{
		{"the digest it produced", builtDigest},
		{"the base it was built from", fips.Recipe.From},
		{"the recipe's digest", fips.Recipe.RecipeSHA256()},
		{"the justification", "stock opencv aborts at import"},
	} {
		if !strings.Contains(out, want.value) {
			t.Errorf("no audit record carries %s (%s):\n%s", want.what, want.value, out)
		}
	}

	if fips.Built == nil {
		t.Fatal("nothing was recorded as built")
	}
	if fips.Built.Digest != builtDigest {
		t.Errorf("built digest = %q, want %q", fips.Built.Digest, builtDigest)
	}
	if fips.Built.Stale {
		t.Errorf("an image built from the recipe in force reads stale: %s", fips.Built.Why)
	}
	// §5 names the builder as part of the provenance. A blank one makes the
	// row say an image exists and nothing about who caused it to.
	if fips.Built.BuiltBy == "" || fips.Built.BuiltAt == "" {
		t.Errorf("the build records no builder or time: %+v", fips.Built)
	}
}

// "A derived image is built once. Rebuilding is explicit" — a `build` that
// quietly rebuilt would be the silent change the audit chain exists to prevent.
func TestASecondBuildHasToBeCalledRebuild(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerBackend(t, fipsDescriptor)
	st := stubBuild(t, builtDigest)
	a.mustBuild(t, st, "build")

	code, stderr := a.buildWith(t, st, "build", "again")
	if code == ExitOK {
		t.Fatal("a second `build` rebuilt without being asked to")
	}
	if !strings.Contains(stderr, "rebuild") {
		t.Errorf("the refusal does not name the verb that would do it: %s", stderr)
	}

	st2 := stubBuild(t, "sha256:"+strings.Repeat("2", 64))
	a.mustBuild(t, st2, "rebuild")
	if got := a.backendNames(t)["vllm-fips"].Built.Digest; got != "sha256:"+strings.Repeat("2", 64) {
		t.Errorf("rebuild left %q", got)
	}
}

// §5: `backend list` shows a derive whose base has moved as `stale`. Derived
// from the recipe in force, so it cannot disagree with the descriptor beside it.
func TestADeriveWhoseBaseHasMovedReadsStale(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerBackend(t, fipsDescriptor)
	st := stubBuild(t, builtDigest)
	a.mustBuild(t, st, "build")

	moved := strings.Replace(fipsDescriptor,
		"sha256:61fc8a896b0a4fbbbdc063bc4b0dbc25ce98e02b5050c24aeb7830ac02039b14",
		"sha256:"+strings.Repeat("9", 64), 1)
	a.registerBackend(t, moved)

	built := a.backendNames(t)["vllm-fips"].Built
	if built == nil || !built.Stale {
		t.Fatalf("a derive whose base moved does not read stale: %+v", built)
	}
	if !strings.Contains(built.Why, "base image has moved") {
		t.Errorf("the reason does not say which half moved: %q", built.Why)
	}
	// Nothing was rebuilt and nothing changed: a base bump does not trigger a
	// build, because silently changing what is serving is the thing this
	// prevents.
	if built.Digest != builtDigest {
		t.Errorf("the recorded image changed when the descriptor did: %q", built.Digest)
	}

	code, out, _ := a.run("backend", "list")
	if code != ExitOK || !strings.Contains(out, "stale") {
		t.Errorf("the listing does not show it as stale:\n%s", out)
	}
}

// A derive's image is not in the component manifest and never will be: the
// manifest pins what a release ships, and this was made on this site.
func TestModelRegisterPinsWhatTheBuildProduced(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerBackend(t, fipsDescriptor)

	models := t.TempDir()
	dir := filepath.Join(models, "hub", "models--acme--tiny")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Before the build there is nothing to pin, and saying so beats a
	// deployment that refuses on a node for a reason nobody can trace here.
	code, _, stderr := a.run("model", "register", "acme/tiny", "--node", "gpu-01",
		"--backend", "vllm-fips", "--models-dir", models, "--port", "8001",
		"--yes", "--justify", "test")
	if code == ExitOK {
		t.Fatal("a model was registered on a derive with no image")
	}
	if !strings.Contains(stderr, "backend build") {
		t.Errorf("the refusal does not say what to do about it: %s", stderr)
	}

	st := stubBuild(t, builtDigest)
	a.mustBuild(t, st, "build")

	code, _, stderr = a.run("model", "register", "acme/tiny", "--node", "gpu-01",
		"--backend", "vllm-fips", "--models-dir", models, "--port", "8001",
		"--yes", "--justify", "test")
	if code != ExitOK {
		t.Fatalf("model register: exit %d: %s", code, stderr)
	}

	if got := a.scalar(t, `SELECT image_digest FROM deployment`); got != builtDigest {
		t.Errorf("the deployment pinned %q, want the digest the build produced %q",
			got, builtDigest)
	}
}

// There is no recipe to run, and saying that beats a build that fails later
// for a reason an operator has to work backwards from.
func TestBuildingABackendWithNoRecipeIsRefused(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	code, _, stderr := a.run("backend", "build", "vllm", "--yes", "--justify", "test")
	if code == ExitOK {
		t.Fatal("a built-in with no recipe was built")
	}
	if !strings.Contains(stderr, "not a derived image") {
		t.Errorf("the refusal does not say why: %s", stderr)
	}
}

// "A failed build produces no image and replaces none, and deployments on the
// previous digest keep serving."
func TestAFailedBuildReplacesNothing(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerBackend(t, fipsDescriptor)
	st := stubBuild(t, builtDigest)
	a.mustBuild(t, st, "build")

	prev := buildDerive
	buildDerive = func(_ context.Context, _ derive.Options) (derive.Result, error) {
		return derive.Result{}, errors.New("step 1 (pip install x): exit status 1")
	}
	t.Cleanup(func() { buildDerive = prev })

	code, _ := a.buildWith(t, st, "rebuild", "test")
	if code == ExitOK {
		t.Fatal("a failed build succeeded")
	}
	if got := a.backendNames(t)["vllm-fips"].Built.Digest; got != builtDigest {
		t.Errorf("a failed build replaced the image that was there: %q", got)
	}
	code, out, _ := a.run("audit", "list", "--format", "json")
	if code == ExitOK && strings.Count(out, `"backend.rebuild"`) != 0 {
		t.Errorf("a build that produced nothing wrote a record claiming it did:\n%s", out)
	}
}

func (a *appliance) mustBuild(t *testing.T, st *stubbed, verb string) {
	t.Helper()
	if code, stderr := a.buildWith(t, st, verb, "test fixture"); code != ExitOK {
		t.Fatalf("backend %s: exit %d: %s", verb, code, stderr)
	}
}

// unpinnedDescriptor is the same derive with the version dropped — the recipe a
// default site may register and a regulated one may not.
var unpinnedDescriptor = strings.Replace(fipsDescriptor,
	"opencv-python-headless==4.12.0.88", "opencv-python-headless", 1)

func (a *appliance) regulated(t *testing.T) {
	t.Helper()
	if code, _, stderr := a.run("policy", "apply", "regulated"); code != ExitOK {
		t.Fatalf("apply regulated: %d %s", code, stderr)
	}
}

// §5's policy row: what `regulated` adds is that sources must be pinned and
// come from a named index, so the build is reproducible rather than merely
// recorded.
func TestARegulatedSiteRefusesAnUnpinnedRecipe(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.regulated(t)

	code, _, stderr := a.run("backend", "register", "--file", a.descriptorFile(t, unpinnedDescriptor),
		"--yes", "--justify", "FIPS override for this site")
	if code == ExitOK {
		t.Fatal("a regulated site registered a recipe that floats")
	}
	if !strings.Contains(stderr, "exact version") {
		t.Errorf("the refusal does not say what is missing: %s", stderr)
	}

	// And the index, the other half of the row.
	noIndex := strings.Replace(fipsDescriptor, "index_url = \"https://pypi.internal/simple\"\n", "", 1)
	code, _, stderr = a.run("backend", "register", "--file", a.descriptorFile(t, noIndex),
		"--yes", "--justify", "FIPS override for this site")
	if code == ExitOK {
		t.Fatal("a regulated site registered a recipe with no named index")
	}
	if !strings.Contains(stderr, "index_url") {
		t.Errorf("the refusal does not name the field: %s", stderr)
	}

	// **The pinned form still registers under `regulated`.** §5 is explicit
	// that `allow_custom_backends = false` and `allow_derived_images = true`
	// are consistent, so a derive is gated by the second and not the first —
	// a FIPS override is the motivating case, not the thing being guarded
	// against.
	code, _, stderr = a.run("backend", "register", "--file", a.descriptorFile(t, fipsDescriptor),
		"--yes", "--justify", "FIPS override for this site")
	if code != ExitOK {
		t.Fatalf("a regulated site refused the pinned derive it is meant to allow: %s", stderr)
	}
	if _, ok := a.backendNames(t)["vllm-fips"]; !ok {
		t.Error("the derive did not register")
	}
}

// A profile can be tightened after the fact. A site that moved to `regulated`
// last week must not still be able to build the unpinned recipe it registered
// before, or the flag would be advice rather than a control.
func TestTighteningTheProfileStopsAnUnpinnedBuild(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerBackend(t, unpinnedDescriptor)
	st := stubBuild(t, builtDigest)

	// Under the default profile it builds, which is the point of the two
	// profiles differing.
	a.mustBuild(t, st, "build")

	a.regulated(t)
	code, stderr := a.buildWith(t, st, "rebuild", "rebuilding after the base moved")
	if code == ExitOK {
		t.Fatal("a regulated site rebuilt a recipe that floats")
	}
	if !strings.Contains(stderr, "require_pinned_derives") {
		t.Errorf("the refusal does not name the setting that caused it: %s", stderr)
	}
	// Nothing that is serving changed: the image built before the profile
	// moved is still the image on record.
	if got := a.backendNames(t)["vllm-fips"].Built.Digest; got != builtDigest {
		t.Errorf("tightening the profile changed what is on record: %q", got)
	}
}

// §5: the result is "stored in the control plane's mirror and served to nodes
// like any other image". A node can neither build this image nor pull it, so
// without the export there is nothing anywhere a GPU host could fetch.
func TestABuildLeavesItsImageInTheMirror(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerBackend(t, fipsDescriptor)
	st := stubBuild(t, builtDigest)
	st.dest = filepath.Join(st.dist, api.DerivedImageFile(builtDigest))
	a.mustBuild(t, st, "build")

	want := st.dest
	if _, err := os.Stat(want); err != nil {
		if entries, rerr := os.ReadDir(st.dist); rerr == nil {
			t.Fatalf("the build left no image in the mirror cache: %v (holds %v)", err, entries)
		}
		t.Fatalf("the build left no image in the mirror cache: %v", err)
	}
	// The digest and not the tag: the node asks for the file by the digest its
	// deployment pins, so exporting the tag would leave a name nothing asks for.
	if len(st.saved) != 1 || st.saved[0] != builtDigest {
		t.Errorf("exported %v, want the digest %q", st.saved, builtDigest)
	}
	// **Written under another name and renamed.** The mirror serves whatever is
	// in the cache directory, with no notion of a file still being written, so
	// a save straight to the served name is a window in which a node fetches a
	// truncated tar and reports a load failure that names nothing.
	if len(st.savedTo) != 1 || st.savedTo[0] == want {
		t.Errorf("the export wrote directly to the name the mirror serves (%v)", st.savedTo)
	}
	if st.destSeen {
		t.Error("the served name existed while the export was still writing")
	}
}

// An export that fails leaves an image no node can reach, so recording it would
// claim a deployment is possible that is not.
func TestABuildThatCannotExportRecordsNothing(t *testing.T) {
	a := newAppliance(t)
	a.enrolled("gpu-01")
	a.registerBackend(t, fipsDescriptor)
	st := stubBuild(t, builtDigest)
	st.failed = "no space left on device"

	code, stderr := a.buildWith(t, st, "build", "test fixture")
	if code == ExitOK {
		t.Fatal("a build whose image never reached the mirror was recorded")
	}
	if !strings.Contains(stderr, "node cannot fetch it") {
		t.Errorf("the failure does not say what the consequence is: %s", stderr)
	}
	if b := a.backendNames(t)["vllm-fips"].Built; b != nil {
		t.Errorf("an image nothing can fetch was recorded as built: %+v", b)
	}
}
