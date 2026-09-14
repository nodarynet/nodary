package bundle

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/components"
)

// site is a cache with two archives in it and one image component, which is
// the shape of every real bundle: things that were downloaded and things the
// container runtime holds.
func site(t *testing.T) (dist string, archives, images []components.Component) {
	t.Helper()
	dist = t.TempDir()

	for _, spec := range []struct{ name, version, body string }{
		{"containerd", "2.3.4", "containerd bytes"},
		{"runc", "1.2.3", "runc bytes"},
	} {
		c := components.Component{Name: spec.name, Version: spec.version,
			Kind: components.KindArchive, Group: components.GroupRuntime,
			Roles: []components.Role{components.RoleNode}}
		sum := sha256.Sum256([]byte(spec.body))
		c.Platforms = map[string]components.Artifact{
			"linux/amd64": {URL: "https://example.test/x", SHA256: hex.EncodeToString(sum[:])},
		}
		if err := os.WriteFile(filepath.Join(dist, components.ArtifactName(c, "linux/amd64")),
			[]byte(spec.body), 0o644); err != nil {
			t.Fatal(err)
		}
		archives = append(archives, c)
	}

	images = []components.Component{{
		Name: "vllm", Version: "0.23.0", Kind: components.KindImage,
		Group: components.GroupBackend, Roles: []components.Role{components.RoleNode},
		Platforms: map[string]components.Artifact{
			"linux/amd64": {Image: "vllm/vllm-openai@sha256:" + strings.Repeat("a", 64)},
		},
	}}
	return dist, archives, images
}

// fakeRuntime stands in for nerdctl: `save` writes a file, `load` records that
// it was asked, and `pull` does nothing. The point is the plumbing, not
// containerd.
type fakeRuntime struct {
	calls  []string
	loaded []string
	body   string
	fail   string
}

func (f *fakeRuntime) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if f.fail != "" && args[0] == f.fail {
		return []byte("runtime said no"), fmt.Errorf("exit status 1")
	}
	switch args[0] {
	case "save":
		body := f.body
		if body == "" {
			body = "image layers"
		}
		return nil, os.WriteFile(args[2], []byte(body), 0o644)
	case "load":
		f.loaded = append(f.loaded, args[2])
	}
	return nil, nil
}

// pinned is the manifest an air-gapped binary embeds — the expectation that
// does not travel inside the archive.
func pinned(archives []components.Component) *components.Manifest {
	return &components.Manifest{Schema: components.SchemaVersion,
		NodaryVersion: "0.0.1", Components: archives}
}

func create(t *testing.T, dist string, archives, images []components.Component,
	rt *fakeRuntime) (string, Manifest) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "site.tar")
	var run Runner
	if rt != nil {
		run = rt.run
	}
	m, err := Create(context.Background(), CreateOptions{
		Out: out, Platform: "linux/amd64", Dist: dist,
		Components: archives, Images: images,
		NodaryVersion: "0.0.1", Run: run,
	})
	if err != nil {
		t.Fatalf("creating: %v", err)
	}
	return out, m
}

// The whole deliverable: what a connected machine writes is what an air-gapped
// one gets, laid out so the ordinary install path finds its cache already warm.
func TestABundleRoundTrips(t *testing.T) {
	dist, archives, images := site(t)
	rt := &fakeRuntime{}
	out, made := create(t, dist, archives, images, rt)

	if len(made.Components) != 2 || len(made.Images) != 1 {
		t.Fatalf("manifest = %+v", made)
	}
	// It pulls before it saves: a connected machine building for a site it
	// will never see again must not export a stale local copy of a
	// digest-pinned reference.
	if len(rt.calls) < 2 || !strings.HasPrefix(rt.calls[0], "nerdctl pull") {
		t.Errorf("runtime calls = %v, want a pull before the save", rt.calls)
	}

	// Read without extracting: the question an operator asks about a file
	// somebody handed them.
	head, err := Read(out)
	if err != nil {
		t.Fatal(err)
	}
	if head.Platform != "linux/amd64" || head.Bytes() == 0 {
		t.Errorf("head = %+v", head)
	}

	cache := t.TempDir()
	loader := &fakeRuntime{}
	_, opened, err := Open(context.Background(), out, OpenOptions{
		Dist: cache, Pinned: pinned(archives), Platform: "linux/amd64", Run: loader.run})
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if len(opened) != 3 {
		t.Fatalf("opened %d members, want 3: %+v", len(opened), opened)
	}
	if len(loader.loaded) != 1 {
		t.Errorf("images loaded = %v, want one", loader.loaded)
	}

	// **The layout is the whole trick.** Each artifact lands under exactly the
	// name components.Fetch looks for, so the install that follows re-hashes
	// it against the embedded manifest and reports `cached` — the same check
	// the online path runs, reached by the same code.
	for _, c := range archives {
		name := components.ArtifactName(c, "linux/amd64")
		if _, err := os.Stat(filepath.Join(cache, name)); err != nil {
			t.Errorf("%s is not in the cache under the name fetch looks for: %v", name, err)
		}
	}
	got, err := components.Fetch(context.Background(), archives, components.FetchOptions{
		Dir: cache, Platform: "linux/amd64"})
	if err != nil {
		t.Fatalf("the ordinary fetch path did not accept an opened bundle: %v", err)
	}
	for _, f := range got {
		if f.Placement != components.PlacedCached {
			t.Errorf("%s came back %q, want cached — an offline install would have gone to "+
				"the network", f.Component, f.Placement)
		}
	}
}

// A member that does not match what the bundle says is a transfer that went
// wrong. Caught while it is written, never after it is in place.
func TestATamperedMemberIsRefused(t *testing.T) {
	dist, archives, _ := site(t)
	out, _ := create(t, dist, archives, nil, nil)

	// Rewrite one member's bytes without touching bundle.json.
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	swapped := []byte(strings.Replace(string(body), "runc bytes", "evil bytes", 1))
	if len(swapped) != len(body) {
		t.Fatal("the fixture changed the archive's length, which is not the case under test")
	}
	if err := os.WriteFile(out, swapped, 0o644); err != nil {
		t.Fatal(err)
	}

	cache := t.TempDir()
	_, _, err = Open(context.Background(), out, OpenOptions{
		Dist: cache, Pinned: pinned(archives), Platform: "linux/amd64"})
	if err == nil {
		t.Fatal("a tampered member was extracted")
	}
	if !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("wrong error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(cache, "runc-1.2.3-linux-amd64.tar.gz")); statErr == nil {
		t.Error("the bad member was left in the cache, where the next install would use it")
	}
}

// **The check that only this can make.** A bundle whose members and whose
// bundle.json were edited together is internally consistent — nothing inside
// it disagrees. What catches that is the manifest compiled into the binary
// doing the install, which is the one expectation that did not travel in the
// archive.
func TestAnInternallyConsistentBundleIsStillCheckedAgainstWhatThisBuildPins(t *testing.T) {
	dist, archives, _ := site(t)

	// A bundle built from a cache whose contents are not what the real
	// manifest pins: the sender's own digests agree with their files.
	senders := make([]components.Component, len(archives))
	copy(senders, archives)
	body := "different bytes entirely"
	sum := sha256.Sum256([]byte(body))
	senders[1].Platforms = map[string]components.Artifact{
		"linux/amd64": {URL: "https://example.test/x", SHA256: hex.EncodeToString(sum[:])},
	}
	if err := os.WriteFile(filepath.Join(dist,
		components.ArtifactName(senders[1], "linux/amd64")), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := create(t, dist, senders, nil, nil)

	// Opened by a binary pinning the original digests.
	cache := t.TempDir()
	_, _, err := Open(context.Background(), out, OpenOptions{
		Dist: cache, Pinned: pinned(archives), Platform: "linux/amd64"})
	if err == nil {
		t.Fatal("a bundle that agrees with itself was installed without being checked against " +
			"what this binary pins")
	}
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("wrong error: %v", err)
	}
	if !strings.Contains(err.Error(), "this build pins") {
		t.Errorf("the refusal does not say which side disagrees: %v", err)
	}
}

// A cache somebody changed after `components fetch` verified it must not be
// carried into a bundle that nobody will check again until it is on a machine
// with no network.
func TestCreateRefusesACacheThatDoesNotMatchTheManifest(t *testing.T) {
	dist, archives, _ := site(t)
	if err := os.WriteFile(filepath.Join(dist,
		components.ArtifactName(archives[0], "linux/amd64")), []byte("swapped"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Create(context.Background(), CreateOptions{
		Out: filepath.Join(t.TempDir(), "site.tar"), Platform: "linux/amd64", Dist: dist,
		Components: archives, NodaryVersion: "0.0.1"})
	if err == nil {
		t.Fatal("a cache that does not match the manifest was bundled")
	}
	if !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("wrong error: %v", err)
	}
}

// An interrupted create must leave nothing that looks installable.
func TestAFailedCreateWritesNoBundle(t *testing.T) {
	dist, archives, images := site(t)
	out := filepath.Join(t.TempDir(), "site.tar")
	rt := &fakeRuntime{fail: "save"}
	_, err := Create(context.Background(), CreateOptions{
		Out: out, Platform: "linux/amd64", Dist: dist,
		Components: archives, Images: images, NodaryVersion: "0.0.1", Run: rt.run})
	if err == nil {
		t.Fatal("a failed export produced a bundle")
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("a half-written bundle was left where an operator would ship it")
	}
}

// A file that is not a bundle, and a bundle from another schema, are different
// answers and neither is a crash.
func TestReadRefusesWhatIsNotABundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(path, []byte("this is not a tar"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); !errors.Is(err, ErrNotABundle) {
		t.Errorf("err = %v, want ErrNotABundle", err)
	}
}

// Images are verified whether or not they are loaded, because `--no-images` is
// about what reaches the container runtime and never about what is checked.
func TestImagesAreVerifiedEvenWhenNotLoaded(t *testing.T) {
	dist, archives, images := site(t)
	out, _ := create(t, dist, archives, images, &fakeRuntime{})

	_, opened, err := Open(context.Background(), out, OpenOptions{
		Dist: t.TempDir(), Pinned: pinned(archives), Platform: "linux/amd64", Run: nil})
	if err != nil {
		t.Fatal(err)
	}
	var sawImage bool
	for _, o := range opened {
		if o.Name == "vllm" {
			sawImage = true
			if o.Loaded {
				t.Error("an image was loaded with no runtime to load it")
			}
			if o.SHA256 == "" {
				t.Error("an image went unverified because it was not being loaded")
			}
		}
	}
	if !sawImage {
		t.Error("the image was skipped entirely")
	}
}

// **The bundle's own record is the only check an image gets.** The embedded
// manifest pins archives by SHA-256, so a tampered archive is caught twice
// over — but an image is pinned by a reference the manifest carries for the
// *runtime* to verify on load, and nothing in the component manifest holds the
// digest of an export tarball. Without bundle.json's own record, a corrupted
// multi-gigabyte image would be handed to `nerdctl load` unchecked.
func TestATamperedImageIsRefusedByTheBundlesOwnRecord(t *testing.T) {
	dist, archives, images := site(t)
	rt := &fakeRuntime{body: "image layers aaaa"}
	out, _ := create(t, dist, archives, images, rt)

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	swapped := []byte(strings.Replace(string(body), "image layers aaaa", "image layers bbbb", 1))
	if len(swapped) != len(body) {
		t.Fatal("the fixture changed the archive's length, which is not the case under test")
	}
	if err := os.WriteFile(out, swapped, 0o644); err != nil {
		t.Fatal(err)
	}

	loader := &fakeRuntime{}
	_, _, err = Open(context.Background(), out, OpenOptions{
		Dist: t.TempDir(), Pinned: pinned(archives), Platform: "linux/amd64", Run: loader.run})
	if err == nil {
		t.Fatal("a tampered image export was accepted")
	}
	if !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("wrong error: %v", err)
	}
	if len(loader.loaded) != 0 {
		t.Error("the bad image reached the container runtime before it was checked")
	}
}

// A bundle is written to a temporary file and renamed, so that a create which
// dies partway through leaves nothing an operator would ship.
//
// The failure is induced from inside the tar loop — Progress runs between
// members — because that is the only place it can be: an export that fails
// happens before the archive is opened at all, so the earlier test proves the
// scratch directory is cleaned and not that the output is atomic.
func TestAnInterruptedWriteLeavesNoBundle(t *testing.T) {
	dist, archives, _ := site(t)
	out := filepath.Join(t.TempDir(), "site.tar")

	var n int
	_, err := Create(context.Background(), CreateOptions{
		Out: out, Platform: "linux/amd64", Dist: dist,
		Components: archives, NodaryVersion: "0.0.1",
		Progress: func(string) {
			// Take the second member away after the first has been written, so
			// addFile fails with the archive already open.
			if n++; n == 2 {
				os.Remove(filepath.Join(dist,
					components.ArtifactName(archives[1], "linux/amd64")))
			}
		},
	})
	if err == nil {
		t.Fatal("a member that vanished mid-write produced a bundle")
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("a half-written bundle was left at the output path, where an operator would " +
			"copy it to media and discover it on an air-gapped machine")
	}
}

// A bundle.json that names more than the archive carries is a truncated
// transfer, and the missing member would otherwise be silently absent — an
// install that then reaches the network for it, on a machine with none.
func TestABundleMissingAMemberItNamesIsRefused(t *testing.T) {
	dist, archives, _ := site(t)
	out, made := create(t, dist, archives, nil, nil)
	if len(made.Components) != 2 {
		t.Fatalf("the fixture needs two members, got %d", len(made.Components))
	}

	// Keep the manifest, drop the payload: exactly what a copy cut short does.
	truncated := filepath.Join(t.TempDir(), "truncated.tar")
	if err := keepFirstEntry(out, truncated); err != nil {
		t.Fatal(err)
	}

	_, _, err := Open(context.Background(), truncated, OpenOptions{
		Dist: t.TempDir(), Pinned: pinned(archives), Platform: "linux/amd64"})
	if err == nil {
		t.Fatal("a bundle carrying none of what it names was opened successfully")
	}
	if !errors.Is(err, ErrNotABundle) {
		t.Errorf("wrong error: %v", err)
	}
}

// keepFirstEntry rewrites a tar with only its first member, which for a bundle
// is bundle.json.
func keepFirstEntry(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	tr := tar.NewReader(in)
	tw := tar.NewWriter(out)
	h, err := tr.Next()
	if err != nil {
		return err
	}
	body, err := io.ReadAll(tr)
	if err != nil {
		return err
	}
	h.Size = int64(len(body))
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	if _, err := tw.Write(body); err != nil {
		return err
	}
	return tw.Close()
}
