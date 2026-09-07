package components

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// serveArtifact stands in for an upstream release, so the fetch logic is tested
// without the network. The real artifacts are exercised separately, gated on
// -short, because they are tens of megabytes.
func serveArtifact(t *testing.T, body []byte) (*httptest.Server, string) {
	t.Helper()
	sum := sha256.Sum256(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, hex.EncodeToString(sum[:])
}

func component(url, sum string) Component {
	return Component{
		Name: "testcomp", Version: "1.0.0", Kind: KindBinary,
		Roles: []Role{RoleNode}, Group: GroupRuntime,
		Platforms: map[string]Artifact{"linux/amd64": {URL: url, SHA256: sum}},
	}
}

func TestFetchVerifiesBeforeItPlaces(t *testing.T) {
	srv, sum := serveArtifact(t, []byte("a pinned artifact"))
	dir := t.TempDir()

	got, err := Fetch(context.Background(), []Component{component(srv.URL, sum)},
		FetchOptions{Dir: dir, Platform: "linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Placement != PlacedFetched {
		t.Fatalf("fetched = %+v", got)
	}
	if _, err := os.Stat(got[0].Path); err != nil {
		t.Errorf("the artifact was not placed: %v", err)
	}

	// A second run skips by digest and makes no request.
	var served int
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		_, _ = w.Write([]byte("a pinned artifact"))
	})
	again, err := Fetch(context.Background(), []Component{component(srv.URL, sum)},
		FetchOptions{Dir: dir, Platform: "linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Placement != PlacedCached {
		t.Errorf("placement = %q, want cached", again[0].Placement)
	}
	if served != 0 {
		t.Errorf("the second run downloaded %d times, want 0", served)
	}
}

// docs/specs/01-install.md §2 makes verification unskippable for the binary,
// and a component arrives over the same kind of channel.
func TestFetchRefusesAnArtifactThatDoesNotMatchItsDigest(t *testing.T) {
	srv, _ := serveArtifact(t, []byte("not what the manifest pins"))
	dir := t.TempDir()
	pinned := strings.Repeat("a", 64)

	_, err := Fetch(context.Background(), []Component{component(srv.URL, pinned)},
		FetchOptions{Dir: dir, Platform: "linux/amd64"})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("error = %v, want ErrDigestMismatch", err)
	}

	// And nothing was left behind. A verified-after-placement design would have
	// left the wrong bytes at the destination.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			t.Errorf("a refused artifact was left at %s", e.Name())
		}
	}
}

// Re-running an install re-verifies rather than re-downloads, so something that
// replaced a cached artifact is caught on the next run instead of trusted
// because the file exists.
func TestATamperedCacheIsRefusedRatherThanReplaced(t *testing.T) {
	srv, sum := serveArtifact(t, []byte("a pinned artifact"))
	dir := t.TempDir()
	c := component(srv.URL, sum)

	got, err := Fetch(context.Background(), []Component{c}, FetchOptions{Dir: dir, Platform: "linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(got[0].Path, []byte("something else entirely"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = Fetch(context.Background(), []Component{c}, FetchOptions{Dir: dir, Platform: "linux/amd64"})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("error = %v, want ErrDigestMismatch", err)
	}
	// Refused, not silently repaired: overwriting would erase the only evidence
	// that something put a different file where nodary keeps a pinned one.
	body, err := os.ReadFile(got[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "something else entirely" {
		t.Error("the tampered file was overwritten, erasing the evidence")
	}
}

// A node fetches from its control plane and contacts nothing else:
// docs/specs/01-install.md §3.
func TestABaseURLPointsAFetchAtTheMirror(t *testing.T) {
	body := []byte("served by the control plane")
	sum := sha256.Sum256(body)

	var asked string
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		_, _ = w.Write(body)
	}))
	defer mirror.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the node contacted upstream; 01 §3 says only the control plane does")
	}))
	defer upstream.Close()

	c := component(upstream.URL+"/containerd.tar.gz", hex.EncodeToString(sum[:]))
	got, err := Fetch(context.Background(), []Component{c},
		FetchOptions{Dir: t.TempDir(), Platform: "linux/amd64", BaseURL: mirror.URL})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Placement != PlacedFetched {
		t.Errorf("placement = %q", got[0].Placement)
	}
	// The mirror is asked by the cache's own name, not upstream's filename: two
	// upstreams name their files differently, and a cache serving both under
	// their own names is one nobody can reason about.
	if asked != "/testcomp-1.0.0-linux-amd64" {
		t.Errorf("the mirror was asked for %q", asked)
	}
}

// R5-11: ownership is recorded, never inferred.
func TestOwnershipDistinguishesPlacedFromFound(t *testing.T) {
	path := filepath.Join(t.TempDir(), OwnershipFile)

	if err := Record(path, "0.0.1",
		Owned{Component: "containerd", Version: "2.3.4",
			Path: "/usr/local/bin/containerd", Placed: true},
		// Found already present, and acceptable. A host may have containerd
		// installed by its operator and in use by something else.
		Owned{Component: "runc", Version: "1.4.0",
			Path: "/usr/local/sbin/runc", Placed: false},
	); err != nil {
		t.Fatal(err)
	}

	got, err := LoadOwnership(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Components) != 2 {
		t.Fatalf("components = %+v", got.Components)
	}
	rm := got.Removable()
	if len(rm) != 1 || rm[0].Component != "containerd" {
		t.Errorf("removable = %+v, want only what nodary placed — removing what it "+
			"found would take down whatever else was using it", rm)
	}

	// Recording the same path again replaces rather than duplicates, so an
	// install that is re-run does not grow the record.
	if err := Record(path, "0.0.1", Owned{Component: "runc", Version: "1.4.1",
		Path: "/usr/local/sbin/runc", Placed: true}); err != nil {
		t.Fatal(err)
	}
	got, _ = LoadOwnership(path)
	if len(got.Components) != 2 {
		t.Errorf("re-recording a path duplicated it: %+v", got.Components)
	}
	if len(got.Removable()) != 2 {
		t.Error("the updated entry did not take")
	}
}

// A missing record is an empty one: nothing has been installed yet, which is
// not an error.
func TestAnAbsentOwnershipRecordIsEmpty(t *testing.T) {
	got, err := LoadOwnership(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("a missing record errored: %v", err)
	}
	if len(got.Components) != 0 {
		t.Errorf("components = %+v", got.Components)
	}
}

// --- extraction ---------------------------------------------------------------

// tarGz builds an archive from name→content, with an optional escaping entry.
func tarGz(t *testing.T, files map[string]string, mode int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "a.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractPlacesRegularFilesAndSetsTheirMode(t *testing.T) {
	archive := tarGz(t, map[string]string{
		"bin/containerd": "#!/bin/true", "LICENSE": "text",
	}, 0o755)
	dir := t.TempDir()

	got, err := Extract(archive, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("extracted %+v", got)
	}
	info, err := os.Stat(filepath.Join(dir, "bin", "containerd"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %o, want 0755", info.Mode().Perm())
	}
}

// A digest pins *which* archive, not what a future release of it contains, so
// every entry is still checked.
func TestExtractRefusesAnEntryThatEscapesItsDirectory(t *testing.T) {
	archive := tarGz(t, map[string]string{"../../escaped": "x"}, 0o644)
	dir := filepath.Join(t.TempDir(), "into")

	if _, err := Extract(archive, dir); err == nil {
		t.Fatal("an escaping entry was extracted")
	} else if !strings.Contains(err.Error(), "outside") {
		t.Errorf("error = %v, want it to name the escape", err)
	}
}

// The mode bits are attacker-controlled in the general case, and nothing nodary
// installs needs setuid.
func TestExtractDropsSetuid(t *testing.T) {
	archive := tarGz(t, map[string]string{"bin/tool": "x"}, 0o4755)
	dir := t.TempDir()

	if _, err := Extract(archive, dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "bin", "tool"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetuid != 0 {
		t.Errorf("mode = %v, setuid survived extraction", info.Mode())
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %o, want 0755", info.Mode().Perm())
	}
}
