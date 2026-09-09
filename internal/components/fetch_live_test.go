package components

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// The pinned runtime, fetched and extracted for real.
//
// `components verify` already checks that every URL resolves. This checks the
// thing that actually breaks an install: that the bytes at those URLs hash to
// what the manifest pins, and that the archives contain the binaries the unit
// template and the CNI configuration name. A digest that drifted, or an
// upstream that reorganized its tarball, is an install that fails on a GPU host
// rather than in a pipeline.
//
// Skipped under -short, because it is tens of megabytes over the network.
func TestTheRealRuntimeComponentsFetchAndContainWhatWeExpect(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	// The four the node needs to run a deployment at all. The NVIDIA container
	// toolkit is a distro package rather than a pinned archive, and the images
	// are pulled by the runtime — neither is fetched here.
	want := map[string][]string{
		"containerd":  {"bin/containerd", "bin/containerd-shim-runc-v2"},
		"nerdctl":     {"nerdctl"},
		"cni-plugins": {"bridge", "portmap", "host-local"},
		"runc":        nil, // a bare binary, not an archive
	}

	var comps []Component
	for _, c := range m.ForPlatform("linux/amd64") {
		if _, ok := want[c.Name]; ok {
			comps = append(comps, c)
		}
	}
	if len(comps) != len(want) {
		t.Fatalf("found %d of the %d runtime components in the manifest", len(comps), len(want))
	}

	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	got, err := Fetch(ctx, comps, FetchOptions{Dir: dir, Platform: "linux/amd64"})
	if err != nil {
		// A network failure is a skip; a digest mismatch is not.
		if isDigestMismatch(err) {
			t.Fatalf("a pinned artifact no longer matches its digest: %v", err)
		}
		t.Skipf("cannot reach the component sources: %v", err)
	}
	if len(got) != len(comps) {
		t.Fatalf("fetched %d of %d", len(got), len(comps))
	}

	for _, f := range got {
		if f.Bytes == 0 {
			t.Errorf("%s fetched zero bytes", f.Component)
		}
		members, ok := want[f.Component]
		if !ok || members == nil {
			// runc: a bare binary. It only has to be there and be non-empty.
			continue
		}
		out := filepath.Join(dir, "x", f.Component)
		extracted, err := Extract(f.Path, out)
		if err != nil {
			t.Errorf("extracting %s: %v", f.Component, err)
			continue
		}
		have := map[string]bool{}
		for _, e := range extracted {
			have[filepath.Base(e.Path)] = true
			have[e.Name] = true
		}
		for _, member := range members {
			if !have[member] && !have[filepath.Base(member)] {
				t.Errorf("%s's archive has no %s. The unit template and the CNI "+
					"configuration name it, so an install would place nothing and a "+
					"deployment would fail at start.", f.Component, member)
			}
		}
	}

	// And the second run is free, which is what makes the install step
	// idempotent in the sense docs/specs/01-install.md §4 means.
	again, err := Fetch(ctx, comps, FetchOptions{Dir: dir, Platform: "linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range again {
		if f.Placement != PlacedCached {
			t.Errorf("%s was re-downloaded on the second run", f.Component)
		}
	}
}

func isDigestMismatch(err error) bool { return errors.Is(err, ErrDigestMismatch) }
