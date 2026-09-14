package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
)

var errNotFound = errors.New("exit status 1")

const localRef = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// imageHost is a runtime that reports an image present only after it has been
// loaded, which is the sequence the fetch depends on.
type imageHost struct {
	loaded  map[string]bool
	calls   []string
	loadErr bool
	// leaves is what a `load` puts in the store; empty means it loads
	// something other than what was asked for.
	leaves string
}

func (i *imageHost) run(_ context.Context, name string, args ...string) ([]byte, error) {
	i.calls = append(i.calls, name+" "+strings.Join(args, " "))
	switch {
	case len(args) > 1 && args[0] == "image" && args[1] == "inspect":
		if i.loaded[args[2]] {
			return nil, nil
		}
		return []byte("no such object"), errNotFound
	case args[0] == "load":
		if i.loadErr {
			return []byte("unexpected EOF"), errNotFound
		}
		if i.leaves != "" {
			i.loaded[i.leaves] = true
		}
		return nil, nil
	}
	return nil, nil
}

func imageDaemon(t *testing.T, srv *httptest.Server, h *imageHost) *Daemon {
	t.Helper()
	d := &Daemon{
		Config: Config{Server: srv.URL, ModelsDir: t.TempDir()},
		Host:   Host{Run: h.run},
	}
	d.client.Store(srv.Client())
	return d
}

// The property R6-15 exists for: an image that is only in the control plane's
// store reaches the node that has to run it.
func TestTheNodeFetchesAnImageOnlyTheControlPlaneHas(t *testing.T) {
	var served atomic.Int32
	want := api.Prefix + "/agent/dist/" + api.DerivedImageFile(localRef)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != want {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		served.Add(1)
		w.Write([]byte("a tar"))
	}))
	defer srv.Close()

	h := &imageHost{loaded: map[string]bool{}, leaves: localRef}
	d := imageDaemon(t, srv, h)

	if err := d.ensureImage(context.Background(), localRef); err != nil {
		t.Fatalf("fetching an image the mirror holds: %v", err)
	}
	if served.Load() != 1 {
		t.Errorf("the mirror was asked %d times, want 1", served.Load())
	}

	// And not again: the second reconcile finds it in the store, so a node
	// does not re-download gigabytes every sixty seconds.
	if err := d.ensureImage(context.Background(), localRef); err != nil {
		t.Fatal(err)
	}
	if served.Load() != 1 {
		t.Errorf("the mirror was asked %d times; an image already loaded was fetched again",
			served.Load())
	}

	// Nothing is left behind in the models directory: the tar is tens of
	// gigabytes and the disk it lands on is the one holding the weights.
	entries, err := os.ReadDir(d.Config.ModelsDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".nodary-image-") {
			t.Errorf("the download was left in %s", filepath.Join(d.Config.ModelsDir, e.Name()))
		}
	}
}

// Every other image nodary runs is a digest-pinned registry reference the
// runtime fetches for itself. Diverting those through the mirror would put a
// hop, and a failure mode, in front of every deployment to no purpose.
func TestAnOrdinaryImageIsNotFetchedFromTheMirror(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the mirror was asked for %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	h := &imageHost{loaded: map[string]bool{}}
	d := imageDaemon(t, srv, h)
	for _, ref := range []string{
		"vllm/vllm-openai@sha256:" + strings.Repeat("a", 64),
		"registry.internal/nodary/vllm-fips@sha256:" + strings.Repeat("b", 64),
		"docker.io/library/redis:7",
	} {
		if err := d.ensureImage(context.Background(), ref); err != nil {
			t.Errorf("%s: %v", ref, err)
		}
	}
	if len(h.calls) != 0 {
		t.Errorf("the runtime was consulted about a registry reference: %v", h.calls)
	}
}

// `load` reports success for a tar it managed to read. What has to be true is
// that the digest the deployment pins is now in the store — a mirror serving
// the wrong file would otherwise surface as `nerdctl run` failing much later,
// with nothing pointing back here.
func TestALoadThatLeavesTheWrongImageIsAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("a tar of something else"))
	}))
	defer srv.Close()

	h := &imageHost{loaded: map[string]bool{}, leaves: "sha256:" + strings.Repeat("9", 64)}
	d := imageDaemon(t, srv, h)
	err := d.ensureImage(context.Background(), localRef)
	if err == nil {
		t.Fatal("a load that left the wrong image was accepted")
	}
	if !strings.Contains(err.Error(), localRef) {
		t.Errorf("the failure does not name what was missing: %v", err)
	}
}

// A mirror that has not got it is the case an operator has to be able to read:
// it means the build never exported, not that the network is down.
func TestAMirrorThatHasNotGotItSaysSo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	d := imageDaemon(t, srv, &imageHost{loaded: map[string]bool{}})
	err := d.ensureImage(context.Background(), localRef)
	if err == nil {
		t.Fatal("a 404 from the mirror was not an error")
	}
	if !strings.Contains(err.Error(), "backend build") {
		t.Errorf("the failure does not say what would put it there: %v", err)
	}
}

func (i *imageHost) saw(substr string) bool {
	for _, c := range i.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}
