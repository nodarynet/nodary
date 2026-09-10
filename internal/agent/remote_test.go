package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// remoteFixture serves the given files under /acme/tiny/resolve/main/<name>,
// the same URL shape stage-model.sh and the real HuggingFace API use, and
// returns their manifest — sha256sum format, matching ParseManifest and what
// an operator would actually hand to `model register --manifest`.
func remoteFixture(t *testing.T, files map[string]string) (*httptest.Server, string) {
	t.Helper()
	var manifest strings.Builder
	mux := http.NewServeMux()
	for name, body := range files {
		body := body
		mux.HandleFunc("/acme/tiny/resolve/main/"+name, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			if r.Method == http.MethodHead {
				return
			}
			w.Write([]byte(body))
		})
		sum := sha256.Sum256([]byte(body))
		manifest.WriteString(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	}
	return httptest.NewServer(mux), manifest.String()
}

func waitFor(t *testing.T, dl *Downloader, dir, manifest, digest string, want string) Stage {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := dl.Status("acme/tiny", manifest, digest, dir)
		if st.State == want || time.Now().After(deadline) {
			return st
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDownloaderStagesAFreshModel(t *testing.T) {
	srv, manifest := remoteFixture(t, map[string]string{
		"config.json":       `{"model_type":"tiny"}`,
		"model.safetensors": "weights, allegedly",
	})
	defer srv.Close()
	digest := sha256.Sum256([]byte(manifest))

	root := t.TempDir()
	dir, err := ModelDir(root, "hf-cache", "acme/tiny")
	if err != nil {
		t.Fatal(err)
	}
	dl := &Downloader{BaseURL: srv.URL, Client: srv.Client(), byModel: map[string]*download{}}

	st := waitFor(t, dl, dir, manifest, hex.EncodeToString(digest[:]), StateStaged)
	if st.State != StateStaged {
		t.Fatalf("state = %s (%s), want staged", st.State, st.Reason)
	}
	if st.Bytes != st.Total || st.Bytes == 0 {
		t.Errorf("bytes = %d, total = %d, want them equal and non-zero once staged", st.Bytes, st.Total)
	}

	// Placed exactly where source: local would have found it, manifest
	// included — VerifyStaged is what confirms that, not a hand-rolled check.
	v := VerifyStaged(root, "hf-cache", "acme/tiny", hex.EncodeToString(digest[:]))
	if v.State != StateStaged {
		t.Errorf("VerifyStaged on the result = %s (%s), want staged", v.State, v.Reason)
	}
	if _, err := os.Stat(dir + ".downloading"); !os.IsNotExist(err) {
		t.Errorf("the temp directory was left behind: %v", err)
	}
}

func TestDownloaderDoesNotStartASecondDownloadForTheSameModel(t *testing.T) {
	var hits int
	mux := http.NewServeMux()
	mux.HandleFunc("/acme/tiny/resolve/main/config.json", func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Length", "2")
		if r.Method != http.MethodHead {
			// Slow enough that a second Status call lands while this is
			// still the only goroutine running.
			time.Sleep(100 * time.Millisecond)
			w.Write([]byte("{}"))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sum := sha256.Sum256([]byte("{}"))
	manifest := hex.EncodeToString(sum[:]) + "  config.json\n"
	digest := sha256.Sum256([]byte(manifest))

	root := t.TempDir()
	dir, _ := ModelDir(root, "hf-cache", "acme/tiny")
	dl := &Downloader{BaseURL: srv.URL, Client: srv.Client(), byModel: map[string]*download{}}

	dl.Status("acme/tiny", manifest, hex.EncodeToString(digest[:]), dir)
	dl.Status("acme/tiny", manifest, hex.EncodeToString(digest[:]), dir)
	waitFor(t, dl, dir, manifest, hex.EncodeToString(digest[:]), StateStaged)

	// One HEAD and one GET for the one file — two hits. A third would mean a
	// second goroutine started for the same model.
	if hits != 2 {
		t.Errorf("the server saw %d requests for one file, want exactly 2 (HEAD + GET)", hits)
	}
}

func TestDownloaderResumesAFileAlreadyCorrectOnDisk(t *testing.T) {
	const body = "weights, allegedly"
	sum := sha256.Sum256([]byte(body))
	manifest := hex.EncodeToString(sum[:]) + "  model.safetensors\n"
	digest := sha256.Sum256([]byte(manifest))

	root := t.TempDir()
	dir, _ := ModelDir(root, "hf-cache", "acme/tiny")
	tmp := dir + ".downloading"
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "model.safetensors"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/acme/tiny/resolve/main/model.safetensors", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			return
		}
		t.Error("a file already correct on disk was re-downloaded")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dl := &Downloader{BaseURL: srv.URL, Client: srv.Client(), byModel: map[string]*download{}}
	st := waitFor(t, dl, dir, manifest, hex.EncodeToString(digest[:]), StateStaged)
	if st.State != StateStaged {
		t.Fatalf("state = %s (%s), want staged", st.State, st.Reason)
	}
}

func TestDownloaderCatchesAWrongHash(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/acme/tiny/resolve/main/config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		if r.Method != http.MethodHead {
			w.Write([]byte("{}"))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// A manifest naming a digest the served content will not actually match.
	manifest := strings.Repeat("a", 64) + "  config.json\n"
	digest := sha256.Sum256([]byte(manifest))

	root := t.TempDir()
	dir, _ := ModelDir(root, "hf-cache", "acme/tiny")
	dl := &Downloader{BaseURL: srv.URL, Client: srv.Client(), byModel: map[string]*download{}}

	st := waitFor(t, dl, dir, manifest, hex.EncodeToString(digest[:]), StateCorrupt)
	if st.State != StateCorrupt {
		t.Fatalf("state = %s, want corrupt", st.State)
	}
	if st.Reason == "" {
		t.Error("corrupt with no reason: a terminal state that does not say what went wrong " +
			"is how it becomes a permanent mystery")
	}
}

func TestDownloaderCatchesATamperedManifest(t *testing.T) {
	dl := &Downloader{BaseURL: "http://unused.invalid", Client: http.DefaultClient, byModel: map[string]*download{}}
	manifest := strings.Repeat("a", 64) + "  config.json\n"
	// A digest that does not match the manifest body at all.
	st := waitFor(t, dl, t.TempDir(), manifest, strings.Repeat("0", 64), StateCorrupt)
	if st.State != StateCorrupt {
		t.Fatalf("state = %s, want corrupt", st.State)
	}
	if !strings.Contains(st.Reason, "hashes to") {
		t.Errorf("reason = %q, want it to name the mismatch", st.Reason)
	}
}

// R4-37: while a download is running, Status reports bytes done against a
// total known up front — not just "0" until it suddenly finishes. Both files'
// sizes come from HEAD requests that happen before any GET, so Total is known
// the instant staging starts; this blocks the second file's GET so the test
// can observe the point after the first file lands and before the second
// does, where done is nonzero and still short of total.
func TestDownloaderReportsBytesAgainstTotalWhileInProgress(t *testing.T) {
	const small = `{"model_type":"tiny"}`
	const big = "a large-enough second file to make a second GET request"
	unblock := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/acme/tiny/resolve/main/config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(small)))
		if r.Method != http.MethodHead {
			w.Write([]byte(small))
		}
	})
	mux.HandleFunc("/acme/tiny/resolve/main/model.safetensors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(big)))
		if r.Method != http.MethodHead {
			<-unblock
			w.Write([]byte(big))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sum1 := sha256.Sum256([]byte(small))
	sum2 := sha256.Sum256([]byte(big))
	// Manifest text, not remoteFixture: file order has to be config.json
	// first so the first file to land is the one this test can predict.
	manifest := hex.EncodeToString(sum1[:]) + "  config.json\n" +
		hex.EncodeToString(sum2[:]) + "  model.safetensors\n"
	digest := sha256.Sum256([]byte(manifest))
	sum := hex.EncodeToString(digest[:])

	root := t.TempDir()
	dir, _ := ModelDir(root, "hf-cache", "acme/tiny")
	dl := &Downloader{BaseURL: srv.URL, Client: srv.Client(), byModel: map[string]*download{}}

	deadline := time.Now().Add(5 * time.Second)
	var st Stage
	for {
		st = dl.Status("acme/tiny", manifest, sum, dir)
		if st.Bytes == int64(len(small)) || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(unblock)

	if st.Total != int64(len(small)+len(big)) {
		t.Errorf("total = %d, want %d: both files' sizes are known before either downloads",
			st.Total, len(small)+len(big))
	}
	if st.Bytes != int64(len(small)) {
		t.Fatalf("bytes = %d, want %d: only the first file had landed", st.Bytes, len(small))
	}
	if st.Bytes == st.Total {
		t.Fatal("bytes == total while the second file was still blocked; this test proves nothing mid-flight")
	}

	final := waitFor(t, dl, dir, manifest, sum, StateStaged)
	if final.State != StateStaged {
		t.Fatalf("state = %s (%s), want staged", final.State, final.Reason)
	}
}

func TestDownloaderResetClearsCacheAndRetries(t *testing.T) {
	srv, manifest := remoteFixture(t, map[string]string{"config.json": `{"model_type":"tiny"}`})
	defer srv.Close()
	digest := sha256.Sum256([]byte(manifest))
	sum := hex.EncodeToString(digest[:])

	root := t.TempDir()
	dir, _ := ModelDir(root, "hf-cache", "acme/tiny")
	dl := &Downloader{BaseURL: srv.URL, Client: srv.Client(), byModel: map[string]*download{}}

	st := waitFor(t, dl, dir, manifest, sum, StateStaged)
	if st.State != StateStaged {
		t.Fatalf("state = %s (%s), want staged", st.State, st.Reason)
	}

	// Deleted out from under a "staged" cache entry: without Reset, Status
	// would keep replaying the stale entry forever — the bug this exists to
	// fix.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if ok := dl.Reset("acme/tiny", dir); !ok {
		t.Fatal("Reset reported failure")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("Reset left something behind at %s", dir)
	}

	st = waitFor(t, dl, dir, manifest, sum, StateStaged)
	if st.State != StateStaged {
		t.Fatalf("after Reset, state = %s (%s), want staged again", st.State, st.Reason)
	}
}
