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

// runStaging runs one download to completion the way the transient unit does
// — synchronously, as the whole of a process (R4-30) — and returns the verdict
// it recorded. The orchestration around it, which is what the agent half does,
// is tested in stageunit_test.go.
func runStaging(t *testing.T, baseURL, dir, manifest, digest string) Stage {
	t.Helper()
	path := requestPath(dir)
	if err := writeStageRequest(path, stageRequest{Model: "acme/tiny", Dir: dir,
		BaseURL: baseURL, ManifestBody: manifest, ManifestSHA256: digest}); err != nil {
		t.Fatal(err)
	}
	st, err := RunStaging(path)
	if err != nil {
		t.Fatal(err)
	}
	// Whatever the child returns it has also written down, because the file is
	// the only thing the agent half ever reads.
	onDisk, ok := readProgress(progressPath(dir))
	if !ok {
		t.Fatalf("the staging unit finished %s and recorded nothing", st.State)
	}
	if onDisk.State != st.State || onDisk.Bytes != st.Bytes || onDisk.Reason != st.Reason {
		t.Errorf("recorded %+v but returned %+v", onDisk, st)
	}
	return st
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
	st := runStaging(t, srv.URL, dir, manifest, hex.EncodeToString(digest[:]))
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

	st := runStaging(t, srv.URL, dir, manifest, hex.EncodeToString(digest[:]))
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
	st := runStaging(t, srv.URL, dir, manifest, hex.EncodeToString(digest[:]))
	if st.State != StateCorrupt {
		t.Fatalf("state = %s, want corrupt", st.State)
	}
	if st.Reason == "" {
		t.Error("corrupt with no reason: a terminal state that does not say what went wrong " +
			"is how it becomes a permanent mystery")
	}
}

func TestDownloaderCatchesATamperedManifest(t *testing.T) {
	manifest := strings.Repeat("a", 64) + "  config.json\n"
	// A digest that does not match the manifest body at all.
	st := runStaging(t, "http://unused.invalid",
		filepath.Join(t.TempDir(), "models--acme--tiny"), manifest, strings.Repeat("0", 64))
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
	if err := writeStageRequest(requestPath(dir), stageRequest{Model: "acme/tiny", Dir: dir,
		BaseURL: srv.URL, ManifestBody: manifest, ManifestSHA256: sum}); err != nil {
		t.Fatal(err)
	}

	// The unit's own process, run here as a goroutine: observed through the
	// file, which is the only channel the agent half has either.
	done := make(chan Stage, 1)
	go func() {
		st, err := RunStaging(requestPath(dir))
		if err != nil {
			t.Error(err)
		}
		done <- st
	}()

	deadline := time.Now().Add(5 * time.Second)
	var st Stage
	for {
		st, _ = readProgress(progressPath(dir))
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

	if final := <-done; final.State != StateStaged {
		t.Fatalf("state = %s (%s), want staged", final.State, final.Reason)
	}
}

// Weights deleted out from under a `staged` verdict: without Reset, Status
// would replay the stale verdict forever — the bug this exists to fix, and
// one the move to a file on disk makes longer-lived rather than shorter, since
// restarting the agent no longer clears it either.
func TestDownloaderResetClearsTheVerdictAndRetries(t *testing.T) {
	srv, manifest := remoteFixture(t, map[string]string{"config.json": `{"model_type":"tiny"}`})
	defer srv.Close()
	digest := sha256.Sum256([]byte(manifest))
	sum := hex.EncodeToString(digest[:])

	root := t.TempDir()
	dir, _ := ModelDir(root, "hf-cache", "acme/tiny")

	if st := runStaging(t, srv.URL, dir, manifest, sum); st.State != StateStaged {
		t.Fatalf("state = %s (%s), want staged", st.State, st.Reason)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	dl, _ := stagingDownloader(t)
	if st := dl.Status("acme/tiny", manifest, sum, dir); st.State != StateStaged {
		t.Fatalf("state = %s, want the stale staged verdict — otherwise this test proves nothing", st.State)
	}
	if ok := dl.Reset("acme/tiny", dir); !ok {
		t.Fatal("Reset reported failure")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("Reset left something behind at %s", dir)
	}

	if st := runStaging(t, srv.URL, dir, manifest, sum); st.State != StateStaged {
		t.Fatalf("after Reset, state = %s (%s), want staged again", st.State, st.Reason)
	}
}
