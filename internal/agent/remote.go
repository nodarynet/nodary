package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

// Downloader runs `source: remote` staging (R4-33, docs/specs/05-catalog.md
// §3): the agent fetches a model's own weights and verifies each file
// against a manifest the control plane holds — remote has no
// weights-travel-on-removable-media channel the way local does, so there is
// nothing beside the (not yet downloaded) weights to find one in.
//
// One Downloader lives as long as the agent process does, held by Daemon.
// Build runs roughly once a minute and remembers nothing between calls —
// exactly right for VerifyStaged, which re-reads local bytes synchronously
// every time, and wrong for something that can take hours. So the download
// itself runs in a goroutine independent of the reconcile loop; Status is the
// only thing Build calls, and it only ever reports whatever progress exists
// right now, never blocking past a map lookup.
type Downloader struct {
	// BaseURL is HuggingFace's resolve host, a field rather than a literal so
	// a test can point it at an httptest.Server instead of the real network.
	BaseURL string
	// Client is a plain HTTP client — not the mTLS one the agent uses to talk
	// to the control plane, a different trust boundary entirely.
	Client *http.Client
	// Token is HF_TOKEN, read once from the agent process's own environment.
	// One node-wide credential for gated repositories, not a per-model one —
	// a real limitation of this first version, not a hidden one.
	Token string

	mu      sync.Mutex
	byModel map[string]*download
}

// download is one model's progress: written only by the goroutine run
// started for it, read by however many Status calls land while it runs.
type download struct {
	mu     sync.Mutex
	state  string
	bytes  int64
	total  int64
	reason string
}

func (d *download) set(state string, bytes, total int64, reason string) {
	d.mu.Lock()
	d.state, d.bytes, d.total, d.reason = state, bytes, total, reason
	d.mu.Unlock()
}

func (d *download) snapshot() (state string, bytes, total int64, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state, d.bytes, d.total, d.reason
}

// NewDownloader is the production Downloader: HuggingFace, a real client, and
// HF_TOKEN from this process's own environment if the operator set one.
func NewDownloader() *Downloader {
	return &Downloader{
		BaseURL: "https://huggingface.co",
		Client:  &http.Client{}, // no Timeout: a multi-gigabyte transfer has no fixed deadline
		Token:   os.Getenv("HF_TOKEN"),
		byModel: map[string]*download{},
	}
}

// Status starts a download the first time it sees a model needing one, and
// every call after that only reads whatever the running goroutine has
// gotten to. Called from Build every reconcile cycle; never blocks beyond
// the map lookup.
func (dl *Downloader) Status(modelID, manifestBody, manifestSHA256, dir string) Stage {
	dl.mu.Lock()
	d, ok := dl.byModel[modelID]
	if !ok {
		d = &download{state: StateStaging}
		dl.byModel[modelID] = d
		go dl.run(modelID, manifestBody, manifestSHA256, dir, d)
	}
	dl.mu.Unlock()

	state, bytes, total, reason := d.snapshot()
	return Stage{Model: modelID, State: state, Bytes: bytes, Total: total, Reason: reason}
}

// run downloads and verifies one model, start to finish. It owns d for its
// entire lifetime; Status only ever reads it.
func (dl *Downloader) run(modelID, manifestBody, manifestSHA256, finalDir string, d *download) {
	// The manifest is checked before it is trusted, the same reason
	// VerifyStaged checks a local one: a manifest that does not hash to what
	// the control plane recorded could have been swapped in transit between
	// whoever computed it and `model register`, and every file would then
	// verify against a manifest for the wrong weights.
	if got := hexSHA256([]byte(manifestBody)); manifestSHA256 != "" && got != manifestSHA256 {
		d.set(StateCorrupt, 0, 0, fmt.Sprintf("%s hashes to %s, and the catalog pins %s",
			ManifestName, short(got), short(manifestSHA256)))
		return
	}
	entries, err := ParseManifest([]byte(manifestBody))
	if err != nil {
		d.set(StateCorrupt, 0, 0, err.Error())
		return
	}
	if len(entries) == 0 {
		d.set(StateCorrupt, 0, 0, ManifestName+" lists no files")
		return
	}

	// A sibling of the final directory, not a subdirectory of it — so a
	// half-finished attempt is never mistaken for a staged one by anything
	// that only looks at whether finalDir exists.
	tmp := finalDir + ".downloading"
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		d.set(StateCorrupt, 0, 0, err.Error())
		return
	}
	resolve := dl.BaseURL + "/" + modelID + "/resolve/main/"

	// The total, from HEAD requests before anything downloads — not trusted
	// from the control plane (nothing here was asked to supply one at
	// registration), and 05 §3 asks for "bytes completed against total".
	var total int64
	for _, e := range entries {
		n, err := dl.contentLength(resolve + e.Path)
		if err != nil {
			d.set(StateCorrupt, 0, 0, fmt.Sprintf("checking %s: %v", e.Path, err))
			return
		}
		total += n
	}
	d.set(StateStaging, 0, total, "")

	var done int64
	for _, e := range entries {
		path := filepath.Join(tmp, e.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			d.set(StateCorrupt, done, total, err.Error())
			return
		}
		// Resumable across agent restarts: a fresh process has no memory of
		// what a killed one did, but a file already on disk that already
		// hashes correctly needs nothing more done to it — the same check
		// VerifyStaged makes, just per-file instead of for the whole model.
		// Anything else (missing, partial, wrong) is fetched whole; this is
		// file-granularity resume, not a mid-file Range request.
		if n, ok := matchingSize(path, e.SHA256); ok {
			done += n
			d.set(StateStaging, done, total, "")
			continue
		}
		n, err := dl.fetch(resolve+e.Path, path)
		if err != nil {
			d.set(StateCorrupt, done, total, fmt.Sprintf("downloading %s: %v", e.Path, err))
			return
		}
		if got, err := fileSHA256(path); err != nil || got != e.SHA256 {
			d.set(StateCorrupt, done, total, fmt.Sprintf("%s does not match the manifest", e.Path))
			return
		}
		done += n
		d.set(StateStaging, done, total, "")
	}

	d.set(StateVerifying, done, total, "")
	// The manifest travels with the weights here too, so a later restage —
	// this node re-verifying, or VerifyStaged asked about the same directory
	// some other way — finds the same file source: local already knows how
	// to read, and this model becomes indistinguishable on disk from one an
	// operator placed by hand.
	if err := os.WriteFile(filepath.Join(tmp, ManifestName), []byte(manifestBody), 0o644); err != nil {
		d.set(StateCorrupt, done, total, err.Error())
		return
	}
	if err := os.Rename(tmp, finalDir); err != nil {
		d.set(StateCorrupt, done, total, fmt.Sprintf("placing the staged weights: %v", err))
		return
	}
	d.set(StateStaged, done, done, "")
}

// Reset discards whatever this Downloader has for modelID — cached progress
// and anything on disk — so the next Status call starts clean.
//
// **Status never revisits a model on its own once it reaches a terminal
// state.** The map entry set by run is permanent for the life of the agent
// process: staged stays staged even if the directory is deleted out from
// under it, and corrupt stays corrupt forever, which is the point of corrupt
// (docs/specs/05-catalog.md §3 makes it terminal, on purpose) but not of
// staged. Reset is the only way either gets revisited short of restarting
// the whole agent — every deployment on the node, to unstick one model.
//
// Called for both `nodary model restage` (weights are corrupt, an operator
// asked to try again) and `unstage` (an operator wants the disk space back);
// Build tells them apart only by whether the model still appears in
// doc.Staging afterward.
func (dl *Downloader) Reset(modelID, dir string) bool {
	err1 := os.RemoveAll(dir)
	err2 := os.RemoveAll(dir + ".downloading")
	dl.mu.Lock()
	delete(dl.byModel, modelID)
	dl.mu.Unlock()
	return err1 == nil && err2 == nil
}

func (dl *Downloader) authorize(req *http.Request) {
	if dl.Token != "" {
		req.Header.Set("Authorization", "Bearer "+dl.Token)
	}
}

func (dl *Downloader) contentLength(url string) (int64, error) {
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return 0, err
	}
	dl.authorize(req)
	resp, err := dl.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%s", resp.Status)
	}
	return resp.ContentLength, nil
}

// fetch downloads url into dest whole — not appending, not resuming a
// partial file mid-flight. A partial file from an earlier, killed attempt is
// caught by matchingSize failing on it and this overwriting it cleanly.
func (dl *Downloader) fetch(url, dest string) (int64, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	dl.authorize(req)
	resp, err := dl.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%s", resp.Status)
	}
	f, err := os.Create(dest)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return io.Copy(f, resp.Body)
}

// matchingSize reports whether path already exists and hashes to want, and
// its size if so — read once, not stat-then-read separately, since the
// caller wants both facts from the one pass over the file.
func matchingSize(path, want string) (size int64, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, false
	}
	return n, hex.EncodeToString(h.Sum(nil)) == want
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
