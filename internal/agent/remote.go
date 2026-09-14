package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// Downloader runs `source: remote` staging (R4-33, docs/specs/05-catalog.md
// §3): the agent fetches a model's own weights and verifies each file
// against a manifest the control plane holds — remote has no
// weights-travel-on-removable-media channel the way local does, so there is
// nothing beside the (not yet downloaded) weights to find one in.
//
// It is two halves in one type, on either side of a process boundary (R4-30).
// In the agent, Status is orchestration only: it starts a transient unit per
// model and reads what that unit records. In the unit, RunStaging builds a
// second Downloader and calls run, which is the download itself. Build runs
// roughly once a minute and remembers nothing between calls — exactly right
// for VerifyStaged, which re-reads local bytes synchronously every time, and
// wrong for something that can take hours.
type Downloader struct {
	// BaseURL is HuggingFace's resolve host, a field rather than a literal so
	// a test can point it at an httptest.Server instead of the real network.
	BaseURL string
	// Client is a plain HTTP client — not the mTLS one the agent uses to talk
	// to the control plane, a different trust boundary entirely. Only the
	// child half uses it; in the agent it is nil and nothing reads it.
	Client *http.Client
	// Token is HF_TOKEN, read once from the agent process's own environment.
	// One node-wide credential for gated repositories, not a per-model one —
	// a real limitation of this first version, not a hidden one.
	Token string
	// Host starts and inspects the transient unit. Only the agent half uses
	// it; the child is the unit and has nothing to start.
	Host Host
}

// newDownloadClient has no Timeout, deliberately: a multi-gigabyte transfer
// has no fixed deadline. The unit it runs in is what bounds it.
func newDownloadClient() *http.Client { return &http.Client{} }

// NewDownloader is the production Downloader: HuggingFace, and HF_TOKEN from
// this process's own environment if the operator set one. It holds no client —
// this half starts units and never fetches anything itself.
func NewDownloader(h Host) *Downloader {
	return &Downloader{BaseURL: "https://huggingface.co", Token: os.Getenv("HF_TOKEN"), Host: h}
}

// Status is what Build calls every reconcile cycle. It never blocks past a
// file read and a `systemctl is-active`.
//
// Three facts decide everything, in order: a terminal verdict already on disk,
// a unit still working, and otherwise nothing is happening and one is started.
// That last case covers a first sighting and an interrupted download with the
// same line, which is right — the download resumes from whatever already
// verifies on disk, so restarting it is how it recovers from a reboot, an OOM
// kill, or an agent that was replaced mid-transfer.
func (dl *Downloader) Status(modelID, manifestBody, manifestSHA256, dir string) Stage {
	// context.Background() rather than a threaded one: Build takes no context
	// and every command here is a sub-second call to the service manager.
	ctx := context.Background()

	have, found := readProgress(progressPath(dir))
	have.Model, have.Dir = modelID, dir

	// **A terminal verdict is the record, and it now outlives both the unit
	// that wrote it and this agent process.** The in-memory map this replaces
	// did not: `corrupt` is terminal on purpose (05 §3) and used to be
	// forgotten on every agent restart, which is most of the way to the silent
	// re-download R4-35 exists to prevent.
	if found && (have.State == StateStaged || have.State == StateCorrupt) {
		return have
	}

	switch dl.Host.activeState(ctx, stageUnitName(modelID)) {
	case "active", "activating", "deactivating", "reloading":
		if found {
			return have
		}
		return Stage{Model: modelID, Dir: dir, State: StateStaging}
	}

	if err := dl.start(ctx, stageRequest{Model: modelID, Dir: dir, BaseURL: dl.BaseURL,
		ManifestBody: manifestBody, ManifestSHA256: manifestSHA256, Token: dl.Token}); err != nil {
		return Stage{Model: modelID, Dir: dir, State: StateStaging,
			Reason: "starting the staging unit: " + err.Error()}
	}
	return Stage{Model: modelID, Dir: dir, State: StateStaging}
}

// run downloads and verifies one model, start to finish. It owns d for its
// entire lifetime; Status only ever reads it.
func (dl *Downloader) run(req stageRequest, d *progress) {
	// The manifest is checked before it is trusted, the same reason
	// VerifyStaged checks a local one: a manifest that does not hash to what
	// the control plane recorded could have been swapped in transit between
	// whoever computed it and `model register`, and every file would then
	// verify against a manifest for the wrong weights.
	if got := hexSHA256([]byte(req.ManifestBody)); req.ManifestSHA256 != "" && got != req.ManifestSHA256 {
		d.set(StateCorrupt, 0, 0, fmt.Sprintf("%s hashes to %s, and the catalog pins %s",
			ManifestName, short(got), short(req.ManifestSHA256)))
		return
	}
	entries, err := ParseManifest([]byte(req.ManifestBody))
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
	tmp := req.Dir + ".downloading"
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		d.set(StateCorrupt, 0, 0, err.Error())
		return
	}
	resolve := dl.BaseURL + "/" + req.Model + "/resolve/main/"

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
	if err := os.WriteFile(filepath.Join(tmp, ManifestName), []byte(req.ManifestBody), 0o644); err != nil {
		d.set(StateCorrupt, done, total, err.Error())
		return
	}
	if err := os.Rename(tmp, req.Dir); err != nil {
		d.set(StateCorrupt, done, total, fmt.Sprintf("placing the staged weights: %v", err))
		return
	}
	d.set(StateStaged, done, done, "")
}

// Reset discards everything this node holds for modelID — the weights, a
// half-finished download, and the verdict recorded about them — so the next
// Status call starts clean.
//
// **Status never revisits a model on its own once it reaches a terminal
// state**, which is the point of `corrupt` (docs/specs/05-catalog.md §3 makes
// it terminal, on purpose) and not of `staged`. Reset is the only way either
// gets revisited — and unlike the in-memory map it used to clear, restarting
// the agent is no longer a second way, because the verdict is a file now.
//
// Called for both `nodary model restage` (weights are corrupt, an operator
// asked to try again) and `unstage` (an operator wants the disk space back);
// Build tells them apart only by whether the model still appears in
// doc.Staging afterward.
func (dl *Downloader) Reset(modelID, dir string) bool {
	// Stopped first, and not as a courtesy: a unit still writing into
	// <dir>.downloading would recreate part of what this is removing, and the
	// leftovers would then be attributed to the next attempt.
	_, _ = dl.Host.systemctl(context.Background(), "stop", stageUnitName(modelID))
	err1 := os.RemoveAll(dir)
	err2 := os.RemoveAll(dir + ".downloading")
	_ = os.Remove(progressPath(dir))
	_ = os.Remove(requestPath(dir))
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
