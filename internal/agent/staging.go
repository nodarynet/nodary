package agent

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ManifestName is the per-file digest list, carried beside the weights.
//
// docs/specs/05-catalog.md §1 makes `manifest_sha256` "per-file digests, used to
// verify staging", and the control plane holds only its digest. The list itself
// travels with the weights, because docs/specs/05-catalog.md §3 calls
// `source: local` the air-gapped path: an operator carries hundreds of
// gigabytes on removable media, and a few kilobytes of manifest belongs in the
// same act of carrying.
//
// The pinning still holds end to end. A manifest swapped in transit fails
// against `manifest_sha256`, which arrived over mTLS from an audited
// `model register`. The operator carries the bulk; the control plane carries
// the one digest that makes the bulk checkable.
//
// docs/plans/R4b-backends-and-the-plan.md §2.
const ManifestName = "nodary-manifest.sha256"

// Staging states are docs/specs/05-catalog.md §3's machine. `staging` and
// `verifying` are transient, belonging to a run in progress — `VerifyStaged`
// (source: local) never reports them, since reading local bytes is not slow
// enough to need an intermediate state; `Downloader` (source: remote, R4-33)
// is what produces them, across the many reconcile cycles a real download
// spans.
const (
	StateAbsent    = "absent"
	StateStaging   = "staging"
	StateVerifying = "verifying"
	StateStaged    = "staged"
	StateCorrupt   = "corrupt"
)

// Verdict is what a node concluded about one model's weights.
type Verdict struct {
	State string
	// Reason is set whenever State is not `staged`, and 0006_fleet.sql's CHECK
	// requires it for `corrupt`: a terminal state that does not say what went
	// wrong is how a corrupt artifact becomes a permanent mystery.
	Reason string
	Files  int
	Bytes  int64
}

// ModelDir is where a model's weights live under models_dir.
//
// docs/specs/05-catalog.md §3: for `hf-cache` this is the HuggingFace layout,
// `hub/models--<org>--<name>/`, so an existing cache is adopted without
// restaging rather than copied into a layout of our own invention.
func ModelDir(modelsDir, layout, modelID string) (string, error) {
	switch layout {
	case "hf-cache":
		return filepath.Join(modelsDir, "hub", "models--"+strings.ReplaceAll(modelID, "/", "--")), nil
	case "single-file", "engine-dir":
		// One directory per model id, with the separator flattened: a model id
		// holds a slash and a path component must not.
		return filepath.Join(modelsDir, strings.ReplaceAll(modelID, "/", "--")), nil
	}
	return "", fmt.Errorf("unknown weights layout %q for %s", layout, modelID)
}

// VerifyStaged reads every byte the manifest names and reports what it found.
//
// There is no size-and-mtime fast path, deliberately.
// docs/specs/11-failure-modes.md §2 makes `corrupt` terminal with an explicit
// restage, and the whole value of that is that `staged` means verified. Media
// carried physically is exactly the media that develops quiet bit errors, and
// a size check is blind to every one of them.
//
// The cost is minutes of disk read for a large model. It runs when a model is
// first staged and on an explicit restage — not on every reconcile, which is
// why the verdict is recorded rather than recomputed
// (docs/plans/R4b-backends-and-the-plan.md §3).
func VerifyStaged(modelsDir, layout, modelID, manifestSHA256 string) Verdict {
	dir, err := ModelDir(modelsDir, layout, modelID)
	if err != nil {
		return Verdict{State: StateCorrupt, Reason: err.Error()}
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return Verdict{State: StateAbsent,
			Reason: fmt.Sprintf("%s does not exist; place the weights there and restage", dir)}
	}

	manifestPath := filepath.Join(dir, ManifestName)
	body, err := os.ReadFile(manifestPath)
	if os.IsNotExist(err) {
		// Absent rather than corrupt: nothing is wrong with the weights, the
		// operator has not finished placing them. `corrupt` is terminal and
		// needs a human, and this does not.
		return Verdict{State: StateAbsent,
			Reason: fmt.Sprintf("%s is missing; it travels with the weights", manifestPath)}
	}
	if err != nil {
		return Verdict{State: StateCorrupt, Reason: err.Error()}
	}

	// The manifest is checked before it is trusted. Without this the digest
	// list and the files it describes could both have been replaced together,
	// and every file would verify against a manifest for the wrong weights.
	if got := hexSHA256(body); manifestSHA256 != "" && got != manifestSHA256 {
		return Verdict{State: StateCorrupt,
			Reason: fmt.Sprintf("%s hashes to %s, and the catalog pins %s",
				ManifestName, short(got), short(manifestSHA256))}
	}

	entries, err := ParseManifest(body)
	if err != nil {
		return Verdict{State: StateCorrupt, Reason: err.Error()}
	}
	if len(entries) == 0 {
		return Verdict{State: StateCorrupt, Reason: ManifestName + " lists no files"}
	}

	v := Verdict{State: StateStaged, Files: len(entries)}
	for _, e := range entries {
		path := filepath.Join(dir, e.Path)
		// A manifest entry that escapes the model's directory would let a
		// carried manifest name a file elsewhere on the host and have this
		// report it as staged weights.
		if !within(dir, path) {
			return Verdict{State: StateCorrupt,
				Reason: fmt.Sprintf("%s names %q, which is outside the model directory", ManifestName, e.Path)}
		}
		sum, n, err := hashFile(path)
		if os.IsNotExist(err) {
			return Verdict{State: StateAbsent,
				Reason: fmt.Sprintf("%s is listed in the manifest and is not there", e.Path)}
		}
		if err != nil {
			return Verdict{State: StateCorrupt, Reason: err.Error()}
		}
		if sum != e.SHA256 {
			return Verdict{State: StateCorrupt,
				Reason: fmt.Sprintf("%s hashes to %s, and the manifest says %s",
					e.Path, short(sum), short(e.SHA256))}
		}
		v.Bytes += n
	}
	return v
}

// Entry is one line of the manifest.
type Entry struct {
	SHA256 string
	Path   string
}

// ParseManifest reads `sha256sum` output.
//
// That format and not one of our own: an operator staging by hand produces it
// with `sha256sum *`, checks it with `sha256sum -c`, and needs nodary installed
// for neither. The same reasoning already governs the evidence bundle, which is
// verifiable with stock tools.
func ParseManifest(body []byte) ([]Entry, error) {
	var out []Entry
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	// A digest line is short; a very long one is a file that is not a manifest.
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		// "<64 hex>  path" — two spaces from sha256sum, one from some tools,
		// and a leading "*" for its binary mode.
		fields := strings.SplitN(text, " ", 2)
		if len(fields) != 2 || len(fields[0]) != 64 {
			return nil, fmt.Errorf("%s line %d is not `sha256sum` output: %q", ManifestName, line, text)
		}
		sum := strings.ToLower(fields[0])
		if _, err := hex.DecodeString(sum); err != nil {
			return nil, fmt.Errorf("%s line %d has no digest: %q", ManifestName, line, text)
		}
		path := strings.TrimPrefix(strings.TrimSpace(fields[1]), "*")
		if path == "" {
			return nil, fmt.Errorf("%s line %d names no file", ManifestName, line)
		}
		if seen[path] {
			// Two digests for one file is a manifest that cannot be satisfied,
			// and picking either one silently is picking one at random.
			return nil, fmt.Errorf("%s lists %s twice", ManifestName, path)
		}
		seen[path] = true
		out = append(out, Entry{SHA256: sum, Path: path})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", ManifestName, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// within reports whether path stays inside dir once both are cleaned.
func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, fmt.Errorf("reading %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}

// WriteManifest digests every file beside the weights and writes the list.
//
// The inverse of ParseManifest, and the half that had no implementation: the
// manifest "travels with the weights", which is true once somebody has made
// one, and the only thing that made one was a shell script in this repository
// that is not installed on any customer machine. `model register` calls this.
//
// **Sorted, and in `sha256sum -c` format.** Sorted so re-running produces the
// same bytes and therefore the same manifest digest — the catalog pins that
// digest, so a manifest that varied between runs would report the weights
// corrupt after a re-register. The format so that a machine with no nodary on
// it can still check the media it was handed.
//
// Only the top level. docs/specs/05-catalog.md §3's `hf-cache` layout is flat
// here for the reason internal/agent/plan.go renders `--model` as the directory
// itself, and a manifest that walked subdirectories would describe a layout
// that cannot load.
func WriteManifest(dir string) (sum string, files int, bytes int64, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", 0, 0, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || e.Name() == ManifestName {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "", 0, 0, fmt.Errorf("%s holds no files to digest", dir)
	}

	var b strings.Builder
	for _, name := range names {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return "", 0, 0, err
		}
		h := sha256.New()
		n, err := io.Copy(h, f)
		f.Close()
		if err != nil {
			return "", 0, 0, err
		}
		bytes += n
		// Two spaces, which is what sha256sum writes and what `-c` reads.
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(h.Sum(nil)), name)
	}
	body := []byte(b.String())
	if err := os.WriteFile(filepath.Join(dir, ManifestName), body, 0o644); err != nil {
		return "", 0, 0, err
	}
	return hexSHA256(body), len(names), bytes, nil
}
