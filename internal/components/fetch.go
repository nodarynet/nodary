package components

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/buildinfo"
)

// ErrDigestMismatch is an artifact whose bytes are not what the manifest pins.
//
// It is a hard stop everywhere it appears. docs/specs/01-install.md §2 makes
// signature and digest verification of the binary itself unskippable, and a
// component is the same kind of thing arriving over the same kind of channel.
var ErrDigestMismatch = errors.New("artifact does not match its pinned digest")

// Placement is what happened to one artifact.
type Placement string

const (
	// PlacedFetched means nodary downloaded it.
	PlacedFetched Placement = "fetched"
	// PlacedCached means it was already present and its digest matched, so
	// nothing was downloaded — docs/specs/01-install.md §4's "skip anything
	// already present and correct".
	PlacedCached Placement = "cached"
)

// Fetched is one artifact in the cache.
type Fetched struct {
	Component string    `json:"component"`
	Version   string    `json:"version"`
	Platform  string    `json:"platform"`
	Path      string    `json:"path"`
	SHA256    string    `json:"sha256"`
	Placement Placement `json:"placement"`
	Bytes     int64     `json:"bytes"`
}

// FetchOptions control resolution into a directory.
type FetchOptions struct {
	// Dir is the cache, normally /var/lib/nodary/dist.
	Dir string
	// Platform selects the artifact, e.g. linux/amd64.
	Platform string
	// Client is how artifacts are retrieved. A node passes one pointed at its
	// control plane's mirror; the control plane uses the default.
	Client *http.Client
	// BaseURL replaces the manifest's own URL host, which is what makes a node
	// fetch from its control plane rather than from upstream
	// (docs/specs/01-install.md §3). Empty means fetch from the manifest's URL.
	BaseURL string
	Timeout time.Duration
}

func (o *FetchOptions) setDefaults() {
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Minute
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: o.Timeout}
	}
	if o.Platform == "" {
		o.Platform = buildinfo.Platform()
	}
}

// Fetch resolves the given components into the cache.
//
// Only `archive` and `binary` kinds are fetched. An `image` is pulled by the
// container runtime from a registry by digest, which is a different mechanism
// with different credentials; Verify already reports images as skipped for the
// same reason.
func Fetch(ctx context.Context, comps []Component, o FetchOptions) ([]Fetched, error) {
	o.setDefaults()
	if o.Dir == "" {
		return nil, fmt.Errorf("no cache directory")
	}
	if err := os.MkdirAll(o.Dir, 0o755); err != nil {
		return nil, err
	}

	var out []Fetched
	for _, c := range comps {
		if c.Kind == KindImage {
			continue
		}
		a, ok := c.Platforms[o.Platform]
		if !ok || a.URL == "" {
			return out, fmt.Errorf("%s has no artifact for %s", c.Name, o.Platform)
		}
		got, err := fetchOne(ctx, c, a, o)
		if err != nil {
			return out, err
		}
		out = append(out, got)
	}
	return out, nil
}

// fetchOne places a single artifact, verifying before it lands.
func fetchOne(ctx context.Context, c Component, a Artifact, o FetchOptions) (Fetched, error) {
	name := ArtifactName(c, o.Platform)
	dest := filepath.Join(o.Dir, name)
	f := Fetched{Component: c.Name, Version: c.Version, Platform: o.Platform,
		Path: dest, SHA256: a.SHA256}

	// Already present and correct is a skip, and the check is the digest rather
	// than the file's existence: re-running an install re-verifies rather than
	// re-downloads, so a tampered cache is caught on the next run instead of
	// trusted because the file is there.
	if sum, size, err := hashFile(dest); err == nil {
		if sum == a.SHA256 {
			f.Placement, f.Bytes = PlacedCached, size
			return f, nil
		}
		// Present and wrong. Refused rather than silently replaced: something
		// put a different file where nodary keeps a pinned one, and overwriting
		// it would erase the only evidence of that.
		return f, fmt.Errorf("%w: %s in the cache hashes to %s, and the manifest pins %s",
			ErrDigestMismatch, dest, short(sum), short(a.SHA256))
	}

	url := a.URL
	if o.BaseURL != "" {
		url = strings.TrimRight(o.BaseURL, "/") + "/" + name
	}

	// A temporary file in the destination directory, so the rename below is on
	// one filesystem and therefore atomic.
	tmp, err := os.CreateTemp(o.Dir, "."+name+".*")
	if err != nil {
		return f, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return f, err
	}
	resp, err := o.Client.Do(req)
	if err != nil {
		return f, fmt.Errorf("fetching %s: %w", c.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return f, fmt.Errorf("fetching %s: %s returned %s", c.Name, url, resp.Status)
	}

	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), resp.Body)
	if err != nil {
		return f, fmt.Errorf("downloading %s: %w", c.Name, err)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if sum != a.SHA256 {
		// Verified before it is placed. A digest checked after the file is in
		// position leaves a window where something can use it.
		return f, fmt.Errorf("%w: %s from %s hashes to %s, and the manifest pins %s",
			ErrDigestMismatch, c.Name, url, short(sum), short(a.SHA256))
	}
	if err := tmp.Close(); err != nil {
		return f, err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return f, err
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return f, err
	}
	f.Placement, f.Bytes = PlacedFetched, size
	return f, nil
}

// ArtifactName is the cache's filename for one component on one platform.
//
// Derived from the component and version rather than taken from the URL: two
// upstreams name their files differently, and a mirror serving
// `containerd-2.3.4-linux-amd64.tar.gz` to one node and `containerd.tgz` to
// another would make the cache impossible to reason about.
func ArtifactName(c Component, platform string) string {
	ext := ".tar.gz"
	if c.Kind == KindBinary {
		ext = ""
	}
	return fmt.Sprintf("%s-%s-%s%s", c.Name, c.Version,
		strings.ReplaceAll(platform, "/", "-"), ext)
}

// --- the ownership record -----------------------------------------------------

// OwnershipFile is /etc/nodary/components.json: what nodary placed on this host.
const OwnershipFile = "components.json"

// Owned is one thing nodary put on the host, or found already there.
type Owned struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256,omitempty"`
	// Placed distinguishes what nodary installed from what it found and
	// accepted. **Only what it placed is ever removed.**
	//
	// R5-11: ownership is recorded, never inferred. A host may already have
	// containerd, installed by its operator and in use by something else; an
	// uninstall that removed it because the name appears in nodary's manifest
	// would take that down — on a machine docs/specs/12-node-guardrails.md
	// opens by pointing out is rarely only a nodary node.
	Placed bool   `json:"placed"`
	At     string `json:"at"`
}

// Ownership is the record as a whole.
type Ownership struct {
	NodaryVersion string  `json:"nodary_version"`
	Components    []Owned `json:"components"`
}

// LoadOwnership reads the record. A missing file is an empty record: nothing
// has been installed yet, which is not an error.
func LoadOwnership(path string) (Ownership, error) {
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Ownership{}, nil
	}
	if err != nil {
		return Ownership{}, err
	}
	var o Ownership
	if err := json.Unmarshal(body, &o); err != nil {
		return Ownership{}, fmt.Errorf("reading %s: %w", path, err)
	}
	return o, nil
}

// Record adds entries to the ownership record, replacing any with the same
// path, and writes it.
//
// Written as each artifact lands rather than at the end, so an install killed
// halfway leaves a record of exactly what it had placed by then. A record
// written only on success would leave an interrupted install's files
// unattributed, which is the state R5-11 exists to prevent.
func Record(path, nodaryVersion string, added ...Owned) error {
	existing, err := LoadOwnership(path)
	if err != nil {
		return err
	}
	existing.NodaryVersion = nodaryVersion

	byPath := map[string]int{}
	for i, o := range existing.Components {
		byPath[o.Path] = i
	}
	for _, a := range added {
		if a.At == "" {
			a.At = time.Now().UTC().Format(time.RFC3339)
		}
		if i, ok := byPath[a.Path]; ok {
			existing.Components[i] = a
			continue
		}
		byPath[a.Path] = len(existing.Components)
		existing.Components = append(existing.Components, a)
	}
	sort.Slice(existing.Components, func(i, j int) bool {
		return existing.Components[i].Path < existing.Components[j].Path
	})

	body, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o644)
}

// Removable is what an uninstall may delete: the entries nodary placed.
func (o Ownership) Removable() []Owned {
	var out []Owned
	for _, c := range o.Components {
		if c.Placed {
			out = append(out, c)
		}
	}
	return out
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
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}
