// Package components models the digest-pinned third-party dependency manifest
// that ships embedded in the nodary binary.
//
// The manifest is the single source of truth for what an install fetches, and
// the same data drives both the online path (resolve from upstream) and the
// offline path (`nodary bundle create`), so the two verify identically.
// See docs/adr/0004-release-artifacts-and-channels.md.
package components

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

//go:embed components.json
var embedded []byte

// Kind distinguishes how a component is fetched and placed.
type Kind string

const (
	// KindArchive is a tarball unpacked into place.
	KindArchive Kind = "archive"
	// KindBinary is a single executable placed directly.
	KindBinary Kind = "binary"
	// KindImage is a container image pulled by digest.
	KindImage Kind = "image"
)

// Role is the install role that needs a component.
type Role string

const (
	RoleServer Role = "server"
	RoleNode   Role = "node"
)

// Group is the selection unit exposed as `--components`.
type Group string

const (
	// GroupCore is installed by every server; the minimal control plane.
	GroupCore Group = "core"
	// GroupObservability is Prometheus, Grafana and dcgm-exporter.
	GroupObservability Group = "observability"
	// GroupRuntime is containerd and friends, on every node.
	GroupRuntime Group = "runtime"
	// GroupGPU is the NVIDIA container toolkit.
	GroupGPU Group = "gpu"
	// GroupBackend is a model-server image: vLLM, SGLang, llama.cpp.
	//
	// Backends are selected with `--backends`, never with `--components`.
	// Which one a site needs follows from the models it enables, and each is
	// several gigabytes, so pulling "all" of them at install time would be a
	// large and useless download.
	GroupBackend Group = "backend"
)

// Artifact is one component built for one platform.
//
// Archives and binaries carry URL plus SHA256. Images carry a digest-pinned
// reference and nothing else: the digest is inside Image.
type Artifact struct {
	URL    string `json:"url,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Image  string `json:"image,omitempty"`
}

// Component is one third-party dependency across all platforms it supports.
type Component struct {
	Name      string              `json:"name"`
	Version   string              `json:"version"`
	Kind      Kind                `json:"kind"`
	Roles     []Role              `json:"roles"`
	Group     Group               `json:"group"`
	Notes     string              `json:"notes,omitempty"`
	Platforms map[string]Artifact `json:"platforms"`
}

// Manifest is the embedded document.
type Manifest struct {
	Schema        int         `json:"schema"`
	NodaryVersion string      `json:"nodary_version"`
	Components    []Component `json:"components"`
}

// SchemaVersion is the manifest schema this binary understands.
const SchemaVersion = 1

// Load returns the manifest embedded in this binary.
func Load() (*Manifest, error) { return parse(embedded) }

// parse decodes and schema-checks a manifest document. Unknown fields are
// rejected so a manifest written by a newer release cannot be silently
// half-understood by an older binary.
func parse(doc []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parsing component manifest: %w", err)
	}
	if m.Schema != SchemaVersion {
		return nil, fmt.Errorf("component manifest schema %d, want %d", m.Schema, SchemaVersion)
	}
	return &m, nil
}

// ForPlatform returns the components available for a platform key such as
// "linux/amd64", sorted by name.
func (m *Manifest) ForPlatform(platform string) []Component {
	var out []Component
	for _, c := range m.Components {
		if _, ok := c.Platforms[platform]; ok {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// HasRole reports whether the component is needed by an install role.
func (c Component) HasRole(r Role) bool {
	for _, have := range c.Roles {
		if have == r {
			return true
		}
	}
	return false
}

// Select resolves a `--components` argument against a role.
//
// "minimal" is the core group; "all" is every group for that role; anything
// else is a comma-separated list of component or group names.
func (m *Manifest) Select(role Role, spec string) ([]Component, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		spec = "minimal"
	}

	var candidates []Component
	for _, c := range m.Components {
		if c.HasRole(role) {
			candidates = append(candidates, c)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })

	// Backends are a separate axis; see GroupBackend.
	filtered := candidates[:0:0]
	for _, c := range candidates {
		if c.Group != GroupBackend {
			filtered = append(filtered, c)
		}
	}
	candidates = filtered

	switch spec {
	case "all":
		return candidates, nil
	case "minimal":
		var out []Component
		for _, c := range candidates {
			// A node's runtime and GPU groups are not optional; without them
			// there is nothing to run a model in.
			if c.Group == GroupCore || c.Group == GroupRuntime || c.Group == GroupGPU {
				out = append(out, c)
			}
		}
		return out, nil
	}

	wanted := map[string]bool{}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			wanted[tok] = true
		}
	}
	var out []Component
	matched := map[string]bool{}
	for _, c := range candidates {
		if wanted[c.Name] || wanted[string(c.Group)] {
			out = append(out, c)
			matched[c.Name] = true
			matched[string(c.Group)] = true
		}
	}
	for w := range wanted {
		if !matched[w] {
			return nil, fmt.Errorf("unknown component or group %q", w)
		}
	}
	return out, nil
}

// Backends returns every model-server image in the manifest, sorted by name.
func (m *Manifest) Backends() []Component {
	var out []Component
	for _, c := range m.Components {
		if c.Group == GroupBackend {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SelectBackends resolves a `--backends` argument. "all" is every backend; an
// empty spec selects none, because a node that has been given no backend has
// simply not been asked to serve anything yet.
func (m *Manifest) SelectBackends(spec string) ([]Component, error) {
	spec = strings.TrimSpace(spec)
	available := m.Backends()

	switch spec {
	case "":
		return nil, nil
	case "all":
		return available, nil
	}

	byName := map[string]Component{}
	for _, c := range available {
		byName[c.Name] = c
	}

	var out []Component
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		c, ok := byName[tok]
		if !ok {
			names := make([]string, 0, len(available))
			for _, a := range available {
				names = append(names, a.Name)
			}
			return nil, fmt.Errorf("unknown backend %q (have: %s)", tok, strings.Join(names, ", "))
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// digestRe matches a digest-pinned image reference. A tag alone is rejected:
// an unpinned image is exactly the supply-chain hole the manifest closes.
var digestRe = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`)

// Validate checks the manifest's internal consistency without touching the
// network. Every structural rule that install-time verification depends on is
// asserted here, so a malformed manifest fails at build time rather than on a
// host.
func (m *Manifest) Validate() []error {
	var errs []error
	seen := map[string]bool{}

	for _, c := range m.Components {
		where := "component " + c.Name

		if c.Name == "" {
			errs = append(errs, fmt.Errorf("component with empty name"))
			continue
		}
		if seen[c.Name] {
			errs = append(errs, fmt.Errorf("%s: duplicate name", where))
		}
		seen[c.Name] = true

		if c.Version == "" {
			errs = append(errs, fmt.Errorf("%s: empty version", where))
		}
		switch c.Kind {
		case KindArchive, KindBinary, KindImage:
		default:
			errs = append(errs, fmt.Errorf("%s: unknown kind %q", where, c.Kind))
		}
		if len(c.Roles) == 0 {
			errs = append(errs, fmt.Errorf("%s: no roles", where))
		}
		for _, r := range c.Roles {
			if r != RoleServer && r != RoleNode {
				errs = append(errs, fmt.Errorf("%s: unknown role %q", where, r))
			}
		}
		switch c.Group {
		case GroupCore, GroupObservability, GroupRuntime, GroupGPU, GroupBackend:
		default:
			errs = append(errs, fmt.Errorf("%s: unknown group %q", where, c.Group))
		}
		if len(c.Platforms) == 0 {
			errs = append(errs, fmt.Errorf("%s: no platforms", where))
		}

		for plat, a := range c.Platforms {
			at := fmt.Sprintf("%s [%s]", where, plat)
			if !strings.Contains(plat, "/") {
				errs = append(errs, fmt.Errorf("%s: malformed platform key", at))
			}
			if c.Kind == KindImage {
				if a.Image == "" {
					errs = append(errs, fmt.Errorf("%s: image kind with no image reference", at))
				} else if !digestRe.MatchString(a.Image) {
					errs = append(errs, fmt.Errorf("%s: image reference is not digest-pinned: %s", at, a.Image))
				}
				if a.URL != "" || a.SHA256 != "" {
					errs = append(errs, fmt.Errorf("%s: image kind must not carry url or sha256", at))
				}
				continue
			}
			if a.Image != "" {
				errs = append(errs, fmt.Errorf("%s: %s kind must not carry an image reference", at, c.Kind))
			}
			if a.URL == "" {
				errs = append(errs, fmt.Errorf("%s: missing url", at))
			} else if !strings.HasPrefix(a.URL, "https://") {
				errs = append(errs, fmt.Errorf("%s: url is not https", at))
			}
			if a.SHA256 == "" {
				errs = append(errs, fmt.Errorf("%s: missing sha256", at))
			} else if !sha256Re.MatchString(a.SHA256) {
				errs = append(errs, fmt.Errorf("%s: malformed sha256 %q", at, a.SHA256))
			}
		}
	}
	return errs
}
