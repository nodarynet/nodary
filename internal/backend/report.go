package backend

import "sort"

// Report is one backend as both front ends render it.
//
// A projection, in the one package that owns the descriptor, because a
// projection is exactly where the CLI and the API quietly stop agreeing —
// nothing calls a renderer twice, so a field added on one side is never missed
// on the other until somebody compares two screens.
//
// It is not the Descriptor itself. `args` and `extra` are the *names* a
// document may use rather than the templates they render to, because that is
// the question an operator has when they are about to write `params`: not
// "how does max_context reach vLLM" but "may I say max_context at all".
type Report struct {
	Name string `json:"name"`
	// Source is "built-in" or "registered". An operator debugging a
	// deployment needs to know whether the descriptor came out of this binary
	// or out of a file somebody added, because only one of those is the same
	// on every host in the fleet.
	Source        string       `json:"source"`
	API           string       `json:"api"`
	WeightsLayout string       `json:"weights_layout"`
	MountPath     string       `json:"mount_path,omitempty"`
	ContainerPort int          `json:"container_port"`
	ImageDefault  string       `json:"image_default,omitempty"`
	Capabilities  Capabilities `json:"capabilities"`
	// Args are the canonical parameter names this backend translates, and
	// Extra the backend-specific ones it merely passes through. The
	// distinction is the whole of dev/specs/04-backends.md §3, so it survives
	// into the rendering rather than being flattened into one list.
	Args  []string `json:"args"`
	Extra []string `json:"extra,omitempty"`
	Probe Probe    `json:"probe"`
	// Prepare is nil unless this backend builds something before it serves.
	// An operator reading a listing has to be able to tell that registering a
	// model on this backend costs hours before it answers anything, and how
	// many — §4's whole point is that the phase exists and is not free.
	Prepare *Prepare `json:"prepare,omitempty"`
	// SHA256 is the digest of a registered descriptor's bytes, empty for a
	// built-in. §9 requires registration to record it, and this is where an
	// operator checks what is actually in force against what they registered.
	SHA256 string `json:"sha256,omitempty"`
	// Recipe is the derive this descriptor declares, nil for anything else.
	// Present even when nothing has been built, because "this backend has a
	// recipe and no image yet" is the state `backend build` exists to leave.
	Recipe *Derive `json:"recipe,omitempty"`
	// Built is what a build produced, nil until one has. §5 makes rebuilding
	// explicit, so an operator has to be able to see both that an image exists
	// and that the recipe behind it has moved.
	Built *Built `json:"built,omitempty"`
}

// Built is one derive's current image, as `backend show` reports it.
type Built struct {
	Image        string `json:"image"`
	Digest       string `json:"digest"`
	BaseDigest   string `json:"base_digest"`
	RecipeSHA256 string `json:"recipe_sha256"`
	BuiltAt      string `json:"built_at"`
	BuiltBy      string `json:"built_by"`
	// Stale is derived, never stored: the recipe in force no longer hashes to
	// what was built. A stored flag would be one more thing that can disagree
	// with the descriptor beside it, and it would need a writer on every path
	// that edits one.
	Stale bool `json:"stale"`
	// Why says which half moved, because the two call for different reading:
	// a base bump is somebody else's release, a step change is this site's own
	// edit.
	Why string `json:"why,omitempty"`
}

// Staleness compares a built image against the recipe now in force.
func (b *Built) Staleness(d *Derive) {
	if b == nil || d == nil || b.RecipeSHA256 == d.RecipeSHA256() {
		return
	}
	b.Stale = true
	b.Why = "the recipe has changed since this image was built"
	if b.BaseDigest != d.From {
		b.Why = "the base image has moved to " + d.From
	}
}

// SourceBuiltIn and SourceRegistered are Report.Source.
const (
	SourceBuiltIn    = "built-in"
	SourceRegistered = "registered"
)

func NewReport(d Descriptor, source, sha string) Report {
	b := d.Backend
	return Report{
		Name: b.Name, Source: source, API: b.API,
		WeightsLayout: b.WeightsLayout, MountPath: b.MountPath,
		ContainerPort: b.ContainerPort, ImageDefault: b.ImageDefault,
		Capabilities: b.Capabilities,
		Args:         keys(b.Args), Extra: keys(b.Extra),
		Probe: b.Probe, Prepare: b.Prepare, SHA256: sha, Recipe: b.Derive,
	}
}

// Reports renders a whole set, sorted by name so two calls answer alike.
func Reports(all map[string]Descriptor) []Report {
	out := []Report{}
	for _, n := range Names(all) {
		out = append(out, NewReport(all[n], SourceBuiltIn, ""))
	}
	return out
}

func keys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
