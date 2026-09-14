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
	// distinction is the whole of docs/specs/04-backends.md §3, so it survives
	// into the rendering rather than being flattened into one list.
	Args  []string `json:"args"`
	Extra []string `json:"extra,omitempty"`
	Probe Probe    `json:"probe"`
	// SHA256 is the digest of a registered descriptor's bytes, empty for a
	// built-in. §9 requires registration to record it, and this is where an
	// operator checks what is actually in force against what they registered.
	SHA256 string `json:"sha256,omitempty"`
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
		Probe: b.Probe, SHA256: sha,
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
