package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Derive is dev/specs/04-backends.md §5: a base image corrected for this site.
//
// **Not `prepare`, and confusing the two bends the model out of shape.** A
// prepare takes staged weights and produces an engine directory, on the node,
// once per deployment, because the backend cannot serve without it. A derive
// takes a base image and produces a new image, on the control plane, once per
// site, because the image is wrong for this host — vLLM's bundled OpenCV
// aborting at import on a FIPS host is the motivating case, and a CVE backport,
// an internal CA bundle or a pinned transitive dependency are the same shape.
type Derive struct {
	// From is the base image, digest-pinned. A tag is refused for the reason
	// the component manifest refuses one: a tag is a name for whatever is
	// behind it today, and a build whose input can change underneath it
	// produces an artifact whose provenance record means nothing.
	From string `json:"from" toml:"from"`
	// Steps are commands run in order, each a layer. **Not a shell**: they are
	// split on whitespace and executed, so there is no pipe, no redirection and
	// no substitution — a step that reads like shell is refused rather than
	// quietly having its operators passed to the program as arguments.
	Steps []string `json:"steps" toml:"steps"`
	// IndexURL is the package index. Optional here; R6-11 makes it required
	// under a profile that sets require_pinned_derives.
	IndexURL string `json:"index_url,omitempty" toml:"index_url"`
	// TimeoutS bounds the build, for prepare.timeout_s's reason: without one a
	// wedged build is indistinguishable from a slow one, forever.
	TimeoutS int `json:"timeout_s" toml:"timeout_s"`
}

// RecipeSHA256 is the digest of what a build consumes: the base image, the
// steps in order, and the index they may reach.
//
// **The recipe and not the descriptor.** A derive whose probe timeout or
// justification changed has the same recipe and does not need rebuilding;
// hashing the whole document would tell an operator it does, and `stale` would
// become noise instead of the one signal §5 gives it — "the thing this image
// was built from has moved".
//
// `timeout_s` is excluded for the same reason: it is a ceiling on the build,
// not an input to it, so raising it must not invalidate an image.
//
// The framing is injective because R6-08 refuses a newline in a step, so no
// step can spell the separator and no two recipes can hash alike.
func (d Derive) RecipeSHA256() string {
	h := sha256.New()
	fmt.Fprintf(h, "from\n%s\n", d.From)
	fmt.Fprintf(h, "index_url\n%s\n", strings.TrimSpace(d.IndexURL))
	for _, s := range d.Steps {
		fmt.Fprintf(h, "step\n%s\n", s)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// digestPinned matches `repo@sha256:<64 hex>`, which is the only form a base
// image may take.
var digestPinned = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`)

// shellish are the characters that make a string a shell command rather than an
// argv. A step carrying one was written expecting a shell it will not get.
const shellish = "|&;<>()$`\\\"'\n\t*?[]{}"

// validateDerive checks the derive form of a descriptor.
//
// A derive is validated *instead of* the full form, not in addition to it: it
// carries a name, an `inherits` and a `[backend.derive]` table and nothing
// else, so every field the ordinary validation requires is one a derive must
// not have.
func (d Descriptor) validateDerive() error {
	b := d.Backend
	if b.Derive == nil {
		// `inherits` without the table is a descriptor that says it varies
		// something and never says how. It would inherit everything and change
		// nothing, which is a second name for the parent.
		return fmt.Errorf("%w: %s: inherits is set with no [backend.derive]; a derive that "+
			"changes nothing is another name for %s", ErrInvalid, b.Name, b.Inherits)
	}
	if b.Inherits == b.Name {
		return fmt.Errorf("%w: %s: inherits itself", ErrInvalid, b.Name)
	}

	// **Everything else is refused, which is what "the blast radius is an image
	// and nothing else" means.** §5 names argument vocabulary, weight layout
	// and probe; the rest are refused on the same principle rather than left
	// for somebody to discover is load-bearing. Widening this later needs a
	// reason and is cheap; narrowing it after operators depend on a field is
	// not.
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"api", b.API != ""},
		{"weights_layout", b.WeightsLayout != ""},
		{"mount_path", b.MountPath != ""},
		{"container_port", b.ContainerPort != 0},
		{"image_default", b.ImageDefault != ""},
		{"args", len(b.Args) > 0},
		{"extra", len(b.Extra) > 0},
		{"env", len(b.Env) > 0},
		{"env_wsl2", len(b.EnvWSL2) > 0},
		// Capabilities holds a slice, so it is compared field by field rather
		// than with !=. Spelled out so a field added there is a compile error
		// here rather than a silently unchecked one.
		{"capabilities", b.Capabilities.TensorParallel || b.Capabilities.ExpertParallel ||
			b.Capabilities.LoRA || b.Capabilities.CPUOffload ||
			len(b.Capabilities.Quantization) > 0},
		{"probe", b.Probe != Probe{}},
		{"metrics", b.Metrics != Metrics{}},
		{"prepare", b.Prepare != nil},
	} {
		if f.set {
			return fmt.Errorf("%w: %s: a derive may not set %s — it inherits everything but "+
				"the image from %s, which is what keeps the change to an image",
				ErrInvalid, b.Name, f.name, b.Inherits)
		}
	}

	dv := b.Derive
	switch {
	case strings.TrimSpace(dv.From) == "":
		return fmt.Errorf("%w: %s: derive.from is required", ErrInvalid, b.Name)
	case !digestPinned.MatchString(dv.From):
		return fmt.Errorf("%w: %s: derive.from %q is not digest-pinned; it must be "+
			"repo@sha256:… so the build's input cannot change underneath its record",
			ErrInvalid, b.Name, dv.From)
	case len(dv.Steps) == 0:
		return fmt.Errorf("%w: %s: derive.steps is empty; a derive with no steps produces a "+
			"copy of %s under a second name", ErrInvalid, b.Name, dv.From)
	case dv.TimeoutS <= 0:
		return fmt.Errorf("%w: %s: derive.timeout_s must be positive — without a ceiling a "+
			"wedged build is indistinguishable from a slow one", ErrInvalid, b.Name)
	}
	for i, step := range dv.Steps {
		if strings.TrimSpace(step) == "" {
			return fmt.Errorf("%w: %s: derive.steps[%d] is empty", ErrInvalid, b.Name, i)
		}
		if n := strings.IndexAny(step, shellish); n >= 0 {
			return fmt.Errorf("%w: %s: derive.steps[%d] contains %q — steps are an argv, not a "+
				"shell, so a pipe or a redirection would reach the program as an argument "+
				"instead of doing what it looks like", ErrInvalid, b.Name, i, step[n:n+1])
		}
	}
	// **https only, and refused here rather than at build time.** A build
	// reaches its index through a CONNECT tunnel (R6-09), which carries TLS end
	// to end and cannot read or alter what is installed. Plain HTTP would put
	// that proxy in the middle of the bytes whose digest the build is about to
	// record. An operator reading their own file should learn this now, not an
	// hour into a build.
	if u := strings.TrimSpace(dv.IndexURL); u != "" && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("%w: %s: derive.index_url %q must be https — the build reaches it "+
			"through a tunnel that carries TLS end to end, and cleartext would put nodary in "+
			"the middle of what the build installs", ErrInvalid, b.Name, u)
	}
	return nil
}

// Resolve applies a derive's inheritance and returns anything else unchanged.
//
// **Every read of a stored descriptor goes through this**, because a derive
// that has not been resolved is a descriptor with no argument vocabulary, no
// weight layout and no probe. A deployment on one would be refused for the
// reasons of a backend that does not exist, which is not what is wrong with it.
func Resolve(d Descriptor) (Descriptor, error) {
	if d.Backend.Inherits == "" {
		return d, nil
	}
	parent, err := Get(d.Backend.Inherits)
	if err != nil {
		return Descriptor{}, fmt.Errorf("%w: %s inherits %s, which this build does not have: %v",
			ErrInvalid, d.Backend.Name, d.Backend.Inherits, err)
	}
	return Inherit(parent, d)
}

// Inherit resolves a derive against its parent.
//
// The parent's whole descriptor with the derive's name on it: argument
// vocabulary, weight layout, probe, capabilities and environment all come from
// the parent, so a deployment of `vllm-fips` is configured exactly as a
// deployment of `vllm` is. That is the property §5 is after — a derive is not a
// new backend, it is the same backend with a corrected image.
//
// **The parent may not itself be a derive.** §5 says a derive inherits a
// built-in, and a chain would make "what does this backend actually do" a walk
// rather than a lookup — with no cycle detection anywhere and every layer
// another place for a vocabulary to drift.
//
// ImageDefault is deliberately cleared rather than set to the base: the image
// this backend serves is the one its build produces, and naming the base here
// would let a deployment start on the *uncorrected* image — the exact failure
// the derive exists to prevent, arrived at by inheriting too much.
func Inherit(parent, derived Descriptor) (Descriptor, error) {
	if derived.Backend.Derive == nil {
		return Descriptor{}, fmt.Errorf("%w: %s is not a derive", ErrInvalid, derived.Backend.Name)
	}
	if parent.Backend.Derive != nil || parent.Backend.Inherits != "" {
		return Descriptor{}, fmt.Errorf("%w: %s inherits %s, which is itself a derive; a derive "+
			"varies a built-in", ErrInvalid, derived.Backend.Name, parent.Backend.Name)
	}
	if parent.Backend.Name != derived.Backend.Inherits {
		return Descriptor{}, fmt.Errorf("%w: %s inherits %s, not %s",
			ErrInvalid, derived.Backend.Name, derived.Backend.Inherits, parent.Backend.Name)
	}

	out := parent
	out.Backend.Name = derived.Backend.Name
	out.Backend.Inherits = derived.Backend.Inherits
	out.Backend.Derive = derived.Backend.Derive
	out.Backend.ImageDefault = ""
	return out, nil
}
