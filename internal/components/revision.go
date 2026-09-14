package components

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nodarynet/nodary/internal/minisign"
)

// TrustedKey is the public key this build trusts for manifest revisions.
//
// **Its own key**, like the advisory feed's and for the same reason ADR 0005 §3
// gives: a manifest revision is published from a pipeline, and one key for both
// would put a pipeline-reachable secret in the position of also minting
// licenses. Stamped in at release with -ldflags; while it holds the
// placeholder, nothing verifies and every install runs the floor.
var TrustedKey = placeholderKey

const placeholderKey = "untrusted comment: placeholder\nPLACEHOLDER-NOT-A-REAL-KEY\n"

// RevisionName and RevisionSig are where an applied revision lives, beside the
// configuration and with its signature next to it — the way a license arrives
// and the way the advisory feed does.
const (
	RevisionName = "components.json"
	RevisionSig  = "components.json.minisig"
)

// ErrStale is a revision at or below the floor.
//
// **Ignored, not rejected** (ADR 0007). An offline site replaying a bundle it
// already opened should keep working: a revision it has already superseded is
// not an attack and failing closed on one would make the safest delivery
// mechanism the most fragile.
var ErrStale = errors.New("manifest revision is not newer than the floor")

// ErrUnverified is a revision whose signature did not check out. Distinct from
// ErrStale because the outcomes differ: this one is reported loudly and the
// floor is used; a stale one is ordinary.
var ErrUnverified = errors.New("manifest revision does not verify")

// VerifyRevision checks a revision's signature and decodes it.
//
// Verification comes first and there is no way to skip it, for the reason
// ADR 0004 gives about the trust decision: this document decides what bytes a
// fleet installs, and an unsigned one is a way to point every node at something
// else.
func VerifyRevision(doc []byte, signature string) (*Manifest, error) {
	pub, err := minisign.ParsePublicKey(TrustedKey)
	if err != nil {
		if strings.Contains(TrustedKey, "PLACEHOLDER") {
			return nil, fmt.Errorf("%w: %w", ErrUnverified, minisign.ErrPlaceholder)
		}
		return nil, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	if _, err := minisign.Verify(pub, doc, signature); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	m, err := parse(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	// A revision that does not describe a usable fleet is refused whole. ADR
	// 0007: a manifest is never partially applied.
	if errs := m.Validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%w: %v", ErrUnverified, errs[0])
	}
	// **An empty manifest is well-formed and is not a manifest.** Validate
	// walks the components and finds nothing wrong with none of them, so a
	// revision pinning zero components verified, superseded the floor, and left
	// the fleet pinning nothing at all — found by a test that expected it to be
	// refused. A revision replaces the floor wholesale, so "carries no
	// components" is the one shape that must never win that replacement.
	if len(m.Components) == 0 {
		return nil, fmt.Errorf("%w: it pins no components, so it cannot replace a manifest "+
			"that does", ErrUnverified)
	}
	return m, nil
}

// Source says which manifest an install is running, so that `which manifest` is
// an answer rather than an inference from a version string.
type Source struct {
	// Revision is the effective manifest's revision.
	Revision int `json:"revision"`
	// Applied is true when a signed revision superseded the floor.
	Applied bool `json:"applied"`
	// Floor is the embedded manifest's revision, always.
	Floor int `json:"floor"`
	// Why is set when a revision was present and not used. It is never a
	// silent condition: an operator who applied a revision and is still
	// running the floor has to be told which, and why.
	Why string `json:"why,omitempty"`
}

// Effective resolves the manifest this install should use.
//
// **The floor is the normal state, not a fallback.** An install with no
// network, no bundle and no revision behaves exactly as it did before this
// existed; a revision is an improvement on it. That is also why every failure
// here returns the floor with an explanation rather than an error: nothing
// about resolving a manifest should be able to stop an install that would
// otherwise have worked.
func Effective(configDir string) (*Manifest, Source, error) {
	floor, err := Load()
	if err != nil {
		return nil, Source{}, err
	}
	src := Source{Revision: floor.Revision, Floor: floor.Revision}

	doc, err := os.ReadFile(filepath.Join(configDir, RevisionName))
	if err != nil {
		// No revision is the ordinary case and says nothing.
		return floor, src, nil
	}
	sig, err := os.ReadFile(filepath.Join(configDir, RevisionSig))
	if err != nil {
		src.Why = "the revision has no signature beside it, and there is no unsigned mode"
		return floor, src, nil
	}
	m, err := VerifyRevision(doc, string(sig))
	if err != nil {
		src.Why = err.Error()
		return floor, src, nil
	}
	if m.Revision <= floor.Revision {
		src.Why = fmt.Sprintf("revision %d is not newer than this build's %d",
			m.Revision, floor.Revision)
		return floor, src, nil
	}
	src.Revision, src.Applied = m.Revision, true
	return m, src, nil
}
