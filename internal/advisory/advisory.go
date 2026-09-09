// Package advisory reads the signed advisory feed and matches it against the
// digests this binary pins.
//
// **The mechanism is here and free; the content is the product.**
// docs/adr/0005-editions-and-the-advisory-feed.md draws that line for the whole
// edition split, and it falls the same way here: verifying a revision and
// matching it against the manifest is a hundred lines of standard library, and
// what a customer pays for is a *current* revision. So there is no license
// check in this package. Possession of a recent signed feed is the
// entitlement — an old one is worth nothing, which is precisely what a
// subscription sells — and gating the verb as well would only stop somebody
// reading content we had already given them.
//
// The feed maps **component digest → advisory → recommended digest**, never
// version to version. A version string is what a project calls a release; a
// digest is what is actually on the disk, and the whole point of
// docs/adr/0007-independent-component-manifest.md is that nodary pins the
// second.
package advisory

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/nodarynet/nodary/internal/minisign"
)

// TrustedKey is the public key this build trusts for feed revisions.
//
// **Deliberately not the license key**, though docs/tasks/R9-evidence-remediation.md
// says "the same trust root as R9-02" and this is the same *mechanism*: an
// embedded minisign key, stamped in at release with -ldflags, refusing to
// verify anything while it holds the placeholder.
//
// The two keys have incompatible exposure. A license signs entitlements — low
// volume, long-lived, and a key that can live offline. A feed revision is
// **generated in CI** (ADR 0005 §3), so its key has to be reachable from an
// automated pipeline. One key for both would put a CI-accessible secret in the
// position of also minting licenses, and would mean a feed-key rotation
// invalidated every license in the field.
var TrustedKey = placeholder

const placeholder = "untrusted comment: placeholder\nPLACEHOLDER-NOT-A-REAL-KEY\n"

var (
	// ErrInvalid is a revision that does not verify or does not parse.
	ErrInvalid = errors.New("the advisory feed is not valid")
	// ErrNoStatement is a revision missing the statement ADR 0005 requires.
	ErrNoStatement = errors.New("the advisory feed carries no statement of what it is")
)

// Feed is one revision.
type Feed struct {
	// Revision increases. A site that has seen 12 learns nothing from 11.
	Revision int `toml:"revision"`
	// Generated is when the scanners ran, not when the file was fetched. It is
	// the only thing that says how stale this answer is.
	Generated time.Time `toml:"generated"`
	// Statement is ADR 0005's "what this is and is not": a report of what
	// public sources say about digests nodary pins, at the time it was
	// generated, and **not** a warranty.
	//
	// Required **inside every revision, not only in documentation, because the
	// revision is what outlives the sales conversation**. A revision without it
	// does not parse — which is the difference between a requirement and a
	// note, and this one exists because publishing a feed makes nodary a
	// security-information vendor. The wording is the publisher's; that there
	// is one is enforced here, so no revision can quietly drop it.
	Statement  string     `toml:"statement"`
	Advisories []Advisory `toml:"advisory"`
}

// Advisory is one public report against one or more pinned digests.
type Advisory struct {
	// ID is the public identifier, normally a CVE.
	ID string `toml:"id"`
	// Component names the manifest entry, so a reader can act without decoding
	// a digest by hand.
	Component string `toml:"component"`
	// Affected are the digests this applies to. Digests, not versions: a
	// rebuilt tarball with the same version string is a different artifact.
	Affected []string `toml:"affected"`
	// Fixed is the digest to move to, empty when no fix is published.
	//
	// Empty is a real and common state, and it is reported as "no fix
	// published" rather than omitted. An advisory nobody can act on yet is
	// still one an assessor expects to see a decision about — R9-16 and R9-17
	// are that decision, and they need this row to exist first.
	Fixed    string `toml:"fixed"`
	Severity string `toml:"severity"`
	Source   string `toml:"source"`
	Summary  string `toml:"summary"`
}

// Parse verifies a revision and decodes it.
//
// Verification comes first and there is no way to skip it. A feed is
// security information about a customer's own supply chain; an unsigned one is
// a way to tell somebody their runtime is fine.
func Parse(src, signature string) (Feed, error) {
	pub, err := minisign.ParsePublicKey(TrustedKey)
	if err != nil {
		if strings.Contains(TrustedKey, "PLACEHOLDER") {
			return Feed{}, fmt.Errorf("%w: %w", ErrInvalid, minisign.ErrPlaceholder)
		}
		return Feed{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if _, err := minisign.Verify(pub, []byte(src), signature); err != nil {
		return Feed{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	var f Feed
	md, err := toml.Decode(src, &f)
	if err != nil {
		return Feed{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	// A key this build does not understand is a revision written by a newer
	// publisher. Refused rather than half-read: silently ignoring a field is
	// how a feed comes to say less than it thinks it does.
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return Feed{}, fmt.Errorf("%w: it uses %v, which this build does not understand",
			ErrInvalid, undecoded)
	}
	if strings.TrimSpace(f.Statement) == "" {
		return Feed{}, ErrNoStatement
	}
	if f.Revision < 1 {
		return Feed{}, fmt.Errorf("%w: revision %d", ErrInvalid, f.Revision)
	}
	return f, nil
}

// Finding is one advisory that applies to something this install actually
// pins.
type Finding struct {
	Advisory Advisory `json:"advisory"`
	// Pinned is the digest the manifest holds, which is what made this match.
	Pinned string `json:"pinned"`
	// Platform is which artifact matched, because a component is pinned once
	// per platform and an advisory may reach only one of them.
	Platform string `json:"platform"`
}

// Pin is one digest this build pins.
type Pin struct {
	Component string
	Platform  string
	SHA256    string
}

// Match reports the advisories that apply to the given pins.
//
// **An empty feed produces an empty result, not an error** (R9-15). A revision
// that found nothing is an answer — the most common one — and a verb that
// failed on it would train people to ignore the failure.
//
// Matching is on the digest alone. The component name in an advisory is for
// the reader; using it to match would mean a renamed manifest entry silently
// stopped matching advisories that still apply to the bytes on disk.
func (f Feed) Match(pins []Pin) []Finding {
	byDigest := map[string][]Pin{}
	for _, p := range pins {
		d := normalizeDigest(p.SHA256)
		byDigest[d] = append(byDigest[d], p)
	}

	var out []Finding
	for _, a := range f.Advisories {
		for _, affected := range a.Affected {
			for _, p := range byDigest[normalizeDigest(affected)] {
				out = append(out, Finding{Advisory: a, Pinned: p.SHA256, Platform: p.Platform})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Advisory.ID != out[j].Advisory.ID {
			return out[i].Advisory.ID < out[j].Advisory.ID
		}
		return out[i].Platform < out[j].Platform
	})
	return out
}

// normalizeDigest accepts `sha256:…` and a bare hex digest as the same thing.
//
// The manifest writes bare hex and a feed written by hand is likely to carry
// the prefixed form. A mismatch here would report a clean install, which is
// the one wrong answer this package must not give.
func normalizeDigest(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "sha256:"))
}

// Age is how stale this revision is.
func (f Feed) Age(now time.Time) time.Duration { return now.Sub(f.Generated) }
