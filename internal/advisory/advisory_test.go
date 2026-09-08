package advisory

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/minisign"
)

// publisher stands in for the signing pipeline of ADR 0005 §3.
type publisher struct {
	priv ed25519.PrivateKey
	id   [8]byte
}

func newPublisher(t *testing.T) *publisher {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &publisher{priv: priv}
	copy(p.id[:], []byte("feedtest"))

	previous := TrustedKey
	TrustedKey = minisign.EncodePublicKey(minisign.PublicKey{ID: p.id, Key: pub})
	t.Cleanup(func() { TrustedKey = previous })
	return p
}

func (p *publisher) sign(src string) string {
	return minisign.Sign(p.priv, p.id, []byte(src), "nodary advisory feed")
}

// emptyRevision is R9-14's deliverable: the shape, with nothing in it.
//
// An empty revision is the normal case — most days nothing new applies to the
// digests nodary pins — so it is the one that has to be right first.
const emptyRevision = `revision = 1
generated = 2026-09-08T00:00:00Z
statement = """
This feed reports what public sources said about the digests nodary pins, at the
time it was generated. It is not a warranty, not a guarantee of completeness,
and not a substitute for vulnerability management.
"""
`

func TestAnEmptySignedRevisionIsAnAnswerAndNotAnError(t *testing.T) {
	p := newPublisher(t)

	f, err := Parse(emptyRevision, p.sign(emptyRevision))
	if err != nil {
		t.Fatalf("an empty revision did not parse: %v", err)
	}
	if f.Revision != 1 {
		t.Errorf("revision = %d, want 1", f.Revision)
	}

	// R9-15: matched against real pins, it produces an empty result rather than
	// an error. A verb that failed here would fail on almost every run, and a
	// signal that always fires is one people stop reading.
	findings := f.Match([]Pin{
		{Component: "containerd", Platform: "linux/amd64", SHA256: "9d68969855fbf676"},
		{Component: "runc", Platform: "linux/amd64", SHA256: "abcdef0123456789"},
	})
	if len(findings) != 0 {
		t.Errorf("an empty feed produced %d finding(s)", len(findings))
	}
}

// TestARevisionWithoutTheStatementDoesNotParse is ADR 0005 §3 made structural.
//
// The statement ships **inside every revision, not only in documentation,
// because the revision is what outlives the sales conversation**. Enforcing it
// at parse time is what makes that a requirement rather than a note somebody
// remembers.
func TestARevisionWithoutTheStatementDoesNotParse(t *testing.T) {
	p := newPublisher(t)
	src := "revision = 1\ngenerated = 2026-09-08T00:00:00Z\n"
	if _, err := Parse(src, p.sign(src)); !errors.Is(err, ErrNoStatement) {
		t.Errorf("a revision with no statement returned %v, want ErrNoStatement", err)
	}

	// Whitespace is not a statement either, which is the version somebody
	// writes when they want the field to go away without deleting it.
	src = "revision = 1\ngenerated = 2026-09-08T00:00:00Z\nstatement = \"   \"\n"
	if _, err := Parse(src, p.sign(src)); !errors.Is(err, ErrNoStatement) {
		t.Errorf("a whitespace statement returned %v, want ErrNoStatement", err)
	}
}

// TestAnUnverifiedRevisionIsNeverRead is the property that makes the feed worth
// having at all.
//
// A feed is security information about somebody's own supply chain. An attacker
// who can substitute one can tell a site its runtime is fine, which is a more
// useful lie than any it could tell by tampering with a single advisory.
func TestAnUnverifiedRevisionIsNeverRead(t *testing.T) {
	p := newPublisher(t)
	sig := p.sign(emptyRevision)

	tampered := strings.Replace(emptyRevision, "revision = 1", "revision = 2", 1)
	if _, err := Parse(tampered, sig); !errors.Is(err, ErrInvalid) {
		t.Errorf("a tampered revision returned %v, want ErrInvalid", err)
	}

	other := newPublisher(t) // replaces TrustedKey with a different key
	if _, err := Parse(emptyRevision, p.sign(emptyRevision)); !errors.Is(err, ErrInvalid) {
		t.Errorf("a revision signed by the wrong key returned %v, want ErrInvalid", err)
	}
	// And the right one still verifies, so the test above is not passing for
	// some other reason.
	if _, err := Parse(emptyRevision, other.sign(emptyRevision)); err != nil {
		t.Errorf("the current publisher's own revision was refused: %v", err)
	}
}

// TestADevelopmentBuildTrustsNothing: the placeholder key must refuse, the same
// way install.sh's does. A build that verified against a placeholder would
// accept any feed at all.
func TestADevelopmentBuildTrustsNothing(t *testing.T) {
	previous := TrustedKey
	TrustedKey = placeholder
	t.Cleanup(func() { TrustedKey = previous })

	_, err := Parse(emptyRevision, "whatever")
	if !errors.Is(err, ErrInvalid) || !errors.Is(err, minisign.ErrPlaceholder) {
		t.Errorf("a placeholder build returned %v, want an invalid/placeholder refusal", err)
	}
}

// TestMatchingIsOnTheDigest covers the choice ADR 0007 forces.
//
// A version string is what a project calls a release; a digest is what is on
// the disk. Matching on name and version would miss a rebuilt artifact and
// would break the moment a manifest entry is renamed.
func TestMatchingIsOnTheDigest(t *testing.T) {
	p := newPublisher(t)
	src := emptyRevision + `
[[advisory]]
id = "CVE-2026-0001"
component = "containerd"
affected = ["sha256:AAAA1111", "bbbb2222"]
fixed = "sha256:cccc3333"
severity = "high"
source = "https://example.invalid/CVE-2026-0001"
summary = "a thing"
`
	f, err := Parse(src, p.sign(src))
	if err != nil {
		t.Fatal(err)
	}

	pins := []Pin{
		// Prefixed in the feed, bare in the manifest, and upper case in one of
		// them. All three are the same artifact, and treating them as different
		// would report a clean install — the one wrong answer this must never
		// give.
		{Component: "containerd", Platform: "linux/amd64", SHA256: "aaaa1111"},
		{Component: "containerd", Platform: "linux/arm64", SHA256: "sha256:BBBB2222"},
		{Component: "runc", Platform: "linux/amd64", SHA256: "dddd4444"},
	}
	findings := f.Match(pins)
	if len(findings) != 2 {
		t.Fatalf("matched %d pin(s), want 2: %+v", len(findings), findings)
	}
	if findings[0].Platform != "linux/amd64" || findings[1].Platform != "linux/arm64" {
		t.Errorf("findings are not ordered by platform: %+v", findings)
	}
	if findings[0].Advisory.Fixed != "sha256:cccc3333" {
		t.Errorf("the recommended digest was lost: %q", findings[0].Advisory.Fixed)
	}

	// A component nobody pins produces nothing, however loudly the feed shouts.
	if got := f.Match([]Pin{{Component: "runc", SHA256: "dddd4444"}}); len(got) != 0 {
		t.Errorf("matched %d advisory against a digest this build does not pin", len(got))
	}
}

// TestARevisionFromANewerPublisherIsRefused stops a feed being half-read.
//
// Silently ignoring a field is how a revision comes to say less than its
// publisher thinks it does — and here the thing being dropped could be the one
// that matters.
func TestARevisionFromANewerPublisherIsRefused(t *testing.T) {
	p := newPublisher(t)
	src := emptyRevision + "withdrawn = [\"CVE-2026-0001\"]\n"
	if _, err := Parse(src, p.sign(src)); !errors.Is(err, ErrInvalid) {
		t.Errorf("a revision using an unknown field returned %v, want ErrInvalid", err)
	}
}

func TestAgeIsMeasuredFromGeneration(t *testing.T) {
	p := newPublisher(t)
	f, err := Parse(emptyRevision, p.sign(emptyRevision))
	if err != nil {
		t.Fatal(err)
	}
	// Generation, not fetch: a revision copied onto an air-gapped site last
	// night is as stale as the day it was made.
	at := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	if got := f.Age(at); got != 10*24*time.Hour {
		t.Errorf("age = %v, want 240h", got)
	}
}
