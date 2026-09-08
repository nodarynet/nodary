package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/advisory"
	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/minisign"
)

// signedFeed writes a revision and its signature, and points this build's trust
// at the key that signed it.
func signedFeed(t *testing.T, body string) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var id [8]byte
	copy(id[:], []byte("clitest1"))

	previous := advisory.TrustedKey
	advisory.TrustedKey = minisign.EncodePublicKey(minisign.PublicKey{ID: id, Key: pub})
	t.Cleanup(func() { advisory.TrustedKey = previous })

	path := filepath.Join(t.TempDir(), "advisories.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sig := minisign.Sign(priv, id, []byte(body), "nodary advisory feed")
	if err := os.WriteFile(path+".minisig", []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const feedHeader = `revision = 7
generated = 2026-09-01T00:00:00Z
statement = "A report of what public sources said about the digests nodary pins. Not a warranty."
`

// TestAdvisoryCheckOnAnEmptyRevisionSaysWhatItChecked is R9-15's `done:` line.
//
// The failure mode this guards is not an exception — it is a verb that prints
// "ok" without having looked at anything. "Nothing found" and "nothing checked"
// read identically, and only one of them is good news.
func TestAdvisoryCheckOnAnEmptyRevisionSaysWhatItChecked(t *testing.T) {
	feed := signedFeed(t, feedHeader)

	code, stdout, stderr := runWithStdin(t, "", "advisory", "check", "--feed", feed)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "revision 7") {
		t.Errorf("the output does not name the revision it read: %s", stdout)
	}
	if !strings.Contains(stdout, "no advisory in this revision applies") {
		t.Errorf("an empty revision did not produce an empty result: %s", stdout)
	}
	// It says how many digests it looked at, so "nothing found" is checkable.
	if strings.Contains(stdout, "checked 0 pinned digest(s)") {
		t.Errorf("it checked nothing and reported success: %s", stdout)
	}
	// ADR 0005: the statement travels with the answer, not only with the file.
	if !strings.Contains(stderr, "Not a warranty") {
		t.Errorf("the statement was not shown with the result: %s", stderr)
	}
}

// TestAdvisoryCheckMatchesARealPinnedDigest walks the whole verb against a
// digest this binary actually ships.
func TestAdvisoryCheckMatchesARealPinnedDigest(t *testing.T) {
	m, err := components.Load()
	if err != nil {
		t.Fatal(err)
	}
	var pinned, name string
	for _, c := range m.Components {
		if art, ok := c.Platforms["linux/amd64"]; ok && art.SHA256 != "" {
			pinned, name = art.SHA256, c.Name
			break
		}
	}
	if pinned == "" {
		t.Skip("the manifest pins no linux/amd64 digest")
	}

	feed := signedFeed(t, feedHeader+`
[[advisory]]
id = "CVE-2026-9999"
component = "`+name+`"
affected = ["sha256:`+strings.ToUpper(pinned)+`"]
severity = "high"
summary = "a test advisory against a digest this build really pins"
`)

	code, stdout, stderr := runWithStdin(t, "", "advisory", "check",
		"--feed", feed, "--platform", "linux/amd64")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "CVE-2026-9999") {
		t.Errorf("an advisory against a pinned digest was not reported: %s", stdout)
	}
	// The feed writes it prefixed and upper case, the manifest writes it bare
	// and lower. Reporting a clean install here is the one wrong answer.
	if !strings.Contains(stdout, pinned) {
		t.Errorf("the pinned digest was not shown: %s", stdout)
	}
	// No `fixed` in this advisory, which is a real and common state.
	if !strings.Contains(stdout, "no fix published") {
		t.Errorf("an advisory with no fix was not reported as such: %s", stdout)
	}
}

// TestAdvisoryCheckRefusesAnUnsignedFeed: there is no unsigned mode. An
// attacker who can substitute a feed can tell a site its runtime is fine, which
// is a more useful lie than any single forged advisory.
func TestAdvisoryCheckRefusesAnUnsignedFeed(t *testing.T) {
	feed := signedFeed(t, feedHeader)
	if err := os.WriteFile(feed, []byte(feedHeader+"\n# tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runWithStdin(t, "", "advisory", "check", "--feed", feed)
	if code == ExitOK {
		t.Error("a tampered feed was accepted")
	}
	if !strings.Contains(stderr, "not valid") {
		t.Errorf("the refusal does not say the feed failed to verify: %s", stderr)
	}

	// And a missing signature is refused rather than treated as absent.
	if err := os.Remove(feed + ".minisig"); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runWithStdin(t, "", "advisory", "check", "--feed", feed); code == ExitOK {
		t.Errorf("a feed with no signature was accepted: %s", stderr)
	}
}

// TestAdvisoryCheckWithNoFeedSaysSo distinguishes "no subscription" from "a
// revision that found nothing", which look the same to anybody who only reads
// the exit code.
func TestAdvisoryCheckWithNoFeedSaysSo(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nothing-here.toml")
	code, _, stderr := runWithStdin(t, "", "advisory", "check", "--feed", missing)
	if code == ExitOK {
		t.Error("a missing feed reported success")
	}
	if !strings.Contains(stderr, "no feed at") {
		t.Errorf("the message does not distinguish a missing feed: %s", stderr)
	}
}
