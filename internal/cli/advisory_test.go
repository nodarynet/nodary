package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/advisory"
	"github.com/nodarynet/nodary/internal/audit"
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

// pinnedAdvisory builds a feed naming a digest this build really pins, so the
// clock under test runs against a finding the verb would genuinely report.
func pinnedAdvisory(t *testing.T, id string) string {
	t.Helper()
	m, err := components.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range m.Components {
		if art, ok := c.Platforms["linux/amd64"]; ok && art.SHA256 != "" {
			return feedHeader + "\n[[advisory]]\nid = \"" + id + "\"\ncomponent = \"" +
				c.Name + "\"\naffected = [\"sha256:" + art.SHA256 + "\"]\n" +
				"severity = \"high\"\nsummary = \"a test advisory\"\n"
		}
	}
	t.Skip("the manifest pins no linux/amd64 digest")
	return ""
}

// R9-16: inaction is what has to become visible. A finding nobody has decided
// about is not a worse vulnerability than the one beside it — it is the same
// one with nobody's name against it, and that is the thing an assessor asks
// about.
func TestAKnownAdvisoryWithNoDecisionStartsAClock(t *testing.T) {
	a := newAppliance(t)
	feed := signedFeed(t, pinnedAdvisory(t, "CVE-2026-9001"))

	code, stdout, stderr := a.run("advisory", "check", "--feed", feed,
		"--platform", "linux/amd64")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "clock") || !strings.Contains(stdout, "since revision 7") {
		t.Errorf("no clock was reported against the finding:\n%s", stdout)
	}
	// Seen today, so it is not yet overdue under either profile's interval.
	if strings.Contains(stdout, "POA&M") {
		t.Errorf("a finding seen for the first time today is already a POA&M item:\n%s", stdout)
	}

	// Run it again: a verb an operator is meant to run on a whim must not clear
	// its own evidence.
	if code, _, stderr = a.run("advisory", "check", "--feed", feed,
		"--platform", "linux/amd64"); code != ExitOK {
		t.Fatalf("second run: %d %s", code, stderr)
	}
	if n := a.scalar(t, `SELECT count(*) FROM advisory_finding`); n != "1" {
		t.Errorf("two looks produced %s rows", n)
	}
}

// The clock only exists where the record does. A check run with no control
// plane still reports the findings — withholding them because a clock could not
// be written would hide the useful half — and says why there is no clock,
// because a report with no clock and a clock that found nothing look the same.
func TestWithoutAControlPlaneTheFindingsStillArrive(t *testing.T) {
	feed := signedFeed(t, pinnedAdvisory(t, "CVE-2026-9002"))
	// A path that cannot be opened as a database, because store.Open creates
	// what is merely missing: this one has a regular file where it needs a
	// directory.
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runWithStdin(t, "", "advisory", "check", "--feed", feed,
		"--platform", "linux/amd64", "--db", filepath.Join(blocked, "nodary.db"))
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "CVE-2026-9002") {
		t.Errorf("the finding was withheld for want of a clock:\n%s", stdout)
	}
	if !strings.Contains(stderr, "No control plane here") {
		t.Errorf("the missing clock was not explained:\n%s", stderr)
	}
}

// An overdue finding has to be visible in the machine-readable output too:
// `--format json` is what a site's own monitoring reads (10 §4), and a POA&M
// item nobody is told about is the failure this task is named after.
func TestAnOverdueFindingIsMarkedInJSON(t *testing.T) {
	a := newAppliance(t)
	feed := signedFeed(t, pinnedAdvisory(t, "CVE-2026-9003"))

	if code, _, stderr := a.run("advisory", "check", "--feed", feed,
		"--platform", "linux/amd64"); code != ExitOK {
		t.Fatalf("seeding: %s", stderr)
	}
	// Age the sighting past the default profile's thirty days.
	a.execSQL(`UPDATE advisory_finding SET first_seen_at = '` +
		time.Now().AddDate(0, 0, -45).UTC().Format(audit.TimeFormat) + `'`)

	code, stdout, stderr := a.run("advisory", "check", "--feed", feed,
		"--platform", "linux/amd64", "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var out struct {
		Interval int `json:"decision_interval_days"`
		Known    []struct {
			ID   string `json:"advisory_id"`
			Days int    `json:"days_known"`
			POAM bool   `json:"poam"`
		} `json:"known"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("%v: %s", err, stdout)
	}
	if out.Interval != 30 {
		t.Errorf("the default profile's interval is %d, want 30", out.Interval)
	}
	if len(out.Known) != 1 || !out.Known[0].POAM || out.Known[0].Days < 44 {
		t.Errorf("a 45-day-old finding is not marked: %+v", out.Known)
	}
}
