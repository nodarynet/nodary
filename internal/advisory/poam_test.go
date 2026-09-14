package advisory

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/store"
	"github.com/nodarynet/nodary/internal/store/storetest"
)

func clockDB(t *testing.T) *store.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nodary.db")
	storetest.Place(t, path)
	db, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func oneFinding(id, component, platform, digest string) []Finding {
	return []Finding{{
		Advisory: Advisory{ID: id, Component: component, Affected: []string{digest}},
		Pinned:   digest, Platform: platform,
	}}
}

// The clock is the deliverable, and the only part of a finding that cannot be
// recomputed from the feed and the manifest. A second look must not restart it:
// an advisory known for a month is a POA&M item, and a verb an operator runs on
// a whim would otherwise clear its own evidence every time.
func TestASecondLookDoesNotRestartTheClock(t *testing.T) {
	db := clockDB(t)
	ctx := context.Background()
	first := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	findings := oneFinding("CVE-2026-0001", "containerd", "linux/amd64", "aaaa1111")

	seen, err := Record(ctx, db, first, 11, findings)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || !seen[0].FirstSeen.Equal(first) {
		t.Fatalf("the first sighting was not recorded: %+v", seen)
	}

	// A month later, a newer revision, the same finding.
	later := first.AddDate(0, 1, 0)
	seen, err = Record(ctx, db, later, 13, findings)
	if err != nil {
		t.Fatal(err)
	}
	if !seen[0].FirstSeen.Equal(first) {
		t.Errorf("the clock restarted: %s, want %s", seen[0].FirstSeen, first)
	}
	// And the revision recorded stays the one that first carried it — that is
	// the answer to "since when could you have known", not "which revision are
	// you reading today".
	if seen[0].FeedRevision != 11 {
		t.Errorf("the recorded revision moved to %d", seen[0].FeedRevision)
	}
	if got := seen[0].Days(later); got < 30 || got > 31 {
		t.Errorf("%d days known, want about 31", got)
	}
}

// A finding against a digest the site has since moved off is not the same
// finding as one against the digest it runs now, so it gets its own clock —
// upgrading a component must not inherit the old artifact's overdue status.
func TestADifferentDigestIsADifferentFinding(t *testing.T) {
	db := clockDB(t)
	ctx := context.Background()
	old := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	if _, err := Record(ctx, db, old, 11,
		oneFinding("CVE-2026-0001", "containerd", "linux/amd64", "aaaa1111")); err != nil {
		t.Fatal(err)
	}

	now := old.AddDate(0, 2, 0)
	seen, err := Record(ctx, db, now, 14,
		oneFinding("CVE-2026-0001", "containerd", "linux/amd64", "bbbb2222"))
	if err != nil {
		t.Fatal(err)
	}
	if !seen[0].FirstSeen.Equal(now) {
		t.Errorf("a finding against a new digest inherited an old clock: %s", seen[0].FirstSeen)
	}
}

// The digest is normalized before it is stored, for the same reason Match
// normalizes before it compares: `sha256:AAAA` and `aaaa` are one artifact, and
// storing them as two would give one finding two clocks and neither would be
// right.
func TestTheStoredDigestIsNormalized(t *testing.T) {
	db := clockDB(t)
	ctx := context.Background()
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	if _, err := Record(ctx, db, at, 11,
		oneFinding("CVE-2026-0001", "containerd", "linux/amd64", "sha256:AAAA1111")); err != nil {
		t.Fatal(err)
	}
	seen, err := Record(ctx, db, at.AddDate(0, 1, 0), 12,
		oneFinding("CVE-2026-0001", "containerd", "linux/amd64", "aaaa1111"))
	if err != nil {
		t.Fatal(err)
	}
	if !seen[0].FirstSeen.Equal(at) {
		t.Errorf("the same artifact got two clocks: %s, want %s", seen[0].FirstSeen, at)
	}

	var n int
	if err := db.Read().QueryRowContext(ctx,
		`SELECT count(*) FROM advisory_finding`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d rows for one finding", n)
	}
}

// POA&M status is derived on every read and never stored, so changing the
// interval — or recording a decision — cannot leave a stale flag behind.
func TestTheIntervalDecidesAndZeroTurnsItOff(t *testing.T) {
	first := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	k := Known{FirstSeen: first, FeedRevision: 11}
	now := first.AddDate(0, 0, 20)

	if k.POAM(now, 30) {
		t.Error("20 days is a POA&M item under a 30-day interval")
	}
	if !k.POAM(now, 14) {
		t.Error("20 days is not a POA&M item under a 14-day interval")
	}
	// Exactly at the interval counts: "after 14 days" is answered on day 14,
	// not on day 15.
	if !k.POAM(first.AddDate(0, 0, 14), 14) {
		t.Error("the interval is exclusive at its own boundary")
	}
	// An unconfigured interval reports nothing rather than reporting
	// everything, which is what a site that has not set one should get.
	if k.POAM(now, 0) || k.POAM(now, -1) {
		t.Error("an unset interval made everything overdue")
	}
	// A clock that has not started yet is zero days old, not negative.
	if got := (Known{FirstSeen: now}).Days(first); got != 0 {
		t.Errorf("a future sighting reports %d days", got)
	}
}
