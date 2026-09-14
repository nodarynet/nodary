package advisory

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/store"
)

// seeded gives a database holding one finding, first seen `ago` before now.
func seeded(t *testing.T, id string, ago time.Duration) (*store.DB, time.Time) {
	t.Helper()
	db := clockDB(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if _, err := Record(context.Background(), db, now.Add(-ago), 11,
		oneFinding(id, "containerd", "linux/amd64", "aaaa1111")); err != nil {
		t.Fatal(err)
	}
	return db, now
}

// decider runs Decide inside a real audit mutation, because audit.Mutation is
// unimplementable outside its own package — which is the mechanism, not an
// inconvenience.
func decider(t *testing.T, db *store.DB) func(now time.Time, id, platform, decision,
	justification string, review *time.Time) error {
	t.Helper()
	delivery := audit.NewDelivery(nil, audit.Warn, io.Discard)
	t.Cleanup(func() { delivery.Close() })
	log := audit.New(db, delivery)
	root := identity.LocalRoot()
	root.Actor.ID = "test"

	return func(now time.Time, id, platform, decision, justification string,
		review *time.Time) error {
		_, err := log.Act(context.Background(),
			audit.Request{Actor: root.Actor, Action: "advisory.decide"},
			func(m audit.Mutation) error {
				_, err := Decide(context.Background(), m, now, id, platform,
					decision, justification, "", review)
				return err
			})
		return err
	}
}

// The vocabulary is three words and there is no fourth, because the fourth —
// doing nothing — is the state the finding is already in.
func TestTheDecisionVocabularyIsClosed(t *testing.T) {
	when := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		decision string
		review   *time.Time
		ok       bool
	}{
		{DecisionPatch, nil, true},
		{DecisionAccept, nil, true},
		{DecisionDefer, &when, true},
		// A deferral with no date is an acceptance that did not say so, and the
		// difference is what these rows are read for.
		{DecisionDefer, nil, false},
		// Only a deferral comes back.
		{DecisionAccept, &when, false},
		{"ignore", nil, false},
		{"", nil, false},
	} {
		err := ValidDecision(c.decision, c.review)
		if (err == nil) != c.ok {
			t.Errorf("%q with review=%v: %v", c.decision, c.review != nil, err)
		}
	}
}

// A decision closes the clock. That is the whole of R9-17: the finding does not
// go away, it stops being one nobody has looked at.
func TestADecisionClosesTheClock(t *testing.T) {
	db, now := seeded(t, "CVE-2026-0001", 60*24*time.Hour)
	ctx := context.Background()
	decide := decider(t, db)

	open, err := Matching(ctx, db.Read(), "CVE-2026-0001", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if !open[0].Open(now) {
		t.Fatal("an undecided finding is not open")
	}

	if err := decide(now, "CVE-2026-0001", "", DecisionAccept,
		"no default route, no DNS, loopback only; verify-egress asserts it", nil); err != nil {
		t.Fatal(err)
	}

	after, err := Matching(ctx, db.Read(), "CVE-2026-0001", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if after[0].Open(now) {
		t.Error("an accepted finding is still open")
	}
	if after[0].Justification == "" {
		t.Error("the justification was not recorded, which is what the row is for")
	}
	// The clock keeps running underneath — the finding was known for sixty days
	// and the record should still say so — it is simply no longer undecided.
	k := Known{FirstSeen: after[0].FirstSeen, Decided: after[0]}
	if k.Days(now) < 59 {
		t.Errorf("the decision rewrote the clock: %d days", k.Days(now))
	}
	if k.POAM(now, 30) {
		t.Error("a decided finding is still a POA&M item")
	}
}

// A deferral is not a mute button. It comes back, and the months spent deferring
// are months the finding was known — which is what an assessor counts.
func TestADeferralComesBackWithItsOriginalClock(t *testing.T) {
	db, now := seeded(t, "CVE-2026-0002", 40*24*time.Hour)
	ctx := context.Background()
	decide := decider(t, db)

	review := now.AddDate(0, 3, 0)
	if err := decide(now, "CVE-2026-0002", "", DecisionDefer,
		"upstream has no fix; revisit at the next maintenance window", &review); err != nil {
		t.Fatal(err)
	}

	got, err := Matching(ctx, db.Read(), "CVE-2026-0002", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Open(now) {
		t.Error("a live deferral is open")
	}
	// The day it comes back, and every day after.
	if !got[0].Open(review) || !got[0].Open(review.AddDate(0, 1, 0)) {
		t.Error("a deferral past its review date did not reopen")
	}
	// And the clock still runs from the first sighting, not from the deferral.
	later := review.AddDate(0, 0, 1)
	k := Known{FirstSeen: got[0].FirstSeen, Decided: got[0]}
	if !k.POAM(later, 30) {
		t.Errorf("a reopened deferral known %d days is not a POA&M item", k.Days(later))
	}
}

// Deciding something this install has never seen is a refusal, not a silent
// no-op: an operator who mistypes a CVE id would otherwise believe a decision
// was recorded, and the row an assessor looks for would not be there.
func TestDecidingAnUnknownAdvisoryIsRefused(t *testing.T) {
	db, now := seeded(t, "CVE-2026-0003", time.Hour)
	decide := decider(t, db)

	err := decide(now, "CVE-2026-9999", "", DecisionAccept, "a typo", nil)
	if !errors.Is(err, ErrNoSuchFinding) {
		t.Fatalf("a decision about nothing returned %v", err)
	}
	// Narrowing to a platform the advisory does not reach is the same mistake.
	if err := decide(now, "CVE-2026-0003", "linux/arm64", DecisionAccept, "x", nil); !errors.Is(
		err, ErrNoSuchFinding) {
		t.Errorf("a decision against the wrong platform returned %v", err)
	}
}

// One advisory id names a set, not a row: a CVE reaches every platform whose
// pinned digest it matches, and deciding per platform by hand is a way to leave
// one undecided.
func TestOneDecisionCoversEveryPlatformTheAdvisoryReaches(t *testing.T) {
	db := clockDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	both := []Finding{
		{Advisory: Advisory{ID: "CVE-2026-0004", Component: "runc"},
			Pinned: "aaaa1111", Platform: "linux/amd64"},
		{Advisory: Advisory{ID: "CVE-2026-0004", Component: "runc"},
			Pinned: "bbbb2222", Platform: "linux/arm64"},
	}
	if _, err := Record(ctx, db, now, 11, both); err != nil {
		t.Fatal(err)
	}

	if err := decider(t, db)(now, "CVE-2026-0004", "", DecisionPatch,
		"moving to the recommended digest at the next window", nil); err != nil {
		t.Fatal(err)
	}
	got, err := Matching(ctx, db.Read(), "CVE-2026-0004", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want two findings, got %d", len(got))
	}
	for _, f := range got {
		if f.Decision != DecisionPatch {
			t.Errorf("%s was left undecided", f.Platform)
		}
	}

	// And --platform narrows it when that is genuinely what is meant.
	one, err := Matching(ctx, db.Read(), "CVE-2026-0004", "linux/arm64", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 1 || one[0].Platform != "linux/arm64" {
		t.Errorf("--platform did not narrow: %+v", one)
	}
}
