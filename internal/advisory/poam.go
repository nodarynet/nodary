package advisory

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
)

// Store is the narrow slice of a database this package needs. An interface so
// a test can drive the clock without a control plane, and so this package does
// not import internal/store to write one table.
type Store interface {
	WriteTx(context.Context, func(*sql.Tx) error) error
}

// Known is a finding this install has seen, with the clock attached.
type Known struct {
	Finding
	// FirstSeen is when a revision carrying this finding first reached *this
	// site*, which is the only defensible answer to "when could you have
	// known". It is not the revision's `generated` stamp: a site that updated
	// to a newer revision would see every clock reset, so being current would
	// make an overdue finding look new.
	FirstSeen time.Time `json:"first_seen"`
	// FeedRevision is the revision that first carried it here.
	FeedRevision int `json:"feed_revision"`
	// Decided is the choice recorded against it, zero when there is none.
	Decided Decision `json:"decided"`
}

// Days is how long this finding has been known here, rounded down.
func (k Known) Days(now time.Time) int {
	d := now.Sub(k.FirstSeen)
	if d < 0 {
		return 0
	}
	return int(d.Hours() / 24)
}

// POAM reports whether this finding has gone undecided long enough to be a
// plan-of-action item.
//
// **Derived, never stored.** R9-17 records the decision that stops this clock;
// nothing writes a "poam" flag, so there is no state to go stale when the
// interval changes or when a decision lands. An interval of zero or less turns
// the reporting off rather than making everything overdue on sight, which is
// what a site that has not configured one should get.
func (k Known) POAM(now time.Time, afterDays int) bool {
	return afterDays > 0 && k.Decided.Open(now) && k.Days(now) >= afterDays
}

// Record notes each finding as seen, and returns them with their clocks.
//
// The first sighting wins: a second run of `advisory check` must not restart a
// clock that has been running for a month. That is the whole reason this is a
// row rather than a recomputation — everything else about a finding is derived
// from the feed and the manifest, and only "since when" cannot be.
//
// It is not an audit mutation. Nobody decided anything by looking, and a verb
// meant to be run on a whim would otherwise bury the chain.
func Record(ctx context.Context, db Store, now time.Time, revision int,
	findings []Finding) ([]Known, error) {

	var out []Known
	// One transaction: a run that recorded half its sightings would leave
	// clocks starting at different moments for findings that arrived together.
	err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		var err error
		out, err = record(ctx, tx, now, revision, findings)
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Advisory.ID != out[j].Advisory.ID {
			return out[i].Advisory.ID < out[j].Advisory.ID
		}
		return out[i].Platform < out[j].Platform
	})
	return out, nil
}

func record(ctx context.Context, tx *sql.Tx, now time.Time, revision int,
	findings []Finding) ([]Known, error) {

	stamp := now.UTC().Format(audit.TimeFormat)
	var out []Known
	for _, f := range findings {
		digest := normalizeDigest(f.Pinned)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO advisory_finding
			   (advisory_id, component, platform, digest, first_seen_at, feed_revision)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT (advisory_id, component, platform, digest) DO NOTHING`,
			f.Advisory.ID, f.Advisory.Component, f.Platform, digest, stamp, revision,
		); err != nil {
			return nil, fmt.Errorf("recording %s: %w", f.Advisory.ID, err)
		}

		// Read back rather than assumed: the row may predate this run by a
		// month, and it may already carry a decision that closes the clock.
		var seen string
		var rev int
		var decision, justification, by, at, review sql.NullString
		if err := tx.QueryRowContext(ctx,
			`SELECT first_seen_at, feed_revision, decision, justification, decided_by,
			        decided_at, review_at
			   FROM advisory_finding
			  WHERE advisory_id = ? AND component = ? AND platform = ? AND digest = ?`,
			f.Advisory.ID, f.Advisory.Component, f.Platform, digest,
		).Scan(&seen, &rev, &decision, &justification, &by, &at, &review); err != nil {
			return nil, fmt.Errorf("reading %s: %w", f.Advisory.ID, err)
		}
		first, err := time.Parse(audit.TimeFormat, seen)
		if err != nil {
			return nil, fmt.Errorf("%s has an unreadable first_seen_at %q: %w",
				f.Advisory.ID, seen, err)
		}
		d := Decision{AdvisoryID: f.Advisory.ID, Component: f.Advisory.Component,
			Platform: f.Platform, Digest: digest, FirstSeen: first, FeedRevision: rev,
			Decision: decision.String, Justification: justification.String, DecidedBy: by.String}
		if d.DecidedAt, err = optTime(at, audit.TimeFormat); err != nil {
			return nil, err
		}
		if d.ReviewAt, err = optTime(review, time.DateOnly); err != nil {
			return nil, err
		}
		out = append(out, Known{Finding: f, FirstSeen: first, FeedRevision: rev, Decided: d})
	}
	return out, nil
}
