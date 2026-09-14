package advisory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
)

// The three decisions, and there is no fourth (pivot §6).
//
// Doing nothing is not among them: that is the state a finding is already in,
// and R9-16's clock exists to make it visible. All three of these close the
// clock, and all three are somebody's name against a choice.
const (
	// DecisionPatch — move to the recommended digest.
	DecisionPatch = "patch"
	// DecisionDefer — not now, with a date it comes back.
	DecisionDefer = "defer"
	// DecisionAccept — this risk is accepted, with the compensating control
	// named in the justification.
	DecisionAccept = "accept"
)

// Decisions is the vocabulary, for a refusal that can name it.
var Decisions = []string{DecisionPatch, DecisionDefer, DecisionAccept}

// ErrNoSuchFinding is a decision about something this install has not seen.
//
// Deliberately not a silent no-op. An operator who mistypes a CVE id and is
// told nothing would believe a decision was recorded, and the row an assessor
// later looks for would not be there.
var ErrNoSuchFinding = errors.New("no such finding")

// Decision is one recorded choice, as it is read back.
type Decision struct {
	AdvisoryID    string     `json:"advisory_id"`
	Component     string     `json:"component"`
	Platform      string     `json:"platform"`
	Digest        string     `json:"digest"`
	FirstSeen     time.Time  `json:"first_seen"`
	FeedRevision  int        `json:"feed_revision"`
	Decision      string     `json:"decision,omitempty"`
	Justification string     `json:"justification,omitempty"`
	DecidedBy     string     `json:"decided_by,omitempty"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
	ReviewAt      *time.Time `json:"review_at,omitempty"`
}

// Open reports whether this finding still needs a decision.
//
// A deferral past its review date is open again, and its clock still runs from
// the original sighting: the months spent deferring are months the finding was
// known, which is what an assessor counts. Without that, one `defer` would be
// a mute button with a date on it.
func (d Decision) Open(now time.Time) bool {
	if d.Decision == "" {
		return true
	}
	return d.Decision == DecisionDefer && d.ReviewAt != nil && !now.Before(*d.ReviewAt)
}

// ValidDecision checks the vocabulary and the one argument that goes with it.
func ValidDecision(decision string, review *time.Time) error {
	if !slices.Contains(Decisions, decision) {
		return fmt.Errorf("%w: %q is not a decision; it is one of %s",
			identity.ErrBadName, decision, strings.Join(Decisions, ", "))
	}
	// A deferral with no date is an acceptance that did not say so, and the
	// difference is exactly what an assessor reads these rows for.
	if decision == DecisionDefer && review == nil {
		return fmt.Errorf("%w: a deferral needs a date it comes back; without one it is an "+
			"acceptance that did not say so", identity.ErrBadName)
	}
	if decision != DecisionDefer && review != nil {
		return fmt.Errorf("%w: only a deferral takes a review date", identity.ErrBadName)
	}
	return nil
}

// Matching are the findings one decision would cover.
//
// An advisory id names a set, not a row: one CVE reaches every platform whose
// pinned digest it matches, and deciding per platform by hand is a way to leave
// one undecided. --platform narrows it when that is genuinely what is meant.
func Matching(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, id, platform string, now time.Time) ([]Decision, error) {

	query := `SELECT advisory_id, component, platform, digest, first_seen_at, feed_revision,
	                 decision, justification, decided_by, decided_at, review_at
	            FROM advisory_finding WHERE advisory_id = ?`
	args := []any{id}
	if platform != "" {
		query += ` AND platform = ?`
		args = append(args, platform)
	}
	rows, err := q.QueryContext(ctx, query+` ORDER BY component, platform, digest`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Decision
	for rows.Next() {
		var d Decision
		var seen string
		var decision, justification, by, at, review sql.NullString
		if err := rows.Scan(&d.AdvisoryID, &d.Component, &d.Platform, &d.Digest, &seen,
			&d.FeedRevision, &decision, &justification, &by, &at, &review); err != nil {
			return nil, err
		}
		if d.FirstSeen, err = time.Parse(audit.TimeFormat, seen); err != nil {
			return nil, fmt.Errorf("%s has an unreadable first_seen_at %q: %w",
				d.AdvisoryID, seen, err)
		}
		d.Decision, d.Justification, d.DecidedBy = decision.String, justification.String, by.String
		if d.DecidedAt, err = optTime(at, audit.TimeFormat); err != nil {
			return nil, err
		}
		if d.ReviewAt, err = optTime(review, time.DateOnly); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		where := ""
		if platform != "" {
			where = " on " + platform
		}
		return nil, fmt.Errorf("%w: %s names no finding this install has seen%s; "+
			"`nodary advisory check` is what records one", ErrNoSuchFinding, id, where)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Platform < out[j].Platform })
	return out, nil
}

func optTime(v sql.NullString, layout string) (*time.Time, error) {
	if !v.Valid || v.String == "" {
		return nil, nil
	}
	t, err := time.Parse(layout, v.String)
	if err != nil {
		return nil, fmt.Errorf("unreadable timestamp %q: %w", v.String, err)
	}
	return &t, nil
}

// Decide records one decision against every finding an advisory matches.
//
// **This one is a mutation and goes through the chain**, unlike Record above:
// somebody chose something, and "the chain already is the remediation record"
// is about exactly this act. No parallel workflow, no approval queue — the
// justification is the ceremony's, because a second justification field would
// mean two answers to the same question and an assessor reading whichever one
// was blank.
func Decide(ctx context.Context, m audit.Mutation, now time.Time,
	id, platform, decision, justification, by string, review *time.Time) (int, error) {

	if err := ValidDecision(decision, review); err != nil {
		return 0, err
	}
	tx := m.Tx()
	found, err := Matching(ctx, tx, id, platform, now)
	if err != nil {
		return 0, err
	}

	var reviewAt any
	if review != nil {
		reviewAt = review.UTC().Format(time.DateOnly)
	}
	var actor any
	if by != "" {
		actor = by
	}
	stamp := now.UTC().Format(audit.TimeFormat)
	for _, f := range found {
		if _, err := tx.ExecContext(ctx,
			`UPDATE advisory_finding
			    SET decision = ?, justification = ?, decided_by = ?, decided_at = ?,
			        review_at = ?
			  WHERE advisory_id = ? AND component = ? AND platform = ? AND digest = ?`,
			decision, justification, actor, stamp, reviewAt,
			f.AdvisoryID, f.Component, f.Platform, f.Digest); err != nil {
			return 0, fmt.Errorf("recording the decision for %s on %s: %w",
				f.AdvisoryID, f.Platform, err)
		}
	}
	m.Detail("findings_decided", len(found))
	m.Detail("decision", decision)
	return len(found), nil
}

// All is every finding this install has seen, decided or not.
//
// The evidence bundle's remediation member (R9-13): what was known, decided, by
// whom, with what justification. Undecided findings are in it too — a plan of
// action is mostly the things nobody has got to yet, and a member that listed
// only the closed ones would be the wrong half.
func All(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]Decision, error) {

	rows, err := q.QueryContext(ctx,
		`SELECT advisory_id, component, platform, digest, first_seen_at, feed_revision,
		        decision, justification, decided_by, decided_at, review_at
		   FROM advisory_finding ORDER BY advisory_id, component, platform, digest`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Decision
	for rows.Next() {
		var d Decision
		var seen string
		var decision, justification, by, at, review sql.NullString
		if err := rows.Scan(&d.AdvisoryID, &d.Component, &d.Platform, &d.Digest, &seen,
			&d.FeedRevision, &decision, &justification, &by, &at, &review); err != nil {
			return nil, err
		}
		if d.FirstSeen, err = time.Parse(audit.TimeFormat, seen); err != nil {
			return nil, err
		}
		d.Decision, d.Justification, d.DecidedBy = decision.String, justification.String, by.String
		if d.DecidedAt, err = optTime(at, audit.TimeFormat); err != nil {
			return nil, err
		}
		if d.ReviewAt, err = optTime(review, time.DateOnly); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
