// Package retention removes what docs/specs/08-data-model.md §3 says is no
// longer kept.
//
// It takes a transaction rather than a database, because the one thing this
// must never be is quiet: "a retention job that silently deletes evidence is
// indistinguishable from tampering" is R2-14's `done:` criterion, and the way
// it is met is that the deletes and the audit record naming what they removed
// commit together or not at all (audit.Log.Act).
package retention

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
)

// joinTokenGrace is how long a join token outlives its own expiry before it is
// purged. docs/specs/08-data-model.md §3 names 24h. An expired token grants
// nothing, so this is about being able to see one that was used or missed in
// the hours afterwards, not about the token still working.
const joinTokenGrace = 24 * time.Hour

// Window is how long each table keeps rows, from the active policy profile.
//
// Two numbers rather than one, and they are not interchangeable: the whole
// point of the audit floor is that a shorter window somewhere else can never
// reach the chain.
type Window struct {
	AuditDays int
	UsageDays int
}

// Removed is what one prune took out, in the terms the audit record uses.
type Removed struct {
	// AuditFrom and AuditThrough are the sequence range removed, inclusive.
	// Zero means the chain was not touched.
	AuditFrom    int64
	AuditThrough int64
	// AuditAnchor is the hash of the last removed record, which is what the
	// surviving chain is verified against afterwards (migration 0019).
	AuditAnchor string

	// UsageRows is raw rows removed, UsageGroups the aggregate rows they were
	// rolled into. Both, because one row standing for a thousand is the point.
	UsageRows   int64
	UsageGroups int64
	JoinTokens  int64

	// UsageBefore and AuditBefore are the cutoffs this pass used. They are what
	// makes the audit record name a *range* rather than a count, which is
	// R2-14's `done:` criterion.
	UsageBefore string
	AuditBefore string
}

// Any reports whether the prune had anything to do. A prune that removed
// nothing still writes its record — that it ran and found nothing is a fact
// worth the same line as any other — but a caller may want to say so.
func (r Removed) Any() bool {
	return r.AuditThrough > 0 || r.UsageRows > 0 || r.JoinTokens > 0
}

// Prune applies every retention rule in docs/specs/08-data-model.md §3's table.
//
// revision and usage_daily are absent because that table gives them no window:
// both are indefinite, and usage_daily is the thing usage is rolled *into*.
func Prune(ctx context.Context, tx *sql.Tx, w Window, now time.Time) (Removed, error) {
	r, err := start(w, now)
	if err != nil {
		return Removed{}, err
	}
	if err := pruneUsage(ctx, tx, &r); err != nil {
		return Removed{}, err
	}
	if err := pruneJoinTokens(ctx, tx, stamp(now.Add(-joinTokenGrace)), &r); err != nil {
		return Removed{}, err
	}
	if err := pruneAudit(ctx, tx, &r); err != nil {
		return Removed{}, err
	}
	return r, nil
}

// Plan reports what Prune would remove, changing nothing.
//
// It exists because the attestation ceremony previews inside a read-only
// transaction (core.preview), so the render cannot be Prune itself. Both sides
// resolve the same cutoffs through start and the same prefix through
// auditPrefix, which is what keeps the preview an operator approves and the
// delete they get from drifting apart.
//
// Stable across the two renders the ceremony requires: every cutoff is behind
// `now`, so rows written while the operator reads the preview are newer than
// all of them and change no count.
func Plan(ctx context.Context, tx *sql.Tx, w Window, now time.Time) (Removed, error) {
	r, err := start(w, now)
	if err != nil {
		return Removed{}, err
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*), count(DISTINCT substr(ts, 1, 10) || '|' || coalesce(user_id, '') || '|' || coalesce(model_id, ''))
		  FROM usage WHERE ts < ?`, r.UsageBefore).Scan(&r.UsageRows, &r.UsageGroups); err != nil {
		return Removed{}, fmt.Errorf("counting the usage to roll up: %w", err)
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM join_token WHERE expires_at < ?`,
		stamp(now.Add(-joinTokenGrace))).Scan(&r.JoinTokens); err != nil {
		return Removed{}, fmt.Errorf("counting expired join tokens: %w", err)
	}
	if err := auditPrefix(ctx, tx, &r); err != nil {
		return Removed{}, err
	}
	return r, nil
}

// start validates the windows and fixes the cutoffs for one pass, so the two
// halves of a ceremony cannot compute them differently.
func start(w Window, now time.Time) (Removed, error) {
	if w.AuditDays < 1 || w.UsageDays < 1 {
		return Removed{}, fmt.Errorf("retention windows must be at least a day, not audit=%d usage=%d",
			w.AuditDays, w.UsageDays)
	}
	return Removed{
		UsageBefore: before(now, w.UsageDays),
		AuditBefore: before(now, w.AuditDays),
	}, nil
}

func before(now time.Time, days int) string {
	return stamp(now.Add(-time.Duration(days) * 24 * time.Hour))
}

// stamp renders a cutoff the way every table stores its timestamps, which is
// what makes a string comparison the right one: audit.TimeFormat is fixed-width
// UTC, so lexical order is chronological order.
func stamp(t time.Time) string { return t.UTC().Format(audit.TimeFormat) }

// pruneUsage rolls raw rows into the daily aggregate and then drops them.
//
// Rolled first and in the same transaction, so there is no window in which the
// rows are gone and the total they contributed to is not yet written.
func pruneUsage(ctx context.Context, tx *sql.Tx, r *Removed) error {
	// The WHERE clause is load-bearing beyond selecting rows: SQLite cannot
	// tell an upsert's ON from a join's ON in an INSERT ... SELECT without one.
	//
	// ponytail: a usage row with a null user or model conflicts with nothing —
	// SQL treats two nulls as distinct — so a second prune touching the same
	// day appends a row instead of merging into it. Every reader of usage_daily
	// sums, so the totals stay right; give the aggregate a non-null sentinel
	// key if a reader ever needs to address one row.
	rolled, err := tx.ExecContext(ctx, `
		INSERT INTO usage_daily (day, user_id, model_id, requests, prompt_tokens, completion_tokens)
		SELECT substr(ts, 1, 10), user_id, model_id, count(*), sum(prompt_tokens), sum(completion_tokens)
		  FROM usage
		 WHERE ts < ?
		 GROUP BY substr(ts, 1, 10), user_id, model_id
		    ON CONFLICT (day, user_id, model_id) DO UPDATE SET
		       requests          = requests + excluded.requests,
		       prompt_tokens     = prompt_tokens + excluded.prompt_tokens,
		       completion_tokens = completion_tokens + excluded.completion_tokens`, r.UsageBefore)
	if err != nil {
		return fmt.Errorf("rolling usage into the daily aggregate: %w", err)
	}
	r.UsageGroups, _ = rolled.RowsAffected()

	dropped, err := tx.ExecContext(ctx, `DELETE FROM usage WHERE ts < ?`, r.UsageBefore)
	if err != nil {
		return fmt.Errorf("pruning usage: %w", err)
	}
	r.UsageRows, _ = dropped.RowsAffected()
	return nil
}

func pruneJoinTokens(ctx context.Context, tx *sql.Tx, cutoff string, r *Removed) error {
	res, err := tx.ExecContext(ctx, `DELETE FROM join_token WHERE expires_at < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("purging expired join tokens: %w", err)
	}
	r.JoinTokens, _ = res.RowsAffected()
	return nil
}

// auditPrefix resolves the longest prefix of the chain that is entirely older
// than the cutoff, reading only. Leaves AuditThrough at zero when there is
// nothing to remove.
//
// **A prefix by sequence, bounded by the first record young enough to keep —
// not every record with an old timestamp.** Those differ exactly when a clock
// went backwards, which audit.KindClockWentBack exists because it happens: one
// old-stamped record among younger ones would otherwise drag everything before
// it out with it, deleting records inside the window the profile protects. The
// floor is what this is for, so it is enforced against sequence, where the
// chain's own order lives, rather than against a timestamp anyone's NTP daemon
// can move.
//
// The tail is always kept. The prune's own audit record is appended to the same
// transaction after pruneAudit returns (audit.Log.Act), and it must have a
// predecessor to chain to — an emptied table would restart it at genesis while
// the anchor said otherwise, so the prune would refuse to verify itself.
func auditPrefix(ctx context.Context, tx *sql.Tx, r *Removed) error {
	var keepFrom int64
	err := tx.QueryRowContext(ctx,
		`SELECT seq FROM audit WHERE ts >= ? ORDER BY seq LIMIT 1`, r.AuditBefore).Scan(&keepFrom)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Every record is older than the cutoff. Keep the last one anyway.
		if err := tx.QueryRowContext(ctx,
			`SELECT seq FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&keepFrom); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil // an empty chain
			}
			return fmt.Errorf("reading the end of the chain: %w", err)
		}
	case err != nil:
		return fmt.Errorf("finding where the audit window starts: %w", err)
	}
	if keepFrom <= 1 {
		return nil
	}

	var (
		from   int64
		anchor string
	)
	if err := tx.QueryRowContext(ctx,
		`SELECT min(seq), (SELECT hash FROM audit WHERE seq = ?) FROM audit WHERE seq < ?`,
		keepFrom-1, keepFrom).Scan(&from, &anchor); err != nil {
		return fmt.Errorf("reading the range to remove: %w", err)
	}
	if anchor == "" {
		return fmt.Errorf("the record at seq %d carries no hash to anchor the chain to", keepFrom-1)
	}

	r.AuditFrom, r.AuditThrough, r.AuditAnchor = from, keepFrom-1, anchor
	return nil
}

// pruneAudit removes that prefix and records where it cut.
func pruneAudit(ctx context.Context, tx *sql.Tx, r *Removed) error {
	if err := auditPrefix(ctx, tx, r); err != nil || r.AuditThrough == 0 {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM audit WHERE seq <= ?`, r.AuditThrough); err != nil {
		return fmt.Errorf("pruning the chain: %w", err)
	}
	// Written after the delete and in the same transaction: the anchor and the
	// chain it describes are never separately observable.
	if _, err := tx.ExecContext(ctx,
		`UPDATE installation SET pruned_through_seq = ?, pruned_through_hash = ? WHERE singleton = 1`,
		r.AuditThrough, r.AuditAnchor); err != nil {
		return fmt.Errorf("recording where the chain was cut: %w", err)
	}
	return nil
}
