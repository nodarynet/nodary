package retention

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/store"
)

var now = time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

func daysAgo(n int) time.Time { return now.AddDate(0, 0, -n) }

func openDB(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "nodary.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// record appends one audit record stamped at a chosen time, which is the whole
// point: retention is about age, so the fixtures have to be old.
func record(t *testing.T, db *store.DB, at time.Time) audit.Record {
	t.Helper()
	r, err := audit.Append(context.Background(), db, audit.Entry{
		TS:      at,
		Actor:   audit.Actor{ID: "root", Method: "local"},
		Source:  audit.Source{Version: "0.0.1-rc1"},
		Action:  "model.register",
		Outcome: audit.OutcomeSuccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var usageSeq int

func nextUsageID() string {
	usageSeq++
	return fmt.Sprintf("use_%012d", usageSeq)
}

func usageRow(t *testing.T, db *store.DB, at time.Time, user, model string, prompt, completion int64) {
	t.Helper()
	// usage.user_id is a foreign key, so the row has to belong to somebody.
	exec(t, db, `INSERT OR IGNORE INTO user (id, name, role, state, created_at)
	             VALUES (?, ?, 'user', 'active', ?)`, user, user, stamp(daysAgo(365)))
	exec(t, db, `INSERT INTO usage (id, ts, user_id, model_id, prompt_tokens, completion_tokens, status)
	             VALUES (?, ?, ?, ?, ?, ?, 200)`,
		nextUsageID(), stamp(at), user, model, prompt, completion)
}

func exec(t *testing.T, db *store.DB, q string, args ...any) {
	t.Helper()
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), q, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// prune runs one pass in its own transaction, standing in for the audited
// mutation the CLI wraps it in.
func prune(t *testing.T, db *store.DB, w Window) Removed {
	t.Helper()
	var r Removed
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		var err error
		r, err = Prune(context.Background(), tx, w, now)
		return err
	}); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	return r
}

func count(t *testing.T, db *store.DB, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.Read().QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The spec's usage row: raw past the window, rolled into the daily aggregate
// rather than discarded, because usage_daily is what long-range reporting is
// built on once the rows behind it are gone.
func TestUsagePastTheWindowIsRolledUpAndNotMerelyDeleted(t *testing.T) {
	db := openDB(t)
	usageRow(t, db, daysAgo(100), "usr_a", "m", 10, 5)
	usageRow(t, db, daysAgo(100), "usr_a", "m", 7, 3)
	usageRow(t, db, daysAgo(99), "usr_b", "m", 1, 1)
	usageRow(t, db, daysAgo(10), "usr_a", "m", 1000, 1000)

	r := prune(t, db, Window{AuditDays: 1095, UsageDays: 90})

	if r.UsageRows != 3 || r.UsageGroups != 2 {
		t.Errorf("removed %d rows over %d days, want 3 over 2", r.UsageRows, r.UsageGroups)
	}
	if n := count(t, db, `SELECT count(*) FROM usage`); n != 1 {
		t.Errorf("%d raw rows survived, want the one inside the window", n)
	}
	// The two same-day rows for one user and model became one aggregate, summed.
	got := count(t, db, `SELECT requests FROM usage_daily WHERE day = ? AND user_id = 'usr_a'`,
		daysAgo(100).Format("2006-01-02"))
	if got != 2 {
		t.Errorf("requests = %d, want the two rolled rows counted", got)
	}
	if tok := count(t, db, `SELECT prompt_tokens FROM usage_daily WHERE day = ? AND user_id = 'usr_a'`,
		daysAgo(100).Format("2006-01-02")); tok != 17 {
		t.Errorf("prompt tokens = %d, want 17 summed", tok)
	}
}

// A second pass over a day the first one already wrote must add to the row, not
// replace it — otherwise a prune interrupted halfway loses everything it had
// already accounted for.
func TestASecondRollupOfOneDayAddsToIt(t *testing.T) {
	db := openDB(t)
	usageRow(t, db, daysAgo(100), "usr_a", "m", 10, 5)
	prune(t, db, Window{AuditDays: 1095, UsageDays: 90})
	usageRow(t, db, daysAgo(100), "usr_a", "m", 4, 2)
	prune(t, db, Window{AuditDays: 1095, UsageDays: 90})

	if n := count(t, db, `SELECT count(*) FROM usage_daily`); n != 1 {
		t.Fatalf("%d aggregate rows, want one merged", n)
	}
	if tok := count(t, db, `SELECT prompt_tokens FROM usage_daily`); tok != 14 {
		t.Errorf("prompt tokens = %d, want 14", tok)
	}
}

// The floor, which is the reason Window carries two numbers. A short usage
// window must not reach the chain: this is the bug where one cutoff is computed
// and passed to everything.
func TestAShortUsageWindowDoesNotReachTheChain(t *testing.T) {
	db := openDB(t)
	old := record(t, db, daysAgo(200))
	record(t, db, daysAgo(1))
	usageRow(t, db, daysAgo(200), "usr_a", "m", 1, 1)

	r := prune(t, db, Window{AuditDays: 1095, UsageDays: 1})

	if r.UsageRows != 1 {
		t.Errorf("usage rows removed = %d, want the 200-day-old one", r.UsageRows)
	}
	if r.AuditThrough != 0 {
		t.Fatalf("the chain was pruned through seq %d under a 1095-day floor", r.AuditThrough)
	}
	if n := count(t, db, `SELECT count(*) FROM audit WHERE seq = ?`, old.Seq); n != 1 {
		t.Error("a record inside the audit window was removed")
	}
}

// Pruning the chain is only defensible if what is left still verifies, which is
// migration 0019's whole argument. Any other outcome is the product reporting
// its own retention job as tampering.
func TestAPrunedChainStillVerifies(t *testing.T) {
	db := openDB(t)
	for _, d := range []int{400, 399, 398, 20, 1} {
		record(t, db, daysAgo(d))
	}

	r := prune(t, db, Window{AuditDays: 90, UsageDays: 90})

	if r.AuditFrom != 1 || r.AuditThrough != 3 {
		t.Fatalf("removed seq %d–%d, want 1–3", r.AuditFrom, r.AuditThrough)
	}
	res, err := audit.VerifyDB(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("the chain did not verify after a prune: %v", res.Break)
	}
	if !res.Anchored || res.FirstSeq != 4 {
		t.Errorf("anchored = %t from seq %d, want true from 4", res.Anchored, res.FirstSeq)
	}
}

// audit.KindClockWentBack exists because a clock does go back. One stale
// timestamp among younger records must not drag them out with it: the prefix is
// decided by sequence, where the chain's own order lives.
func TestOneStaleTimestampDoesNotDragYoungerRecordsOut(t *testing.T) {
	db := openDB(t)
	record(t, db, daysAgo(400)) // seq 1, genuinely old
	record(t, db, daysAgo(2))   // seq 2, inside the window
	record(t, db, daysAgo(400)) // seq 3, a clock that went back
	record(t, db, daysAgo(1))   // seq 4

	r := prune(t, db, Window{AuditDays: 90, UsageDays: 90})

	if r.AuditThrough != 1 {
		t.Fatalf("pruned through seq %d, want 1 — the prefix stops at the first record worth keeping", r.AuditThrough)
	}
	if n := count(t, db, `SELECT count(*) FROM audit WHERE seq = 3`); n != 1 {
		t.Error("a record was removed for a timestamp its sequence contradicts")
	}
}

// The chain always keeps a tail, whatever the window says. The prune's own
// record is appended to this same transaction and needs a predecessor; an
// emptied table would restart it at genesis while the anchor said otherwise.
func TestPruningNeverEmptiesTheChain(t *testing.T) {
	db := openDB(t)
	for _, d := range []int{400, 399, 398} {
		record(t, db, daysAgo(d))
	}

	prune(t, db, Window{AuditDays: 90, UsageDays: 90})

	if n := count(t, db, `SELECT count(*) FROM audit`); n != 1 {
		t.Fatalf("%d records left, want the tail kept", n)
	}
	res, err := audit.VerifyDB(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Errorf("the remaining tail did not verify: %v", res.Break)
	}
}

func TestJoinTokensArePurgedADayAfterExpiry(t *testing.T) {
	db := openDB(t)
	for name, expires := range map[string]time.Time{
		"jt_stale":   now.Add(-25 * time.Hour),
		"jt_expired": now.Add(-23 * time.Hour),
		"jt_live":    now.Add(time.Hour),
	} {
		exec(t, db, `INSERT INTO join_token (id, hash, prefix, uses_left, expires_at, created_by, created_at)
		             VALUES (?, ?, 'nodary_jt_abc', 1, ?, 'root', ?)`,
			name, fmt.Sprintf("%064d", len(name)), stamp(expires), stamp(daysAgo(1)))
	}

	r := prune(t, db, Window{AuditDays: 1095, UsageDays: 90})

	if r.JoinTokens != 1 {
		t.Errorf("purged %d join tokens, want 1", r.JoinTokens)
	}
	if n := count(t, db, `SELECT count(*) FROM join_token WHERE id = 'jt_expired'`); n != 1 {
		t.Error("a token expired within the grace window was purged early")
	}
	if n := count(t, db, `SELECT count(*) FROM join_token WHERE id = 'jt_stale'`); n != 0 {
		t.Error("a token a day past expiry survived")
	}
}

// The ceremony shows an operator what Plan found and then applies what Prune
// does. If those disagree, the attestation is describing something other than
// what happened — which is the one failure the ceremony exists to prevent.
func TestThePreviewMatchesWhatIsRemoved(t *testing.T) {
	db := openDB(t)
	for _, d := range []int{400, 399, 398, 20, 1} {
		record(t, db, daysAgo(d))
	}
	for _, d := range []int{200, 200, 150, 3} {
		usageRow(t, db, daysAgo(d), "usr_a", "m", 2, 1)
	}
	exec(t, db, `INSERT INTO join_token (id, hash, prefix, uses_left, expires_at, created_by, created_at)
	             VALUES ('jt_old', ?, 'nodary_jt_a', 1, ?, 'root', ?)`,
		fmt.Sprintf("%064d", 1), stamp(now.Add(-48*time.Hour)), stamp(daysAgo(9)))

	var planned, done Removed
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		var err error
		if planned, err = Plan(context.Background(), tx, Window{AuditDays: 90, UsageDays: 90}, now); err != nil {
			return err
		}
		done, err = Prune(context.Background(), tx, Window{AuditDays: 90, UsageDays: 90}, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if planned != done {
		t.Errorf("the preview and the act disagree:\n plan  %+v\n prune %+v", planned, done)
	}
	if !planned.Any() || planned.UsageRows != 3 || planned.JoinTokens != 1 || planned.AuditThrough != 3 {
		t.Errorf("plan = %+v, want 3 usage rows, 1 token and the chain cut at 3", planned)
	}
}

// A pass with nothing to do still reports cleanly, and still writes its record
// when the CLI wraps it: that it ran and found nothing is the fact that makes a
// gap in the chain's prune history mean something.
func TestAnEmptyDatabasePrunesToNothing(t *testing.T) {
	db := openDB(t)
	r := prune(t, db, Window{AuditDays: 1095, UsageDays: 90})
	if r.Any() {
		t.Errorf("removed %+v from an empty database", r)
	}
}

// audit.Log.Act runs the mutation and then appends the record describing it to
// the same transaction, so the prune's own record lands on a chain this pass
// has just cut. That record must chain to what survived, not restart at
// genesis — which is what would happen if the prune had emptied the table, and
// it would leave the anchor describing a chain that no longer exists.
//
// This is the shape internal/cli's `prune` produces, minus the ceremony.
func TestThePrunesOwnRecordChainsToWhatSurvived(t *testing.T) {
	db := openDB(t)
	for _, d := range []int{400, 399, 398, 397} {
		record(t, db, daysAgo(d))
	}

	ctx := context.Background()
	var written audit.Record
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		r, err := Prune(ctx, tx, Window{AuditDays: 90, UsageDays: 90}, now)
		if err != nil {
			return err
		}
		written, err = audit.AppendTx(tx, audit.Entry{
			TS:      now,
			Actor:   audit.Actor{ID: "root", Method: "local"},
			Source:  audit.Source{Version: "0.0.1-rc1"},
			Action:  "data.prune",
			Outcome: audit.OutcomeSuccess,
			Detail:  map[string]any{"audit_seq_through": r.AuditThrough},
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if written.Seq != 5 {
		t.Errorf("the prune's record is seq %d, want 5 — it restarted the chain", written.Seq)
	}
	res, err := audit.VerifyDB(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("the chain did not verify after pruning and recording it: %v", res.Break)
	}
	if !res.Anchored || res.FirstSeq != 4 || res.LastSeq != 5 {
		t.Errorf("anchored = %t over seq %d-%d, want true over 4-5", res.Anchored, res.FirstSeq, res.LastSeq)
	}
}

// usage.user_id and usage.model_id are nullable; usage_daily's are not, because
// they are its primary key and a STRICT table makes those NOT NULL. One
// unattributed request used to fail the whole pass on a constraint error,
// taking the join tokens and the chain down with it.
func TestUnattributedUsageRollsUpRatherThanFailingThePass(t *testing.T) {
	db := openDB(t)
	usageRow(t, db, daysAgo(100), "usr_a", "m", 5, 5)
	exec(t, db, `INSERT INTO usage (id, ts, prompt_tokens, completion_tokens, status)
	             VALUES (?, ?, 4, 1, 400)`, nextUsageID(), stamp(daysAgo(100)))

	r := prune(t, db, Window{AuditDays: 1095, UsageDays: 90})

	if r.UsageRows != 2 || r.UsageGroups != 2 {
		t.Fatalf("removed %d rows into %d groups, want 2 and 2", r.UsageRows, r.UsageGroups)
	}
	if tok := count(t, db, `SELECT prompt_tokens FROM usage_daily WHERE user_id = '' AND model_id = ''`); tok != 4 {
		t.Errorf("the unattributed row landed as %d prompt tokens, want 4", tok)
	}
}
