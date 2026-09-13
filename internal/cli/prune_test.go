package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/store"
)

const stampFormat = "2006-01-02T15:04:05.000Z"

// oldUsage writes metering rows dated well past any retention window. They are
// inserted rather than served because usage rows carry no hash — unlike audit
// records, which cannot be backdated without breaking the chain that makes
// them worth keeping.
//
// user_id is left null on purpose: it is nullable in the schema, and the
// aggregate's primary key includes it, so this is the path where SQL's "two
// nulls do not conflict" rule applies.
func (a *appliance) oldUsage(t *testing.T, days, n int) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ts := time.Now().AddDate(0, 0, -days).UTC().Format(stampFormat)
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		for i := range n {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO usage (id, ts, model_id, prompt_tokens, completion_tokens, status)
				 VALUES (?, ?, 'demo/model', 3, 2, 200)`,
				"use_"+ts+string(rune('a'+i)), ts); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func (a *appliance) scalar(t *testing.T, q string) string {
	t.Helper()
	db, err := store.Open(context.Background(), a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v sql.NullString
	if err := db.Read().QueryRowContext(context.Background(), q).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v.String
}

func TestPruneRollsUsageUpAndSaysSoInTheRecord(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "operator")
	a.oldUsage(t, 200, 3)
	a.oldUsage(t, 2, 1)

	code, _, stderr := a.run("prune", "--yes", "--justify", "quarterly retention pass")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "3 usage rows rolled into 1 daily row") {
		t.Errorf("stderr = %q", stderr)
	}

	if n := a.scalar(t, `SELECT count(*) FROM usage`); n != "1" {
		t.Errorf("%s raw rows left, want the one inside the window", n)
	}
	if n := a.scalar(t, `SELECT requests FROM usage_daily`); n != "3" {
		t.Errorf("aggregate requests = %s, want 3", n)
	}

	// The record has to name the range, not just that something happened:
	// that is R2-14's whole `done:` criterion.
	var detail map[string]any
	raw := a.scalar(t, `SELECT detail_json FROM audit WHERE action = 'data.prune' ORDER BY seq DESC LIMIT 1`)
	if err := json.Unmarshal([]byte(raw), &detail); err != nil {
		t.Fatalf("detail = %q: %v", raw, err)
	}
	for _, k := range []string{"usage_before", "usage_rows", "usage_rolled_into", "usage_retention_days", "audit_retention_days"} {
		if _, ok := detail[k]; !ok {
			t.Errorf("the record does not carry %s: %v", k, detail)
		}
	}
	if detail["usage_rows"] != float64(3) {
		t.Errorf("usage_rows = %v, want 3", detail["usage_rows"])
	}
}

// Plan exists so the ceremony can preview inside a read-only transaction. If it
// wrote anything, the preview an operator declines would already have happened.
func TestADeclinedPruneChangesNothing(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "operator")
	a.oldUsage(t, 200, 2)

	code, stdout, stderr := a.run("prune", "--dry-run", "--justify", "checking what would go")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	if !strings.Contains(stdout+stderr, "usage_rows") {
		t.Errorf("the preview did not name what would be removed: %q / %q", stdout, stderr)
	}
	if n := a.scalar(t, `SELECT count(*) FROM usage`); n != "2" {
		t.Errorf("%s usage rows left after a dry run, want 2", n)
	}
	if n := a.scalar(t, `SELECT count(*) FROM audit WHERE action = 'data.prune'`); n != "0" {
		t.Errorf("a dry run wrote %s prune records", n)
	}
}

// A pass with nothing to do is still an act, and still recorded. A retention
// history with gaps in it cannot be told from one that was edited.
func TestAPruneThatRemovesNothingIsStillRecorded(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "operator")

	code, _, stderr := a.run("prune", "--yes", "--justify", "scheduled pass")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "nothing was old enough to remove") {
		t.Errorf("stderr = %q", stderr)
	}
	if n := a.scalar(t, `SELECT count(*) FROM audit WHERE action = 'data.prune'`); n != "1" {
		t.Errorf("%s prune records, want 1", n)
	}
}

// The chain is the product's claim, so the verb that can cut it must leave it
// verifying by the product's own verifier.
func TestTheChainStillVerifiesAfterAPrune(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "operator")
	a.oldUsage(t, 200, 2)

	if code, _, stderr := a.run("prune", "--yes", "--justify", "retention"); code != ExitOK {
		t.Fatalf("prune: exit %d: %s", code, stderr)
	}
	code, stdout, stderr := a.run("audit", "verify")
	if code != ExitOK {
		t.Fatalf("audit verify: exit %d: %s\n%s", code, stderr, stdout)
	}
}
