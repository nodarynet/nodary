package audit

import (
	"context"
	"database/sql"
	"testing"

	"github.com/nodarynet/nodary/internal/store"
)

// prune removes every record at or before seq and records the cut, which is
// what internal/retention does. It is spelled out here rather than imported so
// this package's test does not depend on the one that calls it.
func prune(t *testing.T, db *store.DB, through int64) {
	t.Helper()
	ctx := context.Background()
	hash, ok, err := hashAt(ctx, db, through)
	if err != nil || !ok {
		t.Fatalf("reading the hash at seq %d: %v (found %t)", through, err, ok)
	}
	setAnchor(t, db, sql.NullInt64{Int64: through, Valid: true}, sql.NullString{String: hash, Valid: true})
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM audit WHERE seq <= ?`, through)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func setAnchor(t *testing.T, db *store.DB, seq sql.NullInt64, hash sql.NullString) {
	t.Helper()
	if err := db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(
			`UPDATE installation SET pruned_through_seq = ?, pruned_through_hash = ? WHERE singleton = 1`,
			seq, hash)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// The point of migration 0019: retention is specified behavior, so the chain it
// leaves behind must verify. TestADatabaseMayNotBeAFragment is the other half —
// the same truncation with no anchor is still KindNotGenesis — and the two
// together are the whole claim.
func TestAPrunedDatabaseVerifiesAgainstTheCutItRecorded(t *testing.T) {
	db, _ := chainOf(t, 6)
	prune(t, db, 2)

	res, err := VerifyDB(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a pruned chain did not verify: %v", res.Break)
	}
	if !res.Anchored || !res.Fragment {
		t.Errorf("anchored = %t, fragment = %t; want both", res.Anchored, res.Fragment)
	}
	if res.FirstSeq != 3 || res.Records != 4 {
		t.Errorf("first seq = %d over %d records, want 3 over 4", res.FirstSeq, res.Records)
	}
}

// An anchor is only worth having if it is checked. Each of these is a database
// whose surviving records are internally sound and whose anchor does not
// describe them — which is what deleting more than the anchor admits to looks
// like.
func TestAnAnchorThatDoesNotMeetTheChainIsRefused(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name string
		bend func(t *testing.T, db *store.DB)
	}{
		{"the hash is not the record's", func(t *testing.T, db *store.DB) {
			setAnchor(t, db,
				sql.NullInt64{Int64: 2, Valid: true},
				sql.NullString{String: "00", Valid: true})
		}},
		{"more was removed than the anchor claims", func(t *testing.T, db *store.DB) {
			if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
				_, err := tx.Exec(`DELETE FROM audit WHERE seq = 3`)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			db, _ := chainOf(t, 6)
			prune(t, db, 2)
			c.bend(t, db)

			res, err := VerifyDB(ctx, db)
			if err != nil {
				t.Fatal(err)
			}
			if res.OK() || res.Break.Kind != KindNotAnchored {
				t.Errorf("break = %v, want the chain refused as not joining its anchor", res.Break)
			}
		})
	}
}

// Half an anchor verifies nothing while looking like it does, so it is an error
// rather than a chain that quietly falls back to genesis.
func TestAHalfWrittenAnchorIsRefusedOutright(t *testing.T) {
	db, _ := chainOf(t, 3)
	setAnchor(t, db, sql.NullInt64{Int64: 1, Valid: true}, sql.NullString{})

	if _, err := VerifyDB(context.Background(), db); err == nil {
		t.Fatal("a half-written anchor was accepted")
	}
}
