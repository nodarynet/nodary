package observed

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/store"
)

// TestHeartbeatConsumesAnAckedResetRequest is R4-35/R4-36's ack half:
// `nodary model restage`/`unstage` leaves a row in `stage_reset` for the
// agent to act on, and the agent reports back which models it actually
// discarded on its next heartbeat. That report should consume exactly the
// rows it names, leaving an unrelated one untouched.
func TestHeartbeatConsumesAnAckedResetRequest(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Format(audit.TimeFormat)
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node (name, state, created_at) VALUES (?, 'approved', ?)`, "gpu-01", now); err != nil {
			return err
		}
		for _, id := range []string{"acme/tiny", "acme/other"} {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO model (id, backend, source, artifact, created_at) VALUES (?, 'vllm', 'remote', 'hf-cache', ?)`,
				id, now); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO stage_reset (node_name, model_id, requested_at) VALUES (?, ?, ?)`,
				"gpu-01", id, now); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := Heartbeat(ctx, db, "gpu-01", NodeReport{ResetDone: []string{"acme/tiny"}}, time.Now()); err != nil {
		t.Fatal(err)
	}

	var left []string
	rows, err := db.Read().QueryContext(ctx, `SELECT model_id FROM stage_reset WHERE node_name = ?`, "gpu-01")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		left = append(left, id)
	}

	if len(left) != 1 || left[0] != "acme/other" {
		t.Errorf("stage_reset rows left = %v, want only [acme/other]: acme/tiny was acked, acme/other was not", left)
	}
}

// R4-37: staging progress is reported as bytes against a total, and this is
// the one hop that actually writes it — everywhere else along the way is a
// field carried from one struct to the next, and this is where it lands in
// the database `nodary node show` reads back.
func TestHeartbeatWritesStagingBytesAgainstTotal(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Format(audit.TimeFormat)
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node (name, state, created_at) VALUES (?, 'approved', ?)`, "gpu-01", now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO model (id, backend, source, artifact, created_at) VALUES (?, 'vllm', 'remote', 'hf-cache', ?)`,
			"acme/tiny", now)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	report := NodeReport{Staging: []StagingReport{
		{Model: "acme/tiny", State: "staging", BytesDone: 40, BytesTotal: 100},
	}}
	if err := Heartbeat(ctx, db, "gpu-01", report, time.Now()); err != nil {
		t.Fatal(err)
	}

	var done, total int64
	row := db.Read().QueryRowContext(ctx,
		`SELECT bytes_done, bytes_total FROM staging WHERE node_name = ? AND model_id = ?`,
		"gpu-01", "acme/tiny")
	if err := row.Scan(&done, &total); err != nil {
		t.Fatal(err)
	}
	if done != 40 || total != 100 {
		t.Errorf("bytes_done, bytes_total = %d, %d, want 40, 100", done, total)
	}
}
