package observed

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/store"
)

// Usage is one inference request, and it is a closed record.
//
// **There is no field here for what the request said, and there is not going to
// be one.** docs/adr/0006-cui-boundary-and-fips.md makes "nodary records that a
// request happened, never what it said" a structural guarantee, and this struct
// plus 0006_fleet.sql's `usage` table are where "structural" is cashed out: a
// closed schema has nowhere to write it, so the guarantee does not depend on
// anybody remembering it.
//
// The gateway is the first thing in this product that ever holds a prompt. It
// holds it for as long as it takes to proxy it and puts it nowhere, and
// TestNoRequestContentReachesStorage in internal/gateway fails the build if a
// path to storage appears.
//
// This lives in internal/observed for the reason the package comment gives: a
// usage row is an observation, not a decision. It is written per request at a
// volume the audit chain would choke on, and pruned on a schedule the audit
// chain must never be pruned on (docs/specs/08-data-model.md §3).
type Usage struct {
	TS               time.Time
	UserID           string
	TokenID          string
	Route            string
	ModelID          string
	DeploymentID     string
	NodeName         string
	RequestID        string
	PromptTokens     int64
	CompletionTokens int64
	Latency          time.Duration
	Status           int
	Streamed         bool
	// Partial means accounting is incomplete — a stream that ended without its
	// usage chunk. docs/specs/06-gateway.md §3: usage is never silently
	// dropped, because if disconnecting erased it, metering would be trivially
	// avoidable and the quota system decorative.
	Partial bool
}

// RecordUsage writes one metering row.
//
// Through store.WriteTx and not audit.Log.Act, and the reasoning is
// 0006_fleet.sql's: this is telemetry at request volume, and burying a month's
// administrative acts under it would make the chain unreadable for the assessor
// it exists for. The column list is exhaustive and fixed, which is what makes
// the closed-schema guarantee checkable by reading this function.
func RecordUsage(ctx context.Context, db *store.DB, u Usage) error {
	id, err := usageID()
	if err != nil {
		return err
	}
	return db.WriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO usage (id, ts, user_id, token_id, route, model_id, deployment_id,
			                    node_name, request_id, prompt_tokens, completion_tokens,
			                    latency_ms, status, streamed, partial)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, u.TS.UTC().Format(audit.TimeFormat), nullOr(u.UserID), nullOr(u.TokenID),
			nullOr(u.Route), nullOr(u.ModelID), nullOr(u.DeploymentID), nullOr(u.NodeName),
			nullOr(u.RequestID), u.PromptTokens, u.CompletionTokens,
			u.Latency.Milliseconds(), u.Status, boolInt(u.Streamed), boolInt(u.Partial))
		if err != nil {
			return fmt.Errorf("recording usage: %w", err)
		}
		return nil
	})
}

func usageID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating a usage id: %w", err)
	}
	return "use_" + hex.EncodeToString(b), nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
