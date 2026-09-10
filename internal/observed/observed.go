// Package observed holds the database writes that are observations rather than
// decisions.
//
// Everything a person decides goes through audit.Log.Act, and
// TestNothingBypassesTheSeam in internal/audit enforces that by scanning for
// .WriteTx( outside a short list of directories. This package is on that list,
// and it exists so the list can stay short: the alternative is exempting
// internal/api, which would put every handler in the product outside the gate
// in order to let a heartbeat through.
//
// The rule this package is allowed to exist under:
//
//   - It writes only what a machine reported about itself. Inventory, unit
//     states, staging progress, and — when R3 lands — usage rows.
//   - It never writes anything a person chose. Not `node.state`, not approval,
//     not configuration, not identity. Those are decisions, they belong in the
//     audit chain, and a function here that touched one would be the seam
//     defeated by a package named to sound harmless.
//   - Every statement below names its columns explicitly. A write that used
//     `SET` over a computed column list could not be reviewed against the rule
//     above by reading it.
//
// The reasoning for the split, and the rejected alternatives, are in
// docs/plans/R4a-agent-protocol.md §4. The short version is that a heartbeat
// every fifteen seconds per node is not evidence: burying a month's
// administrative acts under a hundred and seventy thousand records makes the
// chain unreadable, which is a cost paid by the assessor the chain is for.
package observed

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/store"
)

// NodeReport is one heartbeat: docs/specs/03-agent.md §1.
type NodeReport struct {
	AgentVersion  string
	Protocol      int
	Arch          string
	OS            string
	DriverVersion string
	// GPUsJSON and TopologyJSON are already-valid JSON documents. The caller
	// validates them, because the caller is what parsed them off the wire.
	GPUsJSON     string
	TopologyJSON string
	Deployments  []DeploymentReport
	Staging      []StagingReport
	// ResetDone is models this node just discarded in response to a
	// `nodary model restage`/`unstage` request — an observation of what
	// happened, the same as the rest of this report, not a decision.
	ResetDone []string
	// RestartDone is deployments this node just cycled in response to a
	// `nodary model restart` request — the same shape ResetDone uses, for
	// the same reason.
	RestartDone []string
}

type DeploymentReport struct {
	ID     string
	State  string
	Health string
	Error  string
}

type StagingReport struct {
	Model      string
	State      string
	BytesDone  int64
	BytesTotal int64
	Error      string
}

// Heartbeat records what a node reports about itself.
//
// `state`, `approved_by` and `approved_at` are absent from every statement
// here: a node cannot promote itself by reporting that it has.
func Heartbeat(ctx context.Context, db *store.DB, name string, r NodeReport, seen time.Time) error {
	stamp := seen.UTC().Format(audit.TimeFormat)
	return db.WriteTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`UPDATE node SET last_seen = ?, agent_version = ?, protocol = ?,
			                 arch = ?, os = ?, driver_version = ?,
			                 gpus_json = ?, topology_json = ?
			 WHERE name = ?`,
			stamp, r.AgentVersion, r.Protocol, r.Arch, r.OS, r.DriverVersion,
			r.GPUsJSON, r.TopologyJSON, name); err != nil {
			return fmt.Errorf("recording the heartbeat from %s: %w", name, err)
		}

		// UPDATE, not upsert: a node may report on what the control plane
		// placed there and may not create a deployment the configuration does
		// not know about. An unknown id changes nothing.
		for _, d := range r.Deployments {
			if _, err := tx.ExecContext(ctx,
				`UPDATE deployment SET state = ?, health = ?, last_error = ?, updated_at = ?
				 WHERE id = ? AND node_name = ?`,
				d.State, orDefault(d.Health, "unknown"), nullOr(d.Error), stamp, d.ID, name); err != nil {
				return fmt.Errorf("recording deployment %s on %s: %w", d.ID, name, err)
			}
		}

		// Staging is an upsert, because the row is the progress record and it
		// does not exist until the node starts. The EXISTS guard is the same
		// rule as above by another route: a model nobody registered gets no row.
		for _, st := range r.Staging {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO staging (model_id, node_name, state, bytes_done, bytes_total, error, updated_at)
				 SELECT ?, ?, ?, ?, ?, ?, ?
				 WHERE EXISTS (SELECT 1 FROM model WHERE id = ?)
				 ON CONFLICT (model_id, node_name) DO UPDATE SET
				     state = excluded.state, bytes_done = excluded.bytes_done,
				     bytes_total = excluded.bytes_total, error = excluded.error,
				     updated_at = excluded.updated_at`,
				st.Model, name, st.State, st.BytesDone, positiveOrNull(st.BytesTotal),
				nullOr(st.Error), stamp, st.Model); err != nil {
				return fmt.Errorf("recording staging of %s on %s: %w", st.Model, name, err)
			}
		}

		// Consumed once acted on, the same as a join token's uses_left: the
		// row's only job was asking the agent to do this, and it did.
		for _, modelID := range r.ResetDone {
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM stage_reset WHERE node_name = ? AND model_id = ?`,
				name, modelID); err != nil {
				return fmt.Errorf("clearing the reset request for %s on %s: %w", modelID, name, err)
			}
		}
		for _, deploymentID := range r.RestartDone {
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM deployment_restart WHERE node_name = ? AND deployment_id = ?`,
				name, deploymentID); err != nil {
				return fmt.Errorf("clearing the restart request for %s on %s: %w", deploymentID, name, err)
			}
		}
		return nil
	})
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func nullOr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func positiveOrNull(n int64) any {
	if n <= 0 {
		return nil
	}
	return n
}

// TouchToken records that a credential was used.
//
// identity.Touch does the same thing inside an audited act, which is right for
// an administrative mutation: the credential's last use and the change it made
// commit together. An inference request is not a mutation and produces no audit
// record (docs/specs/06-gateway.md §3 makes it a usage row), so the touch has
// nowhere to ride along and becomes an observation of its own.
//
// It is an observation by the package's own rule: a credential being presented
// is something that happened, not something anybody decided. And it is what
// makes stale-credential cleanup possible, which docs/specs/06-gateway.md §2
// names as the reason for recording it at all.
//
// A failure is returned and not swallowed, but the caller is expected to log
// rather than refuse: a request that authenticated correctly should not fail
// because a timestamp could not be written.
func TouchToken(ctx context.Context, db *store.DB, id string, now time.Time) error {
	if id == "" {
		return fmt.Errorf("recording a use with no credential")
	}
	return db.WriteTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`UPDATE token SET last_used_at = ? WHERE id = ?`,
			now.UTC().Truncate(time.Millisecond).Format(audit.TimeFormat), id); err != nil {
			return fmt.Errorf("recording the use of %s: %w", id, err)
		}
		return nil
	})
}
