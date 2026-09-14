package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/fleet"
	"github.com/nodarynet/nodary/internal/store"
)

// revisionsSegment is the configuration history: what changed, when, who
// authored it and what they said.
//
// **The whole chain, not the reporting period's slice.** The audit segment is
// bounded and carries an anchor for exactly that reason; a revision chain needs
// neither, because it is one row per `config apply` — small enough that the
// complete chain fits, and a complete chain verifies end to end with nothing to
// take on trust. A window would also be misleading in a way the audit window is
// not: the configuration in force during the period is usually a revision from
// before it.
//
// **The snapshots are not in it.** A revision's row carries its hash, and 13 §3
// is about a bundle an assessor verifies with `sha256sum` and `minisign` alone
// — the hashes prove the history is intact, and embedding every snapshot would
// multiply the bundle by the size of the configuration for something nobody
// reads by hand. `nodary config show --revision N` is where a body comes from.
func revisionsSegment(ctx context.Context, db *store.DB, opt Options) ([]byte, error) {
	revisions, err := config.List(ctx, db.Read(), allRevisions, 0)
	if err != nil {
		return nil, fmt.Errorf("listing revisions: %w", err)
	}
	if len(revisions) == 0 {
		return pending("revision", "no configuration has been applied on this install"), nil
	}

	var out bytes.Buffer
	// List is newest first, and a chain reads forward.
	for i := len(revisions) - 1; i >= 0; i-- {
		r := revisions[i]
		line, err := json.Marshal(map[string]any{
			"kind": "revision", "seq": r.Seq, "ts": r.TS.UTC().Format(time.RFC3339),
			"actor": r.Actor, "justification": r.Justification,
			"prev_hash": r.PrevHash, "hash": r.Hash,
			// Whether this revision falls inside the reported period. The row
			// is here either way — the configuration in force during a period
			// is usually older than it — and saying which is which is what
			// stops a reader having to compare timestamps by hand.
			"in_period": !r.TS.Before(opt.From) && !r.TS.After(opt.To),
		})
		if err != nil {
			return nil, err
		}
		out.Write(append(line, '\n'))
	}
	return out.Bytes(), nil
}

// allRevisions is a limit high enough to be none. config.List defaults to 50
// and has no unlimited value; a bundle that silently carried the most recent
// fifty would be a truncated history reported as a complete one, which is the
// one failure this member must not have.
const allRevisions = 1 << 30

// nodesSegment is the approval records, with the inventory each node offered at
// the time.
//
// The offer rather than the current inventory, which is the whole point of
// 02 §1: it is what the node put on the table and what an administrator agreed
// to, written once at enrollment and never restated. A member that reported
// today's `gpus` would describe the machine, not the agreement.
func nodesSegment(ctx context.Context, db *store.DB, now time.Time) ([]byte, error) {
	nodes, err := fleet.Nodes(ctx, db.Read(), now)
	if err != nil {
		return nil, fmt.Errorf("listing nodes: %w", err)
	}
	if len(nodes) == 0 {
		return pendingJSON("nodes", "no node has enrolled on this install"), nil
	}

	rows := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		row := map[string]any{
			"name": n.Name, "state": n.State, "arch": n.Arch, "os": n.OS,
			"driver_version": n.DriverVersion, "agent_version": n.AgentVersion,
			"protocol": n.Protocol, "reboot_policy": n.RebootPolicy,
			"cert_expires_at": n.CertExpiresAt,
			"offer":           raw(n.Offer), "constraints": raw(n.Constraints),
		}
		if n.ApprovedAt != "" {
			row["approved_at"] = n.ApprovedAt
		}
		// Absent for a console approval: 07 §1 makes local root a real
		// principal without a user row, so the chain is what names who.
		if n.ApprovedBy != "" {
			row["approved_by"] = n.ApprovedBy
		}
		rows = append(rows, row)
	}
	doc, err := json.MarshalIndent(map[string]any{
		"schema": 1, "kind": "nodes", "nodes": rows,
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(doc, '\n'), nil
}

// raw keeps a stored JSON document as a document rather than a string, and
// turns an absent one into null instead of into invalid JSON.
func raw(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
