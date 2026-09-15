package cli

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/policy"
	"github.com/nodarynet/nodary/internal/retention"
)

// cmdPrune is `nodary prune` — dev/specs/08-data-model.md §3's retention,
// applied once.
//
// **Through the ceremony rather than as a background goroutine in the server,
// and that is the whole design.** The spec calls pruning a periodic task, and
// the obvious reading is a ticker inside nodary-server. But §3's own sentence
// is that "a retention job that silently deletes evidence is indistinguishable
// from tampering", and a goroutine has no actor, no justification and no
// intent to bind — it would need a synthetic principal invented for it, which
// is the one thing dev/specs/07-identity-audit.md §3's seam exists to stop.
// A verb gets the preview, the intent hash, the justification, the TOTP
// re-authentication and the record for free, and the period comes from a
// systemd timer, which is what schedules things on this appliance already.
//
// Gated on PermPolicyApply rather than a permission of its own. What may be
// pruned is decided by audit_retention_days and usage_retention_days, so the
// role that sets those already decides this; executing what it configured is
// not a second privilege, and dev/specs/07-identity-audit.md §1's table is
// the vocabulary rather than a place to add to.
//
// A pass that removes nothing still writes its record. That it ran and found
// nothing is the fact that makes a gap in the history mean something.
func cmdPrune(e env, args []string) int {
	fs := newFlagSet(e, "prune")
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	format := formatFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(e.stderr, "nodary prune: takes no arguments; the windows come from the active policy\n")
		return ExitUsage
	}

	s, ok := openSession(e, "prune", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	// Fixed once. The render runs twice by contract, and a cutoff recomputed
	// from a fresh clock on the second run would hash differently from the one
	// the operator approved.
	now := s.now

	var removed retention.Removed
	rec, applied, code := s.attested(e, "prune", change{
		action: "data.prune",
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			w, err := retentionWindow(ctx, tx)
			if err != nil {
				return nil, err
			}
			planned, err := retention.Plan(ctx, tx, w, now)
			if err != nil {
				return nil, err
			}
			return prunePreview(w, planned), nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := identity.Authorize(s.who.Role, identity.PermPolicyApply); err != nil {
				return err
			}
			if err := s.touch(m); err != nil {
				return err
			}
			ctx := context.Background()
			// Re-read inside the mutation rather than carried from the render:
			// the profile is what decides how far back this reaches, so it is
			// read in the transaction that acts on it.
			w, err := retentionWindow(ctx, m.Tx())
			if err != nil {
				return err
			}
			if removed, err = retention.Prune(ctx, m.Tx(), w, now); err != nil {
				return err
			}
			for k, v := range prunePreview(w, removed) {
				m.Detail(k, v)
			}
			return nil
		},
	}, cer, *format)
	if !applied {
		return code
	}

	if !removed.Any() {
		fmt.Fprintf(e.stderr, "prune: nothing was old enough to remove\n")
	} else {
		fmt.Fprintf(e.stderr, "prune: %d usage %s rolled into %d daily %s, %d join %s purged\n",
			removed.UsageRows, plural("row", int(removed.UsageRows)),
			removed.UsageGroups, plural("row", int(removed.UsageGroups)),
			removed.JoinTokens, plural("token", int(removed.JoinTokens)))
		if removed.AuditThrough > 0 {
			fmt.Fprintf(e.stderr, "prune: audit seq %d-%d removed; the chain now verifies from seq %d against the cut\n",
				removed.AuditFrom, removed.AuditThrough, removed.AuditThrough+1)
		}
	}
	reportRecord(e, rec)
	return ExitOK
}

func retentionWindow(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (retention.Window, error) {
	p, _, err := policy.Active(ctx, q)
	if err != nil {
		return retention.Window{}, fmt.Errorf("reading the active policy: %w", err)
	}
	return retention.Window{AuditDays: p.AuditRetentionDays, UsageDays: p.UsageRetentionDays}, nil
}

// prunePreview is what the operator approves and what the record says, built
// once so those cannot differ. The windows are in it because the same counts
// under a different retention setting are a different act.
func prunePreview(w retention.Window, r retention.Removed) map[string]any {
	p := map[string]any{
		"audit_retention_days": w.AuditDays,
		"usage_retention_days": w.UsageDays,
		"usage_before":         r.UsageBefore,
		"usage_rows":           r.UsageRows,
		"usage_rolled_into":    r.UsageGroups,
		"join_tokens":          r.JoinTokens,
	}
	if r.AuditThrough > 0 {
		p["audit_before"] = r.AuditBefore
		p["audit_seq_from"] = r.AuditFrom
		p["audit_seq_through"] = r.AuditThrough
	}
	return p
}
