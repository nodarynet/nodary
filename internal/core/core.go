// Package core performs an attested mutation.
//
// It is the answer to the cross-cutting constraint in docs/tasks/README.md:
// "the CLI and the HTTP API call the same core functions. Neither holds
// business logic." Until R2 there was one front end, so the constraint could
// not be violated and could not be tested; this package is what makes it hold
// by construction once there are two.
//
// The split runs along what a front end knows that this package cannot: where a
// credential came from, whether there is a human to prompt, and how to render
// an outcome. Everything else — what ceremony the active profile demands,
// whether an intent still binds, whether a code verifies — is here, once.
package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/attest"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/policy"
	"github.com/nodarynet/nodary/internal/secret"
	"github.com/nodarynet/nodary/internal/store"
)

// Change is one mutation, described well enough to attest to.
type Change struct {
	Action string
	Target *audit.Target
	// Render produces the preview. It runs twice — once against a read snapshot
	// to show and hash, once inside the transaction to bind — so it must read
	// state rather than echo arguments, or it hashes something that cannot move.
	Render attest.Render
	// Apply performs the change, given the preview the bind confirmed.
	Apply func(audit.Mutation, any) error
}

// Request is everything a front end supplies.
type Request struct {
	Principal identity.Principal
	Ceremony  attest.Ceremony
	// Intent is the hash a caller approved: the CLI's own preview, or an API
	// client's X-Nodary-Intent. Empty means the caller approved whatever this
	// call renders, which is what an interactive confirmation amounts to.
	Intent string
	// DryRun renders and hashes and applies nothing.
	DryRun bool
	// RequestID travels into the audit record, so a user's report of one bad
	// request resolves to one row without guesswork (R2-24).
	RequestID string
}

// Outcome is what happened.
type Outcome struct {
	Preview    any
	IntentHash string
	Record     audit.Record
	Applied    bool
	// Profile is the policy that was in force, so a caller can explain a
	// refusal without reading it again.
	Profile policy.Profile
}

// Deps are the process's own handles.
type Deps struct {
	DB  *store.DB
	Log *audit.Log
	Key func() (*secret.Key, error)
	Now time.Time
}

// Act runs docs/specs/07-identity-audit.md §2 and then the change.
//
// Preview, hash, ceremony, confirmation-free apply, the re-render that binds
// the approved preview to what is applied, and the TOTP that is spent inside
// the act it authorises. A front end that skipped any of it would be a front
// end with less ceremony than the other one, which is the divergence the
// cross-cutting constraint exists to prevent.
func Act(ctx context.Context, d Deps, req Request, c Change) (Outcome, error) {
	active, _, err := policy.Active(ctx, d.DB.Read())
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{Profile: active}

	if out.Preview, err = preview(ctx, d.DB, c.Render); err != nil {
		return out, err
	}
	if out.IntentHash, err = attest.Hash(out.Preview); err != nil {
		return out, err
	}
	if req.DryRun {
		return out, nil
	}

	// An intent supplied by a caller must match what this call renders, before
	// anything else happens. An API client that approved one change and sent
	// the hash of another is refused here rather than after a transaction.
	if req.Intent != "" && req.Intent != out.IntentHash {
		return out, fmt.Errorf("%w: approved %s, now %s",
			attest.ErrIntentChanged, shortHash(req.Intent), shortHash(out.IntentHash))
	}

	cer := req.Ceremony
	cer.Unattended = req.Principal.Token.Unattended
	cer.Local = req.Principal.Local()
	if err := attest.Require(active, cer); err != nil {
		// Returned rather than resolved: a CLI can prompt for a code and an API
		// cannot, and deciding which is a front end's business.
		return out, err
	}

	r := audit.Request{
		Actor: req.Principal.Actor, Action: c.Action, Target: c.Target,
		Justification: cer.Justification, IntentHash: out.IntentHash,
	}
	out.Record, err = d.Log.Act(ctx, r, func(m audit.Mutation) error {
		if req.RequestID != "" {
			m.Detail("request_id", req.RequestID)
		}
		if err := touch(ctx, m, d.Now, req.Principal); err != nil {
			return err
		}
		// Recorded rather than silent: under a profile that requires
		// re-authentication, an act that did not carry one has to say why.
		if active.RequireTOTP && !attest.NeedsTOTP(active, cer) {
			if cer.Local {
				m.Detail("totp_exempt", "local")
			} else {
				m.Detail("totp_exempt", "unattended")
			}
		}
		if attest.NeedsTOTP(active, cer) {
			k, err := d.Key()
			if err != nil {
				return err
			}
			if _, err := identity.VerifyTOTP(ctx, m, d.Now, k, req.Principal.User.Name, cer.TOTPCode); err != nil {
				return err
			}
		}
		bound, err := attest.Bind(ctx, m.Tx(), c.Render, out.IntentHash)
		if err != nil {
			return err
		}
		return c.Apply(m, bound)
	})
	if err != nil {
		return out, err
	}
	out.Applied = true
	return out, nil
}

// Preview renders a change without applying it, for a caller that wants the
// hash before deciding.
func Preview(ctx context.Context, d Deps, c Change) (any, string, error) {
	p, err := preview(ctx, d.DB, c.Render)
	if err != nil {
		return nil, "", err
	}
	h, err := attest.Hash(p)
	return p, h, err
}

// preview runs a render outside any mutation, in a transaction it rolls back.
//
// A read-only connection would be simpler and would not do: a render sees the
// same snapshot semantics as the apply path only if it runs in a transaction,
// and a preview that read differently from the bind would refuse changes that
// had not moved.
func preview(ctx context.Context, db *store.DB, r attest.Render) (any, error) {
	tx, err := db.Read().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("opening a preview transaction: %w", err)
	}
	defer tx.Rollback()
	return r(ctx, tx)
}

// touch records the use of the credential that authorised an act, inside that
// act, because nothing outside internal/audit may write on its own.
func touch(ctx context.Context, m audit.Mutation, now time.Time, p identity.Principal) error {
	if p.Local() {
		return nil
	}
	return identity.Touch(ctx, m, now, p.Token.ID)
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// ErrNotPermitted is re-exported so a front end can map it without importing
// three packages to build one error table.
var (
	ErrDenied        = identity.ErrDenied
	ErrIntentChanged = attest.ErrIntentChanged
	ErrTOTPRequired  = attest.ErrTOTPRequired
)

// IsPolicyRefusal reports whether an error is the active profile refusing.
//
// One predicate, used by the CLI's exit codes and the API's status codes, so a
// policy refusal cannot be exit 5 in one front end and 500 in the other.
func IsPolicyRefusal(err error) bool {
	return errors.Is(err, attest.ErrJustification) ||
		errors.Is(err, attest.ErrJustificationShort) ||
		errors.Is(err, attest.ErrTOTPRequired) ||
		errors.Is(err, attest.ErrUnattendedForbidden)
}
