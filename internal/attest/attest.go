// Package attest holds the rules of docs/specs/07-identity-audit.md §2: the
// preview an operator approves, the hash that binds it to what is applied, and
// the ceremony the active profile demands before either happens.
//
// It performs no I/O and prompts for nothing. The CLI reads a terminal and R2's
// HTTP layer reads headers, and both ask the same questions here — which is the
// cross-cutting constraint in docs/tasks/README.md applied before there is a
// second front end to disagree with.
package attest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/canonical"
	"github.com/nodarynet/nodary/internal/policy"
)

// Render produces the preview of a change, against the state it will act on.
//
// It is a function rather than a value because binding a value computed once
// binds nothing: it would still match after the world moved, having never been
// recomputed. docs/specs/07-identity-audit.md §3 requires the change be
// re-rendered and re-hashed at apply time, and this is what gets run twice.
type Render func(context.Context, *sql.Tx) (any, error)

// Errors, mapped to exit codes by the caller. The distinction that matters is
// ErrTOTPRequired against a code that simply failed to verify: the first is
// policy refusing the operation, the second is a failed authentication, and
// docs/specs/10-cli.md §5 gives them different codes.
var (
	ErrIntentChanged       = errors.New("what would be applied is no longer what was previewed")
	ErrJustification       = errors.New("policy requires a justification")
	ErrJustificationShort  = errors.New("justification is too short")
	ErrTOTPRequired        = errors.New("policy requires a TOTP code for this act")
	ErrUnattendedForbidden = errors.New("policy forbids unattended tokens")
	ErrLifetimeTooLong     = errors.New("policy caps how long a credential may live")
)

// Hash is the intent_hash of a rendered change.
//
// Canonical JSON is what makes it reproducible across processes and Go
// versions, which is the entire reason R1-01 exists.
func Hash(change any) (string, error) {
	h, err := canonical.HashHex(change)
	if err != nil {
		return "", fmt.Errorf("hashing the change: %w", err)
	}
	return h, nil
}

// Bind re-runs a render inside the mutation's transaction and refuses if the
// result no longer hashes to what was approved.
//
// docs/specs/11-failure-modes.md §3: moving state between preview and apply
// produces a refusal, not a silent apply of something the operator never saw.
func Bind(ctx context.Context, tx *sql.Tx, r Render, approved string) (any, error) {
	change, err := r(ctx, tx)
	if err != nil {
		return nil, err
	}
	now, err := Hash(change)
	if err != nil {
		return nil, err
	}
	if now != approved {
		return nil, fmt.Errorf("%w: approved %s, now %s", ErrIntentChanged, short(approved), short(now))
	}
	return change, nil
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// Ceremony is what the caller offered towards an attestation.
type Ceremony struct {
	Justification string
	// TOTPCode is empty when none was supplied. Whether it verifies is decided
	// inside the mutation, because spending the step is itself a write.
	TOTPCode string
	// Unattended reports that the credential was minted --allow-unattended.
	// docs/specs/07-identity-audit.md §2 makes that grant the substitute for a
	// person being present, and the grant is itself in the chain.
	Unattended bool
	// Local reports the local-root principal: somebody running the CLI on the
	// host with no credential, which docs/plans/R1c-identity.md resolves to
	// admin. It has no user row and therefore no TOTP seed, so a code cannot be
	// demanded of it -- and the same reasoning R1c gives applies unchanged:
	// anyone who can open the database can already do anything to it, so asking
	// them for a second factor stored in that same database buys nothing. The
	// chain records the act as method "local", which is what an assessor reads.
	Local bool
	// Interactive reports that there is a human who could be prompted. A
	// non-interactive caller is not asked for something it cannot produce; it
	// is refused, which is the honest answer.
	Interactive bool
}

// NeedsTOTP reports whether this act must carry a code.
func NeedsTOTP(p policy.Profile, c Ceremony) bool {
	return p.RequireTOTP && !c.Unattended && !c.Local
}

// Require checks an attestation against the active profile.
//
// It is called before the transaction opens, so an operator learns what is
// missing before anything starts rather than after a rollback.
func Require(p policy.Profile, c Ceremony) error {
	// Runes rather than bytes: a length in bytes would let an accented or
	// non-Latin justification fail a floor an ASCII one of the same length
	// passes, which is a rule nobody wrote down.
	n := len([]rune(c.Justification))
	if p.RequireJustification && n == 0 {
		return fmt.Errorf("%w: pass --justify", ErrJustification)
	}
	// The floor applies to anything actually supplied, required or not. A
	// profile setting a minimum without requiring the field means "optional,
	// but say something real if you say anything"; the alternative is a length
	// nobody enforces, which is the silently ineffective setting R1d refuses
	// elsewhere. The required-and-empty case has already returned, so this one
	// branch covers both.
	if n > 0 && n < p.MinJustificationLength {
		return fmt.Errorf("%w: %d characters, policy requires %d",
			ErrJustificationShort, n, p.MinJustificationLength)
	}

	if NeedsTOTP(p, c) && c.TOTPCode == "" {
		if !c.Interactive {
			return fmt.Errorf("%w: this credential was not minted --allow-unattended, and there is nobody to prompt",
				ErrTOTPRequired)
		}
		return ErrTOTPRequired
	}
	return nil
}

// AllowUnattendedMint reports whether a token may be minted with the grant.
//
// Refused outright under a profile that sets allow_unattended_tokens = false
// (docs/specs/07-identity-audit.md §2), because the grant is the whole route
// around re-authentication and a profile that closes it must close it at the
// mint rather than at every later use.
func AllowUnattendedMint(p policy.Profile) error {
	if !p.AllowUnattendedTokens {
		return fmt.Errorf("%w: the %q profile sets allow_unattended_tokens = false", ErrUnattendedForbidden, p.Name)
	}
	return nil
}

// AllowTokenLifetime refuses a credential that would outlive the active
// profile's token_max_ttl_days.
//
// Checked at the mint for the same reason AllowUnattendedMint is: a ceiling
// applied at use would let the credential exist, and the thing an assessor
// reads is the token table, not the request log.
//
// A credential that never expires is refused under every profile rather than
// only under a short one. token_max_ttl_days is at least 1 by construction
// (Profile.validate), so no finite ceiling admits an infinite lifetime, and
// saying so by name beats reporting that forever exceeds 365 days.
func AllowTokenLifetime(p policy.Profile, now, expires time.Time) error {
	max := time.Duration(p.TokenMaxTTLDays) * 24 * time.Hour
	if expires.IsZero() {
		return fmt.Errorf("%w: the %q profile sets token_max_ttl_days = %d, and this would never expire",
			ErrLifetimeTooLong, p.Name, p.TokenMaxTTLDays)
	}
	if d := expires.Sub(now); d > max {
		return fmt.Errorf("%w: the %q profile sets token_max_ttl_days = %d, and this would live %d days",
			ErrLifetimeTooLong, p.Name, p.TokenMaxTTLDays, int(d.Hours()/24))
	}
	return nil
}
