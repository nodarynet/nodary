package identity

import (
	"context"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
)

// Principal is who is performing an action, and what they may do.
//
// It is what the CLI and, in R2, the HTTP API both produce, so that a
// permission check and an audit record are decided from one value rather than
// from two parallel notions of "the caller".
type Principal struct {
	// User is the account acting. Zero for a local root invocation, which is
	// not an account.
	User User
	// Token is the credential presented. Zero for local root.
	Token Token
	// Role is what the permission checks are made against.
	Role Role
	// Actor is what the audit record carries.
	Actor audit.Actor
}

// Local reports whether this is the local-root principal.
func (p Principal) Local() bool { return p.Token.ID == "" }

// LocalRoot is the principal for a local invocation by root.
//
// docs/specs/07-identity-audit.md §1 argues for it directly: an appliance that
// cannot authenticate its own administrator when the network is degraded is an
// appliance that cannot be recovered. It is also honest about what is already
// true — anyone who can open the database can change it, and the hash chain is
// what makes that detectable rather than impossible — so demanding a credential
// that the same filesystem access could mint would buy nothing.
//
// The record says method "local", so an auditor can tell these apart from
// authenticated actions at a glance.
func LocalRoot() Principal {
	return Principal{
		Role:  RoleAdmin,
		Actor: audit.Actor{ID: "root", Method: "local"},
	}
}

// ResolveToken authenticates a presented credential into a principal.
//
// It does not write. Recording the use is Touch's job, inside the act this
// principal goes on to authorise, because nothing in this package may reach
// the database outside a mutation.
func ResolveToken(ctx context.Context, q Querier, now time.Time, presented string) (Principal, error) {
	u, t, err := Authenticate(ctx, q, now, presented)
	if err != nil {
		return Principal{}, err
	}
	return Principal{
		User:  u,
		Token: t,
		Role:  u.Role,
		Actor: audit.Actor{
			ID:     u.ID,
			Method: "token",
			// The credential used, not a session: R1 has no sessions, and
			// naming the token is what lets a revocation be traced to
			// everything it was used for.
			Session: t.ID,
		},
	}, nil
}
