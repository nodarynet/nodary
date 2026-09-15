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
// Local reports whether this is the local-root principal: somebody invoking the
// CLI on the control-plane host, with the filesystem access LocalRoot's comment
// below argues from. It is the actor method, and not the absence of a token.
//
// **It was `p.Token.ID == ""`, and a browser session has no token.** So every
// session-authenticated act read as local root: dev/specs/07-identity-audit.md
// §2's `require_totp` was silently not enforced in the web console — the one
// place [R8-03](../../dev/tasks/R8-ui-mutating.md) says a live cookie must not
// satisfy it — and internal/core wrote `totp_exempt: "local"` into the audit
// chain about a request that arrived over the network. A false statement in the
// record an assessor reads is worse than the missing prompt.
//
// The other question that expression was answering — "is there a credential
// whose use should be recorded" — is HasToken, below. They were one expression
// because until the console existed no principal had one answer and not the
// other.
func (p Principal) Local() bool { return p.Actor.Method == "local" }

// HasToken reports whether a credential with a use record authorized this act.
// A session cookie is a credential and has none: 07 §1 makes it short-lived and
// server-side, so there is no row to stamp.
func (p Principal) HasToken() bool { return p.Token.ID != "" }

// LocalRoot is the principal for a local invocation by root.
//
// dev/specs/07-identity-audit.md §1 argues for it directly: an appliance that
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
// principal goes on to authorize, because nothing in this package may reach
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
