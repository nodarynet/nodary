package identity

import (
	"testing"

	"github.com/nodarynet/nodary/internal/audit"
)

// Local means local root, and a session cookie is not that.
//
// **This was `p.Token.ID == ""`.** A session carries no token, so every act a
// browser made read as local root: dev/specs/07-identity-audit.md §2's
// `require_totp` was not enforced in the console — the one place
// dev/tasks/R8-ui-mutating.md says a live cookie must not satisfy it — and the
// audit chain recorded `totp_exempt: "local"` about a request that arrived over
// the network, which is a false statement in the record an assessor reads.
func TestASessionIsNotLocalRoot(t *testing.T) {
	for _, c := range []struct {
		what  string
		who   Principal
		local bool
		token bool
	}{
		{"local root", LocalRoot(), true, false},
		{
			what: "a browser session",
			// Exactly what internal/api's cookie path builds: a user, a role,
			// and an actor that says how they arrived. No token, because 07 §1
			// makes a session short-lived and server-side.
			who:   Principal{Role: RoleAdmin, Actor: audit.Actor{ID: "usr_1", Method: "session"}},
			local: false, token: false,
		},
		{
			what:  "a personal token",
			who:   Principal{Role: RoleAdmin, Token: Token{ID: "tok_1"}, Actor: audit.Actor{ID: "usr_1", Method: "token"}},
			local: false, token: true,
		},
	} {
		if got := c.who.Local(); got != c.local {
			t.Errorf("%s: Local() = %v, want %v", c.what, got, c.local)
		}
		// The other question the old expression was answering, kept apart:
		// there is nothing to stamp for a session, and that is not the same
		// statement as "this came from the console's own host".
		if got := c.who.HasToken(); got != c.token {
			t.Errorf("%s: HasToken() = %v, want %v", c.what, got, c.token)
		}
	}
}
