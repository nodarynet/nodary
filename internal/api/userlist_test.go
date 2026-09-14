package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
)

// tokenForRole adds a user in that role and returns a personal token for them.
func tokenForRole(t *testing.T, f *fixture, name string, role identity.Role) string {
	t.Helper()
	ctx := context.Background()
	root := identity.LocalRoot()
	root.Actor.ID = "test"
	var plain string
	if _, err := f.log.Act(ctx, audit.Request{Actor: root.Actor, Action: "user.add"},
		func(m audit.Mutation) error {
			if _, err := identity.Add(ctx, m, identity.RoleAdmin, time.Now(),
				name, name+"@example.test", role); err != nil {
				return err
			}
			var err error
			_, plain, err = identity.MintToken(ctx, m, identity.RoleAdmin, time.Now(),
				name, identity.KindPersonal, "t", time.Now().AddDate(0, 0, 1), false)
			return err
		}); err != nil {
		t.Fatal(err)
	}
	return plain
}

// `GET /users` is gated by PermStateRead, so every viewer in the fleet can read
// it. docs/specs/07-identity-audit.md §1 gives a viewer "read state", and an
// account's contact address is not fleet state: it is personal data attached to
// a person, and a listing that hands every viewer every address is a harvest
// rather than a read.
//
// Asserted from both sides, because "an admin sees it" is the half that makes
// the field worth carrying at all — `nodary user list` on the host shows it,
// and the same administrator over --server has to see the same listing.
func TestTheUserListingWithholdsEmailFromAViewer(t *testing.T) {
	f := newFixture(t)
	viewer := tokenForRole(t, f, "vic", identity.RoleViewer)
	_ = tokenForRole(t, f, "opal", identity.RoleOperator)

	code, doc := f.do(http.MethodGet, "/users", viewer, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("a viewer cannot read state: %d %v", code, doc)
	}
	if body := toJSON(doc); strings.Contains(body, "@example.test") {
		t.Errorf("a viewer was handed every account's email address:\n%s", body)
	}

	code, doc = f.do(http.MethodGet, "/users", f.admin, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("an admin cannot list users: %d %v", code, doc)
	}
	body := toJSON(doc)
	if !strings.Contains(body, "opal@example.test") {
		t.Errorf("an administrator cannot see the addresses they manage:\n%s", body)
	}
	// created_at is not withheld from anybody: when an account was created is
	// the same kind of fact as its role, and `nodary user list` has always
	// shown it. Without it, the same verb answers differently depending on
	// which road it took.
	if !strings.Contains(body, "created_at") {
		t.Errorf("the listing carries no created_at, which the CLI's own renders:\n%s", body)
	}
	if _, viewerDoc := f.do(http.MethodGet, "/users", viewer, nil, nil); !strings.Contains(
		toJSON(viewerDoc), "created_at") {
		t.Error("created_at was withheld from a viewer; only the address is privileged")
	}
}
