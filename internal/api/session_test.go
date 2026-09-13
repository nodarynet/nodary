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

// loginCookie signs in over the real listener and returns the session cookie,
// which f.do cannot carry: everything else in these tests authenticates with a
// bearer token, and the token path has always re-read the user row.
func (f *fixture) loginCookie(user, password string) *http.Cookie {
	f.t.Helper()
	resp, err := f.client.Post(f.srv.URL+"/api/v1/auth/login", "application/json",
		strings.NewReader(`{"username":"`+user+`","password":"`+password+`"}`))
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("login: status %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "nodary_session" {
			return c
		}
	}
	f.t.Fatal("login set no session cookie")
	return nil
}

// whoamiWith asks the control plane who the holder of this cookie is.
func (f *fixture) whoamiWith(c *http.Cookie) int {
	f.t.Helper()
	req, err := http.NewRequest("GET", f.srv.URL+"/api/v1/auth/whoami", nil)
	if err != nil {
		f.t.Fatal(err)
	}
	req.AddCookie(c)
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func (f *fixture) suspend(name string) {
	f.t.Helper()
	ctx := context.Background()
	root := identity.LocalRoot()
	root.Actor.ID = "test"
	if _, err := f.log.Act(ctx, audit.Request{Actor: root.Actor, Action: "user.suspend"},
		func(m audit.Mutation) error {
			_, err := identity.Suspend(ctx, m, identity.RoleAdmin, time.Now(), name)
			return err
		}); err != nil {
		f.t.Fatal(err)
	}
}

// Suspending an account has to end its open sessions, and it did not: a session
// held a copy of the identity.Principal made at sign-in, so the only thing that
// stopped a suspended administrator was the TTL — 10080 minutes under the
// `default` profile, which is a week of continued privileged access after the
// decision to remove it.
func TestSuspendingAUserEndsAnOpenSessionOnTheNextRequest(t *testing.T) {
	f := newFixture(t)
	f.setPassword("alice", "correct horse battery staple")
	c := f.loginCookie("alice", "correct horse battery staple")

	if got := f.whoamiWith(c); got != http.StatusOK {
		t.Fatalf("before suspension: status %d, want 200", got)
	}

	f.suspend("alice")

	// No sleep and no new sign-in: the very next request with the same cookie.
	if got := f.whoamiWith(c); got != http.StatusUnauthorized {
		t.Errorf("after suspension: status %d, want 401", got)
	}
	// And again, to prove the refusal is not a one-off from dropping the entry.
	if got := f.whoamiWith(c); got != http.StatusUnauthorized {
		t.Errorf("second request after suspension: status %d, want 401", got)
	}
}

// A session whose user no longer exists is refused for the same reason, and
// must not resolve to a zero principal with an empty role.
func TestASessionForADeletedUserResolvesToNobody(t *testing.T) {
	f := newFixture(t)
	f.setPassword("alice", "correct horse battery staple")
	c := f.loginCookie("alice", "correct horse battery staple")

	if code, doc := f.do("DELETE", "/users/alice", f.admin,
		nil, map[string]string{"X-Nodary-Justify": "offboarding"}); code != http.StatusOK {
		t.Fatalf("delete: %d %v", code, doc)
	}
	if got := f.whoamiWith(c); got != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", got)
	}
}
