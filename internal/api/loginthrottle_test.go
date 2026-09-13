package api_test

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
)

func (f *fixture) setPassword(name, password string) {
	f.t.Helper()
	ctx := context.Background()
	root := identity.LocalRoot()
	root.Actor.ID = "test"
	if _, err := f.log.Act(ctx, audit.Request{Actor: root.Actor, Action: "user.passwd"},
		func(m audit.Mutation) error {
			return identity.SetPassword(ctx, m, identity.RoleAdmin, name, password)
		}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) attempt(user, password string) (int, map[string]any) {
	f.t.Helper()
	return f.do("POST", "/auth/login", "",
		map[string]any{"username": user, "password": password}, nil)
}

// NIST SP 800-171 3.1.8, on the one endpoint reachable before any credential
// exists. Until this landed there was no lockout, no throttle and no delay on
// failed authentication anywhere in the tree.
func TestRepeatedFailuresLockOutAndSayForHowLong(t *testing.T) {
	f := newFixture(t)
	f.setPassword("alice", "correct horse battery staple")

	for i := 1; i <= 5; i++ {
		if code, doc := f.attempt("alice", "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d %v", i, code, doc)
		}
	}

	code, doc := f.attempt("alice", "wrong")
	if code != http.StatusTooManyRequests {
		t.Fatalf("the sixth attempt returned %d, want 429: %v", code, doc)
	}
	if !strings.Contains(toJSON(envelope(doc)), "too many failed attempts") {
		t.Errorf("the refusal does not say why: %v", envelope(doc))
	}

	// And the correct password is refused too, which is the point of a lockout
	// — otherwise it only slows down an attacker who was going to fail anyway.
	if code, _ := f.attempt("alice", "correct horse battery staple"); code != http.StatusTooManyRequests {
		t.Errorf("the correct password bypassed the lockout: %d", code)
	}
}

// Every failure mode reads identically to a caller. The comment above
// ErrBadPassword always said the login path must not reveal which; the code
// returned ErrNotActive for a suspended account and ErrNoPassword for one with
// none, which is username enumeration.
func TestEveryAuthenticationFailureLooksTheSame(t *testing.T) {
	f := newFixture(t)
	f.setPassword("alice", "correct horse battery staple")

	ctx := context.Background()
	root := identity.LocalRoot()
	root.Actor.ID = "test"
	// bob exists with no password; carol exists, has one, and is suspended.
	for _, name := range []string{"bob", "carol"} {
		if _, err := f.log.Act(ctx, audit.Request{Actor: root.Actor, Action: "user.add"},
			func(m audit.Mutation) error {
				_, err := identity.Add(ctx, m, identity.RoleAdmin, time.Now(), name, "", identity.RoleUser)
				return err
			}); err != nil {
			t.Fatal(err)
		}
	}
	f.setPassword("carol", "correct horse battery staple")
	if _, err := f.log.Act(ctx, audit.Request{Actor: root.Actor, Action: "user.suspend"},
		func(m audit.Mutation) error {
			_, err := identity.Suspend(ctx, m, identity.RoleAdmin, time.Now(), "carol")
			return err
		}); err != nil {
		t.Fatal(err)
	}

	var seen []string
	for _, tc := range []struct{ user, password string }{
		{"nobody-at-all", "correct horse battery staple"}, // no such account
		{"alice", "wrong"},                        // wrong password
		{"bob", "correct horse battery staple"},   // no password set
		{"carol", "correct horse battery staple"}, // suspended
	} {
		code, doc := f.attempt(tc.user, tc.password)
		if code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401: %v", tc.user, code, doc)
		}
		// Everything but request_id, which is per-request by design and tells
		// an attacker nothing about which account they just probed.
		env := envelope(doc)
		delete(env, "request_id")
		seen = append(seen, toJSON(env))
	}
	for i, got := range seen {
		if got != seen[0] {
			t.Errorf("failure %d is distinguishable from the first:\n  %s\n  %s", i, seen[0], got)
		}
	}
	if !strings.Contains(seen[0], "incorrect username or password") {
		t.Errorf("the shared message is %q", seen[0])
	}
}

// The reason a caller is not told still reaches the operator investigating.
func TestTheRealReasonReachesTheAuditRecordAndNotTheClient(t *testing.T) {
	f := newFixture(t)
	f.setPassword("alice", "correct horse battery staple")

	code, doc := f.attempt("alice", "wrong")
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d", code)
	}
	if body := toJSON(envelope(doc)); strings.Contains(body, "wrong password") {
		t.Errorf("the response names the specific failure: %s", body)
	}

	status, chain := f.do("GET", "/audit?action=auth.login", f.admin, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("reading the chain: %d %v", status, chain)
	}
	if raw := toJSON(chain); !strings.Contains(raw, "wrong password") {
		t.Errorf("the audit record does not carry the reason: %s", raw)
	}
}

// The unbounded-growth half: an attacker who is locked out must not be able to
// keep appending to the chain. A refused attempt is turned away before the
// audit write, not after it.
func TestALockedOutAttemptWritesNoAuditRecord(t *testing.T) {
	f := newFixture(t)
	f.setPassword("alice", "correct horse battery staple")

	for i := 0; i < 5; i++ {
		f.attempt("alice", "wrong")
	}
	before := f.countLogins(t)

	for i := 0; i < 20; i++ {
		if code, _ := f.attempt("alice", "wrong"); code != http.StatusTooManyRequests {
			t.Fatalf("attempt %d was not locked out: %d", i, code)
		}
	}
	if after := f.countLogins(t); after != before {
		t.Errorf("%d audit records were written while locked out", after-before)
	}
}

func (f *fixture) countLogins(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.db.Read().QueryRowContext(context.Background(),
		`SELECT count(*) FROM audit WHERE action = 'auth.login'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A lockout has to tell a client how long to wait, or it is a 429 that invites
// an immediate retry.
func TestALockoutCarriesRetryAfter(t *testing.T) {
	f := newFixture(t)
	f.setPassword("alice", "correct horse battery staple")
	for i := 0; i < 5; i++ {
		f.attempt("alice", "wrong")
	}

	resp, err := f.client.Post(f.srv.URL+"/api/v1/auth/login", "application/json",
		strings.NewReader(`{"username":"alice","password":"wrong"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	after := resp.Header.Get("Retry-After")
	n, convErr := strconv.Atoi(after)
	if convErr != nil || n < 1 {
		t.Errorf("Retry-After = %q, want a positive number of seconds", after)
	}
}
