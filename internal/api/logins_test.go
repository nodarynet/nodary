package api

import (
	"net/http"
	"testing"
	"time"
)

func req(t *testing.T, addr string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.RemoteAddr = addr
	return r
}

// Either key trips. The username alone would let an attacker walk a user list,
// five guesses each, forever; the address alone would let one attacker on a
// shared NAT lock out a whole office.
func TestEitherTheUsernameOrTheAddressLocksOut(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	t.Run("the username, across addresses", func(t *testing.T) {
		l := newLogins()
		for i := 0; i < maxLoginFailures; i++ {
			// A different address every time, so only the username accumulates.
			l.fail(keysFor("alice", req(t, "10.0.0."+string(rune('1'+i))+":40000")), now)
		}
		if l.lockedFor(keysFor("alice", req(t, "10.0.0.99:40000")), now) <= 0 {
			t.Error("five failures against one account from five addresses did not lock the account")
		}
		if l.lockedFor(keysFor("bob", req(t, "10.0.0.99:40000")), now) > 0 {
			t.Error("locking alice locked bob")
		}
	})

	t.Run("the address, across usernames", func(t *testing.T) {
		l := newLogins()
		for _, name := range []string{"a", "b", "c", "d", "e"} {
			l.fail(keysFor(name, req(t, "10.0.0.7:40000")), now)
		}
		// Username-walking is exactly what the address key exists to stop.
		if l.lockedFor(keysFor("never-tried", req(t, "10.0.0.7:40000")), now) <= 0 {
			t.Error("five failures from one address across five accounts did not lock the address")
		}
		if l.lockedFor(keysFor("never-tried", req(t, "10.0.0.8:40000")), now) > 0 {
			t.Error("locking one address locked another")
		}
	})
}

// A lockout engages once, not on every subsequent attempt — it is the moment
// worth an audit record, and re-engaging would reset the clock on every try and
// lock somebody out forever.
func TestALockoutEngagesOnceAndExpires(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	l := newLogins()
	r := req(t, "10.0.0.1:40000")

	for i := 1; i < maxLoginFailures; i++ {
		if l.fail(keysFor("alice", r), now) {
			t.Fatalf("failure %d engaged a lockout before the threshold", i)
		}
	}
	if !l.fail(keysFor("alice", r), now) {
		t.Fatalf("failure %d did not engage a lockout", maxLoginFailures)
	}
	if l.fail(keysFor("alice", r), now.Add(time.Second)) {
		t.Error("a further attempt engaged a second lockout, which would extend it indefinitely")
	}

	if l.lockedFor(keysFor("alice", r), now.Add(loginLockout+time.Second)) > 0 {
		t.Error("the lockout never expires")
	}
}

// Five typos spread over a year must not lock an account on the fifth.
func TestFailuresOlderThanTheWindowDoNotCount(t *testing.T) {
	l := newLogins()
	r := req(t, "10.0.0.1:40000")
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	for i := 0; i < maxLoginFailures-1; i++ {
		l.fail(keysFor("alice", r), now)
	}
	// Long enough later that the earlier failures have aged out.
	later := now.Add(loginWindow + time.Minute)
	if l.fail(keysFor("alice", r), later) {
		t.Error("a failure after the window still counted the stale ones")
	}
	if l.lockedFor(keysFor("alice", r), later) > 0 {
		t.Error("stale failures locked the account")
	}
}

// A success clears the username and deliberately not the address: an attacker
// holding one valid account of their own must not be able to reset the counter
// between guesses at everybody else's.
func TestASuccessClearsTheUsernameAndNotTheAddress(t *testing.T) {
	l := newLogins()
	r := req(t, "10.0.0.1:40000")
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	for i := 0; i < maxLoginFailures; i++ {
		l.fail(keysFor("alice", r), now)
	}
	l.succeed("alice")

	if l.by["user:alice"] != nil {
		t.Error("a successful login left the username's failures in place")
	}
	if a := l.by["addr:10.0.0.1"]; a == nil || a.failures != maxLoginFailures {
		t.Error("a successful login cleared the address's failures")
	}
}

// An attacker inventing a username per attempt must not grow the map forever.
func TestForgetDropsEntriesNothingIsWaitingOn(t *testing.T) {
	l := newLogins()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 50; i++ {
		l.fail([]string{"user:invented" + string(rune('a'+i%26)) + string(rune('a'+i/26))}, now)
	}
	if len(l.by) == 0 {
		t.Fatal("nothing was recorded")
	}
	l.forget(now.Add(loginWindow + loginLockout + time.Minute))
	if len(l.by) != 0 {
		t.Errorf("%d entries survived long past their window", len(l.by))
	}
}

// A forwarded-for header is attacker-controlled: there is no configured proxy
// in front of the control plane, so trusting it would let one client present a
// fresh address per request and never be throttled at all.
func TestTheAddressComesFromTheConnectionAndNotAHeader(t *testing.T) {
	r := req(t, "10.0.0.1:40000")
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.Header.Set("X-Real-IP", "203.0.113.9")

	for _, k := range keysFor("alice", r) {
		if k == "addr:203.0.113.9" {
			t.Fatal("a client-supplied header chose its own throttling key")
		}
	}
	if got := keysFor("alice", r)[1]; got != "addr:10.0.0.1" {
		t.Errorf("address key = %q, want the connection's", got)
	}
}
