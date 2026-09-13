package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// NIST SP 800-171 3.1.8 — "limit unsuccessful logon attempts" — on the one
// endpoint in the product that is reachable before any credential exists.
//
// The numbers are deliberately unexciting. Five attempts is more than a person
// mistypes and far fewer than a guess needs; fifteen minutes is long enough to
// make an online attack pointless and short enough that a locked-out
// administrator is not paging anybody.
const (
	maxLoginFailures = 5
	loginLockout     = 15 * time.Minute
	// loginWindow is how long a failure counts for. Without it, five typos
	// spread over a year would lock an account on the fifth.
	loginWindow = 15 * time.Minute
)

// attempt is one key's recent history.
type attempt struct {
	failures int
	last     time.Time
	until    time.Time
}

// logins throttles failed authentication.
//
// Two keys per attempt: the username and the client address. The username alone
// would let an attacker walk a user list, five guesses each, forever. The
// address alone would let one attacker on a shared NAT lock out a whole office.
// Together, either one trips.
//
// In process, and it says so: a control-plane restart forgives a lockout. That
// is a real weakness against an attacker who can restart the control plane, and
// an attacker who can restart the control plane has root on the machine holding
// the audit chain and does not need to guess passwords. Persisting it would put
// a write on every failed attempt, on the single writer connection this whole
// change exists to stop blocking.
type logins struct {
	mu sync.Mutex
	by map[string]*attempt
}

func newLogins() *logins { return &logins{by: map[string]*attempt{}} }

// keysFor is the pair an attempt is counted against.
//
// The address comes from RemoteAddr and never from X-Forwarded-For. There is no
// configured proxy in front of the control plane, so a forwarded-for header is
// attacker-controlled input — trusting it would let one client present a fresh
// address per request and never be throttled at all.
func keysFor(username string, r *http.Request) []string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return []string{"user:" + username, "addr:" + host}
}

// lockedFor reports how long these keys are locked out for, if they are.
func (l *logins) lockedFor(keys []string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	var longest time.Duration
	for _, k := range keys {
		a, ok := l.by[k]
		if !ok {
			continue
		}
		if d := a.until.Sub(now); d > longest {
			longest = d
		}
	}
	return longest
}

// fail records one failed attempt and reports whether it engaged a lockout.
//
// The report is what the audit record hangs off: the attempts themselves are
// noise, and the moment an account or an address crosses the threshold is the
// security event worth keeping.
func (l *logins) fail(keys []string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	engaged := false
	for _, k := range keys {
		a, ok := l.by[k]
		if !ok {
			a = &attempt{}
			l.by[k] = a
		}
		// A failure older than the window does not count toward this one.
		if !a.last.IsZero() && now.Sub(a.last) > loginWindow {
			a.failures = 0
		}
		a.failures++
		a.last = now
		if a.failures >= maxLoginFailures && now.After(a.until) {
			a.until = now.Add(loginLockout)
			engaged = true
		}
	}
	return engaged
}

// succeed clears the username's history.
//
// Only the username. Clearing the address too would let an attacker with one
// valid account of their own reset the counter between guesses at everybody
// else's, from the same machine.
func (l *logins) succeed(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.by, "user:"+username)
}

// forget drops entries nothing is waiting on, so a long-running control plane
// does not accumulate one per username an attacker invented.
func (l *logins) forget(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, a := range l.by {
		if now.After(a.until) && now.Sub(a.last) > loginWindow {
			delete(l.by, k)
		}
	}
}
