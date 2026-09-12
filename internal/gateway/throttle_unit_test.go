package gateway

import (
	"testing"
	"time"
)

// A bucket holds `capacity` and refills over `per`. The arithmetic is here
// rather than only in an end-to-end test because an off-by-a-factor in the
// refill rate is invisible against a stub upstream and obvious here.
func TestABucketRefillsOverItsWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var b bucket

	// It starts full, so a user's first request is never refused.
	if !b.take(1, 60, time.Minute, start) {
		t.Fatal("a fresh bucket refused the first request")
	}
	// Spend the rest of the minute's allowance.
	for i := 0; i < 59; i++ {
		if !b.take(1, 60, time.Minute, start) {
			t.Fatalf("refused request %d of 60 within one minute", i+2)
		}
	}
	if b.take(1, 60, time.Minute, start) {
		t.Error("a 61st request in the same instant was allowed under rpm = 60")
	}

	// One second later, one token is back: 60 per minute is one per second.
	if !b.take(1, 60, time.Minute, start.Add(time.Second)) {
		t.Error("no token had refilled after a second at 60/minute")
	}

	// And it never over-fills: a bucket idle for an hour still holds a minute.
	b.refill(60, time.Minute, start.Add(time.Hour))
	if b.tokens > 60 {
		t.Errorf("an idle bucket accumulated %v tokens, capacity is 60", b.tokens)
	}
}

// tpm is charged after the fact, so a single very large response is allowed to
// leave the bucket negative. Rounding that away would make one huge request
// free.
func TestSpendingMoreThanTheBucketHoldsDelaysTheNextRequest(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var b bucket
	b.refill(1000, time.Minute, start)
	b.spend(3000, 1000, time.Minute, start)

	if b.tokens >= 0 {
		t.Errorf("tokens = %v, want negative after spending three times the budget", b.tokens)
	}
	// Two minutes of refill are owed before one token is available again.
	if wait := b.waitFor(1, 1000, time.Minute); wait < 2*time.Minute {
		t.Errorf("wait = %v, want at least two minutes", wait)
	}
}

// The most restrictive of every applicable limit binds. A global ceiling a
// per-user limit could raise would not be a ceiling.
func TestTheMostRestrictiveLimitWins(t *testing.T) {
	var l limits
	l.rpm.tighten(600, "user:alice")
	l.rpm.tighten(100, "global")
	if l.rpm.value != 100 || l.rpm.subject != "global" {
		t.Errorf("rpm = %d from %q, want 100 from global", l.rpm.value, l.rpm.subject)
	}

	// And the other direction: a tighter user limit beats a loose global one.
	var m limits
	m.tpm.tighten(100000, "global")
	m.tpm.tighten(5000, "user:alice")
	if m.tpm.value != 5000 || m.tpm.subject != "user:alice" {
		t.Errorf("tpm = %d from %q, want 5000 from user:alice", m.tpm.value, m.tpm.subject)
	}

	// Unset is unlimited and never wins.
	var n limits
	n.daily.tighten(0, "global")
	n.daily.tighten(1000, "role:user")
	if n.daily.value != 1000 {
		t.Errorf("an unset limit beat a real one: %d", n.daily.value)
	}
	if !(limits{}).none() {
		t.Error("an empty limit set does not report itself as empty")
	}
}

// daily_tokens resets at a UTC hour, so "used today" has to mean since that
// hour and not since midnight local or since the process started.
func TestTheDailyWindowStartsAtTheResetHour(t *testing.T) {
	// Just after the reset: the window started today.
	now := time.Date(2026, 3, 4, 0, 30, 0, 0, time.UTC)
	if got := lastDailyReset(now); !got.Equal(time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("reset = %v, want 2026-03-04T00:00Z", got)
	}
	// A non-UTC clock resolves to the same UTC window.
	east := time.FixedZone("UTC+5", 5*3600)
	if got := lastDailyReset(now.In(east)); !got.Equal(time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("a non-UTC clock gave %v", got)
	}
	if s := secondsUntilDailyReset(now); s < 84000 || s > 85000 {
		t.Errorf("resets in %ds, want most of a day", s)
	}
}

// Retry-After: 0 invites a client straight back into the same refusal.
func TestRetryAfterIsNeverZero(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second, time.Millisecond} {
		if got := ceilSeconds(d); got < 1 {
			t.Errorf("ceilSeconds(%v) = %d", d, got)
		}
	}
	if got := ceilSeconds(1500 * time.Millisecond); got != 2 {
		t.Errorf("ceilSeconds(1.5s) = %d, want 2 (rounded up, not down)", got)
	}
}
