package api

import (
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/identity"
)

// An expired session that nobody returns to must still be freed. lookup drops
// one it finds expired, which covers the session somebody comes back to and
// nothing at all for the browser that was closed at five o'clock.
func TestExpiredSessionsAreSweptEvenIfNobodyReturns(t *testing.T) {
	s := newSessionStore()
	now := time.Now()

	for range 100 {
		s.create(identity.Principal{}, time.Minute, now)
	}
	if got := s.count(); got != 100 {
		t.Fatalf("count = %d, want 100", got)
	}

	// An hour later, one new login is enough to clear the dead ones.
	s.create(identity.Principal{}, time.Minute, now.Add(time.Hour))
	if got := s.count(); got != 1 {
		t.Errorf("count = %d after sweeping, want 1 (the new session)", got)
	}
}

// The store never holds a live cookie: a session table whose disclosure hands
// over working credentials is the same defect as storing tokens in the clear.
func TestTheSessionStoreHoldsNoUsableCookie(t *testing.T) {
	s := newSessionStore()
	value := s.create(identity.Principal{}, time.Minute, time.Now())
	if value == "" {
		t.Fatal("no session was issued")
	}
	for k := range s.by {
		if k == value {
			t.Fatal("the store is keyed by the cookie itself")
		}
	}
	if _, ok := s.lookup(value, time.Now()); !ok {
		t.Error("the issued cookie does not resolve")
	}
}
