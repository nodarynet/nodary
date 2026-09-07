package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/policy"
)

// R2-16: a session cookie or `Authorization: Bearer nodary_pt_…`.
const sessionCookie = "nodary_session"

type session struct {
	principal identity.Principal
	expires   time.Time
}

type sessionStore struct {
	mu sync.Mutex
	by map[string]session
}

func newSessionStore() *sessionStore { return &sessionStore{by: map[string]session{}} }

// key is the hash of the cookie value, never the value itself. A session table
// holding live cookies is a table whose disclosure is a fleet-wide compromise,
// and the same reasoning already governs tokens
// (docs/specs/02-enrollment.md §4).
func (s *sessionStore) key(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func (s *sessionStore) create(p identity.Principal, ttl time.Duration, now time.Time) string {
	// Swept on the way in rather than on a timer: a goroutine per server is a
	// lifecycle to get wrong, and the only thing that grows this map is the
	// call that is happening right now.
	s.sweep(now)

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	value := base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.by[s.key(value)] = session{principal: p, expires: now.Add(ttl)}
	return value
}

func (s *sessionStore) lookup(value string, now time.Time) (identity.Principal, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	got, ok := s.by[s.key(value)]
	if !ok {
		return identity.Principal{}, false
	}
	if now.After(got.expires) {
		delete(s.by, s.key(value))
		return identity.Principal{}, false
	}
	return got.principal, true
}

func (s *sessionStore) drop(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.by, s.key(value))
}

// sweep drops sessions that have expired.
//
// lookup already removes one it finds expired, which is enough for a session
// somebody comes back to and nothing at all for one they do not: a browser
// closed at five o'clock leaves an entry that is never read again and never
// freed. On a long-lived control plane that is an unbounded map, so expiry is
// also driven from the outside.
func (s *sessionStore) sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	dropped := 0
	for k, v := range s.by {
		if now.After(v.expires) {
			delete(s.by, k)
			dropped++
		}
	}
	return dropped
}

// count is the live session total, for the test that proves sweeping works.
func (s *sessionStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.by)
}

// authenticate resolves the caller.
//
// A bearer token wins over a cookie: a caller that sent both is a script with a
// stale browser cookie far more often than the reverse, and the token is the
// credential with a revocation record.
func (s *Server) authenticate(r *http.Request) (identity.Principal, error) {
	if h := r.Header.Get("Authorization"); h != "" {
		presented, ok := strings.CutPrefix(h, "Bearer ")
		if !ok {
			return identity.Principal{}, badRequest("Authorization must be a Bearer credential")
		}
		p, err := identity.ResolveToken(r.Context(), s.db.Read(), s.now(), strings.TrimSpace(presented))
		if err != nil {
			return identity.Principal{}, err
		}
		return p, nil
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if p, ok := s.sessions.lookup(c.Value, s.now()); ok {
			return p, nil
		}
		return identity.Principal{}, fmt.Errorf("%w: the session has expired", errNoCredential)
	}
	// Never local root. docs/plans/R1c-identity.md's argument for it is
	// filesystem access to the database; an HTTP caller has none, and treating
	// an unauthenticated request as an administrator would be the same
	// reasoning applied where it does not hold.
	return identity.Principal{}, errNoCredential
}

// sessionTTL is the active profile's, so a `regulated` install's thirty minutes
// is honoured by the thing that issues cookies rather than by a constant.
func (s *Server) sessionTTL(ctx context.Context) time.Duration {
	active, _, err := policy.Active(ctx, s.db.Read())
	if err != nil || active.SessionTTLMinutes <= 0 {
		return 30 * time.Minute
	}
	return time.Duration(active.SessionTTLMinutes) * time.Minute
}
