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

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/policy"
)

// R2-16: a session cookie or `Authorization: Bearer nodary_pt_…`.
const sessionCookie = "nodary_session"

// session holds a user id and nothing else about the user.
//
// It used to hold a whole identity.Principal, and that was the bug: a session
// was a snapshot of who somebody was when they signed in, so suspending an
// account left every open session of it working for the rest of the TTL — up
// to a week under the `default` profile's 10080 minutes. A token has never had
// this problem,
// because identity.Authenticate re-reads the user row on every request. Holding
// the id and resolving it the same way is what makes a cookie and a token
// answer to the same user state.
type session struct {
	userID  string
	expires time.Time
}

type sessionStore struct {
	mu sync.Mutex
	by map[string]session
}

func newSessionStore() *sessionStore { return &sessionStore{by: map[string]session{}} }

// key is the hash of the cookie value, never the value itself. A session table
// holding live cookies is a table whose disclosure is a fleet-wide compromise,
// and the same reasoning already governs tokens
// (dev/specs/02-enrollment.md §4).
func (s *sessionStore) key(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func (s *sessionStore) create(userID string, ttl time.Duration, now time.Time) string {
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
	s.by[s.key(value)] = session{userID: userID, expires: now.Add(ttl)}
	return value
}

func (s *sessionStore) lookup(value string, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	got, ok := s.by[s.key(value)]
	if !ok {
		return "", false
	}
	if now.After(got.expires) {
		delete(s.by, s.key(value))
		return "", false
	}
	return got.userID, true
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
		id, ok := s.sessions.lookup(c.Value, s.now())
		if !ok {
			return identity.Principal{}, fmt.Errorf("%w: the session has expired", errNoCredential)
		}
		// Re-read on every request, exactly as the token path does. A read of
		// one indexed row against the reader pool, which is the price of a
		// suspension taking effect now rather than within a week.
		u, err := identity.GetByID(r.Context(), s.db.Read(), id)
		if err != nil {
			s.sessions.drop(c.Value)
			return identity.Principal{}, err
		}
		if !u.Active() {
			// Dropped rather than merely refused: the session is over, and
			// leaving the entry to expire on its own would keep answering the
			// same question every request until it did.
			s.sessions.drop(c.Value)
			return identity.Principal{}, fmt.Errorf("%w: %q is %s", identity.ErrNotActive, u.Name, u.State)
		}
		// Rebuilt from the row rather than kept: the role comes from the same
		// read, so nothing about the user in a request is a snapshot of who
		// they were at sign-in. (Nothing writes a role change today — there is
		// no verb for one — but when there is, it lands on the next request.)
		return identity.Principal{User: u, Role: u.Role,
			Actor: audit.Actor{ID: u.ID, Method: "session"}}, nil
	}
	// Never local root. dev/plans/R1c-identity.md's argument for it is
	// filesystem access to the database; an HTTP caller has none, and treating
	// an unauthenticated request as an administrator would be the same
	// reasoning applied where it does not hold.
	return identity.Principal{}, errNoCredential
}

// sessionTTL is the active profile's, so a `regulated` install's thirty minutes
// is honored by the thing that issues cookies rather than by a constant.
func (s *Server) sessionTTL(ctx context.Context) time.Duration {
	active, _, err := policy.Active(ctx, s.db.Read())
	if err != nil || active.SessionTTLMinutes <= 0 {
		return 30 * time.Minute
	}
	return time.Duration(active.SessionTTLMinutes) * time.Minute
}
