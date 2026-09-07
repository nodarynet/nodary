package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/core"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/secret"
	"github.com/nodarynet/nodary/internal/store"
)

// Prefix is where every endpoint lives. Versioned from the first release, so
// the second one does not have to invent a way to be compatible.
const Prefix = "/api/v1"

// Server holds the process's handles. It is deliberately small: a handler that
// needed something not here would be a handler doing something the core should.
type Server struct {
	db  *store.DB
	log *audit.Log
	key func() (*secret.Key, error)
	// pki is where the agent CA lives: the enrolment endpoint signs from it and
	// the listener verifies client certificates against it.
	pki  string
	now  func() time.Time
	slog *slog.Logger
	// sessions are the cookie-authenticated logins. In-memory because they are
	// short-lived by policy and because a restart invalidating them is the
	// correct outcome: docs/specs/07-identity-audit.md §2 makes a session a
	// weaker thing than an act's own attestation, and the CLI does not use them
	// at all.
	sessions *sessionStore
}

// Options configure a server.
type Options struct {
	DB   *store.DB
	Log  *audit.Log
	Key  func() (*secret.Key, error)
	PKI  string
	Now  func() time.Time
	Slog *slog.Logger
}

// New builds a server.
func New(o Options) *Server {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Slog == nil {
		o.Slog = slog.Default()
	}
	return &Server{db: o.DB, log: o.Log, key: o.Key, pki: o.PKI, now: o.Now, slog: o.Slog,
		sessions: newSessionStore()}
}

func (s *Server) logf(format string, a ...any) {
	s.slog.Error("api", "detail", fmt.Sprintf(format, a...))
}

// Handler is the routed, middleware-wrapped surface.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux)
	return withRequestID(mux)
}

// deps hands core this process's handles, so an HTTP handler and a CLI verb
// reach the same functions with the same arguments.
func (s *Server) deps() core.Deps {
	return core.Deps{DB: s.db, Log: s.log, Key: s.key, Now: s.now()}
}

// --- request ids -------------------------------------------------------------

type ctxKey int

const requestIDKey ctxKey = iota

// withRequestID mints an id for every request and returns it in a header.
//
// R2-24: it travels into the audit record, so a user's report of one bad
// request resolves to one row without guesswork. A client-supplied id is
// honoured but namespaced, because an id a caller chose must not be able to
// impersonate one the server issued.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := "req_" + randomHex(8)
		if given := r.Header.Get("X-Request-Id"); given != "" && len(given) <= 64 {
			id = "cli_" + sanitise(given)
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

func requestID(r *http.Request) string {
	if v, ok := r.Context().Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}

// sanitise keeps a client-supplied id to characters that cannot break a log
// line or a JSON document.
func sanitise(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		}
	}
	return string(out)
}

// --- helpers -----------------------------------------------------------------

// principalOf resolves who is calling, from a bearer token or a session cookie.
func (s *Server) principalOf(r *http.Request) (identity.Principal, error) {
	return s.authenticate(r)
}
