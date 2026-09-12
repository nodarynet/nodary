// Package gateway serves the OpenAI surface: docs/specs/06-gateway.md.
//
// It is the first thing in this product that ever holds a prompt, and the only
// thing that ever will. docs/adr/0006-cui-boundary-and-fips.md makes "nodary
// records that a request happened, never what it said" structural, so the rule
// this package is written under is narrow and absolute:
//
//	A request or response body is read from one socket and written to another.
//	It is never logged, never stored, never put in an error, and never held
//	after the response is finished.
//
// TestNoRequestContentReachesStorage fails the build if a path from a body to
// storage or a log appears, on the same principle as the audit seam's gate: the
// failure mode is not somebody deciding to log prompts, it is one debug line
// added at 2am in a package where that has never been wrong before.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/observed"
	"github.com/nodarynet/nodary/internal/store"
)

// Server is the gateway process.
type Server struct {
	db   *store.DB
	log  *slog.Logger
	now  func() time.Time
	up   *url.URL
	prox *httputil.ReverseProxy
	// masterKey authenticates the gateway to LiteLLM. It never reaches a
	// client: docs/specs/06-gateway.md §1 has LiteLLM stateless behind a single
	// key, which is what lets it hold no database and no identities.
	masterKey string
	throttle  *throttle
}

// Options configure a gateway.
type Options struct {
	DB        *store.DB
	Upstream  string
	MasterKey string
	Log       *slog.Logger
	Now       func() time.Time
}

// New builds a gateway pointed at LiteLLM.
func New(o Options) (*Server, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	up, err := url.Parse(o.Upstream)
	if err != nil || up.Host == "" {
		return nil, fmt.Errorf("%w: upstream %q is not a URL", ErrBadConfig, o.Upstream)
	}

	s := &Server{db: o.DB, log: o.Log, now: o.Now, up: up, masterKey: o.MasterKey,
		throttle: newThrottle()}
	s.prox = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(up)
			// The client's own Authorization never reaches LiteLLM. It
			// identifies a person to nodary and means nothing upstream, and
			// forwarding a credential past the component that consumed it is
			// how a stateless proxy acquires an identity it should not have.
			r.Out.Header.Set("Authorization", "Bearer "+o.MasterKey)
			r.Out.Header.Del("Cookie")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// 502 and no fallback. docs/specs/06-gateway.md §5: the gateway does
			// not proxy directly to deployments, because that path would bypass
			// routing and fallback logic — and the error carries no body,
			// because the body is the thing this package must not surface.
			s.log.Error("gateway", "detail", "upstream: "+err.Error(),
				"request_id", requestID(r))
			writeError(w, http.StatusBadGateway, "upstream_unavailable",
				"the model gateway is unreachable", nil, requestID(r))
		},
	}
	return s, nil
}

// ErrBadConfig is an unusable gateway configuration.
var ErrBadConfig = errors.New("invalid gateway configuration")

// Handler is the routed surface of docs/specs/06-gateway.md §1.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// The OpenAI surface, and nothing else. A path not listed here is a 404
	// rather than something proxied blind: LiteLLM has an administrative API of
	// its own, and exposing it through a credential nodary issued would hand a
	// client the master key's authority.
	mux.HandleFunc("POST /v1/chat/completions", s.proxyInference)
	mux.HandleFunc("POST /v1/completions", s.proxyInference)
	mux.HandleFunc("POST /v1/embeddings", s.proxyInference)
	mux.HandleFunc("GET /v1/models", s.listModels)
	return withRequestID(mux)
}

// principal resolves the bearer token to a person: docs/specs/06-gateway.md §2.
func (s *Server) principal(r *http.Request) (identity.Principal, error) {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(raw, "Bearer ") {
		return identity.Principal{}, fmt.Errorf("%w: present a service key as `Authorization: Bearer nodary_sk_…`",
			identity.ErrBadToken)
	}
	presented := strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))

	// A read to resolve, and a separate observation to record the use.
	//
	// identity.Authenticate cannot write — last_used_at is stamped by
	// identity.Touch inside the act a credential authorized. An inference
	// request authorizes no act and produces no audit record, so the touch has
	// nothing to ride along with and goes through internal/observed instead:
	// a credential being presented is something that happened, not something
	// anybody decided.
	p, err := identity.ResolveToken(r.Context(), s.db.Read(), s.now(), presented)
	if err != nil {
		return identity.Principal{}, err
	}
	user, tok := p.User, p.Token
	// The kind is checked, not just the credential. docs/specs/02-enrollment.md
	// §4 gives each prefix one purpose — `sk` is inference, `pt` is the CLI and
	// the control-plane API — and docs/specs/06-gateway.md §2 says clients
	// present `nodary_sk_…`.
	//
	// Enforcing it keeps one leaked credential from doing both jobs. A personal
	// token is long-lived on somebody's workstation and can mutate the control
	// plane; accepting it here would make that the same credential that any
	// application holding an inference key uses.
	if tok.Kind != identity.KindService {
		return identity.Principal{}, fmt.Errorf(
			"%w: the inference API takes a service key (%s…), not a %s; mint one with `nodary token create --kind sk`",
			identity.ErrBadToken, identity.KindService.Prefix(), tok.Kind)
	}

	// docs/specs/06-gateway.md §2, point 4. Logged rather than returned: a
	// request that authenticated correctly must not fail because a timestamp
	// could not be written.
	if err := observed.TouchToken(r.Context(), s.db, tok.ID, s.now()); err != nil {
		s.log.Warn("gateway", "detail", err.Error(), "request_id", requestID(r))
	}
	return identity.Principal{User: user, Token: tok, Role: user.Role}, nil
}

// authorize resolves the caller and checks they may use inference at all.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) (identity.Principal, bool) {
	p, err := s.principal(r)
	if err != nil {
		s.fail(w, r, err)
		return identity.Principal{}, false
	}
	if err := identity.Authorize(p.Role, identity.PermInferenceUse); err != nil {
		s.fail(w, r, err)
		return identity.Principal{}, false
	}
	return p, true
}

// routesFor is the caller's model allowlist.
//
// A user with no grants may call nothing. 0010_grants.sql carries the
// reasoning: docs/specs/07-identity-audit.md §5 maps this to AC-3 and AC-6 with
// the words "least privilege by default", and an empty allowlist meaning every
// route would make that sentence false.
func (s *Server) routesFor(ctx context.Context, p identity.Principal) (map[string]bool, error) {
	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT route_name FROM user_route WHERE user_id = ? ORDER BY route_name`, p.User.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

// listModels returns only the routes the caller may use — not the fleet.
//
// docs/specs/06-gateway.md §1 is explicit about that, and the reason is
// consistency with the 403 below: a client that discovers a model here and is
// then refused it has been told two different things by the same server.
func (s *Server) listModels(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r)
	if !ok {
		return
	}
	allowed, err := s.routesFor(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	// The OpenAI list shape, so an unmodified client library works.
	data := []map[string]any{}
	for name := range allowed {
		data = append(data, map[string]any{
			"id": name, "object": "model", "owned_by": "nodary",
			"created": s.now().Unix(),
		})
	}
	sortByID(data)
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

// Serve runs the gateway until the context is cancelled.
//
// Plaintext on loopback by default, unlike the control plane. The gateway sits
// behind whatever terminates TLS for clients — a reverse proxy, or the control
// plane's own listener — and the deployments it proxies to are on 127.0.0.1
// anyway. Binding it to a public address without TLS in front is an operator's
// decision to make, and the flag's default does not make it for them.
func Serve(ctx context.Context, h http.Handler, bind string) error {
	srv := &http.Server{
		Addr: bind, Handler: h,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: a streaming completion legitimately runs for
		// minutes, and a deadline here would cut one off mid-token.
		IdleTimeout: 120 * time.Second,
	}
	done := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		return nil
	}
}
