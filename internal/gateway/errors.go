package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/nodarynet/nodary/internal/identity"
)

// Error is docs/specs/06-gateway.md §6's envelope, which is the same shape the
// control-plane API uses. `code` is stable and machine-readable; `message` is
// for a human.
type Error struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Detail    map[string]any `json:"detail,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
}

var errBadRequest = errors.New("malformed request")

func badRequest(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errBadRequest, fmt.Sprintf(format, a...))
}

// statusFor walks the same error values the control-plane API walks, so a
// revoked token is 401 on both surfaces and a denial is 403 on both. A client
// that learned one should not have to learn the other.
func statusFor(err error) (int, string) {
	switch {
	case errors.Is(err, identity.ErrBadToken),
		errors.Is(err, identity.ErrTokenRevoked),
		errors.Is(err, identity.ErrTokenExpired),
		errors.Is(err, identity.ErrNotActive):
		return http.StatusUnauthorized, "unauthenticated"
	case errors.Is(err, identity.ErrDenied):
		return http.StatusForbidden, "forbidden"
	case errors.Is(err, errBadRequest):
		return http.StatusBadRequest, "bad_request"
	}
	return http.StatusInternalServerError, "internal"
}

// fail writes the envelope.
//
// A 500's message is never returned, for the reason the API gives and one more
// that is specific here: an internal error on this path may have a request body
// somewhere in its chain, and the body is the thing this package exists not to
// surface.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code := statusFor(err)
	body := Error{Code: code, Message: err.Error(), RequestID: requestID(r)}
	if status == http.StatusInternalServerError {
		s.log.Error("gateway", "detail", err.Error(), "request_id", requestID(r))
		body.Message = "the gateway failed to handle this request"
	}
	writeError(w, status, body.Code, body.Message, body.Detail, body.RequestID)
}

func writeError(w http.ResponseWriter, status int, code, message string,
	detail map[string]any, reqID string) {
	writeJSON(w, status, map[string]any{
		"error": Error{Code: code, Message: message, Detail: detail, RequestID: reqID},
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func sortByID(data []map[string]any) {
	sort.Slice(data, func(i, j int) bool {
		a, _ := data[i]["id"].(string)
		b, _ := data[j]["id"].(string)
		return a < b
	})
}

// --- request ids -------------------------------------------------------------

type ctxKey int

const requestIDKey ctxKey = iota

// withRequestID mints an id for every request and returns it in a header.
//
// docs/specs/06-gateway.md §6: it appears in the usage record and in the log,
// so a user's report of one bad request resolves to one row without guesswork —
// which is also the only way to investigate a request whose content nobody
// kept.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := "req_" + randomHex(8)
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
