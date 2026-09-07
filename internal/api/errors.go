// Package api serves docs/specs/09-api.md over HTTP.
//
// It holds no business logic. Every mutating handler builds an
// identity.Principal, an attest.Ceremony and a core.Change and hands them to
// core.Act — the same call the CLI makes — so the two front ends cannot
// disagree about what ceremony a mutation costs. What lives here is what a
// front end knows that the core cannot: how a credential arrived, and how to
// render an outcome as a status code.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/nodarynet/nodary/internal/attest"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/policy"
)

// Error is the envelope of docs/specs/09-api.md §3. `code` is stable and
// machine-readable; `message` is for a human.
type Error struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Detail    map[string]any `json:"detail,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
}

type errorBody struct {
	Error Error `json:"error"`
}

// statusFor maps an error to its status code and stable code.
//
// It walks the same errors.Is chain the CLI's exitFor walks, deliberately: a
// policy refusal must not be exit 5 in one front end and 500 in the other, and
// the only way to guarantee that is for both tables to be driven by the same
// error values.
func statusFor(err error) (int, string) {
	switch {
	case err == nil:
		return http.StatusOK, ""

	case errors.Is(err, identity.ErrBadToken),
		errors.Is(err, identity.ErrTokenRevoked),
		errors.Is(err, identity.ErrTokenExpired),
		errors.Is(err, identity.ErrNotActive),
		errors.Is(err, identity.ErrBadPassword),
		errors.Is(err, identity.ErrNoPassword),
		errors.Is(err, errNoCredential):
		return http.StatusUnauthorized, "unauthenticated"

	// 403 rather than 404 for something the caller may not have. 09 §3 is
	// explicit that hiding existence buys nothing here and costs support time.
	case errors.Is(err, identity.ErrDenied):
		return http.StatusForbidden, "forbidden"

	case errors.Is(err, identity.ErrNotFound),
		errors.Is(err, identity.ErrNoTokens),
		errors.Is(err, config.ErrNoRevision):
		return http.StatusNotFound, "not_found"

	case errors.Is(err, identity.ErrNameTaken),
		errors.Is(err, identity.ErrBadTransition):
		return http.StatusConflict, "conflict"

	case errors.Is(err, attest.ErrIntentChanged):
		return http.StatusPreconditionFailed, "intent_changed"

	case errors.Is(err, attest.ErrJustification):
		return http.StatusForbidden, "justification_required"
	case errors.Is(err, attest.ErrJustificationShort):
		return http.StatusForbidden, "justification_too_short"
	case errors.Is(err, attest.ErrTOTPRequired):
		return http.StatusForbidden, "reauthentication_required"
	case errors.Is(err, attest.ErrUnattendedForbidden):
		return http.StatusForbidden, "unattended_forbidden"
	case errors.Is(err, identity.ErrBadCode):
		return http.StatusUnauthorized, "reauthentication_failed"

	case errors.Is(err, policy.ErrInvalid),
		errors.Is(err, identity.ErrBadName),
		errors.Is(err, identity.ErrUnknownRole),
		errors.Is(err, identity.ErrUnknownKind),
		errors.Is(err, identity.ErrWeakPassword),
		errors.Is(err, config.ErrUnknownNode):
		return http.StatusUnprocessableEntity, "invalid"

	case errors.Is(err, errBadRequest):
		return http.StatusBadRequest, "bad_request"
	}
	return http.StatusInternalServerError, "internal"
}

var (
	errBadRequest   = errors.New("malformed request")
	errNoCredential = errors.New("no credential was presented")
)

func badRequest(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errBadRequest, fmt.Sprintf(format, a...))
}

// fail writes the error envelope.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code := statusFor(err)
	body := errorBody{Error: Error{Code: code, Message: err.Error(), RequestID: requestID(r)}}

	// A 500 is the one case where the caller must not be told what happened:
	// the message can carry a query, a path or a driver's own text. It is
	// logged instead, against the request id the caller was given.
	if status == http.StatusInternalServerError {
		s.logf("request %s: %v", requestID(r), err)
		body.Error.Message = "the server failed to handle this request"
	}
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
