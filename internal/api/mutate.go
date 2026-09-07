package api

import (
	"net/http"

	"github.com/nodarynet/nodary/internal/attest"
	"github.com/nodarynet/nodary/internal/core"
)

// Headers carrying the attestation of docs/specs/07-identity-audit.md §2.
//
// They are the CLI's --justify, --totp and the hash it prints under --dry-run,
// arriving by another road: 09 §2 makes attestation "available to API clients,
// not only the CLI", and the way to keep that promise honest is to parse them
// into the same attest.Ceremony the CLI builds and hand it to the same
// core.Act.
const (
	HeaderIntent  = "X-Nodary-Intent"
	HeaderJustify = "X-Nodary-Justify"
	HeaderTOTP    = "X-Nodary-TOTP"
)

// mutate runs an attested change and writes the outcome.
//
// Every mutating endpoint goes through here, and here does nothing but
// translate: HTTP in, core.Request out, core.Outcome in, HTTP out. A handler
// that decided anything about ceremony would be the second implementation of
// attestation this whole arrangement exists to prevent.
func (s *Server) mutate(w http.ResponseWriter, r *http.Request, c core.Change, onOK func(core.Outcome) any) {
	p, err := s.principalOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	req := core.Request{
		Principal: p,
		Ceremony: attest.Ceremony{
			Justification: r.Header.Get(HeaderJustify),
			TOTPCode:      r.Header.Get(HeaderTOTP),
			// There is nobody to prompt. An API client that must re-authenticate
			// is told so and sends a code; it is never asked interactively,
			// which is what makes attest.Require's non-interactive branch the
			// one that runs here.
			Interactive: false,
		},
		Intent:    r.Header.Get(HeaderIntent),
		DryRun:    r.URL.Query().Get("dry_run") == "true",
		RequestID: requestID(r),
	}

	out, err := core.Act(r.Context(), s.deps(), req, c)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	// R2-18: a dry run returns the rendered change and its intent_hash without
	// applying, and the hash is what the real call sends back as X-Nodary-Intent.
	if req.DryRun {
		writeJSON(w, http.StatusOK, map[string]any{
			"dry_run": true, "action": c.Action,
			"intent_hash": out.IntentHash, "change": out.Preview,
			"request_id": requestID(r),
		})
		return
	}

	body := map[string]any{
		"applied": true, "action": c.Action,
		"intent_hash": out.IntentHash, "audit_seq": out.Record.Seq,
		"request_id": requestID(r),
	}
	if onOK != nil {
		if extra := onOK(out); extra != nil {
			body["result"] = extra
		}
	}
	writeJSON(w, http.StatusOK, body)
}

// read runs an authenticated read.
func (s *Server) read(w http.ResponseWriter, r *http.Request, perm string, fn func(core.Deps) (any, error)) {
	p, err := s.principalOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if perm != "" {
		if err := authorizeRead(p, perm); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	body, err := fn(s.deps())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, body)
}
