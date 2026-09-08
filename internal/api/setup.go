package api

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
)

// SetupPath is where the one-time URL of docs/specs/01-install.md §4 step 9
// points.
//
// Not under Prefix. Everything under /api/v1 is a machine surface; this is the
// one address in the product a person is handed and opens, and `install.sh`
// prints it as `https://host:8443/setup?t=…` because that is what somebody can
// paste into a browser on another machine.
const SetupPath = "/setup"

// setup serves the form and redeems it.
//
// The whole feature exists so that **no default password ever exists**
// (R5-08). Every alternative creates one: a generated password printed at
// install is a default until somebody changes it, and an unauthenticated
// /setup that stays open until first use is a default that lasts until somebody
// notices. A credential that expires in fifteen minutes and dies on first use
// is neither.
//
// The token travels in the query string, which puts it in browser history and
// in any proxy log on the path. That is the cost of a link somebody can be
// handed, and it is paid down by the two properties above rather than by
// pretending the exposure is not real: fifteen minutes after it is printed the
// string in that history is worth nothing.
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	// Never cached, never stored. The page carries a live credential in a
	// hidden field and the response to a redemption names an account.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")

	if r.Method == http.MethodGet {
		s.renderSetup(w, http.StatusOK, r.URL.Query().Get("t"), "")
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderSetup(w, http.StatusBadRequest, "", "the form could not be read")
		return
	}
	token := r.PostFormValue("t")
	name := r.PostFormValue("name")
	email := r.PostFormValue("email")
	password := r.PostFormValue("password")
	if password != r.PostFormValue("confirm") {
		s.renderSetup(w, http.StatusBadRequest, token, "the two passwords do not match")
		return
	}

	var created identity.User
	_, err := s.log.Act(r.Context(), audit.Request{
		// The credential is the actor. There is no account yet, and naming one
		// that does not exist would put a fiction in the chain.
		Actor:  audit.Actor{ID: name, Method: "setup-link"},
		Action: "installation.setup",
		Target: &audit.Target{Kind: "user", ID: name},
	}, func(m audit.Mutation) error {
		var err error
		created, err = identity.RedeemSetup(r.Context(), m, s.now(), token, name, email, password)
		return err
	})
	if err != nil {
		// Status by cause: a spent installation is a conflict, an unusable link
		// is a refusal, and a bad name or a short password is the operator's to
		// correct and keeps them on the form.
		code := http.StatusBadRequest
		switch {
		case errors.Is(err, identity.ErrSetupDone):
			code = http.StatusConflict
		case errors.Is(err, identity.ErrSetupUnavailable):
			code = http.StatusForbidden
		}
		s.renderSetup(w, code, token, err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := setupDone.Execute(w, created.Name); err != nil {
		s.logf("rendering the setup confirmation: %v", err)
	}
}

// renderSetup writes the form, with an error above it when there is one.
func (s *Server) renderSetup(w http.ResponseWriter, code int, token, problem string) {
	w.WriteHeader(code)
	if err := setupForm.Execute(w, struct{ Token, Problem string }{token, problem}); err != nil {
		s.logf("rendering the setup form: %v", err)
	}
}

// The two pages, as html/template so that nothing a caller supplies — a name, a
// token, an error naming either — can be reflected as markup. text/template
// would render the same output and escape none of it.
//
// No stylesheet, no script, no external anything. This page is served by a
// control plane on a self-signed certificate to somebody who has just installed
// it, and a reference to a CDN would be a request that fails on exactly the
// air-gapped host this product is for.
var (
	setupForm = template.Must(template.New("setup").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>nodary — first administrator</title>
<style>
 body{font:16px/1.5 system-ui,sans-serif;max-width:26rem;margin:4rem auto;padding:0 1rem}
 label{display:block;margin:1rem 0 .25rem;font-weight:600}
 input{width:100%;padding:.5rem;font-size:1rem;box-sizing:border-box}
 .problem{background:#fdd;border-left:4px solid #c00;padding:.75rem;margin-bottom:1rem}
 button{margin-top:1.5rem;padding:.6rem 1.2rem;font-size:1rem}
 p.note{color:#555;font-size:.875rem}
</style></head><body>
<h1>Create the first administrator</h1>
{{if .Problem}}<p class="problem">{{.Problem}}</p>{{end}}
<p class="note">This link works once and expires fifteen minutes after it was printed.
Nobody but you will ever know this password.</p>
<form method="post" action="/setup">
 <input type="hidden" name="t" value="{{.Token}}">
 <label for="name">Username</label>
 <input id="name" name="name" autocomplete="username" autofocus required>
 <label for="email">Email</label>
 <input id="email" name="email" type="email" autocomplete="email">
 <label for="password">Password</label>
 <input id="password" name="password" type="password" autocomplete="new-password" required>
 <label for="confirm">Repeat the password</label>
 <input id="confirm" name="confirm" type="password" autocomplete="new-password" required>
 <button type="submit">Create</button>
</form>
</body></html>
`))

	setupDone = template.Must(template.New("done").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>nodary — set up</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:26rem;margin:4rem auto;padding:0 1rem}</style>
</head><body>
<h1>Done</h1>
<p><strong>{{.}}</strong> is an administrator of this control plane, and the setup link is
now dead.</p>
<p>Sign in from the command line with <code>nodary login</code>.</p>
</body></html>
`))
)

// SetupURL is the line an install prints.
func SetupURL(base, token string) string {
	return fmt.Sprintf("%s%s?t=%s", base, SetupPath, token)
}
