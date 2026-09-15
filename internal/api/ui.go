package api

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// UIPath is where the console lives. Under its own prefix rather than at the
// root so that "/" can stay an exact-match redirect: a catch-all would also
// swallow a mistyped /api/v1 path and answer a program with a page.
const UIPath = "/ui/"

// LoginPath is the one page inside the console that a request with no session
// may have.
const LoginPath = UIPath + "login"

//go:embed ui
var uiFS embed.FS

// console is the embedded tree rooted at the directory, so a request for
// /ui/app.js reads "app.js" rather than "ui/app.js".
var console, _ = fs.Sub(uiFS, "ui")

// serveUI is R7-01: the read-only console, served out of the binary behind the
// session cookie.
//
// **Out of the binary, and reaching nothing outside it.** internal/api/setup.go
// already fixed the rule this follows — "no stylesheet, no script, no external
// anything", because a reference to a CDN is a request that fails on exactly
// the air-gapped host this product is for. The console is a page, a stylesheet
// and a script, all embedded; every byte it needs comes from the same binary an
// operator installed.
//
// **Behind the session, including the assets.** The files carry no fleet data —
// everything they show comes from /api/v1, which is authenticated in its own
// right — so gating them buys one thing: an unauthenticated scanner reaching a
// control plane inside a CUI boundary learns nothing, not even that this is
// nodary or which version. That is cheap here and awkward to add later.
func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, UIPath)
	if name == "login" {
		s.serveLogin(w, r)
		return
	}
	if _, err := s.authenticate(r); err != nil {
		// A redirect rather than a 401, because this is a browser following a
		// link and the useful answer is the login form. The API under
		// /api/v1 still answers 401, which is what a program needs.
		http.Redirect(w, r, LoginPath, http.StatusSeeOther)
		return
	}
	if name == "" {
		name = "index.html"
	}
	s.serveAsset(w, r, name)
}

// serveAsset writes one embedded file, or the shell for a path the console
// routes itself.
func (s *Server) serveAsset(w http.ResponseWriter, r *http.Request, name string) {
	// Cleaned before it is used: fs.FS rejects a traversal already, and an
	// explicit refusal is cheaper to read than the absence of one.
	if name = path.Clean(name); strings.HasPrefix(name, "..") || path.IsAbs(name) {
		http.NotFound(w, r)
		return
	}
	body, err := fs.ReadFile(console, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// The console is served to somebody holding a live session inside a CUI
	// boundary, so no intermediary keeps a copy. `no-store` rather than a
	// validator: these files change only when the binary does, and an operator
	// who upgraded and got yesterday's script would see a console disagreeing
	// with its own API.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", contentType(name))
	if strings.HasSuffix(name, ".html") {
		// 09 §3's envelope does not reach a page, so the page gets the
		// protections a page needs. The console loads nothing remote, so the
		// policy can be absolute rather than an allowlist somebody widens.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; "+
				"connect-src 'self'; img-src 'self' data:; form-action 'self'; "+
				"base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
	}
	_, _ = w.Write(body)
}

func contentType(name string) string {
	switch path.Ext(name) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	}
	return "application/octet-stream"
}

// serveLogin is the one page a request with no session may have.
//
// It posts to /api/v1/auth/login like any other client, so the cookie it gets
// is the one the API issues and there is no second way to start a session.
func (s *Server) serveLogin(w http.ResponseWriter, r *http.Request) {
	// A live session has no business here: it would be a form that logs
	// somebody out of the account they are already using by succeeding.
	if _, err := s.authenticate(r); err == nil {
		http.Redirect(w, r, UIPath, http.StatusSeeOther)
		return
	}
	s.serveAsset(w, r, "login.html")
}

// uiRoot is the address an operator types. Exact-match, so it redirects the
// root and nothing else.
func (s *Server) uiRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, UIPath, http.StatusSeeOther)
}
