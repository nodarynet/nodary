package api_test

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
)

// get fetches a path outside /api/v1 without following redirects, because
// where it redirects *to* is the thing under test.
func (f *fixture) get(path string, cookie *http.Cookie) *http.Response {
	f.t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.srv.URL+path, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	client := *f.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// R7-01. The console is served out of the binary, and an unauthenticated
// request gets the login form rather than the console — including for the
// stylesheet and the script, because a scanner reaching a control plane inside
// a CUI boundary should not learn what this is or which version it runs.
func TestTheConsoleIsServedFromTheBinaryBehindASession(t *testing.T) {
	f := newFixture(t)

	for _, path := range []string{"/ui/", "/ui/index.html", "/ui/app.js", "/ui/app.css"} {
		resp := f.get(path, nil)
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("%s with no session: status = %d, want a redirect", path, resp.StatusCode)
			continue
		}
		if got := resp.Header.Get("Location"); got != api.LoginPath {
			t.Errorf("%s redirects to %q, want %q", path, got, api.LoginPath)
		}
	}

	// The root is where an operator types, and it is an exact match: a
	// catch-all would answer a mistyped API path with a page.
	if resp := f.get("/", nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("/ status = %d, want a redirect to the console", resp.StatusCode)
	}
	if resp := f.get("/api/v1/nosuchthing", nil); resp.StatusCode == http.StatusSeeOther {
		t.Error("a mistyped API path was answered with the console")
	}

	// The login page is the one thing a request with no session may have.
	resp := f.get(api.LoginPath, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the login page: status = %d", resp.StatusCode)
	}
	page := body(t, resp)
	if !strings.Contains(page, "<form") {
		t.Error("the login page carries no form")
	}
	// setup.go's rule, which this follows: no stylesheet, no script, no
	// external anything. A CDN reference is a request that fails on exactly
	// the air-gapped host this product is for.
	for _, path := range []string{"login.html", "index.html", "app.js", "app.css", "login.js"} {
		asset := mustAsset(t, f, path)
		for _, remote := range []string{"http://", "https://", "//cdn", "//unpkg", "//fonts."} {
			if strings.Contains(asset, remote) {
				t.Errorf("%s reaches outside the binary: %q", path, remote)
			}
		}
	}
}

// With a session, the console is served — and it says it may not be cached or
// framed, because it is a page rather than an API answer and 09 §3's envelope
// does not reach it.
func TestTheConsoleIsServedToASessionWithItsProtections(t *testing.T) {
	f := newFixture(t)
	f.setPassword("alice", "correct horse battery staple")
	cookie := f.loginCookie("alice", "correct horse battery staple")

	resp := f.get("/ui/", cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the console with a session: status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("content-type = %q", got)
	}
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("the policy is missing %q: %q", want, csp)
		}
	}

	// And the script is served as a script, not as something a browser sniffs.
	if got := f.get("/ui/app.js", cookie).Header.Get("Content-Type"); !strings.HasPrefix(got, "text/javascript") {
		t.Errorf("app.js content-type = %q", got)
	}
	// A session on the login page is sent to the console rather than offered a
	// form that would end the session it already has by succeeding.
	if resp := f.get(api.LoginPath, cookie); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("the login page with a live session: status = %d, want a redirect", resp.StatusCode)
	}
}

func mustAsset(t *testing.T, f *fixture, name string) string {
	t.Helper()
	f.setPassword("alice", "correct horse battery staple")
	resp := f.get("/ui/"+name, f.loginCookie("alice", "correct horse battery staple"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: status = %d", name, resp.StatusCode)
	}
	return body(t, resp)
}

// The console's scripts are embedded, so a syntax error in one ships in the
// binary and shows as a blank page with a message only the browser console
// has. Nothing in Go parses JavaScript, so this borrows a parser when the host
// has one and says so when it does not — a check that runs on CI and on any
// developer machine with node, rather than no check at all.
func TestTheConsoleScriptsParse(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on PATH to parse the console's scripts with")
	}
	entries, err := os.ReadDir(filepath.Join("ui"))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".js" {
			continue
		}
		checked++
		if out, err := exec.Command(node, "--check", filepath.Join("ui", e.Name())).CombinedOutput(); err != nil {
			t.Errorf("%s does not parse: %v\n%s", e.Name(), err, out)
		}
	}
	if checked == 0 {
		t.Error("no scripts were checked; the console has scripts and this found none")
	}
}

// Every endpoint the console fetches, against the real handlers.
//
// **The console holds no business logic, so what it can get wrong is which
// door it knocks on.** A browser test would need a browser; what is worth
// pinning without one is that every path app.js names is a path this server
// serves, and that a screen added later cannot quietly call something that
// answers 404 — the table below is checked against the script, so a new fetch
// with no entry fails here rather than in somebody's browser.
func TestEveryEndpointTheConsoleCallsIsServed(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")
	f.place("gpu-01", "dep_one", 0)
	f.setPassword("alice", "correct horse battery staple")
	cookie := f.loginCookie("alice", "correct horse battery staple")

	// A report, so the node has deployments and staging to render.
	if status, raw := n.call(t, f, http.MethodPost, "/agent/status", api.StatusReport{
		Protocol: api.Protocol, AgentVersion: "0.0.0-test",
		Inventory:   api.Inventory{Arch: "amd64", OS: "linux"},
		Deployments: []api.StatusUnit{{ID: "dep_one", State: "failed", Health: "unknown", Error: "boom"}},
	}); status != http.StatusOK {
		t.Fatalf("status: %d %s", status, raw)
	}

	// The literal each api() call starts with, and a concrete path for it.
	called := map[string]string{
		"/auth/whoami":     "/auth/whoami",
		"/policy":          "/policy",
		"/nodes":           "/nodes",
		"/nodes/":          "/nodes/gpu-01",
		"/models":          "/models",
		"/usage?group_by=": "/usage?group_by=model",
		"/audit":           "/audit",
		"/audit/verify":    "/audit/verify",
		"/deployments/":    "/deployments/dep_one/logs",
	}

	script := mustAsset(t, f, "app.js")
	fetched := map[string]bool{}
	for _, m := range regexp.MustCompile(`api\("([^"]*)"`).FindAllStringSubmatch(script, -1) {
		fetched[m[1]] = true
		if _, ok := called[m[1]]; !ok {
			t.Errorf("app.js fetches %q and this test does not cover it", m[1])
		}
	}
	// And the other direction: an entry here that nothing fetches is an
	// endpoint the console has stopped using.
	for literal := range called {
		if !fetched[literal] {
			t.Errorf("nothing in app.js fetches %q any more", literal)
		}
	}

	for literal, path := range called {
		req, err := http.NewRequest(http.MethodGet, f.srv.URL+api.Prefix+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(cookie)
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("the console calls %s (from %q) and it answers %d", path, literal, resp.StatusCode)
		}
	}
}

// The screens R7 owes, by name.
//
// **This exists because one went missing and nothing noticed.** A `git checkout
// --` during an injection reverted app.js and took the node view with it, and
// the commit after that shipped the GPU topology with nothing displaying it.
// The endpoint test above did not catch it: another screen fetches /nodes/ too,
// so every covered endpoint was still being called. What was actually lost was
// a *view*, so a view is what has to be checked.
func TestTheConsoleDeclaresEveryScreenR7Owes(t *testing.T) {
	f := newFixture(t)
	script := mustAsset(t, f, "app.js")

	declared := map[string]bool{}
	for _, m := range regexp.MustCompile(`route:\s*"([^"]+)"`).FindAllStringSubmatch(script, -1) {
		declared[m[1]] = true
	}
	for _, want := range []struct{ route, owes string }{
		{"fleet", "R7-02: nodes, their state, offer, reboot policy and last seen"},
		{"node", "R7-03: a node's deployments, their health, and the GPU topology"},
		{"catalog", "R7-04: the catalog and staging progress"},
		{"usage", "R7-05: usage over the metering record"},
		{"audit", "R7-06: the audit browser and the chain's verification status"},
		{"attention", "R7-08: refusals, out_of_policy and deployments that are not isolated"},
		{"logs", "R2-29: a failed deployment's captured log"},
	} {
		if !declared[want.route] {
			t.Errorf("the console declares no %q view — %s", want.route, want.owes)
		}
	}
}
