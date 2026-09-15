package api_test

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
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
	for _, path := range []string{
		"login.html", "index.html", "app.js", "app.css", "login.js",
		"nodary.svg", "nodary-dark.svg", "nodary-mark.svg",
	} {
		asset := mustAsset(t, f, path)
		// An xmlns is a namespace *name* that happens to be spelled as a URL.
		// No browser ever resolves one, so it is dropped before the check —
		// otherwise every SVG in the tree fails a test about network access.
		// Anything else that spells out a host still has to answer for itself.
		asset = regexp.MustCompile(`xmlns(:[a-z0-9]+)?="[^"]*"`).ReplaceAllString(asset, "")
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

	// And every asset is served as what it is, not as something a browser
	// sniffs — these go out with `nosniff`, so a type this server does not
	// name is an asset the browser declines to run or draw.
	for path, want := range map[string]string{
		"/ui/app.js":          "text/javascript",
		"/ui/app.css":         "text/css",
		"/ui/nodary.svg":      "image/svg+xml",
		"/ui/nodary-mark.svg": "image/svg+xml",
	} {
		if got := f.get(path, cookie).Header.Get("Content-Type"); !strings.HasPrefix(got, want) {
			t.Errorf("%s content-type = %q, want %s", path, got, want)
		}
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

// nodeForTheConsole finds the JavaScript runtime the two checks below borrow.
//
// On a developer machine without node they skip, which is the right answer: a
// check that runs on CI and on any machine that has a parser is worth more than
// no check at all. On CI it is a failure instead — .github/workflows/ci.yml
// installs node for exactly these two tests, and a check that quietly stopped
// running is worse than one that was never written, because the tree still
// reads as though the screens are covered.
func nodeForTheConsole(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err == nil {
		return node
	}
	if os.Getenv("CI") != "" {
		t.Fatalf("no node on PATH, and CI installs one for the console's checks: %v", err)
	}
	t.Skip("no node on PATH to parse and run the console's scripts with")
	return ""
}

// The console's scripts are embedded, so a syntax error in one ships in the
// binary and shows as a blank page with a message only the browser console
// has. Nothing in Go parses JavaScript, so this borrows a parser when the host
// has one and says so when it does not — a check that runs on CI and on any
// developer machine with node, rather than no check at all.
func TestTheConsoleScriptsParse(t *testing.T) {
	node := nodeForTheConsole(t)
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
		"/deployments":     "/deployments",
		"/routes":          "/routes",
		"/users":           "/users",
		"/tokens":          "/tokens",
		"/limits":          "/limits",
		"/revisions":       "/revisions",
	}

	script := mustAsset(t, f, "app.js")
	fetched := map[string]bool{}
	for _, m := range regexp.MustCompile(`\bapi(?:Read)?\("([^"]*)"`).FindAllStringSubmatch(script, -1) {
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
		{"overview", "the landing screen: fleet health, capacity, usage and the chain"},
		{"fleet", "R7-02: nodes, their state, offer, reboot policy and last seen"},
		{"node", "R7-03: a node's deployments, their health, and the GPU topology"},
		{"catalog", "R7-04: the catalog and staging progress"},
		{"usage", "R7-05: usage over the metering record"},
		{"audit", "R7-06: the audit browser and the chain's verification status"},
		{"attention", "R7-08: refusals, out_of_policy and deployments that are not isolated"},
		{"logs", "R2-29: a failed deployment's captured log"},
		{"routes", "R8-04: route membership"},
		{"people", "R8-04: users and their credentials"},
		{"limits", "R8-04: throttling and quota"},
		{"policy", "R8-04: the active profile and configuration rollback"},
	} {
		if !declared[want.route] {
			t.Errorf("the console declares no %q view — %s", want.route, want.owes)
		}
	}
}

// The stylesheet is a token system, so the way it breaks is a name.
//
// A rule that reads `var(--surfce)` is a rule the browser drops on the floor,
// silently, leaving one panel transparent on a page that otherwise renders —
// and the two palettes mean a token can be defined in the dark block and
// missing from the light one, which shows up for whoever has the other setting.
// Nothing in Go parses CSS. What is worth pinning without a parser is that
// every token a rule reads is one some block defines, that the light palette
// defines all of them, and that the file is not truncated mid-rule.
func TestTheConsoleStylesheetDefinesEveryTokenItUses(t *testing.T) {
	f := newFixture(t)
	sheet := mustAsset(t, f, "app.css")

	if opened, closed := strings.Count(sheet, "{"), strings.Count(sheet, "}"); opened != closed {
		t.Fatalf("app.css has %d { and %d }: it is truncated or a rule is unclosed", opened, closed)
	}

	// The light palette is the base one: the dark block redefines, it does not
	// introduce. Cutting the sheet at the media query is what separates them.
	base := sheet
	if at := strings.Index(sheet, "@media (prefers-color-scheme: dark)"); at > 0 {
		base = sheet[:at]
	} else {
		t.Error("app.css has no dark palette; the console is expected to follow the viewer's scheme")
	}

	defines := func(in string) map[string]bool {
		found := map[string]bool{}
		for _, m := range regexp.MustCompile(`(--[a-z0-9-]+)\s*:`).FindAllStringSubmatch(in, -1) {
			found[m[1]] = true
		}
		return found
	}
	light, all := defines(base), defines(sheet)
	if len(light) == 0 {
		t.Fatal("no custom properties were found; app.css is a token system and this found none")
	}
	for _, m := range regexp.MustCompile(`var\((--[a-z0-9-]+)`).FindAllStringSubmatch(sheet, -1) {
		if !all[m[1]] {
			t.Errorf("app.css reads %s and no block defines it", m[1])
			continue
		}
		if !light[m[1]] {
			t.Errorf("app.css reads %s and only the dark palette defines it", m[1])
		}
	}
}

// Every view, executed against the real handlers.
//
// **The rest of the console's tests read it; this one runs it.** They check
// which endpoints it names, which screens it declares and which tokens its
// stylesheet uses — all of it static, none of it executing a line. The two
// faults that actually reached a commit were a view that vanished and a view
// that rendered the word "null", and no amount of reading found either.
//
// testdata/render.mjs is a DOM with no layout and no events, so this cannot see
// a screen that renders badly. It sees a screen that throws, one that puts
// nothing on the page, and one that lets a JavaScript value through as a word.
// Like TestTheConsoleScriptsParse it borrows node when the host has one.
func TestEveryConsoleViewRenders(t *testing.T) {
	node := nodeForTheConsole(t)
	f := newFixture(t)
	n := f.join("gpu-01")
	f.place("gpu-01", "dep_one", 0)
	f.setPassword("alice", "correct horse battery staple")
	cookie := f.loginCookie("alice", "correct horse battery staple")

	// Something for the screens to render: a node that has reported, with a
	// deployment that failed, which is what puts rows on `attention` and gives
	// `logs` a captured tail to show.
	if status, raw := n.call(t, f, http.MethodPost, "/agent/status", api.StatusReport{
		Protocol: api.Protocol, AgentVersion: "0.0.0-test",
		// A card the driver found, so the fleet table has a count to put a vendor
		// beside. The vendor itself is read from the *offer*, which is the
		// authority on it everywhere else in the tree.
		Inventory: api.Inventory{Arch: "amd64", OS: "linux",
			GPUs: json.RawMessage(`[{"index":0,"name":"card","memory_mib":8192}]`)},
		Deployments: []api.StatusUnit{{ID: "dep_one", State: "failed", Health: "unknown", Error: "boom"}},
	}); status != http.StatusOK {
		t.Fatalf("status: %d %s", status, raw)
	}

	// The fixture serves real TLS with its own certificate, so node is told to
	// trust that one rather than told to trust anything: a harness that turned
	// verification off would be the wrong habit to leave in the tree.
	ca := filepath.Join(t.TempDir(), "fixture.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw,
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(node, filepath.Join("testdata", "render.mjs"), filepath.Join("ui", "app.js"))
	cmd.Env = append(os.Environ(),
		// app.js prefixes every path with /api/v1 itself, so this is the
		// origin and nothing more.
		"ORIGIN="+f.srv.URL,
		"COOKIE="+cookie.Name+"="+cookie.Value,
		"NODE_EXTRA_CA_CERTS="+ca,
		"NODE_NAME=gpu-01",
		"DEPLOYMENT=dep_one",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("a console view did not render: %v\n%s", err, out)
	}

	// R6-17 put a vendor on every card, and the console shows a count. A node's
	// silicon decides which backends may be placed on it — sglang and vLLM are
	// CUDA-only — so a screen that says "1" and not which kind of 1 cannot
	// answer the question an operator opened it to ask.
	for _, route := range []string{"fleet", "node"} {
		if !strings.Contains(textOf(string(out), route), "nvidia") {
			t.Errorf("the %s screen does not say what silicon the node has:\n%s", route, out)
		}
	}
}

// textOf pulls one screen's rendered text out of the harness's output.
func textOf(out, route string) string {
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, "text   "+route+": "); ok {
			return rest
		}
	}
	return ""
}

// The brand files exist twice, and the copies have to stay the same drawing.
//
// The binary embeds internal/api/ui (//go:embed reaches nothing above it) and
// the published site serves docs/, so one file cannot do both jobs. Two copies
// is the cheap answer; two copies that quietly diverge — the console wearing
// last year's logo while the website wears this year's — is what makes it a
// bad one, so they are pinned to each other here.
func TestTheBrandFilesAreTheSameDrawingInBothPlaces(t *testing.T) {
	for _, name := range []string{"nodary.svg", "nodary-dark.svg", "nodary-mark.svg"} {
		embedded, err := os.ReadFile(filepath.Join("ui", name))
		if err != nil {
			t.Fatal(err)
		}
		published, err := os.ReadFile(filepath.Join("..", "..", "docs", "assets", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(embedded, published) {
			t.Errorf("internal/api/ui/%s and docs/assets/%s have drifted apart", name, name)
		}
	}
}
