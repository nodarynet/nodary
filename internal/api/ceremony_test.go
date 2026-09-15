package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
)

// attempt is one step of the ceremony, made exactly as app.js's send() makes
// it: the same query parameter, the same headers, a JSON body.
func (f *fixture) ceremonyStep(method, path string, cookie *http.Cookie, headers map[string]string) (int, map[string]any) {
	f.t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+api.Prefix+path, bytes.NewReader([]byte("{}")))
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &doc)
	return resp.StatusCode, doc
}

// R8-01, driven as the console drives it: preview, take the hash, apply.
//
// **And then the refusal that makes the hash worth having.** 11 §3 turns a
// preview that no longer describes what would happen into a refusal rather
// than an overwrite, so an intent from before somebody else acted is a 412 —
// which is what app.js loops back to the preview on, and the reason it loops
// rather than reporting a failure.
func TestTheBrowsersCeremonyPreviewsThenApplies(t *testing.T) {
	f := newFixture(t)
	f.join("gpu-01")
	f.setPassword("alice", "correct horse battery staple")
	cookie := f.loginCookie("alice", "correct horse battery staple")

	justify := map[string]string{api.HeaderJustify: "the node in the rack we ordered"}

	// 1. The preview, which applies nothing and returns the hash that binds it.
	status, doc := f.ceremonyStep(http.MethodPost, "/nodes/gpu-01/approve?dry_run=true", cookie, justify)
	if status != http.StatusOK {
		t.Fatalf("preview: %d %v", status, doc)
	}
	if doc["applied"] == true {
		t.Error("a dry run applied")
	}
	hash, _ := doc["intent_hash"].(string)
	if hash == "" {
		t.Fatalf("the preview returned no intent_hash, which is what app.js sends back: %v", doc)
	}
	// app.js renders doc.change; a preview with nothing to render would leave
	// an operator approving a blank dialog.
	if doc["change"] == nil {
		t.Errorf("the preview carries no change to show: %v", doc)
	}

	// 2. A stale hash, which is what happens when somebody else acts first.
	stale := map[string]string{
		api.HeaderJustify: "the node in the rack we ordered",
		api.HeaderIntent:  strings.Repeat("0", 64),
	}
	status, doc = f.ceremonyStep(http.MethodPost, "/nodes/gpu-01/approve", cookie, stale)
	if status != http.StatusPreconditionFailed {
		t.Fatalf("a stale intent answered %d, want 412: %v", status, doc)
	}
	if code := errCode(doc); code != "intent_changed" {
		t.Errorf("code = %q, want intent_changed — app.js branches on the status here", code)
	}

	// 3. The hash the preview gave, which applies.
	fresh := map[string]string{
		api.HeaderJustify: "the node in the rack we ordered",
		api.HeaderIntent:  hash,
	}
	status, doc = f.ceremonyStep(http.MethodPost, "/nodes/gpu-01/approve", cookie, fresh)
	if status != http.StatusOK {
		t.Fatalf("applying the previewed hash: %d %v", status, doc)
	}
	if doc["applied"] != true {
		t.Errorf("the response does not say it applied: %v", doc)
	}
	// app.js shows this back as the record the act became.
	if doc["audit_seq"] == nil {
		t.Errorf("no audit_seq for the console to report: %v", doc)
	}
}

// R8-02 and R8-03, which the profile decides and the console only reports.
//
// The console carries no minimum length and no rule about when a code is
// needed: it sends what it has and renders the refusal. That is the whole
// reason it cannot drift from the profile in force.
func TestTheProfileRefusesAndTheConsoleHasNothingToDisagreeWith(t *testing.T) {
	f := newFixture(t)
	f.join("gpu-01")
	f.setPassword("alice", "correct horse battery staple")
	cookie := f.loginCookie("alice", "correct horse battery staple")

	if status, doc := f.do("POST", "/policy/apply", f.admin,
		map[string]any{"profile": "regulated"}, nil); status != http.StatusOK {
		t.Fatalf("moving to regulated: %d %v", status, doc)
	}

	// **The gates are on the apply, not on the preview**, and that is right: a
	// dry run changes nothing, so demanding a reason to *look* would be
	// ceremony for its own sake. It does mean an operator can write a
	// justification the profile will refuse, preview happily, and be refused
	// at the end — which is why app.js loops back to the same dialog carrying
	// the refusal rather than treating it as a failure.
	status, doc := f.ceremonyStep(http.MethodPost, "/nodes/gpu-01/approve", cookie, nil)
	if status != http.StatusForbidden {
		t.Fatalf("no justification: %d %v", status, doc)
	}
	if code := errCode(doc); code != "justification_required" {
		t.Errorf("code = %q, want justification_required", code)
	}

	// One that is too short for this profile — the number lives in the
	// profile, and neither front end carries a copy of it.
	status, doc = f.ceremonyStep(http.MethodPost, "/nodes/gpu-01/approve", cookie,
		map[string]string{api.HeaderJustify: "ok"})
	if status != http.StatusForbidden {
		t.Fatalf("a short justification: %d %v", status, doc)
	}
	if code := errCode(doc); code != "justification_too_short" {
		t.Errorf("code = %q, want justification_too_short", code)
	}

	// A long enough one reaches the second gate: a live session does not
	// satisfy `require_totp`, which is R8-03's whole point.
	status, doc = f.ceremonyStep(http.MethodPost, "/nodes/gpu-01/approve", cookie,
		map[string]string{api.HeaderJustify: "the node in the rack we ordered last quarter"})
	if status != http.StatusForbidden {
		t.Fatalf("with a justification and no code: %d %v", status, doc)
	}
	if code := errCode(doc); code != "reauthentication_required" {
		t.Fatalf("code = %q, want reauthentication_required — app.js prompts for a code on "+
			"exactly this string, and a cookie must not satisfy it", code)
	}
}

// The console and the server have to agree on the names, and nothing else
// makes them: app.js is text in a different language, so a header renamed in
// Go would leave a browser sending a header nobody reads and an operator
// looking at a refusal they cannot act on.
func TestTheConsoleUsesTheHeadersAndCodesTheServerDefines(t *testing.T) {
	f := newFixture(t)
	script := mustAsset(t, f, "app.js")

	for _, want := range []string{api.HeaderJustify, api.HeaderIntent, api.HeaderTOTP, "If-Match"} {
		if !strings.Contains(script, `"`+want+`"`) {
			t.Errorf("app.js never sends %s", want)
		}
	}
	// Every stable code app.js branches on has to be one statusFor can
	// produce. A typo here is a branch that never runs, and the symptom is a
	// console that reports a generic failure for the one refusal it was
	// written to handle.
	produced := map[string]bool{}
	errs, err := os.ReadFile("errors.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`return http\.Status\w+, "([a-z_]+)"`).FindAllStringSubmatch(string(errs), -1) {
		produced[m[1]] = true
	}
	if len(produced) < 5 {
		t.Fatalf("found %d stable codes in errors.go; the scan is wrong", len(produced))
	}
	for _, m := range regexp.MustCompile(`\.code === "([a-z_]+)"`).FindAllStringSubmatch(script, -1) {
		if !produced[m[1]] {
			t.Errorf("app.js branches on the code %q and nothing in errors.go returns it", m[1])
		}
	}
}

func errCode(doc map[string]any) string {
	e, _ := doc["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}
