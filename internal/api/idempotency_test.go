package api_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
)

func (f *fixture) addUser(name, role string) {
	f.t.Helper()
	code, doc, _ := f.doFull("POST", "/users", f.admin,
		map[string]any{"name": name, "role": role},
		map[string]string{api.HeaderJustify: "onboarding for a test"})
	if code != http.StatusOK {
		f.t.Fatalf("adding %s: %d %v", name, code, doc)
	}
}

func (f *fixture) mintToken(name, key string) (int, map[string]any, http.Header) {
	f.t.Helper()
	h := map[string]string{api.HeaderJustify: "a service key for the pipeline"}
	if key != "" {
		h[api.HeaderIdempotency] = key
	}
	return f.doFull("POST", "/tokens", f.admin, map[string]any{"user": name, "kind": "pt"}, h)
}

// tokenCount is every token on the appliance, counted as a delta because the
// fixture mints one of its own to authenticate with.
func (f *fixture) tokenCount() int {
	f.t.Helper()
	code, doc, _ := f.doFull("GET", "/tokens", f.admin, nil, nil)
	if code != http.StatusOK {
		f.t.Fatalf("listing tokens: %d %v", code, doc)
	}
	tokens, _ := doc["tokens"].([]any)
	return len(tokens)
}

// secretOf pulls the plaintext token out of a mint response.
func secretOf(doc map[string]any) string {
	result, _ := doc["result"].(map[string]any)
	s, _ := result["token"].(string)
	return s
}

// 09 §2: a repeat within 24h returns the original response rather than acting
// twice. Minting is where that matters — a second token is a second credential
// that nobody meant to create and nobody knows about.
func TestARepeatedPostReturnsTheFirstResponse(t *testing.T) {
	f := newFixture(t)
	f.addUser("carol", "operator")

	before := f.tokenCount()
	first, doc, _ := f.mintToken("carol", "pipeline-2026-09-13")
	if first != http.StatusOK {
		t.Fatalf("the first mint failed: %d %v", first, doc)
	}

	again, replayed, h := f.mintToken("carol", "pipeline-2026-09-13")
	if again != http.StatusOK {
		t.Fatalf("the repeat failed: %d %v", again, replayed)
	}
	if h.Get(api.HeaderReplay) != "true" {
		t.Error("a replay is not marked as one")
	}
	// The same response, not a second act: same audit record, same token.
	if replayed["audit_seq"] != doc["audit_seq"] {
		t.Errorf("audit_seq = %v, want the first response's %v", replayed["audit_seq"], doc["audit_seq"])
	}
	if replayed["result"] == nil || doc["result"] == nil {
		t.Fatalf("no result to compare: %v / %v", doc, replayed)
	}

	// And the mint happened once, not twice.
	if got := f.tokenCount(); got != before+1 {
		t.Errorf("token count went from %d to %d; the replay minted a second one", before, got)
	}
}

// Without a key, a repeat is a second request and acts again. That is the
// behavior the header exists to change, so it is worth pinning.
func TestWithoutAKeyARepeatActsTwice(t *testing.T) {
	f := newFixture(t)
	f.addUser("carol", "operator")
	before := f.tokenCount()
	for range 2 {
		if code, doc, _ := f.mintToken("carol", ""); code != http.StatusOK {
			t.Fatalf("%d %v", code, doc)
		}
	}
	if got := f.tokenCount(); got != before+2 {
		t.Errorf("token count went from %d to %d, want two more without an Idempotency-Key", before, got)
	}
}

// One key for two different requests is a client bug. Replaying the old
// response to it would hide that bug behind a plausible success.
func TestOneKeyForTwoDifferentRequestsIsRefused(t *testing.T) {
	f := newFixture(t)
	f.addUser("carol", "operator")
	f.addUser("dave", "operator")

	if code, doc, _ := f.mintToken("carol", "shared-key"); code != http.StatusOK {
		t.Fatalf("%d %v", code, doc)
	}
	after := f.tokenCount()
	code, doc, _ := f.mintToken("dave", "shared-key")
	if code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %v", code, doc)
	}
	body, _ := doc["error"].(map[string]any)
	if body["code"] != "idempotency_key_reused" {
		t.Errorf("code = %v: %v", body["code"], doc)
	}
	// And the refusal minted nothing.
	if got := f.tokenCount(); got != after {
		t.Errorf("the refused request changed the token count from %d to %d", after, got)
	}
}

// A refused request has not happened, so its key is free to try again —
// otherwise one malformed attempt burns a key the client will reuse on retry.
func TestAFailedRequestReleasesItsKey(t *testing.T) {
	f := newFixture(t)
	f.addUser("carol", "operator")

	// No justification: refused by the ceremony before anything is written.
	code, _, _ := f.doFull("POST", "/tokens", f.admin,
		map[string]any{"user": "nobody-at-all", "kind": "personal"},
		map[string]string{api.HeaderIdempotency: "retry-me", api.HeaderJustify: "x"})
	if code == http.StatusOK {
		t.Fatal("expected the mint for an unknown user to fail")
	}

	// The same key, now for a request that works.
	if code, doc, _ := f.mintToken("carol", "retry-me"); code != http.StatusOK {
		t.Fatalf("the key was not released by the failure: %d %v", code, doc)
	}
}

// A key is a client's own string, so two clients can choose the same one.
// Handing one caller's response to another is a disclosure, not a wrong answer.
func TestAKeyIsScopedToTheCallerThatUsedIt(t *testing.T) {
	f := newFixture(t)
	f.addUser("carol", "operator")
	code, minted, _ := f.mintToken("carol", "same-string")
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, minted)
	}
	other := secretOf(minted)
	if other == "" {
		t.Fatalf("no token in %v", minted)
	}
	// Alice is an operator and may not manage tokens, so this is refused on
	// permission — the point is that it is *not* answered with the admin's
	// stored response.
	code, doc, h := f.doFull("POST", "/tokens", other,
		map[string]any{"user": "carol", "kind": "pt"},
		map[string]string{api.HeaderIdempotency: "same-string", api.HeaderJustify: "mine"})
	if h.Get(api.HeaderReplay) == "true" {
		t.Fatalf("one caller was handed another's response: %d %v", code, doc)
	}
}

// Every POST is wrapped unless it is named as an exception, so a new endpoint
// cannot quietly arrive without one.
func TestTheIdempotencyExemptionsAreDeliberate(t *testing.T) {
	for path, why := range api.NotIdempotentForTest() {
		if !strings.HasPrefix(path, "/") {
			t.Errorf("%q is not a path", path)
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("%s is exempt for no stated reason", path)
		}
	}
}

// docs/specs/10-cli.md §4: a token is shown exactly once and is never readable
// again. Keeping a replayable copy of the mint response would make that untrue
// of the database file, so the stored copy is sealed under secret.key.
func TestAStoredResponseDoesNotLeaveASecretInTheDatabase(t *testing.T) {
	f := newFixture(t)
	f.addUser("carol", "operator")

	code, doc, _ := f.mintToken("carol", "sealed-please")
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, doc)
	}
	token := secretOf(doc)
	if token == "" {
		t.Fatalf("no token minted: %v", doc)
	}

	var stored []byte
	if err := f.db.Read().QueryRow(
		`SELECT response FROM idempotency WHERE key = 'sealed-please'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) == 0 {
		t.Fatal("nothing was stored, so nothing can be replayed")
	}
	if bytes.Contains(stored, []byte(token)) {
		t.Error("the plaintext token is readable in the idempotency table")
	}

	// And the replay still produces it, which is the whole point of storing it.
	_, replayed, h := f.mintToken("carol", "sealed-please")
	if h.Get(api.HeaderReplay) != "true" {
		t.Fatal("not a replay")
	}
	if secretOf(replayed) != token {
		t.Error("the replay did not return the token the first call did")
	}
}
