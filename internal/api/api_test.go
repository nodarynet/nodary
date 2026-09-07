package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/secret"
	"github.com/nodarynet/nodary/internal/store"
)

type fixture struct {
	t      *testing.T
	srv    *httptest.Server
	db     *store.DB
	log    *audit.Log
	key    *secret.Key
	admin  string // a personal token for an admin
	pki    string
	client *http.Client
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()

	db, err := store.Open(ctx, filepath.Join(dir, "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	key, err := secret.Create(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	// No sinks: these tests read the chain from the database, and delivering to
	// a file would only add a warning on a stream nobody is reading.
	delivery := audit.NewDelivery(nil, audit.Warn, io.Discard)
	t.Cleanup(func() { delivery.Close() })
	log := audit.New(db, delivery)

	f := &fixture{t: t, db: db, log: log, key: key}

	// An admin with a personal token, made through the core so the fixture
	// cannot create a state the product cannot.
	root := identity.LocalRoot()
	root.Actor.ID = "test"
	if _, err := log.Act(ctx, audit.Request{Actor: root.Actor, Action: "user.add"},
		func(m audit.Mutation) error {
			_, err := identity.Add(ctx, m, identity.RoleAdmin, time.Now(), "alice", "", identity.RoleAdmin)
			return err
		}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Act(ctx, audit.Request{Actor: root.Actor, Action: "token.create"},
		func(m audit.Mutation) error {
			_, plain, err := identity.MintToken(ctx, m, identity.RoleAdmin, time.Now(),
				"alice", identity.KindPersonal, "test", time.Now().AddDate(0, 0, 90), false)
			f.admin = plain
			return err
		}); err != nil {
		t.Fatal(err)
	}

	// The PKI the enrolment endpoint signs from. Generated the way `server
	// install` generates it, so a test cannot enroll against a CA no install
	// would have produced.
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := api.EnsureAgentCA(ctx, pki, key, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.pki = pki

	srv := api.New(api.Options{DB: db, Log: log,
		Key: func() (*secret.Key, error) { return key, nil }, PKI: pki, Now: time.Now})
	f.srv = httptest.NewServer(srv.Handler())
	t.Cleanup(f.srv.Close)
	f.client = f.srv.Client()
	return f
}

// do makes a request as the admin unless token is empty.
func (f *fixture) do(method, path, token string, body any, headers map[string]string) (int, map[string]any) {
	f.t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			f.t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, f.srv.URL+api.Prefix+path, rdr)
	if err != nil {
		f.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()

	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return resp.StatusCode, doc
}

func TestAnUnauthenticatedRequestIsRefused(t *testing.T) {
	f := newFixture(t)
	// Never local root: docs/plans/R1c-identity.md's argument for it is
	// filesystem access to the database, and an HTTP caller has none.
	if code, _ := f.do("GET", "/users", "", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", code)
	}
	if code, doc := f.do("GET", "/users", "nodary_pt_notarealtoken", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: %v", code, doc)
	}
}

// R2-17: one envelope, a stable machine-readable code, and a request id.
func TestTheErrorEnvelopeIsUniform(t *testing.T) {
	f := newFixture(t)
	code, doc := f.do("GET", "/users", "", nil, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d", code)
	}
	body, ok := doc["error"].(map[string]any)
	if !ok {
		t.Fatalf("no error envelope: %v", doc)
	}
	for _, k := range []string{"code", "message", "request_id"} {
		if body[k] == nil || body[k] == "" {
			t.Errorf("envelope has no %s: %v", k, body)
		}
	}
	if body["code"] != "unauthenticated" {
		t.Errorf("code = %v", body["code"])
	}
}

// R2-24: the id the caller was given is the id in the audit record, so one
// report resolves to one row.
func TestARequestIDReachesTheAuditRecord(t *testing.T) {
	f := newFixture(t)
	req, _ := http.NewRequest("POST", f.srv.URL+api.Prefix+"/users",
		strings.NewReader(`{"name":"bob","role":"user"}`))
	req.Header.Set("Authorization", "Bearer "+f.admin)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	id := resp.Header.Get("X-Request-Id")
	if id == "" {
		t.Fatal("no X-Request-Id was returned")
	}

	records, err := audit.List(context.Background(), f.db, audit.Filter{Action: "user.add"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rec := range records {
		if raw, err := json.Marshal(rec.Detail); err == nil && strings.Contains(string(raw), id) {
			found = true
		}
	}
	if !found {
		t.Errorf("request id %s is in no audit record", id)
	}
}

// R2-18 and R2-19: a dry run renders and hashes, and the hash is what the real
// call sends back. A stale one is refused with 412.
func TestDryRunThenIntentBinding(t *testing.T) {
	f := newFixture(t)

	code, doc := f.do("POST", "/users?dry_run=true", f.admin,
		map[string]any{"name": "bob", "role": "user"}, nil)
	if code != http.StatusOK {
		t.Fatalf("dry run: %d %v", code, doc)
	}
	if doc["dry_run"] != true {
		t.Errorf("not reported as a dry run: %v", doc)
	}
	hash, _ := doc["intent_hash"].(string)
	if len(hash) != 64 {
		t.Fatalf("intent_hash = %q", hash)
	}
	// Nothing was applied.
	if _, users := f.do("GET", "/users", f.admin, nil, nil); strings.Contains(toJSON(users), "bob") {
		t.Error("a dry run created the user")
	}

	// The real call, carrying the approved hash.
	code, doc = f.do("POST", "/users", f.admin, map[string]any{"name": "bob", "role": "user"},
		map[string]string{api.HeaderIntent: hash})
	if code != http.StatusOK {
		t.Fatalf("apply: %d %v", code, doc)
	}

	// And the same hash again, now stale: bob exists, so the render moved.
	code, doc = f.do("POST", "/users", f.admin, map[string]any{"name": "bob", "role": "user"},
		map[string]string{api.HeaderIntent: hash})
	if code != http.StatusPreconditionFailed {
		t.Errorf("a stale intent returned %d, want 412: %v", code, doc)
	}
	if envelope(doc)["code"] != "intent_changed" {
		t.Errorf("code = %v", envelope(doc)["code"])
	}
}

// R2-20 and the whole point of R2-34: the API demands exactly the ceremony the
// CLI demands, because both ask the same core.
func TestTheAPIDemandsTheSameCeremonyAsTheCLI(t *testing.T) {
	f := newFixture(t)

	// Under `regulated`, a mutation needs a justification.
	if code, doc := f.do("POST", "/policy/apply", f.admin,
		map[string]any{"profile": "regulated"}, nil); code != http.StatusOK {
		t.Fatalf("applying regulated: %d %v", code, doc)
	}

	code, doc := f.do("POST", "/users", f.admin, map[string]any{"name": "bob", "role": "user"}, nil)
	if code != http.StatusForbidden {
		t.Errorf("a mutation with no justification returned %d, want 403: %v", code, doc)
	}
	if got := envelope(doc)["code"]; got != "justification_required" {
		t.Errorf("code = %v, want justification_required", got)
	}

	// Too short is a different code and the same refusal.
	code, doc = f.do("POST", "/users", f.admin, map[string]any{"name": "bob", "role": "user"},
		map[string]string{api.HeaderJustify: "short"})
	if code != http.StatusForbidden || envelope(doc)["code"] != "justification_too_short" {
		t.Errorf("short justification: %d %v", code, envelope(doc))
	}

	// A real one gets through, because the caller is a token principal that is
	// unattended-exempt only if granted — this one is not, so `regulated`'s
	// require_totp must also refuse it, non-interactively, with the way out.
	code, doc = f.do("POST", "/users", f.admin, map[string]any{"name": "bob", "role": "user"},
		map[string]string{api.HeaderJustify: "onboarding the new operator"})
	if code != http.StatusForbidden || envelope(doc)["code"] != "reauthentication_required" {
		t.Errorf("expected a re-authentication refusal, got %d %v", code, envelope(doc))
	}
	if !strings.Contains(toJSON(envelope(doc)), "allow-unattended") {
		t.Errorf("the refusal does not name the way out: %v", envelope(doc))
	}
}

// Login issues a session that honours the active profile's TTL, and the cookie
// authenticates subsequent requests.
func TestLoginIssuesAWorkingSession(t *testing.T) {
	f := newFixture(t)

	// No password is set yet, and that is a distinct answer from a wrong one.
	if code, doc := f.do("POST", "/auth/login", "",
		map[string]any{"username": "alice", "password": "correct horse battery staple"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("status = %d %v", code, doc)
	}

	// Set one through the core, the way R5's setup URL will.
	ctx := context.Background()
	root := identity.LocalRoot()
	root.Actor.ID = "test"
	if _, err := f.log.Act(ctx, audit.Request{Actor: root.Actor, Action: "user.passwd"},
		func(m audit.Mutation) error {
			return identity.SetPassword(ctx, m, identity.RoleAdmin, "alice", "correct horse battery staple")
		}); err != nil {
		t.Fatal(err)
	}

	jar := newJar(t)
	f.client.Jar = jar
	code, doc := f.do("POST", "/auth/login", "",
		map[string]any{"username": "alice", "password": "correct horse battery staple"}, nil)
	if code != http.StatusOK {
		t.Fatalf("login: %d %v", code, doc)
	}
	if doc["user"] != "alice" || doc["role"] != "admin" {
		t.Errorf("login = %v", doc)
	}

	// The cookie alone now authenticates.
	code, doc = f.do("GET", "/auth/whoami", "", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("whoami with a session: %d %v", code, doc)
	}
	if doc["method"] != "session" {
		t.Errorf("whoami = %v", doc)
	}

	// A wrong password says the same thing as an unknown user.
	if code, doc := f.do("POST", "/auth/login", "",
		map[string]any{"username": "alice", "password": "wrong"}, nil); code != http.StatusUnauthorized {
		t.Errorf("a wrong password: %d %v", code, doc)
	}
	if _, doc := f.do("POST", "/auth/login", "",
		map[string]any{"username": "nobody", "password": "wrong"}, nil); !strings.Contains(
		toJSON(envelope(doc)), "incorrect username or password") {
		t.Errorf("an unknown user is distinguishable from a wrong password: %v", envelope(doc))
	}
}

// Permission is checked, and a caller who is authenticated but not permitted
// gets 403 rather than 404 (09 §3).
func TestPermissionIsCheckedAndSaysSo(t *testing.T) {
	f := newFixture(t)

	// A viewer, with their own token.
	ctx := context.Background()
	root := identity.LocalRoot()
	root.Actor.ID = "test"
	var viewer string
	if _, err := f.log.Act(ctx, audit.Request{Actor: root.Actor, Action: "user.add"},
		func(m audit.Mutation) error {
			if _, err := identity.Add(ctx, m, identity.RoleAdmin, time.Now(), "vic", "", identity.RoleViewer); err != nil {
				return err
			}
			_, plain, err := identity.MintToken(ctx, m, identity.RoleAdmin, time.Now(),
				"vic", identity.KindPersonal, "t", time.Now().AddDate(0, 0, 1), false)
			viewer = plain
			return err
		}); err != nil {
		t.Fatal(err)
	}

	if code, _ := f.do("GET", "/users", viewer, nil, nil); code != http.StatusOK {
		t.Errorf("a viewer cannot read state: %d", code)
	}
	code, doc := f.do("POST", "/users", viewer, map[string]any{"name": "bob", "role": "user"}, nil)
	if code != http.StatusForbidden {
		t.Errorf("a viewer created a user: %d %v", code, doc)
	}
	if envelope(doc)["code"] != "forbidden" {
		t.Errorf("code = %v", envelope(doc)["code"])
	}
}

// A secret is shown once at creation and never in a listing (10 §4).
func TestATokenIsShownOnceAndNeverListed(t *testing.T) {
	f := newFixture(t)
	code, doc := f.do("POST", "/tokens", f.admin, map[string]any{"user": "alice", "kind": "sk"}, nil)
	if code != http.StatusOK {
		t.Fatalf("creating a token: %d %v", code, doc)
	}
	result, _ := doc["result"].(map[string]any)
	plain, _ := result["token"].(string)
	if !strings.HasPrefix(plain, "nodary_sk_") {
		t.Fatalf("no credential was returned: %v", doc)
	}
	_, listing := f.do("GET", "/tokens", f.admin, nil, nil)
	if strings.Contains(toJSON(listing), plain) {
		t.Error("the listing carries the credential")
	}
}

func envelope(doc map[string]any) map[string]any {
	if e, ok := doc["error"].(map[string]any); ok {
		return e
	}
	return map[string]any{}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// newJar gives the client somewhere to keep a session cookie.
func newJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return jar
}
