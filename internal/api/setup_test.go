package api_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// bareControlPlane is a control plane with no users, which is the only state
// the setup page has anything to do.
//
// newFixture cannot be reused: it creates `alice` so that the rest of the API
// has somebody to act as, and an installation with an account is past setup.
type bareControlPlane struct {
	srv    *httptest.Server
	client *http.Client
	log    *audit.Log
	db     *store.DB
}

func newBareControlPlane(t *testing.T) *bareControlPlane {
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
	delivery := audit.NewDelivery(nil, audit.Warn, io.Discard)
	t.Cleanup(func() { delivery.Close() })
	log := audit.New(db, delivery)

	srv := api.New(api.Options{DB: db, Log: log,
		Key: func() (*secret.Key, error) { return key, nil }, Now: time.Now})
	ts := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &bareControlPlane{srv: ts, client: ts.Client(), log: log, db: db}
}

// link mints one, the way `server install` does.
func (b *bareControlPlane) link(t *testing.T) string {
	t.Helper()
	var token string
	if _, err := b.log.Act(context.Background(),
		audit.Request{Actor: audit.Actor{ID: "root", Method: "local"}, Action: "installation.setup-link"},
		func(m audit.Mutation) error {
			var err error
			token, _, err = identity.MintSetup(context.Background(), m, time.Now())
			return err
		}); err != nil {
		t.Fatalf("minting a setup link: %v", err)
	}
	return token
}

func (b *bareControlPlane) post(t *testing.T, form url.Values) (int, string) {
	t.Helper()
	resp, err := b.client.PostForm(b.srv.URL+api.SetupPath, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func setupForm(token, name, password string) url.Values {
	return url.Values{"t": {token}, "name": {name}, "email": {"a@example.com"},
		"password": {password}, "confirm": {password}}
}

// TestTheSetupPageCreatesTheFirstAdministratorAndThenCannotBeUsed walks the
// whole of R5-08 over HTTP, because the parts are only a feature together: a
// link that is printed, opened, submitted once, and dead afterwards.
func TestTheSetupPageCreatesTheFirstAdministratorAndThenCannotBeUsed(t *testing.T) {
	b := newBareControlPlane(t)
	token := b.link(t)

	// The printed URL opens. It carries the token into the form, so the person
	// setting the password never has to handle it.
	resp, err := b.client.Get(b.srv.URL + api.SetupPath + "?t=" + token)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d", api.SetupPath, resp.StatusCode)
	}
	if !strings.Contains(string(page), token) {
		t.Error("the form does not carry the token, so submitting it cannot work")
	}
	// Never cached: the page holds a live credential and the confirmation names
	// an account.
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	// A password below the floor keeps the operator on the form, with the
	// reason. It must not create the account.
	if code, body := b.post(t, setupForm(token, "admin", "short")); code != http.StatusBadRequest {
		t.Errorf("a short password returned %d, want 400: %s", code, body)
	} else if !strings.Contains(body, "too short") {
		t.Errorf("the form did not say why: %s", body)
	}

	code, body := b.post(t, setupForm(token, "admin", "correct-horse-battery"))
	if code != http.StatusOK {
		t.Fatalf("setup returned %d: %s", code, body)
	}
	if !strings.Contains(body, "admin") {
		t.Errorf("the confirmation does not name the account: %s", body)
	}

	// The account is real and the password is the one that was typed. This is
	// the assertion the row is about — no default password ever exists, so the
	// only thing that opens this account is what somebody chose here.
	login := func(password string) int {
		body := `{"username":"admin","password":"` + password + `"}`
		resp, err := b.client.Post(b.srv.URL+api.Prefix+"/auth/login",
			"application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := login("correct-horse-battery"); got != http.StatusOK {
		t.Errorf("the new administrator cannot log in: %d", got)
	}
	if got := login("nodary"); got == http.StatusOK {
		t.Error("a guessed password opened the account")
	}

	// And the link is dead — for the same person and for anyone else.
	if code, _ := b.post(t, setupForm(token, "second", "correct-horse-battery")); code != http.StatusConflict {
		t.Errorf("a replayed setup link returned %d, want 409", code)
	}
}

// TestASetupLinkNobodyIssuedIsRefused keeps the page from being a way to seize
// an installation that has not been set up yet.
func TestASetupLinkNobodyIssuedIsRefused(t *testing.T) {
	b := newBareControlPlane(t)
	b.link(t) // a real one exists; the caller does not hold it

	code, _ := b.post(t, setupForm("nodary_st_guessed", "attacker", "correct-horse-battery"))
	if code != http.StatusForbidden {
		t.Errorf("a forged setup link returned %d, want 403", code)
	}
	if _, err := identity.Get(context.Background(), b.db.Read(), "attacker"); err == nil {
		t.Error("a forged setup link created an account")
	}
}
