package gateway_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
)

// setLimit writes one row the way `nodary limits set` does. It is written
// directly rather than through config.Apply because that needs a node and a
// deployment, and none of that is what these tests are about.
func (f *fixture) setLimit(kind, subject string, rpm, tpm, daily, concurrent int) {
	f.t.Helper()
	nz := func(v int) any {
		if v == 0 {
			return nil
		}
		return v
	}
	if err := f.db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), `INSERT INTO limits
			(subject_kind, subject_id, rpm, tpm, daily_tokens, max_concurrent)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (subject_kind, subject_id) DO UPDATE SET
			  rpm = excluded.rpm, tpm = excluded.tpm,
			  daily_tokens = excluded.daily_tokens, max_concurrent = excluded.max_concurrent`,
			kind, subject, nz(rpm), nz(tpm), nz(daily), nz(concurrent))
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
}

// throttled decodes a 429 body.
type throttled struct {
	Error struct {
		Code   string         `json:"code"`
		Detail map[string]any `json:"detail"`
	} `json:"error"`
}

// R3-08. Until this landed, `nodary limits set` wrote a quota and the gateway
// never read it — one researcher's overnight batch could starve everyone else's
// interactive work and nothing in the product noticed.
func TestRPMRefusesOnceTheMinutesAllowanceIsSpent(t *testing.T) {
	f := newFixture(t, completion)
	f.setLimit("user", "bob", 3, 0, 0, 0)

	for i := 1; i <= 3; i++ {
		resp, body := f.post("/v1/chat/completions", f.key, chatBody(false))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d of an allowance of 3: %d %s", i, resp.StatusCode, body)
		}
	}

	resp, body := f.post("/v1/chat/completions", f.key, chatBody(false))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the fourth request returned %d, want 429: %s", resp.StatusCode, body)
	}

	// R3-09: a bare 429 tells a user nothing actionable.
	if after := resp.Header.Get("Retry-After"); after == "" {
		t.Error("no Retry-After header")
	} else if n, err := strconv.Atoi(after); err != nil || n < 1 {
		t.Errorf("Retry-After = %q", after)
	}
	var doc throttled
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("%v in %s", err, body)
	}
	if doc.Error.Code != "rate_limited" {
		t.Errorf("code = %q, want rate_limited", doc.Error.Code)
	}
	if got, _ := doc.Error.Detail["limit"].(string); got != "rpm" {
		t.Errorf("the body does not name which limit was hit: %s", body)
	}
	if got, _ := doc.Error.Detail["subject"].(string); got != "user:bob" {
		t.Errorf("the body does not say whose limit it is: %s", body)
	}
	for _, want := range []string{"limit_value", "used", "resets_in_seconds"} {
		if _, ok := doc.Error.Detail[want]; !ok {
			t.Errorf("the body carries no %q: %s", want, body)
		}
	}
}

// A global ceiling that a per-user limit could raise would not be a ceiling.
func TestAGlobalCeilingBindsEvenWhenTheUsersOwnLimitIsLooser(t *testing.T) {
	f := newFixture(t, completion)
	f.setLimit("user", "bob", 600, 0, 0, 0)
	f.setLimit("global", "global", 1, 0, 0, 0)

	if resp, body := f.post("/v1/chat/completions", f.key, chatBody(false)); resp.StatusCode != http.StatusOK {
		t.Fatalf("the first request: %d %s", resp.StatusCode, body)
	}
	resp, body := f.post("/v1/chat/completions", f.key, chatBody(false))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a per-user limit of 600 escaped a global limit of 1: %d %s", resp.StatusCode, body)
	}
	var doc throttled
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	if got, _ := doc.Error.Detail["subject"].(string); got != "global" {
		t.Errorf("the refusal names %q, want global", got)
	}
}

// A role limit reaches everybody holding it, which is the only way to cap a
// class of user without editing each one.
func TestARoleLimitApplies(t *testing.T) {
	f := newFixture(t, completion)
	f.setLimit("role", "user", 1, 0, 0, 0)

	if resp, _ := f.post("/v1/chat/completions", f.key, chatBody(false)); resp.StatusCode != http.StatusOK {
		t.Fatal("the first request was refused")
	}
	resp, body := f.post("/v1/chat/completions", f.key, chatBody(false))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a role limit did not apply: %d %s", resp.StatusCode, body)
	}
}

// The stub upstream reports 18 tokens a call, so a budget of 20 admits the
// first request at 0 spent, admits the second at 18 spent, and refuses the
// third at 36.
//
// That overshoot is inherent and is pinned here on purpose: a request's cost
// does not exist until its response does, so admission can only ever be decided
// on what is already spent. A budget can therefore be exceeded by at most one
// request — negligible at a real budget of a million tokens, and glaring at a
// budget of 20, which is why the test uses 20.
func TestADailyTokenBudgetRefusesOnceItIsSpent(t *testing.T) {
	f := newFixture(t, completion)
	f.setLimit("user", "bob", 0, 0, 20, 0)

	for i := 1; i <= 2; i++ {
		if resp, body := f.post("/v1/chat/completions", f.key, chatBody(false)); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d, with the budget not yet spent: %d %s", i, resp.StatusCode, body)
		}
	}
	resp, body := f.post("/v1/chat/completions", f.key, chatBody(false))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a daily budget of 20 allowed a third request after 36 tokens: %d %s",
			resp.StatusCode, body)
	}
	var doc throttled
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	if got, _ := doc.Error.Detail["limit"].(string); got != "daily_tokens" {
		t.Errorf("the refusal names %q, want daily_tokens", got)
	}
	// It resets at a UTC hour, not in a minute.
	if secs, _ := doc.Error.Detail["resets_in_seconds"].(float64); secs < 600 {
		t.Errorf("a daily budget claims to reset in %vs", secs)
	}
}

// R3-10: a throttled request is a usage record and never an audit record. One
// is telemetry about how the system behaved; the other is an administrative act
// with an accountable author.
func TestAThrottledRequestIsMeteredAndNotAudited(t *testing.T) {
	f := newFixture(t, completion)
	f.setLimit("user", "bob", 1, 0, 0, 0)

	f.post("/v1/chat/completions", f.key, chatBody(false))
	if resp, _ := f.post("/v1/chat/completions", f.key, chatBody(false)); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatal("the second request was not throttled")
	}

	ctx := context.Background()
	var refused int
	if err := f.db.Read().QueryRowContext(ctx,
		`SELECT count(*) FROM usage WHERE status = 429`).Scan(&refused); err != nil {
		t.Fatal(err)
	}
	if refused != 1 {
		t.Errorf("%d throttled requests were metered, want 1", refused)
	}
	// And it carries no tokens: it never reached a model.
	var tokens int
	if err := f.db.Read().QueryRowContext(ctx,
		`SELECT prompt_tokens + completion_tokens FROM usage WHERE status = 429`).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Errorf("a refused request was charged %d tokens", tokens)
	}

	var audited int
	if err := f.db.Read().QueryRowContext(ctx,
		`SELECT count(*) FROM audit WHERE action LIKE '%throttl%' OR action LIKE '%limit%'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 0 {
		t.Errorf("%d throttle events reached the audit chain", audited)
	}
}

// A caller with no limits set does no throttling work and is never refused.
func TestNoLimitsMeansNoThrottling(t *testing.T) {
	f := newFixture(t, completion)
	for i := 0; i < 25; i++ {
		if resp, body := f.post("/v1/chat/completions", f.key, chatBody(false)); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d was refused with no limits configured: %d %s", i, resp.StatusCode, body)
		}
	}
}

// max_concurrent is the one limit that cannot be tested sequentially: it counts
// requests in flight, so it needs two of them actually overlapping.
func TestMaxConcurrentRefusesASecondInFlightRequest(t *testing.T) {
	release := make(chan struct{})
	arrived := make(chan struct{}, 1)
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-release
		completion(w, r)
	})
	f.setLimit("user", "bob", 0, 0, 0, 1)

	type result struct {
		status int
		body   string
	}
	first := make(chan result, 1)
	go func() {
		resp, body := f.post("/v1/chat/completions", f.key, chatBody(false))
		first <- result{resp.StatusCode, body}
	}()

	// The first request is inside the upstream and holding the only slot.
	<-arrived

	resp, body := f.post("/v1/chat/completions", f.key, chatBody(false))
	if resp.StatusCode != http.StatusTooManyRequests {
		close(release)
		t.Fatalf("a second concurrent request under max_concurrent = 1: %d %s", resp.StatusCode, body)
	}
	var doc throttled
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		close(release)
		t.Fatal(err)
	}
	if got, _ := doc.Error.Detail["limit"].(string); got != "max_concurrent" {
		t.Errorf("the refusal names %q, want max_concurrent", got)
	}

	close(release)
	if got := <-first; got.status != http.StatusOK {
		t.Fatalf("the first request: %d %s", got.status, got.body)
	}

	// The slot is freed when the request finishes, so the next one goes
	// through. A counter that leaked would wedge the user out permanently,
	// which is the failure worth testing for.
	if resp, body := f.post("/v1/chat/completions", f.key, chatBody(false)); resp.StatusCode != http.StatusOK {
		t.Errorf("the slot was not released: %d %s", resp.StatusCode, body)
	}
}
