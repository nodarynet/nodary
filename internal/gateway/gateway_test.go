package gateway_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/gateway"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/store"
)

// The prompt every test sends. If this string ever appears in the database or
// in a log, the guarantee in dev/adr/0006-cui-boundary-and-fips.md is broken —
// so it is distinctive enough to search for.
const secretPrompt = "CUI-CANARY-do-not-store-this-prompt-anywhere"

type fixture struct {
	t        *testing.T
	db       *store.DB
	srv      *httptest.Server
	upstream *httptest.Server
	key      string // a service key for a user granted "acme/tiny"
	logs     *bytes.Buffer
}

// newFixture wires a gateway to a stub upstream that behaves like an
// OpenAI-compatible server.
func newFixture(t *testing.T, upstream http.HandlerFunc) *fixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	db, err := store.Open(ctx, filepath.Join(dir, "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	f := &fixture{t: t, db: db, logs: &bytes.Buffer{}}
	f.upstream = httptest.NewServer(upstream)
	t.Cleanup(f.upstream.Close)

	delivery := audit.NewDelivery(nil, audit.Warn, io.Discard)
	t.Cleanup(func() { delivery.Close() })
	log := audit.New(db, delivery)

	root := identity.LocalRoot()
	root.Actor.ID = "test"
	if _, err := log.Act(ctx, audit.Request{Actor: root.Actor, Action: "user.add"},
		func(m audit.Mutation) error {
			_, err := identity.Add(ctx, m, identity.RoleAdmin, time.Now(), "bob", "", identity.RoleUser)
			return err
		}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Act(ctx, audit.Request{Actor: root.Actor, Action: "token.create"},
		func(m audit.Mutation) error {
			_, plain, err := identity.MintToken(ctx, m, identity.RoleAdmin, time.Now(),
				"bob", identity.KindService, "test", time.Now().AddDate(0, 0, 90), false)
			f.key = plain
			return err
		}); err != nil {
		t.Fatal(err)
	}

	// A route, a grant, and a ready deployment behind the route, written
	// directly: config.Apply would need the whole enrollment, and none of that
	// is what these tests are about.
	//
	// The deployment is not decoration. dev/specs/11-failure-modes.md §4 makes
	// a route with no ready member a 503, so a fixture whose route has nothing
	// behind it is testing the refusal rather than whatever it meant to test.
	now := time.Now().UTC().Format(audit.TimeFormat)
	if err := db.WriteTx(ctx, func(tx *sql.Tx) error {
		for _, stmt := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO route (name, strategy, created_at) VALUES ('acme/tiny', 'round-robin', ?)`,
				[]any{now}},
			{`INSERT INTO user_route (user_id, route_name, granted_at)
			  SELECT id, 'acme/tiny', ? FROM user WHERE name = 'bob'`, []any{now}},
			{`INSERT INTO node (name, state, created_at) VALUES ('gpu-01', 'ready', ?)`, []any{now}},
			{`INSERT INTO model (id, backend, source, artifact, created_at)
			  VALUES ('acme/tiny', 'vllm', 'local', 'hf-cache', ?)`, []any{now}},
			{`INSERT INTO deployment (id, model_id, node_name, backend, state, created_at, updated_at)
			  VALUES ('dep_one', 'acme/tiny', 'gpu-01', 'vllm', 'ready', ?, ?)`, []any{now, now}},
			{`INSERT INTO route_member (route_name, deployment_id, weight) VALUES ('acme/tiny', 'dep_one', 1)`,
				nil},
		} {
			if _, err := tx.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	g, err := gateway.New(gateway.Options{
		DB: db, Upstream: f.upstream.URL, MasterKey: "sk-nodary-master",
		Log: slogTo(f.logs), Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(g.Handler())
	t.Cleanup(f.srv.Close)
	return f
}

// post sends an inference request as the service key unless key is empty.
func (f *fixture) post(path, key string, body any) (*http.Response, string) {
	f.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, f.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		f.t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(out)
}

// chatBody is a request carrying the canary prompt.
func chatBody(stream bool) map[string]any {
	return map[string]any{
		"model":    "acme/tiny",
		"stream":   stream,
		"messages": []map[string]string{{"role": "user", "content": secretPrompt}},
	}
}

// completion is what a non-streaming OpenAI-compatible server answers.
func completion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id": "chatcmpl-1", "object": "chat.completion", "model": "acme/tiny",
		"choices": []map[string]any{{"index": 0, "message": map[string]string{
			"role": "assistant", "content": "hello"}, "finish_reason": "stop"}},
		"usage": map[string]int{"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
	})
}

func TestANonStreamingRequestIsProxiedAndMetered(t *testing.T) {
	f := newFixture(t, completion)

	resp, body := f.post("/v1/chat/completions", f.key, chatBody(false))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "hello") {
		t.Errorf("the response did not reach the client: %s", body)
	}

	u := f.usageRows()
	if len(u) != 1 {
		t.Fatalf("usage rows = %d, want 1", len(u))
	}
	if u[0].prompt != 11 || u[0].completion != 7 {
		t.Errorf("metered %d/%d, want 11/7", u[0].prompt, u[0].completion)
	}
	if u[0].status != 200 || u[0].streamed != 0 || u[0].partial != 0 {
		t.Errorf("row = %+v", u[0])
	}
	if u[0].requestID == "" {
		t.Error("no request id recorded; dev/specs/06-gateway.md §6 makes it the way a report resolves to a row")
	}
	if u[0].requestID != resp.Header.Get("X-Request-Id") {
		t.Errorf("recorded %q, returned %q — a user's report would not resolve",
			u[0].requestID, resp.Header.Get("X-Request-Id"))
	}
}

// R3-15, and the reason this slice exists where it does in the plan.
//
// dev/adr/0006-cui-boundary-and-fips.md: nodary records that a request
// happened, never what it said. This asserts it against the running system —
// the canary goes through the gateway, and then every byte of the database and
// every byte of the gateway's log is searched for it.
func TestNoRequestContentReachesStorage(t *testing.T) {
	f := newFixture(t, completion)

	for _, stream := range []bool{false, true} {
		resp, body := f.post("/v1/chat/completions", f.key, chatBody(stream))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("stream=%v: status = %d: %s", stream, resp.StatusCode, body)
		}
	}
	// And a request that fails, because an error path is where a body most
	// often ends up somewhere it should not.
	f.post("/v1/chat/completions", f.key, map[string]any{
		"model": "acme/forbidden", "messages": []map[string]string{{"content": secretPrompt}}})
	f.post("/v1/chat/completions", f.key, "not-an-object-"+secretPrompt)

	for what, blob := range map[string][]byte{
		"the database":      f.databaseBytes(),
		"the gateway's log": f.logs.Bytes(),
	} {
		if bytes.Contains(blob, []byte(secretPrompt)) {
			t.Errorf("the prompt reached %s. dev/adr/0006-cui-boundary-and-fips.md makes "+
				"\"nodary records that a request happened, never what it said\" structural, "+
				"and this is the assertion that it holds", what)
		}
	}
}

// dev/specs/06-gateway.md §2, all four rows.
func TestAuthenticationRefusesWhatItShould(t *testing.T) {
	f := newFixture(t, completion)

	for _, tc := range []struct {
		what string
		key  string
		want int
	}{
		{"no credential", "", http.StatusUnauthorized},
		{"a key that was never issued", "nodary_sk_neverminted", http.StatusUnauthorized},
		{"a personal token, which is not a service key", f.personalToken(), http.StatusUnauthorized},
	} {
		resp, body := f.post("/v1/chat/completions", tc.key, chatBody(false))
		if resp.StatusCode != tc.want {
			t.Errorf("%s: status = %d, want %d (%s)", tc.what, resp.StatusCode, tc.want, body)
		}
	}

	// A revoked key stops working, and the refusal is 401.
	f.revoke()
	resp, body := f.post("/v1/chat/completions", f.key, chatBody(false))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a revoked key: status = %d, want 401 (%s)", resp.StatusCode, body)
	}
	if len(f.usageRows()) != 0 {
		t.Error("a refused request was metered")
	}
}

// The allowlist, and the status code dev/specs/06-gateway.md §2 argues for.
func TestARouteOutsideTheAllowlistIs403AndNot404(t *testing.T) {
	f := newFixture(t, completion)
	body := chatBody(false)
	body["model"] = "acme/other"

	resp, out := f.post("/v1/chat/completions", f.key, body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", resp.StatusCode, out)
	}
	// The message names what to do. A bare "forbidden" costs support time,
	// which is the same argument §2 makes for not using 404.
	if !strings.Contains(out, "config apply") {
		t.Errorf("the refusal does not say how to fix it: %s", out)
	}
}

// /v1/models returns the caller's routes, not the fleet. A client that
// discovers a model here and is then refused it has been told two different
// things by the same server.
func TestModelsListsOnlyWhatTheCallerMayUse(t *testing.T) {
	f := newFixture(t, completion)
	f.addRoute("acme/secret")

	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+f.key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var list struct {
		Object string `json:"object"`
		Data   []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if list.Object != "list" {
		t.Errorf("object = %q, want the OpenAI list shape", list.Object)
	}
	if len(list.Data) != 1 || list.Data[0].ID != "acme/tiny" {
		t.Errorf("models = %+v, want only the granted route", list.Data)
	}
}

// LiteLLM's own administrative surface must not be reachable through a
// credential nodary issued: that would hand a client the master key's authority.
func TestOnlyTheOpenAISurfaceIsProxied(t *testing.T) {
	var reached []string
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		reached = append(reached, r.URL.Path)
		completion(w, r)
	})

	for _, path := range []string{"/key/generate", "/model/new", "/v1/../key/info", "/health"} {
		resp, _ := f.post(path, f.key, map[string]any{})
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 404", path, resp.StatusCode)
		}
	}
	if len(reached) != 0 {
		t.Errorf("the upstream was reached at %v", reached)
	}
}

// --- fixture helpers ----------------------------------------------------------

type usageRow struct {
	prompt, completion int64
	status             int
	streamed, partial  int
	requestID          string
	route              string
}

func (f *fixture) usageRows() []usageRow {
	f.t.Helper()
	rows, err := f.db.Read().QueryContext(context.Background(),
		`SELECT prompt_tokens, completion_tokens, status, streamed, partial,
		        coalesce(request_id, ''), coalesce(route, '') FROM usage ORDER BY ts, id`)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []usageRow
	for rows.Next() {
		var u usageRow
		if err := rows.Scan(&u.prompt, &u.completion, &u.status, &u.streamed, &u.partial,
			&u.requestID, &u.route); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, u)
	}
	return out
}

// databaseBytes is every byte of the database file and its write-ahead log.
//
// The WAL matters: a row written and not yet checkpointed lives there, so a
// search of the main file alone would miss exactly the content this asserts is
// absent.
func (f *fixture) databaseBytes() []byte {
	f.t.Helper()
	var all []byte
	for _, suffix := range []string{"", "-wal", "-shm"} {
		body, err := os.ReadFile(f.db.Path() + suffix)
		if err != nil {
			continue
		}
		all = append(all, body...)
	}
	if len(all) == 0 {
		f.t.Fatal("read no database bytes, so this asserts nothing")
	}
	return all
}

func (f *fixture) personalToken() string {
	f.t.Helper()
	return f.mint(identity.KindPersonal)
}

func (f *fixture) mint(kind identity.Kind) string {
	f.t.Helper()
	delivery := audit.NewDelivery(nil, audit.Warn, io.Discard)
	defer delivery.Close()
	log := audit.New(f.db, delivery)
	root := identity.LocalRoot()
	root.Actor.ID = "test"
	var plain string
	if _, err := log.Act(context.Background(),
		audit.Request{Actor: root.Actor, Action: "token.create"},
		func(m audit.Mutation) error {
			var err error
			_, plain, err = identity.MintToken(context.Background(), m, identity.RoleAdmin,
				time.Now(), "bob", kind, "extra", time.Now().AddDate(0, 0, 90), false)
			return err
		}); err != nil {
		f.t.Fatal(err)
	}
	return plain
}

func (f *fixture) revoke() {
	f.t.Helper()
	if err := f.db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(),
			`UPDATE token SET revoked_at = ? WHERE kind = 'sk'`,
			time.Now().UTC().Format(audit.TimeFormat))
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) addRoute(name string) {
	f.t.Helper()
	if err := f.db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(),
			`INSERT INTO route (name, strategy, created_at) VALUES (?, 'round-robin', ?)`,
			name, time.Now().UTC().Format(audit.TimeFormat))
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
}

// slogTo captures the gateway's log so a test can search it for content that
// must never appear there.
func slogTo(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// streamingUpstream answers like an OpenAI-compatible server that was asked for
// usage: content chunks, then a final chunk carrying usage, then [DONE].
func streamingUpstream(t *testing.T, sawIncludeUsage *bool, withUsage bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var got struct {
			StreamOptions struct {
				IncludeUsage bool `json:"include_usage"`
			} `json:"stream_options"`
		}
		_ = json.Unmarshal(body, &got)
		*sawIncludeUsage = got.StreamOptions.IncludeUsage

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flush := func() {
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		for _, piece := range []string{"Hel", "lo", " there"} {
			fmt.Fprintf(w, "data: {\"id\":\"c1\",\"model\":\"acme/tiny\",\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", piece)
			flush()
		}
		if withUsage {
			fmt.Fprint(w, "data: {\"id\":\"c1\",\"model\":\"acme/tiny\",\"choices\":[],"+
				"\"usage\":{\"prompt_tokens\":31,\"completion_tokens\":9}}\n\n")
			flush()
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		flush()
	}
}

// dev/specs/06-gateway.md §3: the gateway injects
// stream_options.include_usage, reads the final usage chunk, and passes the
// stream through otherwise untouched.
func TestAStreamIsMeteredAndRelayedUntouched(t *testing.T) {
	var sawIncludeUsage bool
	f := newFixture(t, streamingUpstream(t, &sawIncludeUsage, true))

	resp, body := f.post("/v1/chat/completions", f.key, chatBody(true))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if !sawIncludeUsage {
		t.Error("the gateway did not inject stream_options.include_usage; the stream would carry no usage")
	}

	// Byte for byte. A gateway that re-serialized chunks is a gateway that
	// changed them, and for a stream that is the difference between a client
	// library working and not.
	want := "data: {\"id\":\"c1\",\"model\":\"acme/tiny\",\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n"
	if !strings.Contains(body, want) {
		t.Errorf("a chunk was modified in transit.\ngot:\n%s", body)
	}
	if !strings.HasSuffix(body, "data: [DONE]\n\n") {
		t.Errorf("the terminator did not survive:\n%s", body)
	}

	u := f.usageRows()
	if len(u) != 1 {
		t.Fatalf("usage rows = %d, want 1", len(u))
	}
	if u[0].prompt != 31 || u[0].completion != 9 {
		t.Errorf("metered %d/%d, want 31/9 from the final chunk", u[0].prompt, u[0].completion)
	}
	if u[0].streamed != 1 {
		t.Error("the row does not say it streamed")
	}
	if u[0].partial != 0 {
		t.Error("a stream that reported usage was recorded partial")
	}
}

// dev/specs/06-gateway.md §3: a stream that ends without usage is never
// silently dropped. If disconnecting erased usage, metering would be trivially
// avoidable and the quota system decorative.
func TestAStreamWithNoUsageChunkIsRecordedPartial(t *testing.T) {
	var saw bool
	f := newFixture(t, streamingUpstream(t, &saw, false))

	if resp, body := f.post("/v1/chat/completions", f.key, chatBody(true)); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	u := f.usageRows()
	if len(u) != 1 {
		t.Fatalf("usage rows = %d, want 1 — a stream with no usage still produces a record", len(u))
	}
	if u[0].partial != 1 {
		t.Errorf("row = %+v, want partial: accounting was incomplete and has to say so", u[0])
	}
	// R3-07: metered from what was actually seen go past, not zero. The
	// upstream sent three content-bearing chunks and no usage.
	if u[0].completion != 3 {
		t.Errorf("completion = %d, want 3 — the chunks observed before the stream ended",
			u[0].completion)
	}
	// Prompt tokens are not knowable without the tokenizer the gateway does
	// not have, and a row claiming a number it cannot stand behind is worse
	// than one that says the accounting is partial.
	if u[0].prompt != 0 {
		t.Errorf("prompt = %d, want 0: nothing here can count a prompt", u[0].prompt)
	}
}

// The chunk that only announces the assistant role and the one that only
// carries finish_reason produce no text, so counting them would bill for
// protocol rather than for generation.
func TestOnlyChunksThatCarryTextAreCounted(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flush := func() {
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
		}
		for _, chunk := range []string{
			`{"id":"c1","model":"acme/tiny","choices":[{"delta":{"role":"assistant"}}]}`,
			`{"id":"c1","model":"acme/tiny","choices":[{"delta":{"content":"one"}}]}`,
			`{"id":"c1","model":"acme/tiny","choices":[{"delta":{"content":"two"}}]}`,
			`{"id":"c1","model":"acme/tiny","choices":[{"delta":{},"finish_reason":"stop"}]}`,
		} {
			fmt.Fprintf(w, "data: %s\n\n", chunk)
			flush()
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		flush()
	})

	if resp, body := f.post("/v1/chat/completions", f.key, chatBody(true)); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	u := f.usageRows()
	if len(u) != 1 {
		t.Fatalf("usage rows = %d, want 1", len(u))
	}
	if u[0].completion != 2 {
		t.Errorf("completion = %d, want 2: the role and finish_reason chunks carry no text", u[0].completion)
	}
}

// A chunk boundary is a network artefact and lands anywhere, including inside a
// JSON document. The scanner has to carry the remainder across writes or it
// would miss the usage chunk whenever it happened to be split.
func TestUsageIsFoundWhenAChunkIsSplitAcrossWrites(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		full := "data: {\"model\":\"acme/tiny\",\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":3}}\n\n" +
			"data: [DONE]\n\n"
		// One byte at a time: the worst case, and the one that finds an
		// accumulator that resets per write.
		for i := 0; i < len(full); i++ {
			_, _ = w.Write([]byte{full[i]})
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	})

	if resp, body := f.post("/v1/chat/completions", f.key, chatBody(true)); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	u := f.usageRows()
	if len(u) != 1 || u[0].prompt != 5 || u[0].completion != 3 {
		t.Errorf("rows = %+v, want 5/3 read from a chunk delivered one byte at a time", u)
	}
}

// dev/specs/11-failure-modes.md §4: "No ready deployment on a route — 503 with
// Retry-After; alert raised."
//
// Not a 404, and the difference is what a client does next: told "no such
// model" it gives up, told "not yet" it comes back. The route exists, the
// caller is granted it, and nothing about the request is wrong — what is
// missing is a replica.
func TestARouteWithNoReadyDeploymentIs503(t *testing.T) {
	f := newFixture(t, completion)
	f.setDeploymentState("dep_one", "starting")

	resp, body := f.post("/v1/chat/completions", f.key,
		map[string]any{"model": "acme/tiny", "messages": []any{map[string]any{"role": "user", "content": "hi"}}})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("no Retry-After: a client told to come back needs to know when")
	}
	if !strings.Contains(body, "no_ready_deployment") {
		t.Errorf("body = %s, want a stable code naming the reason", body)
	}
	// 11 §4 asks for an alert, and this is the shape of a fleet that looks
	// healthy from every other angle: the route exists, the grant exists, and
	// nothing is serving it.
	if !strings.Contains(f.logs.String(), "no ready deployment") {
		t.Errorf("nothing was logged:\n%s", f.logs.String())
	}
}

// A deployment an operator disabled is not a ready member, whether or not the
// node has got around to reporting the stop. The decision is the fact.
func TestADisabledDeploymentIsNotAReadyMember(t *testing.T) {
	f := newFixture(t, completion)
	f.disableDeployment("dep_one")

	resp, body := f.post("/v1/chat/completions", f.key,
		map[string]any{"model": "acme/tiny", "messages": []any{map[string]any{"role": "user", "content": "hi"}}})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503: %s", resp.StatusCode, body)
	}
}

// setDeploymentState is how a test says the node has reported something other
// than "serving" about a route's only member.
func (f *fixture) setDeploymentState(id, state string) {
	f.t.Helper()
	f.execDeployment(`UPDATE deployment SET state = ? WHERE id = ?`, state, id)
}

// disableDeployment is `nodary model disable` without the ceremony.
func (f *fixture) disableDeployment(id string) {
	f.t.Helper()
	f.execDeployment(`UPDATE deployment SET disabled = 1 WHERE id = ?`, id)
}

func (f *fixture) execDeployment(query string, args ...any) {
	f.t.Helper()
	if err := f.db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(), query, args...)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
}
