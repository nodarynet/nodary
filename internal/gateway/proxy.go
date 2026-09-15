package gateway

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/observed"
)

// maxRequestBody bounds what the gateway will read before proxying.
//
// It exists because the body must be parsed enough to find `model` and
// `stream`, and an unbounded read of an attacker-chosen body is a way to spend
// a control plane's memory. 8 MiB is generous for a prompt and far below what
// would hurt.
const maxRequestBody = 8 << 20

// inference is the part of a request the gateway understands. Everything else
// in the body is passed through and never inspected: the gateway routes and
// meters, it does not interpret.
type inference struct {
	Model         string           `json:"model"`
	Stream        bool             `json:"stream"`
	StreamOptions *json.RawMessage `json:"stream_options"`
}

// proxyInference authenticates, authorizes, proxies, and meters.
//
// The body is read once, inspected for two fields, and handed to the proxy. It
// is not logged, not stored, and not put in an error — see the package comment.
func (s *Server) proxyInference(w http.ResponseWriter, r *http.Request) {
	started := s.now()
	p, ok := s.authorize(w, r)
	if !ok {
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
	if err != nil {
		s.fail(w, r, badRequest("could not read the request body"))
		return
	}
	var want inference
	if err := json.Unmarshal(body, &want); err != nil {
		// The parse error is not surfaced: Go's JSON errors quote the input,
		// and the input is a prompt.
		s.fail(w, r, badRequest("the request body is not a JSON object"))
		return
	}
	if want.Model == "" {
		s.fail(w, r, badRequest("no model was named"))
		return
	}

	allowed, err := s.routesFor(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !allowed[want.Model] {
		// 403 and not 404: dev/specs/06-gateway.md §2 — the route's existence
		// is not a secret, and a misleading error costs support time. The
		// message names the fix rather than the fact.
		s.fail(w, r, fmt.Errorf("%w: %s is not granted %q; an administrator grants a route with `nodary config apply`",
			identity.ErrDenied, p.User.Name, want.Model))
		return
	}

	// dev/specs/11-failure-modes.md §4: a route with no ready deployment is a
	// 503 with a Retry-After and an alert, not whatever the data plane says
	// about a model it has not been told about.
	//
	// **Before the throttle**, so a request that cannot succeed does not spend
	// the caller's quota on finding that out, and after the allowlist for the
	// reason the throttle gives below.
	ready, err := s.routeHasReadyMember(r.Context(), want.Model)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ready {
		// An alert, because 11 §4 asks for one and because this is the shape of
		// a fleet that looks healthy from every other angle: the route exists,
		// the grant exists, and nothing is serving it.
		s.log.Error("gateway", "detail", "no ready deployment", "route", want.Model,
			"request_id", requestID(r))
		s.fail(w, r, fmt.Errorf("%w: %q has no ready deployment", errNoReadyMember, want.Model))
		return
	}

	// dev/specs/06-gateway.md §4. After the allowlist, because being refused
	// a route is a permanent answer and being throttled is a temporary one:
	// telling somebody to wait for access they will never have is worse than
	// telling them no.
	release, ref, err := s.admit(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if ref != nil {
		// A throttle is a usage record, never an audit record. 06 §4: one is
		// telemetry about system behavior, the other an administrative act with
		// an accountable author, and writing this to the chain would fill it
		// with events nobody performed.
		s.recordThrottled(r, p, want.Model, started)
		s.fail(w, r, ref)
		return
	}

	// dev/specs/06-gateway.md §3: OpenAI-compatible streams omit usage unless
	// stream_options.include_usage is set, so the gateway injects it. A client
	// cannot opt out — opting out of usage reporting would be opting out of
	// nodary's accounting, which makes metering advisory.
	if want.Stream {
		body, err = injectIncludeUsage(body)
		if err != nil {
			s.fail(w, r, badRequest("the request body is not a JSON object"))
			return
		}
	}

	rec := &meter{
		usage: observed.Usage{
			TS: started, UserID: p.User.ID, TokenID: p.Token.ID,
			Route: want.Model, ModelID: want.Model,
			RequestID: requestID(r), Streamed: want.Stream,
		},
		streaming: want.Stream,
	}
	// Always, on every exit below: it frees the concurrency slot and charges
	// tpm what the response actually cost, which is the only moment that number
	// exists.
	defer func() { release(int(rec.usage.PromptTokens + rec.usage.CompletionTokens)) }()

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Del("Content-Length")

	mw := &meteringWriter{ResponseWriter: w, meter: rec}
	s.prox.ServeHTTP(mw, r)
	mw.finish()

	rec.usage.Status = mw.status
	rec.usage.Latency = s.now().Sub(started)

	// Which deployment served it, and therefore which node and which GPUs
	// (deployment_gpu joins from here). The data plane load-balances the
	// members of a route, so this is knowable only from the component that
	// chose — and the id it returns is the one `gateway sync` rendered.
	//
	// Silent when the header is absent: a usage row with no deployment is a
	// row that does not claim one, and guessing the route's first member would
	// put a number against a GPU that may not have run anything.
	if id := mw.Header().Get(s.plane.ServedHeader); s.plane.ServedHeader != "" && id != "" {
		rec.usage.DeploymentID = id
		if model, node, err := s.servedBy(r.Context(), id); err == nil {
			rec.usage.ModelID, rec.usage.NodeName = model, node
		} else if !errors.Is(err, sql.ErrNoRows) {
			s.log.Error("gateway", "detail", "attributing usage to "+id+": "+err.Error(),
				"request_id", requestID(r))
		}
	}
	// R3-07: a stream that ended before its usage chunk is metered from what
	// was actually seen go past, and flagged `partial`.
	//
	// Both halves matter and they are different. **Never silently dropped**,
	// because if disconnecting erased usage, metering would be trivially
	// avoidable by disconnecting and the quota system would be decorative — so
	// the count is charged against tpm and the daily budget by the deferred
	// release above, which reads these fields after this runs. And **flagged**,
	// because a count of content-bearing chunks is not a token count from a
	// tokenizer: prompt tokens are unknowable here at all, so a row that
	// claimed to be complete would be claiming a total it does not have.
	if rec.streaming && !rec.sawUsage {
		rec.usage.Partial = true
		rec.usage.CompletionTokens = rec.observed
	}
	if err := observed.RecordUsage(r.Context(), s.db, rec.usage); err != nil {
		// Logged and not returned: the request succeeded, and failing it after
		// the response has been written would be worse than a missing row. The
		// row's absence is visible in `nodary usage show`.
		s.log.Error("gateway", "detail", "recording usage: "+err.Error(),
			"request_id", requestID(r))
	}
}

// injectIncludeUsage sets stream_options.include_usage on a request body.
//
// It rewrites the one key and leaves the rest of the document byte-identical,
// because the body is a client's and the gateway is not a JSON canonicalizer: a
// re-serialized body is a changed body, and the difference surfaces as an
// upstream rejecting a field this gateway round-tripped through a struct it
// does not fully model.
func injectIncludeUsage(body []byte) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	opts := map[string]any{}
	if raw, ok := doc["stream_options"]; ok {
		if err := json.Unmarshal(raw, &opts); err != nil {
			opts = map[string]any{}
		}
	}
	opts["include_usage"] = true
	raw, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	doc["stream_options"] = raw
	return json.Marshal(doc)
}

// meter accumulates what the response reported. It holds counts and never
// content.
type meter struct {
	usage     observed.Usage
	streaming bool
	sawUsage  bool
	// observed counts stream chunks that carried generated text (R3-07).
	//
	// It is what a stream that ends before its usage chunk is metered from. One
	// chunk is one token for a backend that streams token by token, which vLLM,
	// SGLang and llama.cpp all do by default — so this is a count of chunks
	// presented as a count of tokens, and a backend that batched several per
	// chunk would undercount. That approximation is why the row it produces is
	// flagged `partial`: it says the accounting is incomplete rather than
	// claiming a number it cannot stand behind.
	//
	// The alternative is a tokenizer per model inside the gateway, which is a
	// large dependency and a second place model vocabularies have to be kept in
	// step, bought for an estimate on an exceptional path.
	observed int64
}

// observe reads usage out of one JSON document and keeps only the numbers.
func (m *meter) observe(doc []byte) {
	var body struct {
		Model   string `json:"model"`
		Choices []struct {
			// Chat completions carry generated text in delta.content;
			// /v1/completions carries it in text. Both are counted, and
			// neither is retained: the length is read and the string is
			// dropped with the chunk.
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
			Text string `json:"text"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(doc, &body); err != nil {
		return
	}
	if body.Model != "" {
		// What the upstream actually served, which may differ from the route
		// the client asked for once a route has several members.
		m.usage.ModelID = body.Model
	}
	if m.streaming {
		for _, c := range body.Choices {
			// The chunk that only announces the assistant role, and the one
			// that only carries finish_reason, produce no text and are not
			// counted.
			if c.Delta.Content != "" || c.Text != "" {
				m.observed++
			}
		}
	}
	if body.Usage == nil {
		return
	}
	m.sawUsage = true
	m.usage.PromptTokens = body.Usage.PromptTokens
	m.usage.CompletionTokens = body.Usage.CompletionTokens
}

// meteringWriter passes the response through and reads usage out of it.
//
// It forwards bytes as received. A gateway that re-serialized chunks would be a
// gateway that changed them, and for a streaming response that is the
// difference between a client library working and not.
type meteringWriter struct {
	http.ResponseWriter
	meter  *meter
	status int
	// buf accumulates a non-streaming body, which arrives in one piece and is
	// small. A streaming response is never accumulated: chunks are scanned as
	// they pass and dropped.
	buf     bytes.Buffer
	partial bytes.Buffer
}

func (w *meteringWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *meteringWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.meter.streaming {
		w.scanChunks(b)
	} else if w.buf.Len() < maxRequestBody {
		w.buf.Write(b)
	}
	n, err := w.ResponseWriter.Write(b)
	// Flushed per write so a stream reaches the client as it arrives rather
	// than when the buffer fills.
	if f, ok := w.ResponseWriter.(http.Flusher); ok && w.meter.streaming {
		f.Flush()
	}
	return n, err
}

// scanChunks finds `data: {...}` lines in a server-sent event stream.
//
// It keeps a partial line across writes, because a chunk boundary is a network
// artefact and lands anywhere. Nothing it reads is retained beyond the numbers.
func (w *meteringWriter) scanChunks(b []byte) {
	w.partial.Write(b)
	for {
		line, err := w.partial.ReadBytes('\n')
		if err != nil {
			// An incomplete line: put it back and wait for the rest.
			w.partial.Write(line)
			return
		}
		payload, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("data:"))
		if !ok {
			continue
		}
		payload = bytes.TrimSpace(payload)
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		w.meter.observe(payload)
	}
}

// Flush and Unwrap keep the streaming and hijacking behavior of the wrapped
// writer intact. Without Flush, a streaming response would be buffered by the
// wrapper and arrive all at once.
func (w *meteringWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *meteringWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// finish reads usage from a non-streaming body once the response is complete.
func (w *meteringWriter) finish() {
	if !w.meter.streaming && w.buf.Len() > 0 {
		w.meter.observe(w.buf.Bytes())
	}
}
