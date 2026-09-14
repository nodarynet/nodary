package audit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// receiver stands in for a SIEM's ingest path.
type receiver struct {
	mu      sync.Mutex
	lines   []string
	auth    []string
	status  int
	release chan struct{}
}

func newReceiver() *receiver { return &receiver{status: http.StatusOK} }

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r.release != nil {
		<-r.release
	}
	body := make([]byte, 1<<20)
	n, _ := req.Body.Read(body)
	r.mu.Lock()
	for _, l := range strings.Split(strings.TrimSpace(string(body[:n])), "\n") {
		if l != "" {
			r.lines = append(r.lines, l)
		}
	}
	r.auth = append(r.auth, req.Header.Get("Authorization"))
	status := r.status
	r.mu.Unlock()
	w.WriteHeader(status)
}

func (r *receiver) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

func (r *receiver) headers() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.auth...)
}

// eventually polls rather than sleeping a fixed span: the worker is
// asynchronous by design, so the test has to wait for it and must not encode a
// guess about how long it takes.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestTheHTTPSinkDeliversRecordsAsNDJSON(t *testing.T) {
	rec := newReceiver()
	srv := httptest.NewServer(rec)
	defer srv.Close()

	s := NewHTTPSink(srv.URL, filepath.Join(t.TempDir(), "absent"))
	for i, line := range []string{`{"seq":1}`, `{"seq":2}`, `{"seq":3}`} {
		if err := s.Emit(context.Background(), int64(i+1), []byte(line)); err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got := rec.got()
	if len(got) != 3 {
		t.Fatalf("received %d records, want 3: %v", len(got), got)
	}
	// One JSON document per line, which is what NDJSON means and what
	// `audit export` already writes.
	for i, want := range []string{`{"seq":1}`, `{"seq":2}`, `{"seq":3}`} {
		if got[i] != want {
			t.Errorf("line %d = %q, want %q", i, got[i], want)
		}
	}
}

// Close is what makes an asynchronous sink usable from the CLI, where the
// process holding the worker exits moments after the record is written.
func TestCloseFlushesWhatIsStillQueued(t *testing.T) {
	rec := newReceiver()
	rec.release = make(chan struct{})
	srv := httptest.NewServer(rec)
	defer srv.Close()

	s := NewHTTPSink(srv.URL, filepath.Join(t.TempDir(), "absent"))
	for i := range 5 {
		if err := s.Emit(context.Background(), int64(i), []byte(`{"seq":0}`)); err != nil {
			t.Fatal(err)
		}
	}
	close(rec.release) // let the first POST through; Close flushes the rest
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := rec.got(); len(got) != 5 {
		t.Errorf("received %d of 5 records; Close did not flush: %v", len(got), got)
	}
}

// The whole file contents become the header, so one mechanism serves Splunk's
// "Splunk <tok>", Elastic's "ApiKey <tok>" and a plain "Bearer <tok>".
func TestTheAuthorizationHeaderIsTheTokenFileVerbatim(t *testing.T) {
	rec := newReceiver()
	srv := httptest.NewServer(rec)
	defer srv.Close()

	token := filepath.Join(t.TempDir(), "audit-sink.token")
	if err := os.WriteFile(token, []byte("Splunk 8f3a-bead\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := NewHTTPSink(srv.URL, token)
	if err := s.Emit(context.Background(), 1, []byte(`{"seq":1}`)); err != nil {
		t.Fatal(err)
	}
	s.Close()

	h := rec.headers()
	if len(h) == 0 || h[0] != "Splunk 8f3a-bead" {
		t.Errorf("Authorization = %v, want the file's contents with the newline trimmed", h)
	}
}

// A sink reports asynchronously, so it can only tell its caller about the batch
// before — which is exactly what Delivery renders, as a transition rather than
// a per-record result.
func TestAFailingEndpointIsReportedToTheNextEmit(t *testing.T) {
	rec := newReceiver()
	rec.status = http.StatusServiceUnavailable
	srv := httptest.NewServer(rec)
	defer srv.Close()

	s := NewHTTPSink(srv.URL, filepath.Join(t.TempDir(), "absent"))
	// **Whatever the first emit returns is not a property.** Emit queues the
	// line and reports whatever the worker has most recently seen, so on a
	// loaded machine the POST can complete and record the 503 before Emit
	// returns — and asserting nil here failed on CI while passing 300 runs
	// locally. Reproduced by forcing the window with a sleep before status().
	// What the sink promises is that a failure surfaces on a *later* emit,
	// which is what the loop below tests.
	_ = s.Emit(context.Background(), 1, []byte(`{"seq":1}`))
	eventually(t, "the failure to surface", func() bool {
		return s.Emit(context.Background(), 2, []byte(`{"seq":2}`)) != nil
	})

	err := s.Emit(context.Background(), 3, []byte(`{"seq":3}`))
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("error = %v, want the status the endpoint returned", err)
	}

	// And it recovers, so Delivery can announce that too.
	rec.mu.Lock()
	rec.status = http.StatusOK
	rec.mu.Unlock()
	eventually(t, "the sink to recover", func() bool {
		return s.Emit(context.Background(), 4, []byte(`{"seq":4}`)) == nil
	})
	s.Close()
}

// A wedged endpoint must cost bounded memory, and must not become a way to
// block the mutation path that going asynchronous existed to protect.
func TestAWedgedEndpointDropsRatherThanBlocking(t *testing.T) {
	rec := newReceiver()
	rec.release = make(chan struct{})
	srv := httptest.NewServer(rec)
	defer srv.Close()

	s := NewHTTPSink(srv.URL, filepath.Join(t.TempDir(), "absent"))
	done := make(chan error, 1)
	go func() {
		var last error
		for range httpQueueDepth + httpBatchMax + 64 {
			last = s.Emit(context.Background(), 1, []byte(`{"seq":1}`))
		}
		done <- last
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "dropped") {
			t.Errorf("error = %v, want it to name the drop and the re-sync", err)
		}
		if !strings.Contains(err.Error(), "--from-seq") {
			t.Errorf("the drop does not name the recovery: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Emit blocked on a wedged endpoint; the mutation path would have blocked with it")
	}
	close(rec.release)
	s.Close()
}

func TestSinkSpecRefusals(t *testing.T) {
	for _, c := range []struct{ spec, mentions string }{
		// Audit records say who did what to which object. Not in the clear.
		{"http://siem.example.test/ingest", "plaintext"},
		// A credential in the URL is a credential in server.toml, in the unit,
		// and in every paste of either.
		{"https://user:secret@siem.example.test/in", "credential in the URL"},
		{"https://", "names no host"},
	} {
		if _, err := ParseSinks(c.spec); err == nil {
			t.Errorf("%q was accepted", c.spec)
		} else if !strings.Contains(err.Error(), c.mentions) {
			t.Errorf("%q: refusal does not say %q: %v", c.spec, c.mentions, err)
		} else if !errors.Is(err, ErrBadSinkSpec) {
			t.Errorf("%q: error does not wrap ErrBadSinkSpec", c.spec)
		}
	}

	// The ordinary local-shipper deployment is not the thing being refused.
	for _, ok := range []string{"http://127.0.0.1:8088/services/collector", "http://localhost:9200/_bulk"} {
		sinks, err := ParseSinks(ok)
		if err != nil {
			t.Errorf("%q was refused: %v", ok, err)
			continue
		}
		for _, s := range sinks {
			s.Close()
		}
	}

	// A refusal must not leak the secret it is refusing.
	_, err := ParseSinks("https://user:hunter2@siem.example.test/in")
	if err != nil && strings.Contains(err.Error(), "hunter2") {
		t.Errorf("the refusal printed the credential: %v", err)
	}
}
