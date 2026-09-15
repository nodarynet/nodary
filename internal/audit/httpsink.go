package audit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nodarynet/nodary/internal/paths"
)

// httpSink posts committed records to an NDJSON endpoint — a SIEM's ingest
// path, or a log shipper in front of one (dev/tasks/R2-control-plane.md
// R2-41).
//
// **Asynchronous, and that is the load-bearing decision.** Delivery.Emit runs
// on the mutation's own goroutine right after the commit, so a synchronous POST
// would put a network round trip — and, when the far end is wedged, a timeout —
// between an operator pressing enter and their command returning. The record is
// already in the database by then and the database is the authoritative copy,
// so nothing is lost by handing the line to a worker.
//
// **A full queue drops rather than blocks**, which is the same reasoning
// followed to its end: blocking would reintroduce exactly what going
// asynchronous removed. A drop is reported like any other delivery failure, and
// dev/tasks/R2-control-plane.md R2-41 already names the recovery — `audit
// export --from-seq` re-syncs a destination that fell behind, which is why
// there is no durable spool here to go wrong in its own right.
type httpSink struct {
	url       string
	tokenPath string
	client    *http.Client

	queue  chan []byte
	done   chan struct{}
	closed chan struct{}
	once   sync.Once

	mu sync.Mutex
	// last is what the worker's most recent POST returned, and dropped counts
	// records the queue had no room for since the last success. Both are read
	// by the *next* Emit: a sink that reports asynchronously can only ever tell
	// its caller about the batch before, and Delivery already renders that
	// correctly — it announces a transition rather than a per-record result.
	last    error
	dropped int
}

const (
	// httpQueueDepth is how many records may be waiting. Large enough to
	// absorb a burst — a `config apply` writes one record, a fleet-wide change
	// a handful — and small enough that a wedged endpoint costs bounded memory
	// rather than growing until the control plane is killed.
	httpQueueDepth = 1024
	// httpBatchMax bounds one POST so a backlog drains in several requests
	// instead of one enormous body a receiver may refuse outright.
	httpBatchMax = 256
	// httpTimeout is per POST. A SIEM that has not answered in ten seconds is
	// down, and the worker is better off reporting that than waiting.
	httpTimeout = 10 * time.Second
	// httpCloseGrace bounds the flush a Close waits for, so a short-lived CLI
	// process delivers its one record without being able to hang on exit.
	httpCloseGrace = 5 * time.Second
)

// NewHTTPSink builds a sink posting NDJSON to endpoint.
//
// tokenPath holds the complete Authorization header value, not a bare token —
// "Splunk 8f3…", "Bearer …", "ApiKey …" — because the three destinations R2-41
// names spell the same secret three ways, and a file holding the whole value
// supports all of them without this package learning any of their dialects.
// An absent file means the request is sent unauthenticated, which a real
// endpoint answers with a 401 that is then reported like any other failure.
func NewHTTPSink(endpoint, tokenPath string) Sink {
	s := &httpSink{
		url: endpoint, tokenPath: tokenPath,
		client: &http.Client{Timeout: httpTimeout},
		queue:  make(chan []byte, httpQueueDepth),
		done:   make(chan struct{}),
		closed: make(chan struct{}),
	}
	go s.run()
	return s
}

func (s *httpSink) Name() string { return s.url }

func (s *httpSink) Emit(_ context.Context, _ int64, line []byte) error {
	// Copied because the caller owns line and Delivery hands the same buffer to
	// every sink in turn; the worker reads it after Emit has returned.
	buf := append([]byte(nil), line...)
	select {
	case s.queue <- buf:
	case <-s.closed:
		return fmt.Errorf("audit sink %s is closed", s.url)
	default:
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
	}
	return s.status()
}

// status is what the worker has most recently seen, reported to whichever Emit
// asks next.
func (s *httpSink) status() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dropped > 0 {
		return fmt.Errorf("%d record(s) dropped: the endpoint is not keeping up; "+
			"re-sync with `nodary audit export --from-seq`", s.dropped)
	}
	return s.last
}

func (s *httpSink) Close() error {
	s.once.Do(func() {
		close(s.closed)
		select {
		case <-s.done:
		case <-time.After(httpCloseGrace):
		}
	})
	return s.status()
}

// run drains the queue until Close, then makes one last attempt at whatever is
// still in it.
func (s *httpSink) run() {
	defer close(s.done)
	for {
		select {
		case line := <-s.queue:
			// The line that woke us leads the batch. Appending it after the
			// drained ones sent every batch with its head at the tail, which
			// a receiver ordering by arrival records as the chain going
			// backwards.
			s.post(append([][]byte{line}, s.drain(httpBatchMax-1)...))
		case <-s.closed:
			if batch := s.drain(httpBatchMax); len(batch) > 0 {
				s.post(batch)
			}
			return
		}
	}
}

// drain takes what is already queued without waiting for more.
func (s *httpSink) drain(max int) [][]byte {
	var batch [][]byte
	for len(batch) < max {
		select {
		case line := <-s.queue:
			batch = append(batch, line)
		default:
			return batch
		}
	}
	return batch
}

func (s *httpSink) post(batch [][]byte) {
	err := s.send(batch)
	s.mu.Lock()
	s.last = err
	if err == nil {
		// Cleared only on a success, so the count means "since the endpoint was
		// last reachable" and Delivery can see the sink recover.
		s.dropped = 0
	}
	s.mu.Unlock()
}

func (s *httpSink) send(batch [][]byte) error {
	// NDJSON: one record per line, which is the format `audit export` writes
	// and the shape every destination R2-41 names accepts.
	var body bytes.Buffer
	for _, line := range batch {
		body.Write(line)
		body.WriteByte('\n')
	}

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if auth, err := os.ReadFile(s.tokenPath); err == nil {
		// Read per batch rather than cached at construction, so rotating the
		// credential does not need the control plane restarted.
		if v := strings.TrimSpace(string(auth)); v != "" {
			req.Header.Set("Authorization", v)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		tail, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("%s said %s: %s", s.url, resp.Status, strings.TrimSpace(string(tail)))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return nil
}

// checkEndpoint holds a sink URL to what is safe to send audit records to.
//
// **Plaintext http is refused except to a loopback address.** Audit records
// carry who did what, when, and to which object; shipping that across a network
// in the clear would undo the point of keeping it. The loopback exception is
// not a loophole but the ordinary deployment — a log shipper (Fluent Bit,
// Vector, rsyslog) listening on 127.0.0.1 that owns the TLS to the SIEM itself,
// and refusing that would push operators to turn TLS off somewhere worse.
//
// **Credentials in the URL are refused too.** A userinfo section is how a
// secret ends up in server.toml, in a systemd unit, and in every `policy show`
// paste — which is the whole reason the token lives in a file of its own.
func checkEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %q is not a URL: %v", ErrBadSinkSpec, raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: %q names no host", ErrBadSinkSpec, raw)
	}
	if u.User != nil {
		return fmt.Errorf("%w: %q carries a credential in the URL; put the Authorization "+
			"header value in %s instead, where it is not readable by everyone who can read the configuration",
			ErrBadSinkSpec, u.Redacted(), paths.AuditSinkToken())
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return fmt.Errorf("%w: %q is plaintext to a remote host; audit records say who did what "+
			"and to which object. Use https, or point this at a local shipper on 127.0.0.1",
			ErrBadSinkSpec, raw)
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
