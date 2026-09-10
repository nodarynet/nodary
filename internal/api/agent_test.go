package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/identity"
)

// enrolledNode is a node that has joined, with the client it speaks mTLS on.
type enrolledNode struct {
	name   string
	client *http.Client
}

// join runs docs/specs/02-enrollment.md §1 end to end and returns the node.
func (f *fixture) join(name string) enrolledNode {
	f.t.Helper()
	key, csr := csrFor(f.t)
	status, body := f.enroll(name, f.joinToken(1), csr)
	if status != http.StatusOK {
		f.t.Fatalf("enroll %s: %d %v", name, status, body)
	}
	certPEM, _ := body["certificate"].(string)
	return enrolledNode{name: name, client: f.agentClient(key, certPEM)}
}

// agentClient trusts the test server and presents the node's certificate.
func (f *fixture) agentClient(key *ecdsa.PrivateKey, certPEM string) *http.Client {
	f.t.Helper()
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		f.t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(certPEM),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		f.t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.srv.Certificate())
	return &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}},
	}}
}

// call makes one request as the node.
func (n enrolledNode) call(t *testing.T, f *fixture, method, path string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, f.srv.URL+api.Prefix+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (n enrolledNode) desired(t *testing.T, f *fixture, query string) api.Desired {
	t.Helper()
	status, raw := n.call(t, f, http.MethodGet, "/agent/desired"+query, nil)
	if status != http.StatusOK {
		t.Fatalf("desired: %d %s", status, raw)
	}
	var doc api.Desired
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// place writes a model and a deployment into the configuration, through the
// applier every other configuration change uses.
func (f *fixture) place(node, deployment string, gpu int) {
	f.t.Helper()
	ctx := context.Background()
	root := identity.LocalRoot()
	root.Actor.ID = "test"
	if _, err := f.log.Act(ctx, audit.Request{Actor: root.Actor, Action: "config.apply"},
		func(m audit.Mutation) error {
			snap, err := config.Read(ctx, m.Tx())
			if err != nil {
				return err
			}
			snap.Models = append(snap.Models, config.Model{
				ID: "acme/tiny", Backend: "vllm", Source: "local", Artifact: "hf-cache",
				ManifestSHA256: "", TotalBytes: 4096,
			})
			snap.Deployments = append(snap.Deployments, config.Deployment{
				ID: deployment, ModelID: "acme/tiny", NodeName: node, Backend: "vllm",
				Image: "registry.invalid/vllm@sha256:" + hex64, GPUs: []int{gpu}, Port: 8001,
			})
			if _, err := config.Apply(ctx, m, time.Now(), snap, config.Options{}); err != nil {
				return err
			}
			_, err = config.Record(ctx, m, time.Now(), "test", "a deployment for the agent")
			return err
		}); err != nil {
		f.t.Fatalf("placing a deployment: %v", err)
	}
}

const hex64 = "0000000000000000000000000000000000000000000000000000000000000000"

// The whole of docs/specs/02-enrollment.md §1 and §2, in the order an operator
// performs it. The assertion that matters is the middle one: a node that has
// enrolled and not been approved holds a valid certificate, can heartbeat, and
// receives no work.
func TestANodeIsApprovedBeforeItReceivesAnyWork(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")

	// A deployment is waiting for it, and approval is the only thing missing.
	f.place("gpu-01", "dep_one", 0)

	pending := n.desired(t, f, "")
	if len(pending.Deployments) != 0 {
		t.Errorf("a pending node was given %d deployments; 02 §2 makes approval the gate",
			len(pending.Deployments))
	}
	if pending.Node != "gpu-01" || pending.Protocol != api.Protocol {
		t.Errorf("desired = %+v, want this node and protocol %d", pending, api.Protocol)
	}

	if status, body := f.do(http.MethodPost, "/nodes/gpu-01/approve", f.admin, nil,
		map[string]string{api.HeaderJustify: "the node in the rack we ordered"}); status != http.StatusOK {
		t.Fatalf("approve: %d %v", status, body)
	}

	approved := n.desired(t, f, "")
	if len(approved.Deployments) != 1 {
		t.Fatalf("an approved node was given %d deployments, want 1: %+v",
			len(approved.Deployments), approved)
	}
	d := approved.Deployments[0]
	if d.ID != "dep_one" || d.Network != api.IsolatedNetwork || d.State != "ready" {
		t.Errorf("deployment = %+v, want dep_one on %s wanted ready", d, api.IsolatedNetwork)
	}
	if len(approved.Staging) != 1 || approved.Staging[0].Layout != "hf-cache" {
		t.Errorf("staging = %+v, want the model's layout from the catalog", approved.Staging)
	}
	if approved.Rev == 0 {
		t.Error("rev = 0 after a configuration change; the long-poll has nothing to compare")
	}
}

// TestTheDesiredDocumentCarriesAPendingReset is R4-35/R4-36's request half:
// a row in stage_reset (what `nodary model restage`/`unstage` writes)
// should appear in the desired document as a DesiredReset, with the model's
// layout resolved from the catalog — desiredFor's job, since a model with no
// deployment on this node (the unstage shape) has no DesiredStaging entry to
// read a layout off of.
func TestTheDesiredDocumentCarriesAPendingReset(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")
	f.place("gpu-01", "dep_one", 0)
	if status, body := f.do(http.MethodPost, "/nodes/gpu-01/approve", f.admin, nil,
		map[string]string{api.HeaderJustify: "the node in the rack we ordered"}); status != http.StatusOK {
		t.Fatalf("approve: %d %v", status, body)
	}

	if err := f.db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(),
			`INSERT INTO stage_reset (node_name, model_id, requested_at) VALUES (?, ?, ?)`,
			"gpu-01", "acme/tiny", time.Now().UTC().Format(audit.TimeFormat))
		return err
	}); err != nil {
		t.Fatal(err)
	}

	doc := n.desired(t, f, "")
	if len(doc.Reset) != 1 || doc.Reset[0].Model != "acme/tiny" || doc.Reset[0].Layout != "hf-cache" {
		t.Errorf("reset = %+v, want one entry for acme/tiny with its catalog layout", doc.Reset)
	}
}

// R4-36: `nodary model disable` reaches the agent over the existing
// DesiredDeployment.State field, the seam desiredFor's own comment used to
// name as unimplemented.
func TestADisabledDeploymentIsNamedDisabled(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")
	f.place("gpu-01", "dep_one", 0)
	if status, body := f.do(http.MethodPost, "/nodes/gpu-01/approve", f.admin, nil,
		map[string]string{api.HeaderJustify: "the node in the rack we ordered"}); status != http.StatusOK {
		t.Fatalf("approve: %d %v", status, body)
	}

	if err := f.db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(),
			`UPDATE deployment SET disabled = 1 WHERE id = ?`, "dep_one")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	doc := n.desired(t, f, "")
	if len(doc.Deployments) != 1 || doc.Deployments[0].State != "disabled" {
		t.Errorf("deployments = %+v, want dep_one's State = \"disabled\"", doc.Deployments)
	}
}

// The long-poll's contract: a caller already at the current revision waits, and
// a caller behind it is answered at once.
func TestTheLongPollWaitsOnlyWhenThereIsNothingNew(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")
	f.place("gpu-01", "dep_one", 0)
	if status, body := f.do(http.MethodPost, "/nodes/gpu-01/approve", f.admin, nil,
		map[string]string{api.HeaderJustify: "the node in the rack we ordered"}); status != http.StatusOK {
		t.Fatalf("approve: %d %v", status, body)
	}

	current := n.desired(t, f, "").Rev

	// Behind: answered immediately.
	start := time.Now()
	if got := n.desired(t, f, "?rev=0").Rev; got != current {
		t.Errorf("rev = %d, want the current %d", got, current)
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Errorf("a caller behind the current revision waited %s", waited)
	}

	// Caught up: it blocks, and a change releases it.
	done := make(chan api.Desired, 1)
	go func() { done <- n.desired(t, f, "?rev="+itoa(current)) }()
	select {
	case doc := <-done:
		t.Fatalf("the poll returned rev %d without waiting for a change", doc.Rev)
	case <-time.After(2 * time.Second):
	}
	f.place("gpu-01", "dep_two", 1)
	select {
	case doc := <-done:
		if doc.Rev <= current {
			t.Errorf("released at rev %d, want past %d", doc.Rev, current)
		}
		if len(doc.Deployments) != 2 {
			t.Errorf("deployments = %d, want both", len(doc.Deployments))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the poll did not wake for a configuration change")
	}
}

// A node with no certificate is not a node, whatever it claims in the body.
func TestTheAgentEndpointsRequireAClientCertificate(t *testing.T) {
	f := newFixture(t)
	f.join("gpu-01")

	// An administrator's personal token is a real credential and still not a
	// node: these endpoints are identified by certificate or not at all.
	for _, ep := range []struct{ method, path string }{
		{http.MethodGet, "/agent/desired"},
		{http.MethodPost, "/agent/status"},
	} {
		status, body := f.do(ep.method, ep.path, f.admin, map[string]any{}, nil)
		if status != http.StatusUnauthorized {
			t.Errorf("%s %s without a client certificate: status = %d, want 401 (%v)",
				ep.method, ep.path, status, body)
		}
	}
}

// A certificate superseded by a re-enrollment stops working at once, rather than
// when it eventually expires.
func TestASupersededCertificateIsRefused(t *testing.T) {
	f := newFixture(t)
	n := f.join("gpu-01")

	// Expire the certificate on record so re-enrollment is permitted, then
	// re-enroll with a fresh key.
	if err := f.db.WriteTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(context.Background(),
			`UPDATE node SET cert_expires_at = '2000-01-01T00:00:00.000Z' WHERE name = 'gpu-01'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	key, csr := csrFor(t)
	status, body := f.enroll("gpu-01", f.joinToken(1), csr)
	if status != http.StatusOK {
		t.Fatalf("re-enroll: %d %v", status, body)
	}
	fresh := enrolledNode{name: "gpu-01",
		client: f.agentClient(key, body["certificate"].(string))}

	if status, _ := n.call(t, f, http.MethodGet, "/agent/desired", nil); status != http.StatusUnauthorized {
		t.Errorf("the superseded certificate still works: status = %d", status)
	}
	if status, raw := fresh.call(t, f, http.MethodGet, "/agent/desired", nil); status != http.StatusOK {
		t.Errorf("the fresh certificate does not work: %d %s", status, raw)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// R4-04: the approval record has to name the administrator, carry their
// justification, and record the terms the node advertised — so that neither
// side can later claim terms the other did not see
// (docs/specs/02-enrollment.md §1).
//
// The offer is asserted through the dry run because that is the preview
// core.Act hashes into intent_hash: a field visible only in a log line beside
// the record would not be covered by anything.
func TestApprovalRecordsTheTermsItAgreedTo(t *testing.T) {
	f := newFixture(t)
	f.join("gpu-01")

	status, preview := f.do(http.MethodPost, "/nodes/gpu-01/approve?dry_run=true", f.admin, nil,
		map[string]string{api.HeaderJustify: "the node in the rack we ordered"})
	if status != http.StatusOK {
		t.Fatalf("dry run: %d %v", status, preview)
	}
	change, _ := preview["change"].(map[string]any)
	offer, _ := change["offer"].(map[string]any)
	if offer["max_deployments"] != float64(1) {
		t.Errorf("the approved change does not carry the node's offer: %v", change)
	}
	if change["from"] != "pending" || change["to"] != "approved" {
		t.Errorf("change = %v, want the transition it is approving", change)
	}

	intent, _ := preview["intent_hash"].(string)
	status, done := f.do(http.MethodPost, "/nodes/gpu-01/approve", f.admin, nil,
		map[string]string{api.HeaderJustify: "the node in the rack we ordered",
			api.HeaderIntent: intent})
	if status != http.StatusOK {
		t.Fatalf("approve: %d %v", status, done)
	}

	_, chain := f.do(http.MethodGet, "/audit?action=node.approve", f.admin, nil, nil)
	records, _ := chain["records"].([]any)
	if len(records) != 1 {
		t.Fatalf("audit records = %v, want the one approval", chain)
	}
	rec, _ := records[0].(map[string]any)
	if rec["justification"] != "the node in the rack we ordered" {
		t.Errorf("justification = %v", rec["justification"])
	}
	if rec["intent_hash"] != intent {
		t.Errorf("intent_hash = %v, want the %v the administrator approved",
			rec["intent_hash"], intent)
	}
	actor, _ := rec["actor"].(map[string]any)
	if actor["id"] == nil || actor["id"] == "" {
		t.Errorf("the approval names no administrator: %v", rec)
	}
}
