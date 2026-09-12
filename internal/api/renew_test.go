package api_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/agent"
	"github.com/nodarynet/nodary/internal/api"
)

// renew asks for a fresh certificate over the node's existing mTLS channel.
func (n enrolledNode) renew(t *testing.T, f *fixture, csr string) (int, api.EnrollResponse) {
	t.Helper()
	status, raw := n.call(t, f, http.MethodPost, "/agent/renew", api.RenewRequest{CSR: csr})
	var out api.EnrollResponse
	if status == http.StatusOK {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decoding the renewal: %v in %s", err, raw)
		}
	} else {
		t.Logf("renew: %d %s", status, raw)
	}
	return status, out
}

func leaf(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("not PEM: %q", certPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// R4-05. Without renewal every certificate issued in one install window expires
// in one window, and the control plane loses the whole fleet at once.
func TestANodeRenewsItsOwnCertificateOverMTLS(t *testing.T) {
	f := newFixture(t)
	n := f.join("fractal")

	key, csr := csrFor(t)
	status, out := n.renew(t, f, csr)
	if status != http.StatusOK {
		t.Fatalf("renew: %d", status)
	}
	if out.Node != "fractal" {
		t.Errorf("renewed certificate names %q", out.Node)
	}

	// The subject is built server-side and never taken from the CSR, exactly
	// as at enrollment — csrFor deliberately asks for the wrong name.
	if cn := leaf(t, out.Certificate).Subject.CommonName; cn != "fractal" {
		t.Errorf("the CSR's subject reached the certificate: CN = %q", cn)
	}

	// And the new pair works.
	renewed := enrolledNode{name: "fractal", client: f.agentClient(key, out.Certificate)}
	if code, body := renewed.call(t, f, http.MethodGet, "/agent/desired", nil); code != http.StatusOK {
		t.Errorf("the renewed certificate was refused: %d %s", code, body)
	}
}

// docs/specs/02-enrollment.md §3: issuing supersedes the previous certificate
// immediately, so it stops working at the next request rather than when it
// eventually expires.
func TestRenewalSupersedesThePreviousCertificateAtOnce(t *testing.T) {
	f := newFixture(t)
	n := f.join("fractal")

	if code, _ := n.call(t, f, http.MethodGet, "/agent/desired", nil); code != http.StatusOK {
		t.Fatalf("the original certificate did not work: %d", code)
	}

	_, csr := csrFor(t)
	if status, _ := n.renew(t, f, csr); status != http.StatusOK {
		t.Fatalf("renew: %d", status)
	}

	code, body := n.call(t, f, http.MethodGet, "/agent/desired", nil)
	if code == http.StatusOK {
		t.Fatal("the superseded certificate still works")
	}
	if !strings.Contains(string(body), "superseded") {
		t.Errorf("the refusal does not say why: %d %s", code, body)
	}
}

// The renewal is a credential being issued, so it is evidence and belongs in
// the chain — unlike the heartbeat beside it, which is telemetry.
func TestRenewalIsAudited(t *testing.T) {
	f := newFixture(t)
	n := f.join("fractal")

	_, csr := csrFor(t)
	_, out := n.renew(t, f, csr)
	if out.AuditSeq == 0 {
		t.Fatal("the renewal reported no audit record")
	}

	// By sequence number, not by searching the whole chain: enrollment writes
	// a record naming the same node and the same fields a moment earlier, so a
	// substring search over everything would pass with no renewal record at all.
	// Filtered to the action, then matched on the sequence number the renewal
	// reported: enrollment writes a record naming the same node and the same
	// fields a moment earlier, so a substring search over the whole chain
	// would pass with no renewal record at all.
	status, body := f.do(http.MethodGet, "/audit?action=node.renew", f.admin, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("reading the chain: %d %v", status, body)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Records []struct {
			Seq    int64          `json:"seq"`
			Action string         `json:"action"`
			Actor  map[string]any `json:"actor"`
			Detail map[string]any `json:"detail"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%v in %s", err, raw)
	}
	if len(doc.Records) != 1 {
		t.Fatalf("want exactly one node.renew record, got %d: %s", len(doc.Records), raw)
	}
	got := doc.Records[0]
	if got.Seq != out.AuditSeq {
		t.Errorf("the renewal reported record %d and the chain holds %d", out.AuditSeq, got.Seq)
	}
	if m, _ := got.Actor["method"].(string); m != "node-certificate" {
		t.Errorf("the actor authenticated by %q, want node-certificate: %s", m, raw)
	}
	for _, want := range []string{"cert_expires_at", "fingerprint"} {
		if _, ok := got.Detail[want]; !ok {
			t.Errorf("the record does not carry %q: %s", want, raw)
		}
	}
}

// Renewal is the one node credential operation with no join token in it, so
// the mTLS channel is the whole of the authentication.
func TestRenewalRequiresANodeCertificate(t *testing.T) {
	f := newFixture(t)
	_, csr := csrFor(t)

	status, _ := f.do(http.MethodPost, "/agent/renew", f.admin, api.RenewRequest{CSR: csr}, nil)
	if status == http.StatusOK {
		t.Error("an administrator's bearer token renewed a node certificate")
	}
}

// The two halves against each other, with nothing hand-rolled in between: the
// node's own enrollment, its own renewal, the real endpoint, and the pin as the
// only thing establishing trust.
//
// This is the test that matters for R4-05. Everything else here checks one side
// or the other; a URL typo or a mismatched JSON field would pass all of them and
// then fail sixty days after an install, which is the worst possible moment to
// discover it.
func TestTheNodeRenewsAgainstTheRealControlPlane(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	pin := agent.Fingerprint(f.srv.Certificate().Raw)

	res, err := agent.Enroll(context.Background(), agent.EnrollOptions{
		Server: f.srv.URL, Token: f.joinToken(1), CAFingerprint: pin,
		Name: "gpu-01", Dir: dir, NodeConfig: filepath.Join(dir, "node.toml"),
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	before, err := os.ReadFile(res.KeyPath)
	if err != nil {
		t.Fatal(err)
	}

	d, err := agent.NewDaemon(agent.Config{
		Server: f.srv.URL, Name: "gpu-01", CAFingerprint: pin,
		Certificate: res.CertPath, Key: res.KeyPath,
	}, agent.NodeConfig{}, agent.Host{}, nil)
	if err != nil {
		t.Fatalf("starting the agent: %v", err)
	}
	if err := d.Renew(context.Background()); err != nil {
		t.Fatalf("renew: %v", err)
	}

	// A new key, not the old one reused — the point of rotation.
	after, err := os.ReadFile(res.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) == string(before) {
		t.Error("the node kept its old private key")
	}

	// The pair on disk matches, and it is the pair the control plane now
	// expects: the old certificate was superseded the moment this was issued.
	certPEM, err := os.ReadFile(res.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, after)
	if err != nil {
		t.Fatalf("the renewed certificate does not match the renewed key: %v", err)
	}
	client, err := agent.Client(pin, &pair)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(f.srv.URL + api.Prefix + "/agent/desired")
	if err != nil {
		t.Fatalf("the renewed node cannot reach the agent protocol: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("desired after renewal: status = %d, want 200", resp.StatusCode)
	}

	// And the superseded pair no longer works.
	old, err := tls.X509KeyPair([]byte(res.Certificate), before)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := agent.Client(pin, &old)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := stale.Get(f.srv.URL + api.Prefix + "/agent/desired"); err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("the superseded certificate still reaches the agent protocol")
		}
	}
}
