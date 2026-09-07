package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// csrFor generates a node keypair and its certificate request.
//
// The subject is deliberately wrong — it names a node the caller is not
// enrolling as — because docs/plans/R4a-agent-protocol.md §2 says the server
// must ignore it, and a CSR whose subject happened to be right could not tell
// us whether it does.
func csrFor(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "not-this-name"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// joinToken mints one through the API, as an administrator would.
func (f *fixture) joinToken(uses int) string {
	f.t.Helper()
	status, body := f.do(http.MethodPost, "/tokens/join", f.admin,
		map[string]any{"uses": uses}, nil)
	if status != http.StatusOK {
		f.t.Fatalf("minting a join token: %d %v", status, body)
	}
	result, _ := body["result"].(map[string]any)
	token, _ := result["token"].(string)
	if token == "" {
		f.t.Fatalf("no token in %v", body)
	}
	return token
}

func (f *fixture) enroll(name, token, csr string) (int, map[string]any) {
	f.t.Helper()
	return f.do(http.MethodPost, "/enroll", "", map[string]any{
		"name": name, "token": token, "csr": csr,
		"agent_version": "0.0.0-test",
		"protocol":      1,
		"offer":         map[string]any{"gpus": []int{0}, "max_deployments": 1},
		"inventory":     map[string]any{"arch": "amd64", "os": "linux"},
	}, nil)
}

func TestEnrollIssuesAClientCertificateAndLeavesTheNodePending(t *testing.T) {
	f := newFixture(t)
	_, csr := csrFor(t)

	status, body := f.enroll("gpu-01", f.joinToken(1), csr)
	if status != http.StatusOK {
		t.Fatalf("enroll: %d %v", status, body)
	}
	if body["state"] != "pending" {
		t.Errorf("state = %v, want pending — 02 §2 makes approval a separate step", body["state"])
	}

	certPEM, _ := body["certificate"].(string)
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("no certificate in %v", body)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "gpu-01" {
		t.Errorf("common name = %q, want the enrolled name and not the CSR's subject",
			cert.Subject.CommonName)
	}
	if days := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24; days < 89 || days > 91 {
		t.Errorf("lifetime = %.0f days, want 02 §1's 90", days)
	}

	// It has to chain to the agent CA, or mTLS will refuse it later for a
	// reason nothing here would have caught.
	roots := x509.NewCertPool()
	caPEM, err := os.ReadFile(filepath.Join(f.pki, "agent-ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("the agent CA is not a usable root")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("the issued certificate does not chain to the agent CA: %v", err)
	}

	// The node is visible to an administrator, and it is not approved.
	status, listed := f.do(http.MethodGet, "/nodes", f.admin, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("nodes: %d %v", status, listed)
	}
	nodes, _ := listed["nodes"].([]any)
	if len(nodes) != 1 {
		t.Fatalf("nodes = %v, want the one that enrolled", listed)
	}
}

func TestEnrollRefusesWhatItShould(t *testing.T) {
	f := newFixture(t)
	_, csr := csrFor(t)
	good := f.joinToken(1)

	// Spent by a successful enrolment, so the replay below is a real one.
	if status, body := f.enroll("gpu-01", good, csr); status != http.StatusOK {
		t.Fatalf("enroll: %d %v", status, body)
	}

	for _, tc := range []struct {
		what  string
		name  string
		token string
		csr   string
		want  int
	}{
		{"a replayed token", "gpu-02", good, csr, http.StatusUnauthorized},
		{"no token at all", "gpu-02", "", csr, http.StatusUnauthorized},
		{"a name that is not a hostname", "GPU 02", f.joinToken(1), csr, http.StatusUnprocessableEntity},
		{"a csr that is not PEM", "gpu-02", f.joinToken(1), "not a csr", http.StatusBadRequest},
		{"a live node's name", "gpu-01", f.joinToken(1), csr, http.StatusConflict},
	} {
		status, body := f.enroll(tc.name, tc.token, tc.csr)
		if status != tc.want {
			t.Errorf("%s: status = %d, want %d (%v)", tc.what, status, tc.want, body)
		}
	}
}

// A CSR signed by a key its holder does not have proves nothing, and this is
// the endpoint where an unauthenticated caller chooses the input.
func TestEnrollRefusesACSRWithABorrowedPublicKey(t *testing.T) {
	f := newFixture(t)
	_, csr := csrFor(t)

	// Corrupt the signature while leaving the structure intact.
	block, _ := pem.Decode([]byte(csr))
	block.Bytes[len(block.Bytes)-1] ^= 0xff
	tampered := string(pem.EncodeToMemory(block))

	if status, body := f.enroll("gpu-01", f.joinToken(1), tampered); status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an unverifiable certificate request (%v)", status, body)
	}
}
