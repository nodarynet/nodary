package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/nodarynet/nodary/internal/secret"
)

// The PKI has two unrelated halves, and conflating them is the mistake this
// file exists to prevent (docs/specs/01-install.md §4):
//
//   - the *server* certificate, which operators and agents see on the wire. It
//     is self-signed at install unless a site brings its own (R2-39).
//   - the *internal CA*, which signs agent client certificates and nothing
//     else. Its private key is sealed under secret.key (R2-40).
//
// A site that replaces the server certificate with one from its own CA must not
// thereby change what signs agent certificates, and a compromise of the public
// certificate must not be a compromise of the fleet's identity.

const (
	serverCertName = "server.crt"
	serverKeyName  = "server.key"
	caCertName     = "agent-ca.crt"
	caSealLabel    = "agent-ca"
)

// EnsureServerCertificate generates a self-signed pair if none is configured.
//
// P-256 and SHA-256: both are FIPS-approved and pass under
// GODEBUG=fips140=only, measured in docs/spike-fips-and-manifest.md. Ed25519
// would also pass and is not used here, because a TLS certificate has to be
// accepted by whatever an operator points at it.
func EnsureServerCertificate(dir string, now time.Time, hosts []string) (certPath, keyPath, fingerprint string, err error) {
	certPath = filepath.Join(dir, serverCertName)
	keyPath = filepath.Join(dir, serverKeyName)

	if existing, err := os.ReadFile(certPath); err == nil {
		fp, err := fingerprintOfPEM(existing)
		return certPath, keyPath, fp, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("generating a server key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "nodary control plane"},
		NotBefore:    now.Add(-time.Hour),
		// Long-lived because rotating it means re-pinning every node
		// (--ca-fingerprint), which is an operation an SMB should not face
		// annually. A site that wants shorter brings its own certificate.
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", "", fmt.Errorf("signing the server certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", "", err
	}
	// 0600: the certificate is public and the key is not.
	if err := os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", "", "", err
	}
	fp, err := fingerprintOfPEM(certPEM)
	return certPath, keyPath, fp, err
}

// Fingerprint is what a node pins. SHA-256 over the DER, printed the way
// install.sh and `node install --ca-fingerprint` expect.
func fingerprintOfPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("the certificate is not PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// EnsureAgentCA generates the internal CA if it does not exist, sealing its
// private key under secret.key.
//
// R2-40: unrelated to the server's public TLS certificate. It signs agent
// client certificates and nothing else, so replacing the server certificate
// does not re-identify the fleet, and a compromise of one is not a compromise
// of the other.
func EnsureAgentCA(ctx context.Context, dir string, k *secret.Key, now time.Time) (certPath string, err error) {
	certPath = filepath.Join(dir, caCertName)
	sealedPath := certPath + ".sealed"

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(sealedPath); err == nil {
			return certPath, nil
		}
		// A certificate whose key is gone is worse than neither: it looks
		// usable and cannot sign, and the failure would surface at the first
		// node enrollment.
		return "", fmt.Errorf("%s exists but its sealed key does not: the agent CA cannot sign", certPath)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generating the agent CA key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "nodary agent CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", fmt.Errorf("signing the agent CA: %w", err)
	}
	if err := os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	sealed, err := k.Seal(caSealLabel, "agent-ca", keyDER)
	if err != nil {
		return "", fmt.Errorf("sealing the agent CA key: %w", err)
	}
	if err := os.WriteFile(sealedPath, sealed, 0o600); err != nil {
		return "", err
	}
	return certPath, nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return big.NewInt(1)
	}
	return n
}

// AgentCAPath is the certificate the listener verifies client certificates
// against, and the one EnsureAgentCA wrote.
func AgentCAPath(dir string) string { return filepath.Join(dir, caCertName) }

// agentCertificateLifetime is docs/specs/02-enrollment.md §1's 90-day default.
const agentCertificateLifetime = 90 * 24 * time.Hour

// LoadAgentCA unseals the internal CA so it can sign.
//
// It returns an error rather than a nil key when the sealed half is missing,
// for the reason EnsureAgentCA gives: a CA that cannot sign is worse than no CA
// at all, because it looks usable until the first enrollment.
func LoadAgentCA(dir string, k *secret.Key) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPath := AgentCAPath(dir)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the agent CA: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("%s is not PEM", certPath)
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing the agent CA: %w", err)
	}

	sealed, err := os.ReadFile(certPath + ".sealed")
	if err != nil {
		return nil, nil, fmt.Errorf("reading the sealed agent CA key: %w", err)
	}
	keyDER, err := k.Open(caSealLabel, "agent-ca", sealed)
	if err != nil {
		return nil, nil, fmt.Errorf("unsealing the agent CA key: %w", err)
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing the agent CA key: %w", err)
	}
	return ca, key, nil
}

// SignAgentCertificate issues one node's client certificate, in PEM.
//
// The subject is built here and never taken from the CSR
// (docs/plans/R4a-agent-protocol.md §2): the CSR arrives on the one
// unauthenticated endpoint in the product, and its subject would otherwise
// become the identity mTLS then trusts. It contributes a public key and
// nothing else.
func SignAgentCertificate(ca *x509.Certificate, caKey *ecdsa.PrivateKey,
	node string, pub any, now time.Time) ([]byte, time.Time, error) {
	notAfter := now.Add(agentCertificateLifetime)
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: node, Organization: []string{"nodary node"}},
		// A minute of leeway, not an hour: an agent whose clock is a minute
		// fast should still be able to use the certificate it was just handed,
		// and anything wider is backdating a credential.
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("signing a certificate for %s: %w", node, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), notAfter, nil
}

// PublicKeyFromCSR validates a certificate request and returns the only thing
// taken from it.
//
// One algorithm is accepted. The agent generates this key, so every additional
// curve or algorithm is a code path nothing in the product exercises, on the
// endpoint where an unauthenticated caller chooses the input. P-256 is also
// what EnsureServerCertificate and EnsureAgentCA already use, and it passes
// under GODEBUG=fips140=only (docs/spike-fips-and-manifest.md).
func PublicKeyFromCSR(csrPEM []byte) (any, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: expected a PEM CERTIFICATE REQUEST", errBadRequest)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: unparseable certificate request: %v", errBadRequest, err)
	}
	// Without this the request proves only that somebody copied a public key,
	// not that they hold the private half.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: the certificate request is not signed by its own key: %v",
			errBadRequest, err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: a node key must be ECDSA P-256", errBadRequest)
	}
	return pub, nil
}
