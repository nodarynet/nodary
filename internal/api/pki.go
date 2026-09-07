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
		// node enrolment.
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
