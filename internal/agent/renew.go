package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/api"
)

// renewRetry is how long to wait after a failed renewal.
//
// Renewal starts a third of a lifetime before expiry — thirty days on the
// ninety-day default — so there is no hurry, and retrying on every poll would
// be forty thousand attempts and forty thousand log lines for a control plane
// that is down for a day. Hourly still leaves hundreds of chances.
const renewRetry = time.Hour

// renewalAt is when a certificate should be replaced: two thirds of the way
// through its life, per docs/specs/02-enrollment.md §3.
//
// Computed from the certificate rather than from a constant, so a control
// plane that starts issuing a different lifetime moves its agents' schedules
// with it and nothing has to agree about the number.
func renewalAt(cert *x509.Certificate) time.Time {
	life := cert.NotAfter.Sub(cert.NotBefore)
	return cert.NotBefore.Add(life * 2 / 3)
}

// leafOf returns the parsed certificate from a loaded pair.
func leafOf(pair *tls.Certificate) (*x509.Certificate, error) {
	if pair.Leaf != nil {
		return pair.Leaf, nil
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("this node's certificate is empty")
	}
	return x509.ParseCertificate(pair.Certificate[0])
}

// Renew asks the control plane for a fresh certificate and starts using it.
//
// Exported because it is the operation, not a step inside one: renewIfDue
// decides *when*, and an operator rotating a key they think is compromised
// wants the same thing on demand.
//
// It runs on the poll goroutine, which is the one that already owns every
// field it touches except the client — and that one is swapped atomically,
// because the heartbeat goroutine reads it on its own timer.
func (d *Daemon) Renew(ctx context.Context) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating a new key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: d.Config.Name}}, key)
	if err != nil {
		return fmt.Errorf("building a certificate request: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, err := json.Marshal(api.RenewRequest{CSR: string(csrPEM)})
	if err != nil {
		return err
	}
	url := strings.TrimRight(d.Config.Server, "/") + api.Prefix + "/agent/renew"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.http().Do(req)
	if err != nil {
		return unwrapPin(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return serverError("this node's certificate renewal", resp)
	}
	var out api.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("reading the renewal response: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// The pair has to load before either file is replaced. A certificate that
	// does not match its key would leave this node unable to authenticate at
	// all, and the recovery for that is an administrator re-enrolling it.
	pair, err := tls.X509KeyPair([]byte(out.Certificate), keyPEM)
	if err != nil {
		return fmt.Errorf("the control plane returned a certificate that does not match the key: %w", err)
	}
	client, err := Client(d.Config.CAFingerprint, &pair)
	if err != nil {
		return err
	}
	if err := replacePair(d.Config.Certificate, d.Config.Key, []byte(out.Certificate), keyPEM); err != nil {
		return err
	}

	leaf, err := leafOf(&pair)
	if err != nil {
		return err
	}
	d.client.Store(client)
	d.renewAt = renewalAt(leaf)
	d.Log.Info("agent", "detail", "renewed this node's certificate",
		"expires", out.ExpiresAt, "next_renewal", d.renewAt.UTC().Format(time.RFC3339))
	return nil
}

// replacePair writes a certificate and its key, each through a temporary file
// in the same directory so neither is ever half-written.
//
// It is two renames rather than one, so a crash between them leaves a new
// certificate beside an old key. The window is two syscalls wide and the
// recovery is docs/specs/02-enrollment.md §3's: an administrator re-enrolls
// the node, which keeps its state and its approval. Closing it properly means
// the agent holding both pairs and choosing at startup, which is more
// machinery than a two-syscall window is worth.
//
// ponytail: two renames, not atomic. Promote-on-startup if this ever bites.
func replacePair(certPath, keyPath string, certPEM, keyPEM []byte) error {
	// The key first, matching Enroll: a certificate whose key is missing looks
	// like a working enrollment and is not.
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("writing the new key: %w", err)
	}
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("writing the new certificate: %w", err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	// Durable before it is visible: a rename that survives a power cut while
	// its contents do not is the one outcome worse than no write at all.
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// renewIfDue renews when the certificate has passed two thirds of its life,
// and says nothing at all the rest of the time.
func (d *Daemon) renewIfDue(ctx context.Context) {
	if d.renewAt.IsZero() || time.Now().Before(d.renewAt) {
		return
	}
	if err := d.Renew(ctx); err != nil {
		if ctx.Err() != nil {
			return
		}
		d.Log.Error("agent", "detail", "renewing this node's certificate: "+err.Error(),
			"retry_in", renewRetry.String())
		d.renewAt = time.Now().Add(renewRetry)
	}
}
