// Package agent is the node's half of the protocol: how a GPU host reaches a
// control plane it has been told to trust, and how it joins.
//
// It holds no reconcile logic. What lives here is the trust decision — which
// certificate is the control plane's — and the enrolment that follows from it,
// because both are settled before there is anything to reconcile.
package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/backend"
	"github.com/nodarynet/nodary/internal/buildinfo"
)

// ErrPin is a control plane whose certificate is not the one this node was told
// to expect. It is separate from every transport error on purpose: a connection
// that failed is a problem, and a connection that succeeded to the wrong server
// is an incident.
var ErrPin = errors.New("the control plane's certificate does not match the pinned fingerprint")

// ErrBadConfig is an unusable agent.toml.
var ErrBadConfig = errors.New("invalid agent configuration")

// fingerprintPattern is the form `nodary server install` prints.
var fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// PinnedTLS trusts exactly one certificate and no certificate authority.
//
// docs/specs/02-enrollment.md §1 has the agent pin the control plane by a
// fingerprint carried out of band, and refuse anything else. That check happens
// here, inside the handshake, rather than by fetching the certificate first and
// reconnecting: verifying on first contact is what the specification asks for,
// and it is the only reading with no window between the check and the use.
//
// InsecureSkipVerify disables chain and hostname validation and nothing else —
// VerifyPeerCertificate still runs, and an exact key match is stricter than CA
// validation rather than weaker. This is the same trade
// docs/specs/01-install.md §5 already makes for `curl --insecure
// --pinnedpubkey`, and it looks alarming for the same reason and is not.
func PinnedTLS(fingerprint string) (*tls.Config, error) {
	want := strings.ToLower(strings.TrimSpace(fingerprint))
	if !fingerprintPattern.MatchString(want) {
		return nil, fmt.Errorf("%w: %q is not a fingerprint; `nodary server install` prints sha256:<64 hex>",
			ErrBadConfig, fingerprint)
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("%w: the server presented no certificate", ErrPin)
			}
			got := Fingerprint(rawCerts[0])
			if got != want {
				return fmt.Errorf("%w: expected %s, got %s", ErrPin, want, got)
			}
			return nil
		},
	}, nil
}

// Fingerprint is SHA-256 over a certificate's DER, in the form printed by
// `nodary server install` and stored against a node.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Client is an HTTPS client pinned to one control plane. A node certificate is
// presented when there is one; enrolment is the call made without.
func Client(fingerprint string, cert *tls.Certificate) (*http.Client, error) {
	cfg, err := PinnedTLS(fingerprint)
	if err != nil {
		return nil, err
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{
		// Longer than the 60-second long-poll, so a poll that legitimately
		// blocks for its whole window is not cancelled by its own client.
		Timeout:   90 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg},
	}, nil
}

// EnrollOptions is what an operator supplies on the node.
type EnrollOptions struct {
	Server        string
	Token         string
	CAFingerprint string
	Name          string
	// Dir is where the node's keypair is written.
	Dir string
	// NodeConfig is the path to node.toml. Empty uses the default; a file that
	// is not there offers the whole machine, which is what
	// docs/specs/12-node-guardrails.md §2 makes the right default for a
	// dedicated GPU host.
	NodeConfig string
}

// Result is what enrolment established.
type Result struct {
	Node        string
	State       string
	ExpiresAt   string
	Certificate string
	KeyPath     string
	CertPath    string
}

// Enroll performs steps 3 to 5 of docs/specs/02-enrollment.md §1.
//
// The private key never leaves this machine: it is generated here, the
// certificate request carries only its public half, and the control plane
// returns a certificate for it. Nothing in the protocol can ask for the key,
// because nothing in the protocol has a field for it.
func Enroll(ctx context.Context, opt EnrollOptions) (Result, error) {
	if opt.Name == "" {
		host, err := os.Hostname()
		if err != nil {
			return Result{}, fmt.Errorf("no --name and no hostname to fall back on: %w", err)
		}
		opt.Name = strings.ToLower(host)
	}
	if strings.TrimSpace(opt.Token) == "" {
		return Result{}, fmt.Errorf("%w: a join token is required; mint one with `nodary token join`", ErrBadConfig)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Result{}, fmt.Errorf("generating this node's key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: opt.Name}}, key)
	if err != nil {
		return Result{}, fmt.Errorf("building a certificate request: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	client, err := Client(opt.CAFingerprint, nil)
	if err != nil {
		return Result{}, err
	}
	guardrails, err := LoadNodeConfig(orDefault(opt.NodeConfig, NodeConfigPath()))
	if err != nil {
		return Result{}, err
	}
	inv := LocalInventory(ctx)
	offer, constraints := guardrails.Advertise(inv.GPUs, BackendNames())

	// What the control plane is told exists is the *offer*, not the machine.
	// docs/specs/12-node-guardrails.md §4: a four-GPU host offering three
	// appears as a three-GPU node, so the reported inventory is narrowed here
	// rather than sent whole and filtered at the far end — a control plane that
	// was told about the fourth card could place work on it.
	inv.GPUs = offer.GPUs

	body, err := json.Marshal(api.EnrollRequest{
		Name: opt.Name, Token: opt.Token, CSR: string(csrPEM),
		Offer:        mustJSON(offer),
		Constraints:  mustJSON(constraints),
		Inventory:    inv.raw(),
		AgentVersion: buildinfo.Version,
		Protocol:     api.Protocol,
		RebootPolicy: RebootPolicy(),
	})
	if err != nil {
		return Result{}, err
	}

	url := strings.TrimRight(opt.Server, "/") + api.Prefix + "/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, unwrapPin(err)
	}
	defer resp.Body.Close()

	var out api.EnrollResponse
	if resp.StatusCode != http.StatusOK {
		return Result{}, serverError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Result{}, fmt.Errorf("reading the enrolment response: %w", err)
	}

	res := Result{Node: out.Node, State: out.State, ExpiresAt: out.ExpiresAt,
		Certificate: out.Certificate,
		CertPath:    filepath.Join(opt.Dir, "node.crt"),
		KeyPath:     filepath.Join(opt.Dir, "node.key"),
	}
	if err := os.MkdirAll(opt.Dir, 0o750); err != nil {
		return Result{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return Result{}, err
	}
	// The key first. A certificate on disk whose key is missing looks like a
	// working enrolment and is not, which is the failure EnsureAgentCA already
	// refuses to create on the server side.
	if err := os.WriteFile(res.KeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(res.CertPath, []byte(out.Certificate), 0o644); err != nil {
		return Result{}, err
	}
	return res, nil
}

// serverError turns a refusal into the message the server wrote, because
// "enrolment failed: 401" tells an operator standing at a GPU host nothing.
func serverError(resp *http.Response) error {
	var body struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err == nil && body.Error.Message != "" {
		return fmt.Errorf("the control plane refused enrolment (%s): %s",
			body.Error.Code, body.Error.Message)
	}
	return fmt.Errorf("the control plane refused enrolment: %s", resp.Status)
}

// unwrapPin surfaces a pin failure as itself. net/http buries
// VerifyPeerCertificate's error inside a *url.Error, and a mismatched
// fingerprint reported as "Post …: remote error" is the one failure an operator
// must not misread as a network problem.
func unwrapPin(err error) error {
	if errors.Is(err, ErrPin) {
		return errors.Unwrap(err)
	}
	return err
}

// Inventory is the machine as this node can see it, before it is narrowed by
// node.toml. It is the agent's own type rather than api.Inventory because the
// GPUs are a list here and JSON on the wire, and the narrowing happens between.
type Inventory struct {
	Arch          string
	OS            string
	DriverVersion string
	GPUs          []GPU
}

// raw renders the inventory for the wire.
func (i Inventory) raw() api.Inventory {
	out := api.Inventory{Arch: i.Arch, OS: i.OS, DriverVersion: i.DriverVersion,
		GPUs: json.RawMessage("[]"), Topology: json.RawMessage("{}")}
	if len(i.GPUs) > 0 {
		if raw, err := json.Marshal(i.GPUs); err == nil {
			out.GPUs = raw
		}
	}
	return out
}

// LocalInventory asks the driver what is present.
func LocalInventory(ctx context.Context) Inventory {
	gpus, driver := probeGPUs(ctx)
	return Inventory{Arch: runtime.GOARCH, OS: runtime.GOOS,
		DriverVersion: driver, GPUs: gpus}
}

// BackendNames is what this build can run, before node.toml narrows it.
func BackendNames() []string {
	all, err := backend.Builtins()
	if err != nil {
		return nil
	}
	return backend.Names(all)
}

// mustJSON encodes something this package built. A failure would be a bug in a
// struct definition rather than anything a node could cause, and an empty
// document is a safer thing to send than a half-written one.
func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("{}")
	}
	return raw
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
