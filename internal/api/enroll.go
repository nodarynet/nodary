package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/identity"
)

// Protocol is the agent protocol this build speaks
// (docs/specs/03-agent.md §4). Server and agent are the same binary, so skew
// happens only mid-upgrade.
const Protocol = 1

// nodeNamePattern is stricter than a user name, and deliberately so: a node
// name becomes a certificate common name, a systemd instance after `%i`, a
// container name and a directory. Every one of those has its own opinion about
// what is legal, and the intersection is a hostname.
var nodeNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`)

// EnrollRequest is what a node sends to join. docs/specs/02-enrollment.md §1.
type EnrollRequest struct {
	Name  string `json:"name"`
	Token string `json:"token"`
	// CSR is PEM. Only its public key is used — see PublicKeyFromCSR.
	CSR string `json:"csr"`
	// Offer is what the node is putting on the table: GPU indices, a deployment
	// ceiling, permitted backends. 02 §1 records it in the approval so that
	// neither side can later claim terms the other did not see.
	Offer        json.RawMessage `json:"offer"`
	Inventory    Inventory       `json:"inventory"`
	AgentVersion string          `json:"agent_version"`
	Protocol     int             `json:"protocol"`
	RebootPolicy string          `json:"reboot_policy"`
}

// Inventory is the machine as the node reports it.
type Inventory struct {
	Arch          string          `json:"arch"`
	OS            string          `json:"os"`
	DriverVersion string          `json:"driver_version"`
	GPUs          json.RawMessage `json:"gpus"`
	Topology      json.RawMessage `json:"topology"`
}

// EnrollResponse is the certificate and what the node now is.
type EnrollResponse struct {
	Node        string `json:"node"`
	State       string `json:"state"`
	Certificate string `json:"certificate"`
	ExpiresAt   string `json:"expires_at"`
	Protocol    int    `json:"protocol"`
	AuditSeq    int64  `json:"audit_seq"`
}

// rebootPolicies are the values 0006_fleet.sql's CHECK accepts. Validated here
// so a typo is a 422 naming the alternatives rather than a constraint failure.
var rebootPolicies = []string{"manual-console", "host-managed", "unattended"}

// enroll is the only unauthenticated endpoint in the product
// (docs/specs/03-agent.md §1), which is why almost everything it touches is
// checked before it is used.
//
// It goes through audit.Log.Act rather than core.Act: an enrolling node has no
// principal, no role and nobody to prompt for a TOTP code, and `login` — the
// other mutation performed by somebody who is not yet a principal — already
// takes this path (docs/plans/R4a-agent-protocol.md §3).
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var body EnrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		s.fail(w, r, badRequest("expected an enrolment request"))
		return
	}
	if !nodeNamePattern.MatchString(body.Name) {
		s.fail(w, r, fmt.Errorf("%w: %q is not a usable node name; a hostname is expected",
			identity.ErrBadName, body.Name))
		return
	}
	if body.Protocol != 0 && body.Protocol != Protocol {
		s.fail(w, r, fmt.Errorf("%w: this control plane speaks protocol %d, the agent speaks %d",
			identity.ErrBadName, Protocol, body.Protocol))
		return
	}
	if body.RebootPolicy == "" {
		// The safe default: nodary never initiates a reboot under any policy,
		// and this is the one that also stops an operator assuming it might.
		body.RebootPolicy = "manual-console"
	}
	if !slices.Contains(rebootPolicies, body.RebootPolicy) {
		s.fail(w, r, fmt.Errorf("%w: reboot_policy must be one of %v", identity.ErrBadName, rebootPolicies))
		return
	}
	pub, err := PublicKeyFromCSR([]byte(body.CSR))
	if err != nil {
		s.fail(w, r, err)
		return
	}

	key, err := s.key()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ca, caKey, err := LoadAgentCA(s.pki, key)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	now := s.now()
	var (
		certPEM []byte
		expires time.Time
		state   string
	)
	rec, err := s.log.Act(r.Context(), audit.Request{
		Actor:  audit.Actor{ID: body.Name, Method: "join-token"},
		Action: "node.enroll",
		Target: &audit.Target{Kind: "node", ID: body.Name},
	}, func(m audit.Mutation) error {
		if _, err := identity.RedeemJoinToken(r.Context(), m, now, body.Token); err != nil {
			return err
		}
		existing, err := nodeCertExpiry(r.Context(), m.Tx(), body.Name)
		if err != nil {
			return err
		}
		state = "pending"
		if existing != nil {
			// docs/plans/R4a-agent-protocol.md §8. Re-enrolment is 02 §3's
			// path for a node that was offline past expiry; anything earlier
			// is a leaked token trying to inherit a live node's approval.
			if existing.expires.IsZero() || now.Before(existing.expires) {
				return fmt.Errorf("%w: node %q is already enrolled and its certificate is still valid",
					identity.ErrNameTaken, body.Name)
			}
			state = existing.state
			m.Detail("re_enrolled", true)
		}

		certPEM, expires, err = SignAgentCertificate(ca, caKey, body.Name, pub, now)
		if err != nil {
			return err
		}
		fp, err := fingerprintOfPEM(certPEM)
		if err != nil {
			return err
		}
		if err := upsertEnrolledNode(r.Context(), m.Tx(), body, state, fp, expires, now); err != nil {
			return err
		}
		m.Detail("request_id", requestID(r))
		m.Detail("state", state)
		m.Detail("fingerprint", fp)
		m.Detail("cert_expires_at", expires.UTC().Format(audit.TimeFormat))
		m.Detail("offer", decodedJSON(rawOrDefault(body.Offer, "{}")))
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, EnrollResponse{
		Node: body.Name, State: state, Certificate: string(certPEM),
		ExpiresAt: expires.UTC().Format(audit.TimeFormat),
		Protocol:  Protocol, AuditSeq: rec.Seq,
	})
}

// enrolled is what the node row already says about a name being re-enrolled.
type enrolled struct {
	state   string
	expires time.Time
}

// nodeCertExpiry returns nil when the name is free.
//
// A NULL cert_expires_at comes back as the zero time, which the caller reads as
// "unknown" and refuses — 0009_node_certificate.sql says why.
func nodeCertExpiry(ctx context.Context, tx *sql.Tx, name string) (*enrolled, error) {
	var e enrolled
	var expires sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT state, cert_expires_at FROM node WHERE name = ?`, name).Scan(&e.state, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if expires.Valid {
		if e.expires, err = time.Parse(audit.TimeFormat, expires.String); err != nil {
			return nil, fmt.Errorf("node %s has an unreadable cert_expires_at %q: %w",
				name, expires.String, err)
		}
	}
	return &e, nil
}

// upsertEnrolledNode writes the row, leaving an existing node's approval alone.
//
// The ON CONFLICT list is exhaustive on purpose: approved_by, approved_at and
// departed_at are absent from it, so a re-enrolment cannot grant itself the
// approval 02 §2 requires an administrator to give.
func upsertEnrolledNode(ctx context.Context, tx *sql.Tx, body EnrollRequest,
	state, fingerprint string, expires, now time.Time) error {
	stamp := now.UTC().Format(audit.TimeFormat)
	_, err := tx.ExecContext(ctx,
		`INSERT INTO node (name, fingerprint, state, arch, os, driver_version,
		                   gpus_json, topology_json, offer_json, reboot_policy,
		                   agent_version, protocol, cert_expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
		     fingerprint = excluded.fingerprint,
		     state = excluded.state,
		     arch = excluded.arch,
		     os = excluded.os,
		     driver_version = excluded.driver_version,
		     gpus_json = excluded.gpus_json,
		     topology_json = excluded.topology_json,
		     offer_json = excluded.offer_json,
		     reboot_policy = excluded.reboot_policy,
		     agent_version = excluded.agent_version,
		     protocol = excluded.protocol,
		     cert_expires_at = excluded.cert_expires_at`,
		body.Name, fingerprint, state, body.Inventory.Arch, body.Inventory.OS,
		body.Inventory.DriverVersion, rawOrDefault(body.Inventory.GPUs, "[]"),
		rawOrDefault(body.Inventory.Topology, "{}"), rawOrDefault(body.Offer, "{}"),
		body.RebootPolicy, body.AgentVersion, Protocol,
		expires.UTC().Format(audit.TimeFormat), stamp)
	if err != nil {
		return fmt.Errorf("recording node %s: %w", body.Name, err)
	}
	return nil
}

// rawOrDefault keeps the JSON columns valid: an absent member becomes the
// empty document the schema's DEFAULT would have used.
func rawOrDefault(raw json.RawMessage, empty string) string {
	if len(raw) == 0 || !json.Valid(raw) {
		return empty
	}
	return string(raw)
}
