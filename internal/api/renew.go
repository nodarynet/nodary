package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
)

// RenewRequest carries a new public key and nothing else.
//
// There is no name in it. docs/specs/02-enrollment.md §3 renews "over the
// existing mTLS channel", so the node is whoever the client certificate says
// it is — already checked against the recorded fingerprint by agentNode. A
// name in the body would be a second, weaker claim about identity sitting
// beside a strong one, and the weak one is the one an attacker gets to choose.
type RenewRequest struct {
	// CSR is PEM. As at enrollment, only its public key is used.
	CSR string `json:"csr"`
}

// agentRenew issues a node a fresh certificate before its current one expires.
//
// Without this, every certificate issued in one install window expires in one
// window, and the control plane loses the whole fleet at once. The failure is
// quiet — running deployments keep serving because nothing kills them — so
// what is lost is visibility and control rather than inference, which is the
// worst shape for it to have.
//
// Through audit.Log.Act rather than core.Act, for enroll's reason: the actor
// is a machine presenting a certificate, with no role and nobody to prompt for
// a second factor. It is audited rather than silent, because a credential was
// issued — that is evidence, unlike the heartbeat beside it.
func (s *Server) agentRenew(w http.ResponseWriter, r *http.Request) {
	n, err := s.agentNode(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	var body RenewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		s.fail(w, r, badRequest(`expected {"csr": "-----BEGIN CERTIFICATE REQUEST-----…"}`))
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
	)
	rec, err := s.log.Act(r.Context(), audit.Request{
		Actor:  audit.Actor{ID: n.name, Method: "node-certificate"},
		Action: "node.renew",
		Target: &audit.Target{Kind: "node", ID: n.name},
	}, func(m audit.Mutation) error {
		var err error
		certPEM, expires, err = SignAgentCertificate(ca, caKey, n.name, pub, now)
		if err != nil {
			return err
		}
		fp, err := fingerprintOfPEM(certPEM)
		if err != nil {
			return err
		}
		// Superseding is the same UPDATE that records the new expiry, so there
		// is no instant where the row names one certificate's fingerprint and
		// another's lifetime. 02 §3: the previous certificate stops working at
		// the node's next request rather than when it eventually expires.
		res, err := m.Tx().ExecContext(r.Context(),
			`UPDATE node SET fingerprint = ?, cert_expires_at = ? WHERE name = ?`,
			fp, expires.UTC().Format(audit.TimeFormat), n.name)
		if err != nil {
			return err
		}
		if rows, _ := res.RowsAffected(); rows != 1 {
			// agentNode read the row a moment ago, so this is a node revoked
			// between that read and this write.
			return fmt.Errorf("node %q is no longer enrolled", n.name)
		}
		m.Detail("request_id", requestID(r))
		m.Detail("fingerprint", fp)
		m.Detail("cert_expires_at", expires.UTC().Format(audit.TimeFormat))
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, EnrollResponse{
		Node: n.name, State: n.state, Certificate: string(certPEM),
		ExpiresAt: expires.UTC().Format(audit.TimeFormat),
		Protocol:  Protocol, AuditSeq: rec.Seq,
	})
}
