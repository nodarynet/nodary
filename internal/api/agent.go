package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/identity"
)

// IsolatedNetwork is the CNI network every serving deployment attaches to.
// docs/specs/03-agent.md §5 — it is the egress control, and R4-26 builds it.
const IsolatedNetwork = "nodary-isolated"

// pollInterval and pollWindow implement docs/specs/03-agent.md §1's long-poll.
//
// The handler re-reads one indexed row once a second. For the fleet an SMB
// runs, that is unmeasurable next to a broadcast mechanism with a subscriber
// lifecycle — and a notifier would be wrong the moment a second process writes
// the database, which is not hypothetical because the CLI writes directly.
// It becomes worth replacing when node count makes the read hot, and not
// before (docs/plans/R4a-agent-protocol.md §7).
const (
	pollInterval = time.Second
	pollWindow   = 60 * time.Second
)

// Desired is docs/specs/03-agent.md §2's document: the complete intended state
// of one node, with no imperative commands anywhere in it.
type Desired struct {
	Rev         int64               `json:"rev"`
	Protocol    int                 `json:"protocol"`
	Node        string              `json:"node"`
	Deployments []DesiredDeployment `json:"deployments"`
	Staging     []DesiredStaging    `json:"staging"`
	// Reset names weights the agent should discard and, if still desired
	// elsewhere in this document, restage from nothing — `nodary model
	// restage`/`unstage` (docs/specs/05-catalog.md §3-4). A model here may or
	// may not also appear in Staging: `unstage` targets one with no
	// deployment on this node at all, so it can't be read off a Staging
	// entry the way Build ordinarily resolves a layout.
	Reset []DesiredReset `json:"reset,omitempty"`
	Agent DesiredAgent   `json:"agent"`
}

type DesiredReset struct {
	Model  string `json:"model"`
	Layout string `json:"layout"`
}

type DesiredDeployment struct {
	ID        string          `json:"id"`
	Model     string          `json:"model"`
	Backend   string          `json:"backend"`
	Image     string          `json:"image"`
	GPUs      []int           `json:"gpus"`
	Params    json.RawMessage `json:"params"`
	ExtraArgs json.RawMessage `json:"extra_args"`
	// Env is the container's environment, a JSON object of string to string.
	Env     json.RawMessage `json:"env"`
	Port    int             `json:"port"`
	Network string          `json:"network"`
	State   string          `json:"state"`
}

type DesiredStaging struct {
	Model          string `json:"model"`
	Source         string `json:"source"`
	Layout         string `json:"layout"`
	ManifestSHA256 string `json:"manifest_sha256"`
	ExpectBytes    int64  `json:"expect_bytes"`
	// ManifestBody is the manifest's content, for `source: remote` — the
	// agent has no other way to learn what files a remote model has and what
	// they should hash to. Empty for `source: local`, which finds its
	// manifest beside the weights an operator already placed.
	ManifestBody string `json:"manifest_body,omitempty"`
}

type DesiredAgent struct {
	TargetVersion string `json:"target_version"`
}

// node is the caller of an /agent/ endpoint.
type node struct {
	name  string
	state string
}

// agentNode identifies the calling node from its client certificate.
//
// Three things have to hold, and each closes a different door. The chain must
// be verified — the listener does that, and its absence here means no
// certificate was offered at all. The row must still exist and not have
// departed, because docs/specs/02-enrollment.md §3 says a revoked node's
// certificate is refused on next contact and the server is the side that
// enforces it. And the presented certificate must be the one currently on
// record: a re-enrollment supersedes the previous certificate immediately,
// without waiting for it to expire.
func (s *Server) agentNode(r *http.Request) (node, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return node{}, fmt.Errorf("%w: this endpoint requires a node client certificate", errNoCredential)
	}
	leaf := r.TLS.VerifiedChains[0][0]
	name := leaf.Subject.CommonName

	fp := fingerprintOfDER(leaf.Raw)

	var got node
	var onRecord sql.NullString
	err := s.db.Read().QueryRowContext(r.Context(),
		`SELECT state, fingerprint FROM node WHERE name = ?`, name).Scan(&got.state, &onRecord)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return node{}, fmt.Errorf("%w: node %q is not enrolled", errNoCredential, name)
	case err != nil:
		return node{}, err
	case got.state == "departed":
		return node{}, fmt.Errorf("%w: node %q has been revoked", identity.ErrDenied, name)
	case !onRecord.Valid || onRecord.String != fp:
		return node{}, fmt.Errorf("%w: node %q presented a superseded certificate", errNoCredential, name)
	}
	got.name = name
	return got, nil
}

// agentDesired is the long-poll of docs/specs/03-agent.md §1.
//
// Without `rev` it answers at once, which is a node's first contact. With
// `rev=N` it blocks until the configuration has moved past N or the window
// closes, and then answers with whatever is current — a poll that times out
// returns the same document rather than an error, because "nothing changed" is
// an answer and not a failure.
func (s *Server) agentDesired(w http.ResponseWriter, r *http.Request) {
	n, err := s.agentNode(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	since, wait := int64(-1), false
	if raw := r.URL.Query().Get("rev"); raw != "" {
		since, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || since < 0 {
			s.fail(w, r, badRequest("rev must be a non-negative revision number"))
			return
		}
		wait = true
	}

	seq, err := s.waitForRevision(r.Context(), since, wait)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	doc, err := s.desiredFor(r.Context(), n, seq)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (s *Server) waitForRevision(ctx context.Context, since int64, wait bool) (int64, error) {
	// Real elapsed time, not s.now(): this is how long a socket is held open,
	// and a test or a replay driving the server from a frozen clock must not
	// turn a 60-second window into an unbounded one.
	deadline := time.Now().Add(pollWindow)
	for {
		seq, err := config.LatestSeq(ctx, s.db.Read())
		if err != nil || !wait || seq > since || !time.Now().Before(deadline) {
			return seq, err
		}
		select {
		case <-ctx.Done():
			return seq, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// desiredFor renders one node's slice of the configuration.
//
// A node that is not `approved` or `ready` gets an empty document. That is
// docs/specs/02-enrollment.md §2 in code: possession of a join token gets a
// machine a certificate and a row, and an administrator's approval is what gets
// it a workload. The node can heartbeat throughout, which is what makes the
// waiting state visible rather than silent.
func (s *Server) desiredFor(ctx context.Context, n node, seq int64) (Desired, error) {
	doc := Desired{
		Rev: seq, Protocol: Protocol, Node: n.name,
		Deployments: []DesiredDeployment{}, Staging: []DesiredStaging{},
		Agent: DesiredAgent{TargetVersion: s.agentTargetVersion()},
	}
	if n.state != "approved" && n.state != "ready" {
		return doc, nil
	}

	snap, err := config.Read(ctx, s.db.Read())
	if err != nil {
		return Desired{}, err
	}
	models := map[string]config.Model{}
	for _, m := range snap.Models {
		models[m.ID] = m
	}

	staged := map[string]bool{}
	for _, d := range snap.Deployments {
		if d.NodeName != n.name {
			continue
		}
		doc.Deployments = append(doc.Deployments, DesiredDeployment{
			ID: d.ID, Model: d.ModelID, Backend: d.Backend, Image: d.Image,
			GPUs:      gpusOrEmpty(d.GPUs),
			Params:    rawOrLiteral(d.Params, "{}"),
			ExtraArgs: rawOrLiteral(d.ExtraArgs, "[]"),
			Env:       rawOrLiteral(d.Env, "{}"),
			Port:      d.Port, Network: IsolatedNetwork,
			// Every deployment in the configuration is wanted running. Stopping
			// one without removing it is `nodary model disable`, which is R4-36
			// and not in the MVP; until then this field has one value and says
			// so rather than pretending to be read from somewhere.
			State: "ready",
		})
		if m, ok := models[d.ModelID]; ok && !staged[m.ID] {
			staged[m.ID] = true
			doc.Staging = append(doc.Staging, DesiredStaging{
				Model: m.ID, Source: m.Source, Layout: m.Artifact,
				ManifestSHA256: m.ManifestSHA256, ExpectBytes: m.TotalBytes,
				ManifestBody: m.ManifestBody,
			})
		}
	}

	rows, err := s.db.Read().QueryContext(ctx,
		`SELECT stage_reset.model_id, model.artifact FROM stage_reset
		 JOIN model ON model.id = stage_reset.model_id
		 WHERE stage_reset.node_name = ?`, n.name)
	if err != nil {
		return Desired{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var r DesiredReset
		if err := rows.Scan(&r.Model, &r.Layout); err != nil {
			return Desired{}, err
		}
		doc.Reset = append(doc.Reset, r)
	}
	if err := rows.Err(); err != nil {
		return Desired{}, err
	}
	return doc, nil
}

// agentTargetVersion is what the fleet should be running. This build, until
// R4-13's agent.toml and the self-upgrade path (R5) give it somewhere else to
// come from.
func (s *Server) agentTargetVersion() string { return buildinfo.Version }

func gpusOrEmpty(in []int) []int {
	if in == nil {
		return []int{}
	}
	return in
}

func rawOrLiteral(s, empty string) json.RawMessage {
	if s == "" || !json.Valid([]byte(s)) {
		return json.RawMessage(empty)
	}
	return json.RawMessage(s)
}

// fingerprintOfDER is what the node row stores: the same SHA-256 over DER that
// fingerprintOfPEM computes, from a certificate already parsed off the wire.
func fingerprintOfDER(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}
