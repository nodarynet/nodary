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
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/buildinfo"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/fleet"
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
	Rev      int64 `json:"rev"`
	Protocol int   `json:"protocol"`
	// ProtocolMin and ProtocolMax are the range this control plane accepts,
	// which docs/specs/03-agent.md §4 requires it to advertise. An agent
	// outside the range stops reconciling and keeps running what is up; one
	// that compared only against Protocol would stop for a server that speaks
	// 2 and still accepts 1, which is every server mid-upgrade.
	ProtocolMin int                 `json:"protocol_min"`
	ProtocolMax int                 `json:"protocol_max"`
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
	// Restart names deployments `nodary model restart` (R4-36) asked to be
	// cycled now, on this node — a one-shot request the agent consumes and
	// acknowledges over the heartbeat, the same edge-triggered shape Reset
	// already uses, since docs/specs/03-agent.md §2's protocol has no other
	// way to express "do this now".
	Restart []string `json:"restart,omitempty"`
	// Backends are the operator-registered descriptors this node's deployments
	// need — 04 §9, R6-07. Built-ins are absent: they are compiled into the
	// agent's own binary and are the same on every host.
	//
	// **It travels here because there is nowhere else.** 03 §1 gives the
	// control plane no way to push, so a node's only channel is this document
	// — the same reason a model's manifest_body rides along rather than being
	// found beside weights that have not been downloaded yet (R4-33). The
	// alternative, a descriptor file placed on each node, is two copies of one
	// fact: they drift, the drift is silent, and the chain would record a
	// digest for a descriptor that is not the one the node ran.
	//
	// Only what this node uses, so the document stays the size of the node's
	// own work rather than of the fleet's catalog.
	Backends []DesiredBackend `json:"backends,omitempty"`
	Agent    DesiredAgent     `json:"agent"`
}

// DesiredBackend is one registered descriptor, as its bytes.
//
// The TOML rather than a decoded struct, for the reason POST /config/apply
// takes TOML: the agent parses what the operator wrote, on the version of the
// code that is about to act on it, rather than inheriting the control plane's
// reading of it across a version boundary.
type DesiredBackend struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
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
		Rev: seq, Protocol: Protocol, ProtocolMin: ProtocolMin, ProtocolMax: ProtocolMax,
		Node:        n.name,
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
			State: stateFor(d),
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

	// Only the registered descriptors this node's deployments actually name.
	// A fleet with twenty custom backends and a node running one sends one.
	if len(snap.Backends) > 0 {
		used := map[string]bool{}
		for _, d := range doc.Deployments {
			used[d.Backend] = true
		}
		for _, b := range snap.Backends {
			if !used[b.Name] {
				continue
			}
			sum := sha256.Sum256([]byte(b.Source))
			doc.Backends = append(doc.Backends, DesiredBackend{
				Name: b.Name, Source: b.Source, SHA256: hex.EncodeToString(sum[:])})
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

	// One replica of a roll at a time (R4-22). The rule is fleet.OfferedRestarts
	// because it is a rule about the fleet rather than about this endpoint.
	doc.Restart, err = fleet.OfferedRestarts(ctx, s.db.Read(), n.name)
	if err != nil {
		return Desired{}, err
	}
	return doc, nil
}

// agentTargetVersion is what the fleet should be running. This build, until
// R4-13's agent.toml and the self-upgrade path (R5) give it somewhere else to
// come from.
func (s *Server) agentTargetVersion() string { return buildinfo.Version }

// stateFor is `nodary model disable`'s R4-36 seam: a deployment nothing has
// disabled is wanted running; one it has is a standing decision, not
// something to keep guessing at every heartbeat.
func stateFor(d config.Deployment) string {
	if d.Disabled {
		return "disabled"
	}
	return "ready"
}

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

// EventTimeFormat is the instant an event carries: the node's clock, at the
// moment the thing happened.
//
// It is kept separate from the record's own timestamp, which is the control
// plane's clock at the moment the event arrived. A node that was unreachable
// for an hour delivers an hour-old event, and collapsing the two would put the
// wrong time on it — while trusting the node's clock for the chain's ordering
// would let a node with a wrong clock write records out of sequence.
const EventTimeFormat = audit.TimeFormat

// NodeEvent is something that happened on a node, on its way into the chain.
//
// docs/specs/03-agent.md §1 describes /agent/events as "audit records and
// lifecycle events generated on the node", and that is what this is: the
// control plane writes one record per event, attributed to the node.
type NodeEvent struct {
	// ID is minted on the node so a duplicate is identifiable. Delivery is
	// at-least-once — a batch whose response was lost is sent again — and an
	// append-only chain cannot retract the first copy, so what it can do
	// instead is make the two recognisable as one event.
	ID string `json:"id"`
	// At is the node's clock when this happened.
	At string `json:"at"`
	// Action is the vocabulary of docs/specs/07-identity-audit.md §3, prefixed
	// `node.` so an event is never mistaken for an administrative act.
	Action string         `json:"action"`
	Target string         `json:"target,omitempty"`
	Detail map[string]any `json:"detail,omitempty"`
}

// EventBatch is one delivery.
type EventBatch struct {
	Events []NodeEvent `json:"events"`
}

// maxEventBatch bounds one delivery. The agent sends at most 64; anything
// larger is not this agent.
const maxEventBatch = 1 << 20

// agentEvents writes a node's events into the audit chain (R4-10).
//
// **One record per event, attributed to the node.** The node is the actor
// because it is: nobody asked for a deployment to fail, and recording it
// against the administrator who last touched the model would put somebody's
// name on a thing they did not do.
//
// The outcome is `success` for every one of them, and that reads oddly for an
// event reporting a failure — but the field says whether the *recording*
// happened, not whether the thing reported was good news. A `node.deployment_failed`
// record with outcome `failure` would mean the chain failed to record it.
func (s *Server) agentEvents(w http.ResponseWriter, r *http.Request) {
	n, err := s.agentNode(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var body EventBatch
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEventBatch)).Decode(&body); err != nil {
		s.fail(w, r, badRequest("expected {\"events\":[…]}"))
		return
	}

	accepted := 0
	for _, ev := range body.Events {
		action := strings.TrimSpace(ev.Action)
		if action == "" || !strings.HasPrefix(action, "node.") {
			// Refused rather than recorded under a name it chose: the action
			// vocabulary is what an operator filters the chain by, and a node
			// that could write any action into it could write `user.delete`.
			s.fail(w, r, badRequest("event action %q must begin with \"node.\"", ev.Action))
			return
		}
		req := audit.Request{
			Actor:  audit.Actor{ID: n.name, Method: "node"},
			Action: action,
		}
		if ev.Target != "" {
			req.Target = &audit.Target{Kind: "deployment", ID: ev.Target}
		}
		if _, err := s.log.Act(r.Context(), req, func(m audit.Mutation) error {
			for k, v := range ev.Detail {
				m.Detail(k, v)
			}
			// The node's clock, beside the chain's own. They are different
			// questions — when it happened, and when it was recorded — and a
			// node delivering an hour-old event after an outage answers them
			// differently.
			m.Detail("node_time", ev.At)
			m.Detail("event_id", ev.ID)
			m.Detail("request_id", requestID(r))
			return nil
		}); err != nil {
			// Partial acceptance, reported as such. The agent removes what was
			// accepted and sends the rest again, so a chain that stopped
			// accepting halfway through a batch does not cost the remainder.
			writeJSON(w, http.StatusOK, map[string]any{"accepted": accepted})
			return
		}
		accepted++
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": accepted})
}
