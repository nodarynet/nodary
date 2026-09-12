package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/fleet"
	"github.com/nodarynet/nodary/internal/identity"
	"github.com/nodarynet/nodary/internal/observed"
)

// StaleAfter and Stale are internal/fleet's, re-exported because this package
// named them first and its handlers, its tests and the agent protocol document
// all refer to them here. The rule itself moved so that the CLI could apply it
// without importing the HTTP surface.
const StaleAfter = fleet.StaleAfter

// StatusReport is the heartbeat of docs/specs/03-agent.md §1.
type StatusReport struct {
	Protocol     int             `json:"protocol"`
	AgentVersion string          `json:"agent_version"`
	Rev          int64           `json:"rev"`
	Inventory    Inventory       `json:"inventory"`
	Deployments  []StatusUnit    `json:"deployments"`
	Staging      []StatusStaging `json:"staging"`
	// ResetDone names models this node just discarded and cleared in
	// response to Desired.Reset (`nodary model restage`/`unstage`) — the
	// agent reporting what it did, so the control plane can stop asking for
	// it. See internal/observed's package doc for why this belongs on the
	// heartbeat rather than anywhere audited.
	ResetDone []string `json:"reset_done,omitempty"`
	// RestartDone names deployments this node just cycled in response to
	// Desired.Restart (`nodary model restart`) — the same shape ResetDone
	// uses, for the same reason.
	RestartDone []string `json:"restart_done,omitempty"`
	// Refused is what this node will not run out of the document it was
	// given, and why (R4-15). It is the node's complete current set, not a
	// delta: a refusal that stops being reported has stopped applying.
	Refused []StatusRefusal `json:"refused,omitempty"`
}

type StatusRefusal struct {
	Deployment string `json:"deployment"`
	Reason     string `json:"reason"`
}

type StatusUnit struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Health string `json:"health"`
	Error  string `json:"error"`
}

type StatusStaging struct {
	Model      string `json:"model"`
	State      string `json:"state"`
	BytesDone  int64  `json:"bytes_done"`
	BytesTotal int64  `json:"bytes_total"`
	Error      string `json:"error"`
}

// agentStatus records what a node reports about itself.
//
// It writes through store.WriteTx and produces no audit record. The chain is
// what an assessor reads, and a heartbeat every fifteen seconds per node is
// telemetry — the same line 0006_fleet.sql already draws for `usage`. The
// column list below is exhaustive and fixed, so that "observed state only"
// is visible here rather than only in the plan
// (docs/plans/R4a-agent-protocol.md §4).
func (s *Server) agentStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.agentNode(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var body StatusReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		s.fail(w, r, badRequest("expected a status report"))
		return
	}
	if body.Protocol != 0 && body.Protocol != Protocol {
		s.fail(w, r, fmt.Errorf("%w: this control plane speaks protocol %d, the agent speaks %d",
			identity.ErrBadName, Protocol, body.Protocol))
		return
	}

	report := observed.NodeReport{
		AgentVersion: body.AgentVersion, Protocol: Protocol,
		Arch: body.Inventory.Arch, OS: body.Inventory.OS,
		DriverVersion: body.Inventory.DriverVersion,
		GPUsJSON:      rawOrDefault(body.Inventory.GPUs, "[]"),
		TopologyJSON:  rawOrDefault(body.Inventory.Topology, "{}"),
		ResetDone:     body.ResetDone,
		RestartDone:   body.RestartDone,
		Rev:           body.Rev,
	}
	for _, ref := range body.Refused {
		report.Refusals = append(report.Refusals, observed.RefusalReport{
			Deployment: ref.Deployment, Reason: ref.Reason})
	}
	for _, u := range body.Deployments {
		report.Deployments = append(report.Deployments, observed.DeploymentReport{
			ID: u.ID, State: u.State, Health: u.Health, Error: u.Error})
	}
	for _, st := range body.Staging {
		report.Staging = append(report.Staging, observed.StagingReport{
			Model: st.Model, State: st.State, BytesDone: st.BytesDone,
			BytesTotal: st.BytesTotal, Error: st.Error})
	}
	if err := observed.Heartbeat(r.Context(), s.db, n.name, report, s.now()); err != nil {
		s.fail(w, r, err)
		return
	}

	seq, err := config.LatestSeq(r.Context(), s.db.Read())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// The current revision comes back so an agent that missed a wake-up knows
	// it is behind without waiting for its next long-poll to expire.
	writeJSON(w, http.StatusOK, map[string]any{
		"node": n.name, "state": n.state, "rev": seq, "protocol": Protocol,
	})
}

// Stale reports whether a last_seen timestamp is older than the threshold.
func Stale(lastSeen string, now time.Time) bool { return fleet.Stale(lastSeen, now) }
