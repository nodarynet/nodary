// Package fleet reads what the control plane knows about its nodes and about
// what runs on them.
//
// It exists so both front ends answer "what is out there" the same way.
// dev/specs/10-cli.md §1 makes that a constraint rather than an aspiration —
// neither the CLI nor the HTTP API holds business logic — and this read had
// drifted furthest from it: the API carried its own SQL while `nodary node
// list` was a stub, so the only way to see a fleet *from the machine hosting
// it* was curl with an administrator's token.
//
// Reads, and the node lifecycle. transition.go moves a node between the
// administrative states an operator decides, inside a caller-supplied
// audit.Mutation — so the writes are still inside the seam, and the rules about
// which columns move with a state live in one place rather than once per front
// end.
//
// GPUs, the offer and the constraints stay json.RawMessage rather than becoming
// the structs in internal/agent. Decoding them here would make this package
// import the agent, the agent imports internal/api, and internal/api is the
// caller — a cycle. Passing them through also means the API's response is the
// stored document rather than a re-encoding of it, so a field added on the node
// side reaches a client without being taught to this package first.
package fleet

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/identity"
)

// StaleAfter is dev/specs/11-failure-modes.md §1's silence threshold.
//
// Derived at read time and never stored: a node is stale whether or not
// anything wrote it down, and the alternative needs a sweeper that can leave the
// database claiming `ready` about a node that has been gone for a minute
// (dev/plans/R4a-agent-protocol.md §5).
const StaleAfter = 60 * time.Second

// The agent protocol, dev/specs/03-agent.md §4.
//
// Protocol is what this build speaks; ProtocolMin and ProtocolMax are the range
// it accepts from an agent. Server and agent are the same binary and share a
// version, so skew happens only mid-upgrade and is bounded — but the range is
// what makes an upgrade possible at all: a control plane that accepted only its
// own number would refuse every node in the fleet for as long as the rollout
// took.
//
// Here rather than in internal/api for the reason StaleAfter is here: this is a
// rule about a fleet row, and `nodary node list` has to apply it without
// importing the HTTP surface. internal/api re-exports Protocol under its own
// name, which is where the wire is documented.
const (
	Protocol    = 1
	ProtocolMin = 1
	ProtocolMax = 1
)

// ProtocolSupported reports whether this control plane will act on a document
// from an agent speaking v.
//
// Zero is supported: it is what a report carrying no protocol field looks like,
// and refusing those would refuse an agent too old to have sent one — which is
// precisely the agent an operator needs to still see in the fleet in order to
// upgrade it.
func ProtocolSupported(v int) bool {
	return v == 0 || (v >= ProtocolMin && v <= ProtocolMax)
}

// Stale reports whether a last_seen timestamp is older than the threshold.
func Stale(lastSeen string, now time.Time) bool {
	if lastSeen == "" {
		return true
	}
	ts, err := time.Parse(audit.TimeFormat, lastSeen)
	if err != nil {
		return true
	}
	return now.Sub(ts) > StaleAfter
}

// Node is one row of a fleet listing: the administrative state plus what the
// node last reported about itself.
type Node struct {
	Name          string `json:"name"`
	State         string `json:"state"`
	Stale         bool   `json:"stale"`
	LastSeen      string `json:"last_seen"`
	AgentVersion  string `json:"agent_version"`
	Protocol      int    `json:"protocol"`
	Arch          string `json:"arch"`
	OS            string `json:"os"`
	DriverVersion string `json:"driver_version"`
	RebootPolicy  string `json:"reboot_policy"`
	// LogonTask is 03 §7's other half of reboot safety, and only a WSL2 host
	// answers it: `present`, `absent`, or `unknown` when Windows could not be
	// asked. Empty everywhere else, because the question does not arise.
	LogonTask     string `json:"logon_task"`
	CertExpiresAt string `json:"cert_expires_at"`
	// UpgradeTarget and UpgradeError are why this node is not running the
	// fleet's version (R5-15). Both empty when it is. A fleet that has stopped
	// converging is otherwise visible only as an agent_version that quietly
	// never moves, which reads as "nothing happened" rather than as a fault.
	UpgradeTarget string `json:"upgrade_target,omitempty"`
	UpgradeError  string `json:"upgrade_error,omitempty"`
	// Incompatible is dev/specs/03-agent.md §4's verdict about this node's
	// agent: it speaks a protocol outside what this control plane accepts, so
	// it has stopped reconciling and is running whatever was already up.
	//
	// Derived at read time from the protocol it last reported, the same as
	// Stale and for the same reason: it is true whether or not anything wrote
	// it down, and a stored flag needs clearing by whoever remembers to.
	Incompatible bool   `json:"incompatible"`
	ApprovedBy   string `json:"approved_by"`
	ApprovedAt   string `json:"approved_at"`

	// GPUs is what the driver reported; Offer is what the node's own
	// guardrails let the control plane place on. They are different documents
	// and the difference is diagnostic: a node whose GPUs are present and whose
	// offer is empty is one that refused them, not one that lacks them.
	GPUs        json.RawMessage `json:"gpus"`
	Offer       json.RawMessage `json:"offer"`
	Constraints json.RawMessage `json:"constraints"`
	// Topology is how this node's cards reach each other, from
	// `nvidia-smi topo -m` (R7-03). `{}` on a host with one card, none, or on
	// WSL2 — an index set is only sensible or not when there is more than one
	// card to choose between.
	Topology json.RawMessage `json:"topology"`

	DeploymentCount int `json:"deployment_count"`
	ReadyCount      int `json:"ready_count"`
}

// Deployment is one unit placed on a node, with the routes that name it.
type Deployment struct {
	ID        string   `json:"id"`
	ModelID   string   `json:"model_id"`
	Backend   string   `json:"backend"`
	State     string   `json:"state"`
	Health    string   `json:"health"`
	Port      int      `json:"port"`
	GPUs      []int    `json:"gpus"`
	Routes    []string `json:"routes"`
	LastError string   `json:"last_error"`
	UpdatedAt string   `json:"updated_at"`
	// Egress is the last verdict this node reached about the deployment's
	// isolation (dev/specs/03-agent.md §5, R4-29): `compliant`,
	// `non-compliant`, `inconclusive`, or empty for one that has never run and
	// so has never been probed. EgressReason is why, when it is not the first.
	Egress          string `json:"egress"`
	EgressReason    string `json:"egress_reason"`
	EgressCheckedAt string `json:"egress_checked_at"`
	// Disabled is `nodary model disable`: the configuration says this must not
	// run. Without it here, the verb that turns a deployment off had no verb
	// that showed it was off — the state settles on `stopped`, which is also
	// what an operator's own `systemctl stop` produces and what a node that has
	// not polled yet still reports as `ready`.
	Disabled bool `json:"disabled"`
}

// Staging is one model's progress onto one node.
type Staging struct {
	ModelID    string `json:"model_id"`
	State      string `json:"state"`
	BytesDone  int64  `json:"bytes_done"`
	BytesTotal int64  `json:"bytes_total"`
	Error      string `json:"error"`
}

// Detail is one node and everything placed on it.
//
// Node is embedded rather than nested so the encoding stays flat: the HTTP
// surface answered a node show with its fields at the top level before this
// package existed, and a client reading `.state` should not have to become one
// reading `.node.state` because the CLI wanted the same query.
type Detail struct {
	Node
	Deployments []Deployment `json:"deployments"`
	Staging     []Staging    `json:"staging"`
	// Refusals is what this node will not run and why (R4-15). Empty for a
	// healthy node, and the first thing to read when a deployment sits in
	// `defined` and never starts.
	Refusals []Refusal `json:"refusals"`
}

// Refusal is one deployment this node declined, against the revision it was
// computed from.
type Refusal struct {
	DeploymentID string `json:"deployment_id"`
	Rev          int64  `json:"rev"`
	Reason       string `json:"reason"`
	// Kind is `refused` or `out_of_policy` (internal/observed). They read
	// alike and mean opposite things about whether anything is serving, so a
	// reader that ignores this column gets the more alarming answer for the
	// less alarming case and vice versa.
	Kind      string `json:"kind"`
	UpdatedAt string `json:"updated_at"`
}

const nodeColumns = `name, state, coalesce(last_seen, ''), coalesce(agent_version, ''),
	coalesce(protocol, 0), coalesce(arch, ''), coalesce(os, ''),
	coalesce(driver_version, ''), reboot_policy, coalesce(cert_expires_at, ''),
	coalesce(approved_by, ''), coalesce(approved_at, ''),
	coalesce(upgrade_target, ''), coalesce(upgrade_error, ''),
	gpus_json, offer_json, constraints_json, topology_json, logon_task`

func scanNode(s interface{ Scan(...any) error }, n *Node, now time.Time) error {
	var gpus, offer, constraints, topology string
	if err := s.Scan(&n.Name, &n.State, &n.LastSeen, &n.AgentVersion, &n.Protocol,
		&n.Arch, &n.OS, &n.DriverVersion, &n.RebootPolicy, &n.CertExpiresAt,
		&n.ApprovedBy, &n.ApprovedAt, &n.UpgradeTarget, &n.UpgradeError,
		&gpus, &offer, &constraints, &topology, &n.LogonTask); err != nil {
		return err
	}
	n.Stale = Stale(n.LastSeen, now)
	n.Incompatible = !ProtocolSupported(n.Protocol)
	n.GPUs = json.RawMessage(gpus)
	n.Offer = json.RawMessage(offer)
	n.Constraints = json.RawMessage(constraints)
	n.Topology = json.RawMessage(topology)
	return nil
}

// Nodes lists the fleet, with a deployment tally per node.
//
// The tally is one extra query rather than a correlated subquery per row: a
// listing that costs one statement per node is the shape that stops being
// usable at the fleet size this product is sold into.
func Nodes(ctx context.Context, q config.Querier, now time.Time) ([]Node, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+nodeColumns+` FROM node ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Node{}
	for rows.Next() {
		var n Node
		if err := scanNode(rows, &n, now); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	counts, ready, err := tally(ctx, q)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].DeploymentCount = counts[out[i].Name]
		out[i].ReadyCount = ready[out[i].Name]
	}
	return out, nil
}

func tally(ctx context.Context, q config.Querier) (counts, ready map[string]int, err error) {
	rows, err := q.QueryContext(ctx,
		`SELECT node_name, count(*), sum(state = 'ready') FROM deployment GROUP BY node_name`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	counts, ready = map[string]int{}, map[string]int{}
	for rows.Next() {
		var name string
		var total, up int
		if err := rows.Scan(&name, &total, &up); err != nil {
			return nil, nil, err
		}
		counts[name], ready[name] = total, up
	}
	return counts, ready, rows.Err()
}

// Show reads one node and everything placed on it. sql.ErrNoRows when there is
// no such node, so each front end can say so in its own voice.
func Show(ctx context.Context, q config.Querier, name string, now time.Time) (Detail, error) {
	var d Detail
	row := q.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM node WHERE name = ?`, name)
	if err := scanNode(row, &d.Node, now); err != nil {
		return d, err
	}
	var err error
	if d.Deployments, err = deployments(ctx, q, name); err != nil {
		return d, err
	}
	d.DeploymentCount = len(d.Deployments)
	for _, dep := range d.Deployments {
		if dep.State == "ready" {
			d.ReadyCount++
		}
	}
	if d.Staging, err = staging(ctx, q, name); err != nil {
		return d, err
	}
	d.Refusals, err = refusals(ctx, q, name)
	return d, err
}

func refusals(ctx context.Context, q config.Querier, node string) ([]Refusal, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT deployment_id, rev, reason, kind, updated_at
		 FROM refusal WHERE node_name = ? ORDER BY kind, deployment_id`, node)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Refusal{}
	for rows.Next() {
		var r Refusal
		if err := rows.Scan(&r.DeploymentID, &r.Rev, &r.Reason, &r.Kind, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func deployments(ctx context.Context, q config.Querier, node string) ([]Deployment, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT id, model_id, backend, state, health, coalesce(port, 0),
		        coalesce(last_error, ''), updated_at, coalesce(egress_state, ''),
		        coalesce(egress_reason, ''), coalesce(egress_checked_at, ''), disabled
		 FROM deployment WHERE node_name = ? ORDER BY id`, node)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Deployment{}
	index := map[string]int{}
	for rows.Next() {
		var d Deployment
		if err := rows.Scan(&d.ID, &d.ModelID, &d.Backend, &d.State, &d.Health,
			&d.Port, &d.LastError, &d.UpdatedAt, &d.Egress, &d.EgressReason,
			&d.EgressCheckedAt, &d.Disabled); err != nil {
			return nil, err
		}
		d.GPUs, d.Routes = []int{}, []string{}
		index[d.ID] = len(out)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The GPUs are rows, not a column (0006_fleet.sql), and the route names are
	// what a client actually asks for — a deployment listed without them tells
	// an operator a model is ready while leaving them no way to call it.
	for _, join := range []struct {
		query string
		scan  func(*sql.Rows) error
	}{
		{`SELECT deployment_id, gpu_index FROM deployment_gpu WHERE node_name = ?
		  ORDER BY deployment_id, gpu_index`,
			func(r *sql.Rows) error {
				var id string
				var gpu int
				if err := r.Scan(&id, &gpu); err != nil {
					return err
				}
				if i, ok := index[id]; ok {
					out[i].GPUs = append(out[i].GPUs, gpu)
				}
				return nil
			}},
		{`SELECT m.deployment_id, m.route_name FROM route_member m
		  JOIN deployment d ON d.id = m.deployment_id
		  WHERE d.node_name = ? ORDER BY m.deployment_id, m.route_name`,
			func(r *sql.Rows) error {
				var id, route string
				if err := r.Scan(&id, &route); err != nil {
					return err
				}
				if i, ok := index[id]; ok {
					out[i].Routes = append(out[i].Routes, route)
				}
				return nil
			}},
	} {
		rows, err := q.QueryContext(ctx, join.query, node)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			if err := join.scan(rows); err != nil {
				rows.Close()
				return nil, err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func staging(ctx context.Context, q config.Querier, node string) ([]Staging, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT model_id, state, bytes_done, coalesce(bytes_total, 0), coalesce(error, '')
		 FROM staging WHERE node_name = ? ORDER BY model_id`, node)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Staging{}
	for rows.Next() {
		var s Staging
		if err := rows.Scan(&s.ModelID, &s.State, &s.BytesDone, &s.BytesTotal, &s.Error); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Egress verdicts, dev/specs/03-agent.md §5. The vocabulary is
// internal/agent's — it is what the probe produces — and is restated here
// because this package cannot import that one (internal/agent imports
// internal/api, which imports this). TestTheFleetEgressVocabularyIsTheAgents
// in egress_test.go fails if the two ever drift.
const (
	EgressCompliant    = "compliant"
	EgressNonCompliant = "non-compliant"
	EgressInconclusive = "inconclusive"
	// EgressUnasserted is the empty verdict: nothing has been probed, because
	// nothing has run. It is deliberately not a fourth stored value — the
	// column is simply null — and it exists here so the rule below can name
	// what it returns.
	EgressUnasserted = ""
)

// EgressState is one node's verdict across everything placed on it.
//
// The precedence is the conservative one, and it is here rather than in each
// client because getting it backwards is easy and quiet. One non-compliant
// deployment makes the node non-compliant however many compliant ones surround
// it; the node is compliant only when *every* deployment on it is; and
// anything short of that where something was nonetheless asserted is
// inconclusive, which is the honest word for a partial answer. A node with
// nothing asserted — nothing has run, so nothing has been probed — returns the
// empty verdict rather than being rounded either way.
func EgressState(deployments []Deployment) string {
	compliant, asserted := 0, 0
	for _, d := range deployments {
		switch d.Egress {
		case EgressNonCompliant:
			return EgressNonCompliant
		case EgressCompliant:
			compliant++
			asserted++
		case EgressInconclusive:
			asserted++
		}
	}
	switch {
	case asserted == 0:
		return EgressUnasserted
	case compliant == len(deployments):
		return EgressCompliant
	}
	return EgressInconclusive
}

// Log is what the fleet holds of one deployment's output.
//
// **Captured, not streamed.** dev/specs/00-overview.md §2 makes traffic to a
// node agent-initiated, so the control plane has no channel to ask one for a
// container's stdout on demand — the same wall `gateway sync` met for a route
// on another node. What it does hold is what
// dev/specs/11-failure-modes.md §2 already asks the agent to capture: the last
// hundred lines of the unit's journal, sent on the heartbeat that reported the
// failure. So this answers "why did it fail", which is the question an
// operator has, and not "what is it printing now", which needs a channel that
// does not exist.
type Log struct {
	Deployment string `json:"deployment"`
	Node       string `json:"node"`
	State      string `json:"state"`
	// CapturedAt is the deployment's last update, which for a failure is when
	// the lines below were taken. Named for what it is rather than reused as
	// `updated_at`: a timestamp that means two things is read as the wrong one.
	CapturedAt string `json:"captured_at"`
	// Lines is empty for a deployment that has not failed, and that is an
	// answer rather than a gap — nothing is captured while a deployment is
	// healthy, so an empty string here is "it has not failed", not "the log
	// was lost".
	Lines string `json:"lines"`
}

// DeploymentLog reads what was captured for one deployment.
func DeploymentLog(ctx context.Context, q config.Querier, id string) (Log, error) {
	out := Log{Deployment: id}
	err := q.QueryRowContext(ctx,
		`SELECT node_name, state, coalesce(last_error, ''), updated_at
		 FROM deployment WHERE id = ?`, id).
		Scan(&out.Node, &out.State, &out.Lines, &out.CapturedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Log{}, fmt.Errorf("%w: no deployment %q; `nodary node show` names them",
			identity.ErrNotFound, id)
	}
	return out, err
}
