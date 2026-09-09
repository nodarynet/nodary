// Package fleet reads what the control plane knows about its nodes and about
// what runs on them.
//
// It exists so both front ends answer "what is out there" the same way.
// docs/specs/10-cli.md §1 makes that a constraint rather than an aspiration —
// neither the CLI nor the HTTP API holds business logic — and this read had
// drifted furthest from it: the API carried its own SQL while `nodary node
// list` was a stub, so the only way to see a fleet *from the machine hosting
// it* was curl with an administrator's token.
//
// Reads only. Nothing here writes, so nothing here needs the audit seam.
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
	"time"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
)

// StaleAfter is docs/specs/11-failure-modes.md §1's silence threshold.
//
// Derived at read time and never stored: a node is stale whether or not
// anything wrote it down, and the alternative needs a sweeper that can leave the
// database claiming `ready` about a node that has been gone for a minute
// (docs/plans/R4a-agent-protocol.md §5).
const StaleAfter = 60 * time.Second

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
	CertExpiresAt string `json:"cert_expires_at"`
	ApprovedBy    string `json:"approved_by"`
	ApprovedAt    string `json:"approved_at"`

	// GPUs is what the driver reported; Offer is what the node's own
	// guardrails let the control plane place on. They are different documents
	// and the difference is diagnostic: a node whose GPUs are present and whose
	// offer is empty is one that refused them, not one that lacks them.
	GPUs        json.RawMessage `json:"gpus"`
	Offer       json.RawMessage `json:"offer"`
	Constraints json.RawMessage `json:"constraints"`

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
}

const nodeColumns = `name, state, coalesce(last_seen, ''), coalesce(agent_version, ''),
	coalesce(protocol, 0), coalesce(arch, ''), coalesce(os, ''),
	coalesce(driver_version, ''), reboot_policy, coalesce(cert_expires_at, ''),
	coalesce(approved_by, ''), coalesce(approved_at, ''),
	gpus_json, offer_json, constraints_json`

func scanNode(s interface{ Scan(...any) error }, n *Node, now time.Time) error {
	var gpus, offer, constraints string
	if err := s.Scan(&n.Name, &n.State, &n.LastSeen, &n.AgentVersion, &n.Protocol,
		&n.Arch, &n.OS, &n.DriverVersion, &n.RebootPolicy, &n.CertExpiresAt,
		&n.ApprovedBy, &n.ApprovedAt, &gpus, &offer, &constraints); err != nil {
		return err
	}
	n.Stale = Stale(n.LastSeen, now)
	n.GPUs = json.RawMessage(gpus)
	n.Offer = json.RawMessage(offer)
	n.Constraints = json.RawMessage(constraints)
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
	d.Staging, err = staging(ctx, q, name)
	return d, err
}

func deployments(ctx context.Context, q config.Querier, node string) ([]Deployment, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT id, model_id, backend, state, health, coalesce(port, 0),
		        coalesce(last_error, ''), updated_at
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
			&d.Port, &d.LastError, &d.UpdatedAt); err != nil {
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
