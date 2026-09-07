// Package config holds the configuration snapshot that a revision records, and
// the applier that puts one back.
//
// A snapshot is *desired* state — what somebody decided — and never observed
// state. docs/plans/R2b-revisions.md gives the reasoning: an export is
// "canonical, for provisioning and DR" (docs/specs/08-data-model.md §2), and
// replaying a node's last heartbeat onto a rebuilt control plane asserts
// something false. It also decides what a diff means, since two revisions
// differing because a node checked in would make `config diff` unreadable.
package config

import (
	"context"
	"database/sql"
	"fmt"
)

// Snapshot is the whole of the configuration.
//
// Field order and the `toml`/`json` tags are the wire format twice over: JSON is
// what gets hashed into the revision chain, TOML is what `config export` writes
// and `config apply` reads. Both are rendered from this one type so they cannot
// describe different things.
//
// No `json` tag carries omitempty, and the canonical encoder refuses one: a
// field that disappears when it is empty makes the hash preimage depend on the
// value, so two snapshots that differ only in whether a field was written would
// hash differently while describing the same configuration. The `toml` tags do
// carry it, because that side is a rendering for a human and is never hashed.
type Snapshot struct {
	Nodes       []Node       `json:"nodes" toml:"node"`
	Models      []Model      `json:"models" toml:"model"`
	Deployments []Deployment `json:"deployments" toml:"deployment"`
	Routes      []Route      `json:"routes" toml:"route"`
	Limits      []Limit      `json:"limits" toml:"limits"`
	Policy      *Policy      `json:"policy" toml:"policy,omitempty"`
}

// Node carries only what an administrator decided. Reported inventory,
// `last_seen`, the agent version and the negotiated protocol are all observed
// and are deliberately absent.
type Node struct {
	Name         string `json:"name" toml:"name"`
	State        string `json:"state" toml:"state"`
	Constraints  string `json:"constraints" toml:"constraints,omitempty"`
	RebootPolicy string `json:"reboot_policy" toml:"reboot_policy"`
}

type Model struct {
	ID             string `json:"id" toml:"id"`
	Backend        string `json:"backend" toml:"backend"`
	Source         string `json:"source" toml:"source"`
	Artifact       string `json:"artifact" toml:"artifact"`
	OriginOrg      string `json:"origin_org" toml:"origin_org,omitempty"`
	OriginCountry  string `json:"origin_country" toml:"origin_country,omitempty"`
	License        string `json:"license" toml:"license,omitempty"`
	ManifestSHA256 string `json:"manifest_sha256" toml:"manifest_sha256,omitempty"`
	TotalBytes     int64  `json:"total_bytes" toml:"total_bytes,omitempty"`
	Hints          string `json:"hints" toml:"hints,omitempty"`
}

// Deployment is the placement decision. Its state, health and last error are
// observed: a rollback that restored a deployment to `ready` would be claiming a
// container is running that nobody started.
type Deployment struct {
	ID        string `json:"id" toml:"id"`
	ModelID   string `json:"model_id" toml:"model_id"`
	NodeName  string `json:"node_name" toml:"node_name"`
	Backend   string `json:"backend" toml:"backend"`
	GPUs      []int  `json:"gpus" toml:"gpus"`
	Params    string `json:"params" toml:"params,omitempty"`
	ExtraArgs string `json:"extra_args" toml:"extra_args,omitempty"`
	Port      int    `json:"port" toml:"port,omitempty"`
}

type Route struct {
	Name     string        `json:"name" toml:"name"`
	Strategy string        `json:"strategy" toml:"strategy"`
	Members  []RouteMember `json:"members" toml:"member"`
}

type RouteMember struct {
	DeploymentID string `json:"deployment_id" toml:"deployment_id"`
	Weight       int    `json:"weight" toml:"weight"`
}

type Limit struct {
	SubjectKind   string `json:"subject_kind" toml:"subject_kind"`
	SubjectID     string `json:"subject_id" toml:"subject_id"`
	RPM           int    `json:"rpm" toml:"rpm,omitempty"`
	TPM           int    `json:"tpm" toml:"tpm,omitempty"`
	DailyTokens   int    `json:"daily_tokens" toml:"daily_tokens,omitempty"`
	MaxConcurrent int    `json:"max_concurrent" toml:"max_concurrent,omitempty"`
}

// Policy is the active profile, by name and by source. The source travels
// because a profile named "default" that somebody edited is not the built-in
// one, and a snapshot that recorded only the name could not tell them apart.
type Policy struct {
	Name   string `json:"name" toml:"name"`
	Source string `json:"source" toml:"source"`
}

// Querier is the read surface a snapshot needs. It is satisfied by *sql.DB and
// by *sql.Tx, so a snapshot can be taken inside the transaction that produced
// the change it describes.
type Querier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Read takes a snapshot of the configuration as it stands.
//
// Everything is ordered, because the snapshot is hashed: SQLite's unordered
// result is free to change between runs, and a hash that depends on row order
// would report a configuration change nobody made.
func Read(ctx context.Context, q Querier) (*Snapshot, error) {
	s := &Snapshot{
		Nodes:       []Node{},
		Models:      []Model{},
		Deployments: []Deployment{},
		Routes:      []Route{},
		Limits:      []Limit{},
	}
	for _, step := range []struct {
		what string
		fn   func(context.Context, Querier, *Snapshot) error
	}{
		{"nodes", readNodes},
		{"models", readModels},
		{"deployments", readDeployments},
		{"routes", readRoutes},
		{"limits", readLimits},
		{"the policy profile", readPolicy},
	} {
		if err := step.fn(ctx, q, s); err != nil {
			return nil, fmt.Errorf("reading %s: %w", step.what, err)
		}
	}
	return s, nil
}

func readNodes(ctx context.Context, q Querier, s *Snapshot) error {
	rows, err := q.QueryContext(ctx,
		`SELECT name, state, constraints_json, reboot_policy FROM node ORDER BY name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.Name, &n.State, &n.Constraints, &n.RebootPolicy); err != nil {
			return err
		}
		s.Nodes = append(s.Nodes, n)
	}
	return rows.Err()
}

func readModels(ctx context.Context, q Querier, s *Snapshot) error {
	rows, err := q.QueryContext(ctx, `SELECT id, backend, source, artifact,
		coalesce(origin_org, ''), coalesce(origin_country, ''), coalesce(license, ''),
		coalesce(manifest_sha256, ''), coalesce(total_bytes, 0), hints_json
		FROM model ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var m Model
		if err := rows.Scan(&m.ID, &m.Backend, &m.Source, &m.Artifact, &m.OriginOrg,
			&m.OriginCountry, &m.License, &m.ManifestSHA256, &m.TotalBytes, &m.Hints); err != nil {
			return err
		}
		s.Models = append(s.Models, m)
	}
	return rows.Err()
}

func readDeployments(ctx context.Context, q Querier, s *Snapshot) error {
	rows, err := q.QueryContext(ctx, `SELECT id, model_id, node_name, backend,
		params_json, extra_args_json, coalesce(port, 0) FROM deployment ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var d Deployment
		if err := rows.Scan(&d.ID, &d.ModelID, &d.NodeName, &d.Backend,
			&d.Params, &d.ExtraArgs, &d.Port); err != nil {
			return err
		}
		d.GPUs = []int{}
		s.Deployments = append(s.Deployments, d)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// One query for every deployment's GPUs rather than one per deployment: the
	// snapshot is taken inside the transaction that is committing a change, and
	// holding a write lock open for N round trips is how a fleet-sized config
	// makes every other writer wait.
	gpus, err := q.QueryContext(ctx,
		`SELECT deployment_id, gpu_index FROM deployment_gpu ORDER BY deployment_id, gpu_index`)
	if err != nil {
		return err
	}
	defer gpus.Close()
	byID := map[string]int{}
	for i, d := range s.Deployments {
		byID[d.ID] = i
	}
	for gpus.Next() {
		var id string
		var idx int
		if err := gpus.Scan(&id, &idx); err != nil {
			return err
		}
		if i, ok := byID[id]; ok {
			s.Deployments[i].GPUs = append(s.Deployments[i].GPUs, idx)
		}
	}
	return gpus.Err()
}

func readRoutes(ctx context.Context, q Querier, s *Snapshot) error {
	rows, err := q.QueryContext(ctx, `SELECT name, strategy FROM route ORDER BY name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r Route
		if err := rows.Scan(&r.Name, &r.Strategy); err != nil {
			return err
		}
		r.Members = []RouteMember{}
		s.Routes = append(s.Routes, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	members, err := q.QueryContext(ctx,
		`SELECT route_name, deployment_id, weight FROM route_member ORDER BY route_name, deployment_id`)
	if err != nil {
		return err
	}
	defer members.Close()
	byName := map[string]int{}
	for i, r := range s.Routes {
		byName[r.Name] = i
	}
	for members.Next() {
		var name string
		var m RouteMember
		if err := members.Scan(&name, &m.DeploymentID, &m.Weight); err != nil {
			return err
		}
		if i, ok := byName[name]; ok {
			s.Routes[i].Members = append(s.Routes[i].Members, m)
		}
	}
	return members.Err()
}

func readLimits(ctx context.Context, q Querier, s *Snapshot) error {
	rows, err := q.QueryContext(ctx, `SELECT subject_kind, subject_id,
		coalesce(rpm, 0), coalesce(tpm, 0), coalesce(daily_tokens, 0), coalesce(max_concurrent, 0)
		FROM limits ORDER BY subject_kind, subject_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var l Limit
		if err := rows.Scan(&l.SubjectKind, &l.SubjectID, &l.RPM, &l.TPM,
			&l.DailyTokens, &l.MaxConcurrent); err != nil {
			return err
		}
		s.Limits = append(s.Limits, l)
	}
	return rows.Err()
}

func readPolicy(ctx context.Context, q Querier, s *Snapshot) error {
	var p Policy
	err := q.QueryRowContext(ctx, `SELECT name, source FROM policy WHERE singleton = 1`).
		Scan(&p.Name, &p.Source)
	switch {
	case err == sql.ErrNoRows:
		// No row means the built-in default, which is not a configuration
		// choice anybody made. Recording it would make a fresh install and one
		// that deliberately applied `default` indistinguishable.
		return nil
	case err != nil:
		return err
	}
	s.Policy = &p
	return nil
}
