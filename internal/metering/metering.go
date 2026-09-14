// Package metering reads the closed usage record.
//
// It exists so `nodary usage show` and GET /usage answer the same question the
// same way — docs/tasks/README.md's first cross-cutting constraint — and it is
// a package of its own rather than a function in internal/observed because that
// package's charter is writes: "holds the database writes that are observations
// rather than decisions". A read belongs beside it, not inside it.
//
// Counts only. docs/adr/0006-cui-boundary-and-fips.md makes "nodary records
// that a request happened, never what it said" structural, and there is no
// column here to report content from even if something asked.
package metering

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Querier is the read handle this needs.
type Querier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// ValidGroup reports whether a group_by names a column this will aggregate by.
//
// A fixed set rather than an interpolated flag value: the GROUP BY column is the
// one part of the query that comes from a caller.
func ValidGroup(s string) bool {
	switch s {
	case "user", "model", "node", "route":
		return true
	}
	return false
}

// Row is one line of a usage report, aggregated or not. Counts only.
type Row struct {
	Subject    string `json:"subject"`
	Requests   int64  `json:"requests"`
	Prompt     int64  `json:"prompt_tokens"`
	Completion int64  `json:"completion_tokens"`
}

// Filter narrows a report. Every field is optional.
type Filter struct {
	User, Model, Node, Group string
	// From and To are stored-format bounds, as audit.ParseBound returns them.
	From, To string
}

// queryUsage aggregates the closed record.
//
// The GROUP BY column is chosen from a fixed set rather than interpolated from
// the flag, because it is the one part of this query that comes from a caller.
func Query(ctx context.Context, q Querier, f Filter) ([]Row, error) {
	group := map[string]string{
		"user": "coalesce(u.user_id, '')", "model": "coalesce(u.model_id, '')",
		"node": "coalesce(u.node_name, '')", "route": "coalesce(u.route, '')",
	}[f.Group]
	subject := group
	if group == "" {
		subject, group = "coalesce(u.request_id, u.id)", "u.id"
	}

	where := []string{"1 = 1"}
	var args []any
	// --model matches either the route asked for or the model actually served:
	// the two differ once a route has several members, and an operator asking
	// about a model means both.
	if f.Model != "" {
		where = append(where, "(u.model_id = ? OR u.route = ?)")
		args = append(args, f.Model, f.Model)
	}
	if f.Node != "" {
		where = append(where, "u.node_name = ?")
		args = append(args, f.Node)
	}
	if f.User != "" {
		// By name, because that is what an operator types.
		where = append(where, "u.user_id = (SELECT id FROM user WHERE name = ?)")
		args = append(args, f.User)
	}
	for _, b := range []struct{ op, val string }{{">=", f.From}, {"<=", f.To}} {
		if b.val != "" {
			where = append(where, "u.ts "+b.op+" ?")
			args = append(args, b.val)
		}
	}

	// Busiest first, then by subject. Ungrouped, every count is one, so the
	// order collapses to the subject ascending — which is what lets the HTTP
	// listing page through the unbounded case with a keyed cursor while a
	// grouped report, bounded by how many distinct subjects exist, is returned
	// whole.
	query := fmt.Sprintf(
		`SELECT %s, count(*), coalesce(sum(u.prompt_tokens), 0), coalesce(sum(u.completion_tokens), 0)
		 FROM usage u WHERE %s GROUP BY %s ORDER BY 2 DESC, 1`,
		subject, strings.Join(where, " AND "), group)

	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("reading usage: %w", err)
	}
	defer rows.Close()
	// Empty rather than nil. Both front ends render this straight into
	// `--format json`, which docs/specs/10-cli.md §2 calls a stable schema, and
	// a nil slice marshals as `null` where a script reading "no usage yet"
	// expects `[]`.
	out := []Row{}
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.Subject, &r.Requests, &r.Prompt, &r.Completion); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
