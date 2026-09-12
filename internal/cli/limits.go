package cli

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
)

func cmdLimits(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary limits: expected a subcommand (show, set)\n")
		return ExitUsage
	}
	switch args[0] {
	case "show":
		return cmdLimitsShow(e, args[1:])
	case "set":
		return cmdLimitsSet(e, args[1:])
	}
	fmt.Fprintf(e.stderr, "nodary limits: unknown subcommand %q (want show or set)\n", args[0])
	return ExitUsage
}

func cmdLimitsShow(e env, args []string) int {
	fs := newFlagSet(e, "limits show")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	path, _ := resolveDB(*dbPath)
	db, ok := openForReading(e, "limits show", path)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	snap, err := config.Read(context.Background(), db.Read())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary limits show: %v\n", err)
		return ExitFailure
	}
	if *format == "json" {
		return writeJSON(e, "limits show", map[string]any{
			"limits": snap.Limits, "enforced": true})
	}
	if len(snap.Limits) == 0 {
		fmt.Fprintln(e.stdout, "no limits set")
	}
	for _, l := range snap.Limits {
		fmt.Fprintf(e.stdout, "%-8s %-24s rpm=%s tpm=%s daily=%s concurrent=%s\n",
			l.SubjectKind, l.SubjectID, dashIfUnset(l.RPM), dashIfUnset(l.TPM),
			dashIfUnset(l.DailyTokens), dashIfUnset(l.MaxConcurrent))
	}
	noteLimitsAreEnforced(e)
	return ExitOK
}

func cmdLimitsSet(e env, args []string) int {
	fs := newFlagSet(e, "limits set")
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	format := formatFlag(fs)
	kind := fs.String("kind", "user", "what the limit applies to: user, role or global")
	subject := fs.String("subject", "", "the user, role, or the word global")
	rpm := fs.Int("rpm", 0, "requests per minute")
	tpm := fs.Int("tpm", 0, "tokens per minute")
	daily := fs.Int("daily-tokens", 0, "tokens per day")
	concurrent := fs.Int("max-concurrent", 0, "in-flight requests")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if *kind == "global" && *subject == "" {
		*subject = "global"
	}
	if *subject == "" {
		fmt.Fprintf(e.stderr, "nodary limits set: --subject is required\n")
		return ExitUsage
	}

	s, ok := openSession(e, "limits set", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	want := config.Limit{SubjectKind: *kind, SubjectID: *subject,
		RPM: *rpm, TPM: *tpm, DailyTokens: *daily, MaxConcurrent: *concurrent}

	// Through the same config applier every other configuration change uses, so
	// a limit is a revision like anything else rather than a second writer.
	edit := func(snap *config.Snapshot) {
		for i := range snap.Limits {
			if snap.Limits[i].SubjectKind == want.SubjectKind &&
				snap.Limits[i].SubjectID == want.SubjectID {
				snap.Limits[i] = want
				return
			}
		}
		snap.Limits = append(snap.Limits, want)
	}

	_, applied, code := s.attested(e, "limits set", change{
		action: "config.apply",
		target: &audit.Target{Kind: "limits", ID: want.SubjectKind + ":" + want.SubjectID},
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			have, err := config.Read(ctx, tx)
			if err != nil {
				return nil, err
			}
			next, err := config.Read(ctx, tx)
			if err != nil {
				return nil, err
			}
			edit(next)
			return map[string]any{"changes": config.Changes(have, next),
				"enforced": true}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := s.touch(m); err != nil {
				return err
			}
			next, err := config.Read(context.Background(), m.Tx())
			if err != nil {
				return err
			}
			edit(next)
			if _, err := config.Apply(context.Background(), m, s.now, next, config.Options{}); err != nil {
				return err
			}
			_, err = config.Record(context.Background(), m, s.now, s.who.Actor.ID, *cer.justify)
			return err
		},
	}, cer, *format)
	if !applied {
		return code
	}
	noteLimitsAreEnforced(e)
	return ExitOK
}

// noteLimitsAreEnforced replaces the warning this verb carried while nothing
// read what it wrote (R3-08 – R3-10).
//
// It still says something, because what changed is not only that limits work:
// every applicable limit now binds and the most restrictive one wins, so
// setting a generous per-user limit under a tight global one does not raise
// anybody. An operator who writes 600 and observes 100 should be able to find
// out why without reading the gateway.
func noteLimitsAreEnforced(e env) {
	fmt.Fprintf(e.stderr,
		"\nLimits are enforced by the gateway. A user is subject to their own limit, their\n"+
			"role's and the global one at once, and the most restrictive of the three binds.\n")
}

// dashIfUnset renders an unset limit as a dash rather than 0, because 0 would
// read as "no requests allowed" instead of "no limit".
func dashIfUnset(n int) string {
	if n == 0 {
		return "—"
	}
	return strconv.Itoa(n)
}

// --- usage -------------------------------------------------------------------

func cmdUsage(e env, args []string) int {
	if len(args) > 0 && args[0] != "show" {
		fmt.Fprintf(e.stderr, "nodary usage: unknown subcommand %q (want show)\n", args[0])
		return ExitUsage
	}
	if len(args) > 0 {
		args = args[1:]
	}
	return cmdUsageShow(e, args)
}

// cmdUsageShow reports metered requests: docs/specs/10-cli.md §1.
//
// It reports counts and never content — there is no content to report, which is
// the whole of docs/adr/0006-cui-boundary-and-fips.md's guarantee and is
// visible here as the absence of a `--show-prompts` flag that could not be
// implemented.
func cmdUsageShow(e env, args []string) int {
	fs := newFlagSet(e, "usage show")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	user := fs.String("user", "", "only this user")
	model := fs.String("model", "", "only this model")
	node := fs.String("node", "", "only this node")
	groupBy := fs.String("group_by", "", "aggregate by: user, model, node or route")
	from := fs.String("from", "", "inclusive lower bound, RFC3339 or a date")
	to := fs.String("to", "", "inclusive upper bound")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if *groupBy != "" && !validGroup(*groupBy) {
		fmt.Fprintf(e.stderr, "nodary usage show: --group_by must be user, model, node or route\n")
		return ExitUsage
	}

	path, _ := resolveDB(*dbPath)
	db, ok := openForReading(e, "usage show", path)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	// The same bound parser `audit list` uses, so `--from 2026-09-01` means the
	// same thing on both surfaces. It returns the stored format directly, which
	// is what the comparison below wants.
	lower, err := audit.ParseBound(*from, false)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary usage show: %v\n", err)
		return ExitUsage
	}
	upper, err := audit.ParseBound(*to, true)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary usage show: %v\n", err)
		return ExitUsage
	}

	rows, err := queryUsage(db.Read(), usageFilter{
		user: *user, model: *model, node: *node, group: *groupBy,
		from: lower, to: upper,
	})
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary usage show: %v\n", err)
		return ExitFailure
	}

	if *format == "json" {
		return writeJSON(e, "usage show", map[string]any{"usage": rows})
	}
	if len(rows) == 0 {
		fmt.Fprintln(e.stdout, "no usage recorded")
		return ExitOK
	}
	label := orElse(*groupBy, "request")
	fmt.Fprintf(e.stdout, "%-28s %8s %12s %12s\n", label, "requests", "prompt", "completion")
	for _, r := range rows {
		fmt.Fprintf(e.stdout, "%-28s %8d %12d %12d\n", r.Subject, r.Requests, r.Prompt, r.Completion)
	}
	return ExitOK
}

func validGroup(s string) bool {
	switch s {
	case "user", "model", "node", "route":
		return true
	}
	return false
}

// UsageRow is one line of `usage show`, aggregated or not. Counts only.
type UsageRow struct {
	Subject    string `json:"subject"`
	Requests   int64  `json:"requests"`
	Prompt     int64  `json:"prompt_tokens"`
	Completion int64  `json:"completion_tokens"`
}

type usageFilter struct {
	user, model, node, group string
	from, to                 string
}

// queryUsage aggregates the closed record.
//
// The GROUP BY column is chosen from a fixed set rather than interpolated from
// the flag, because it is the one part of this query that comes from a caller.
func queryUsage(q *sql.DB, f usageFilter) ([]UsageRow, error) {
	group := map[string]string{
		"user": "coalesce(u.user_id, '')", "model": "coalesce(u.model_id, '')",
		"node": "coalesce(u.node_name, '')", "route": "coalesce(u.route, '')",
	}[f.group]
	subject := group
	if group == "" {
		subject, group = "coalesce(u.request_id, u.id)", "u.id"
	}

	where := []string{"1 = 1"}
	var args []any
	// --model matches either the route asked for or the model actually served:
	// the two differ once a route has several members, and an operator asking
	// about a model means both.
	if f.model != "" {
		where = append(where, "(u.model_id = ? OR u.route = ?)")
		args = append(args, f.model, f.model)
	}
	if f.node != "" {
		where = append(where, "u.node_name = ?")
		args = append(args, f.node)
	}
	if f.user != "" {
		// By name, because that is what an operator types.
		where = append(where, "u.user_id = (SELECT id FROM user WHERE name = ?)")
		args = append(args, f.user)
	}
	for _, b := range []struct{ op, val string }{{">=", f.from}, {"<=", f.to}} {
		if b.val != "" {
			where = append(where, "u.ts "+b.op+" ?")
			args = append(args, b.val)
		}
	}

	query := fmt.Sprintf(
		`SELECT %s, count(*), coalesce(sum(u.prompt_tokens), 0), coalesce(sum(u.completion_tokens), 0)
		 FROM usage u WHERE %s GROUP BY %s ORDER BY 2 DESC, 1`,
		subject, strings.Join(where, " AND "), group)

	rows, err := q.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("reading usage: %w", err)
	}
	defer rows.Close()
	var out []UsageRow
	for rows.Next() {
		var r UsageRow
		if err := rows.Scan(&r.Subject, &r.Requests, &r.Prompt, &r.Completion); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
