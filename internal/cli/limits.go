package cli

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strconv"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/metering"
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
	server, credsPath := serverFlag(fs), credentialsFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	rem, code := remoteFor(e, "limits show", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	var limits []config.Limit
	var err error
	if rem != nil {
		limits, err = remoteList[config.Limit](rem, "/limits", "limits", nil)
	} else {
		path, _ := resolveDB(*dbPath)
		db, ok := openForReading(e, "limits show", path)
		if !ok {
			return ExitFailure
		}
		defer db.Close()
		var snap *config.Snapshot
		if snap, err = config.Read(context.Background(), db.Read()); err == nil {
			limits = snap.Limits
		}
	}
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary limits show: %v\n", err)
		return exitFor(err)
	}
	if *format == "json" {
		return writeJSON(e, "limits show", map[string]any{
			"limits": limits, "enforced": true})
	}
	if len(limits) == 0 {
		fmt.Fprintln(e.stdout, "no limits set")
	}
	for _, l := range limits {
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
	server := serverFlag(fs)
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

	want := config.Limit{SubjectKind: *kind, SubjectID: *subject,
		RPM: *rpm, TPM: *tpm, DailyTokens: *daily, MaxConcurrent: *concurrent}

	rem, code := remoteFor(e, "limits set", *server, *credsPath, *dbPath, *keyPath)
	if code >= 0 {
		return code
	}
	if rem != nil {
		// No If-Match, and not by oversight: this verb builds the whole limit
		// out of its flags and reads nothing first, so there is nothing for it
		// to have raced with. `route set` reads the object it edits and does
		// send one.
		_, applied, code := rem.attested(e, "limits set", remoteAct{method: "PUT",
			path: "/limits/" + url.PathEscape(want.SubjectKind) + "/" + url.PathEscape(want.SubjectID),
			body: want}, cer, *format)
		if !applied {
			return code
		}
		noteLimitsAreEnforced(e)
		return ExitOK
	}

	s, ok := openSession(e, "limits set", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

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
	server, credsPath := serverFlag(fs), credentialsFlag(fs)
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
	if *groupBy != "" && !metering.ValidGroup(*groupBy) {
		fmt.Fprintf(e.stderr, "nodary usage show: --group_by must be user, model, node or route\n")
		return ExitUsage
	}

	r, code := remoteFor(e, "usage show", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	// The same bound parser `audit list` uses, so `--from 2026-09-01` means the
	// same thing on both surfaces. Parsed here even for a --server invocation,
	// so a malformed date is a usage error on this machine rather than a round
	// trip that comes back as one.
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

	var rows []metering.Row
	if r != nil {
		q := url.Values{}
		for k, v := range map[string]string{"user": *user, "model": *model,
			"node": *node, "group_by": *groupBy, "from": *from, "to": *to} {
			if v != "" {
				q.Set(k, v)
			}
		}
		if rows, err = remoteList[metering.Row](r, "/usage", "usage", q); err != nil {
			fmt.Fprintf(e.stderr, "nodary usage show: %v\n", err)
			return exitFor(err)
		}
	} else {
		path, _ := resolveDB(*dbPath)
		db, ok := openForReading(e, "usage show", path)
		if !ok {
			return ExitFailure
		}
		defer db.Close()

		rows, err = metering.Query(context.Background(), db.Read(), metering.Filter{
			User: *user, Model: *model, Node: *node, Group: *groupBy,
			From: lower, To: upper,
		})
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary usage show: %v\n", err)
			return ExitFailure
		}
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
