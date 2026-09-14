package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
)

// `nodary route list|show|set` — R4-36's last piece. list/show are thin reads
// over config.Read, the same shape `nodary limits show` already uses; the API
// equivalents (GET /routes, GET /routes/{name}, PUT /routes/{name}) are
// already built (R2-30) and read/write the same config.Route this does, so
// the CLI and the API stay two callers of one core rather than a second
// implementation (docs/tasks/README.md's cross-cutting constraint 1).
func cmdRoute(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary route: expected a subcommand (list, show, set)\n")
		return ExitUsage
	}
	switch args[0] {
	case "list":
		return cmdRouteList(e, args[1:])
	case "show":
		return cmdRouteShow(e, args[1:])
	case "set":
		return cmdRouteSet(e, args[1:])
	}
	fmt.Fprintf(e.stderr, "nodary route: unknown subcommand %q (want list, show or set)\n", args[0])
	return ExitUsage
}

func cmdRouteList(e env, args []string) int {
	fs := newFlagSet(e, "route list")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	server, credsPath := serverFlag(fs), credentialsFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	rem, code := remoteFor(e, "route list", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	var routes []config.Route
	var err error
	if rem != nil {
		routes, err = remoteList[config.Route](rem, "/routes", "routes", nil)
	} else {
		path, _ := resolveDB(*dbPath)
		db, ok := openForReading(e, "route list", path)
		if !ok {
			return ExitFailure
		}
		defer db.Close()
		var snap *config.Snapshot
		if snap, err = config.Read(context.Background(), db.Read()); err == nil {
			routes = snap.Routes
		}
	}
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary route list: %v\n", err)
		return exitFor(err)
	}
	if *format == "json" {
		return writeJSON(e, "route list", map[string]any{"routes": routes})
	}
	if len(routes) == 0 {
		fmt.Fprintln(e.stdout, "no routes")
		return ExitOK
	}
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTRATEGY\tMEMBERS")
	for _, r := range routes {
		fmt.Fprintf(tw, "%s\t%s\t%d\n", r.Name, r.Strategy, len(r.Members))
	}
	return flush(e, "route list", tw)
}

func cmdRouteShow(e env, args []string) int {
	fs := newFlagSet(e, "route show")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	server, credsPath := serverFlag(fs), credentialsFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary route show: expected one route name\n")
		return ExitUsage
	}
	name := fs.Arg(0)
	rem, code := remoteFor(e, "route show", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	var r config.Route
	if rem != nil {
		if err := rem.do("GET", "/routes/"+url.PathEscape(name), nil, &r); err != nil {
			fmt.Fprintf(e.stderr, "nodary route show: %v\n", err)
			return exitFor(err)
		}
	} else {
		path, _ := resolveDB(*dbPath)
		db, ok := openForReading(e, "route show", path)
		if !ok {
			return ExitFailure
		}
		defer db.Close()

		snap, err := config.Read(context.Background(), db.Read())
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary route show: %v\n", err)
			return ExitFailure
		}
		idx := slices.IndexFunc(snap.Routes, func(r config.Route) bool { return r.Name == name })
		if idx < 0 {
			fmt.Fprintf(e.stderr, "nodary route show: no route named %q; `nodary route list` names them\n", name)
			return ExitFailure
		}
		r = snap.Routes[idx]
	}
	if *format == "json" {
		return writeJSON(e, "route show", r)
	}
	fmt.Fprintf(e.stdout, "name      %s\n", r.Name)
	fmt.Fprintf(e.stdout, "strategy  %s\n", r.Strategy)
	if len(r.Members) == 0 {
		fmt.Fprintln(e.stdout, "no deployments")
		return ExitOK
	}
	fmt.Fprintln(e.stdout)
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DEPLOYMENT\tWEIGHT")
	for _, m := range r.Members {
		fmt.Fprintf(tw, "%s\t%d\n", m.DeploymentID, m.Weight)
	}
	return flush(e, "route show", tw)
}

// cmdRouteSet is the asymmetric case docs/specs/05-catalog.md §5 names —
// canarying a second backend, draining one replica without disabling it —
// not the common path, which is a route created alongside a deployment by
// `model register`. --add/--remove are comma-separated deployment ids,
// matching how --gpu already takes a list in this CLI, resolved against the
// route's *current* members and then replace-written whole, exactly what
// PUT /routes/{name} already does server-side.
func cmdRouteSet(e env, args []string) int {
	fs := newFlagSet(e, "route set")
	dbPath, keyPath, credsPath := stateFlags(fs)
	server := serverFlag(fs)
	cer := attestFlags(fs)
	format := formatFlag(fs)
	add := fs.String("add", "", "deployment ids to add, comma-separated")
	remove := fs.String("remove", "", "deployment ids to remove, comma-separated")
	strategy := fs.String("strategy", "", "routing strategy; left as-is when empty and the route already exists")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary route set: expected one route name\n")
		return ExitUsage
	}
	name := fs.Arg(0)
	toAdd := trimmedCSV(*add)
	toRemove := trimmedCSV(*remove)
	if len(toAdd) == 0 && len(toRemove) == 0 && *strategy == "" {
		fmt.Fprintf(e.stderr, "nodary route set: expected --add, --remove or --strategy\n")
		return ExitUsage
	}

	rem, code := remoteFor(e, "route set", *server, *credsPath, *dbPath, *keyPath)
	if code >= 0 {
		return code
	}
	if rem != nil {
		return remoteRouteSet(e, rem, name, *strategy, toAdd, toRemove, cer, *format)
	}

	s, ok := openSession(e, "route set", *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	edit := func(snap *config.Snapshot) {
		idx := slices.IndexFunc(snap.Routes, func(r config.Route) bool { return r.Name == name })
		if idx < 0 {
			snap.Routes = append(snap.Routes, newRoute(name))
			idx = len(snap.Routes) - 1
		}
		editRoute(&snap.Routes[idx], *strategy, toAdd, toRemove)
	}

	rec, applied, code := s.attested(e, "route set", change{
		action: "config.apply",
		target: &audit.Target{Kind: "route", ID: name},
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
			return map[string]any{"changes": config.Changes(have, next)}, nil
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

	reportRouteSet(e, name)
	reportRecord(e, rec)
	return ExitOK
}

// trimmedCSV is splitComma (session.go) with the same trim-and-drop-empty
// filtering cmdModelRegister's --grant already applies at its own call site —
// splitComma alone turns "" into one empty element, not none.
func trimmedCSV(s string) []string {
	var out []string
	for _, part := range splitComma(s) {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func newRoute(name string) config.Route {
	return config.Route{Name: name, Strategy: "round-robin"}
}

// editRoute applies --add, --remove and --strategy to one route.
//
// Both routes to this verb call it. The local one edits the route inside a
// whole snapshot it then applies; the remote one edits the single object it
// read and replaces it with PUT — and the two producing different membership
// for the same flags is the drift this exists to make impossible.
func editRoute(r *config.Route, strategy string, toAdd, toRemove []string) {
	if strategy != "" {
		r.Strategy = strategy
	}
	r.Members = slices.DeleteFunc(r.Members, func(m config.RouteMember) bool {
		return slices.Contains(toRemove, m.DeploymentID)
	})
	for _, id := range toAdd {
		if slices.ContainsFunc(r.Members, func(m config.RouteMember) bool { return m.DeploymentID == id }) {
			continue
		}
		r.Members = append(r.Members, config.RouteMember{DeploymentID: id, Weight: 1})
	}
}

// remoteRouteSet is read, edit, replace — three steps where the local route has
// one transaction.
//
// PUT /routes/{name} replaces the whole object (R2-30), so the membership this
// sends has to be built from the membership it read, and between those two
// requests somebody else can change the same route. That window does not exist
// locally. If-Match closes it: the revision the read saw travels with the
// write, and the control plane refuses it if the configuration has moved. It is
// conservative — the version is the whole configuration's, so an unrelated
// change also refuses — and being wrong that way is a 409 saying what to do,
// where being wrong the other way is a member silently disappearing.
func remoteRouteSet(e env, rem *remote, name, strategy string, toAdd, toRemove []string,
	cer ceremonyFlags, format string) int {
	path := "/routes/" + url.PathEscape(name)
	route := newRoute(name)
	etag, err := rem.get(path, &route)
	var refusal *remoteError
	switch {
	case errors.As(err, &refusal) && refusal.code == "not_found":
		// A route that does not exist yet is created, which is what the local
		// route does. Nothing was read, so there is nothing to have raced with.
		route, etag = newRoute(name), ""
	case err != nil:
		fmt.Fprintf(e.stderr, "nodary route set: %v\n", err)
		return exitFor(err)
	}
	route.Name = name
	editRoute(&route, strategy, toAdd, toRemove)

	out, applied, code := rem.attested(e, "route set",
		remoteAct{method: "PUT", path: path, body: route, ifMatch: etag}, cer, format)
	if !applied {
		return code
	}
	reportRouteSet(e, name)
	reportRecord(e, audit.Record{Seq: out.AuditSeq})
	return ExitOK
}

func reportRouteSet(e env, name string) {
	fmt.Fprintf(e.stderr, "route set: %s will be applied on the agent's next poll (up to 60s)\n", name)
}
