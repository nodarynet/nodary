package cli

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/config"
	"github.com/nodarynet/nodary/internal/store"
)

func cmdConfig(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary config: expected a subcommand (show, diff, export, apply, rollback, list, verify)\n")
		return ExitUsage
	}
	switch args[0] {
	case "show":
		return cmdConfigShow(e, args[1:])
	case "list":
		return cmdConfigList(e, args[1:])
	case "diff":
		return cmdConfigDiff(e, args[1:])
	case "export":
		return cmdConfigExport(e, args[1:])
	case "verify":
		return cmdConfigVerify(e, args[1:])
	case "apply":
		return cmdConfigApply(e, args[1:], "")
	case "rollback":
		return cmdConfigRollback(e, args[1:])
	}
	fmt.Fprintf(e.stderr, "nodary config: unknown subcommand %q\n", args[0])
	return ExitUsage
}

// openConfigRead opens the database for reading and resolves a revision.
func openConfigRead(e env, verb, dbPath string) (*store.DB, bool) {
	path, _ := resolveDB(dbPath)
	db, ok := openForReading(e, verb, path)
	return db, ok
}

func revisionAt(e env, verb string, db *store.DB, seq int64) (*config.Snapshot, bool) {
	ctx := context.Background()
	if seq == 0 {
		// The live configuration, not the last recorded one. `config show` with
		// no revision answers "what is true now", which is not the same
		// question as "what did the last change record" once anything has
		// written outside a revision.
		s, err := config.Read(ctx, db.Read())
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
			return nil, false
		}
		return s, true
	}
	r, err := config.Get(ctx, db.Read(), seq)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary %s: %v\n", verb, err)
		return nil, false
	}
	return r.Snapshot, true
}

func cmdConfigShow(e env, args []string) int {
	fs := newFlagSet(e, "config show")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	server, credsPath := serverFlag(fs), credentialsFlag(fs)
	rev := fs.Int64("rev", 0, "show this revision instead of the live configuration")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	r, code := remoteFor(e, "config show", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	var s *config.Snapshot
	if r != nil {
		var err error
		if s, err = remoteSnapshot(r, *rev); err != nil {
			fmt.Fprintf(e.stderr, "nodary config show: %v\n", err)
			return exitFor(err)
		}
	} else {
		db, ok := openConfigRead(e, "config show", *dbPath)
		if !ok {
			return ExitFailure
		}
		defer db.Close()
		if s, ok = revisionAt(e, "config show", db, *rev); !ok {
			return ExitFailure
		}
	}
	if *format == "json" {
		return writeJSON(e, "config show", s)
	}
	body, err := config.RenderTOML(s)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary config show: %v\n", err)
		return ExitFailure
	}
	e.stdout.Write(body)
	return ExitOK
}

func cmdConfigExport(e env, args []string) int {
	// Export is show without the revision flag and without a text/json choice:
	// docs/specs/08-data-model.md §2 says it emits the file `apply -f` reads.
	fs := newFlagSet(e, "config export")
	dbPath := dbFlag(fs)
	server, credsPath := serverFlag(fs), credentialsFlag(fs)
	out := fs.String("out", "", "write here instead of stdout")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	r, code := remoteFor(e, "config export", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	var s *config.Snapshot
	var err error
	if r != nil {
		s, err = remoteSnapshot(r, 0)
	} else {
		db, ok := openConfigRead(e, "config export", *dbPath)
		if !ok {
			return ExitFailure
		}
		defer db.Close()
		s, err = config.Read(context.Background(), db.Read())
	}
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary config export: %v\n", err)
		return exitFor(err)
	}
	body, err := config.RenderTOML(s)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary config export: %v\n", err)
		return ExitFailure
	}
	if *out == "" {
		e.stdout.Write(body)
		return ExitOK
	}
	if err := os.WriteFile(*out, body, 0o600); err != nil {
		fmt.Fprintf(e.stderr, "nodary config export: %v\n", err)
		return ExitFailure
	}
	fmt.Fprintln(e.stdout, *out)
	return ExitOK
}

func cmdConfigList(e env, args []string) int {
	fs := newFlagSet(e, "config list")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	server, credsPath := serverFlag(fs), credentialsFlag(fs)
	limit := fs.Int("limit", 50, "how many revisions to show")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	rem, code := remoteFor(e, "config list", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	var reports []config.RevisionReport
	if rem != nil {
		// One page of exactly --limit, not the cursor followed to the end: the
		// flag means "the newest N", as it does for `audit list`.
		var body struct {
			Revisions []config.RevisionReport `json:"revisions"`
		}
		if err := rem.do("GET", "/revisions?limit="+strconv.Itoa(*limit), nil, &body); err != nil {
			fmt.Fprintf(e.stderr, "nodary config list: %v\n", err)
			return exitFor(err)
		}
		reports = body.Revisions
	} else {
		db, ok := openConfigRead(e, "config list", *dbPath)
		if !ok {
			return ExitFailure
		}
		defer db.Close()
		revs, err := config.List(context.Background(), db.Read(), *limit, 0)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary config list: %v\n", err)
			return ExitFailure
		}
		reports = config.RevisionReports(revs)
	}

	if *format == "json" {
		return writeJSON(e, "config list", reports)
	}
	for _, r := range reports {
		fmt.Fprintf(e.stdout, "%d\t%s\t%s\t%s\n", r.Seq, r.TS, r.Actor, r.Justification)
	}
	return ExitOK
}

// remoteSnapshot fetches the live configuration, or one revision's.
//
// Two endpoints because they are two questions: the live configuration is not a
// revision — nothing has recorded it yet when it is read — and a revision
// carries a snapshot that was.
func remoteSnapshot(r *remote, rev int64) (*config.Snapshot, error) {
	if rev == 0 {
		var live config.Snapshot
		if err := r.do("GET", "/config/export", nil, &live); err != nil {
			return nil, err
		}
		return &live, nil
	}
	var body struct {
		Snapshot *config.Snapshot `json:"snapshot"`
	}
	if err := r.do("GET", "/revisions/"+strconv.FormatInt(rev, 10), nil, &body); err != nil {
		return nil, err
	}
	if body.Snapshot == nil {
		return nil, fmt.Errorf("revision %d carries no configuration", rev)
	}
	return body.Snapshot, nil
}

func cmdConfigVerify(e env, args []string) int {
	fs := newFlagSet(e, "config verify")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	server, credsPath := serverFlag(fs), credentialsFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	r, code := remoteFor(e, "config verify", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	var (
		n      int64
		broken string
		err    error
	)
	if r != nil {
		// The walk runs where the revisions are. Every one carries a whole
		// configuration snapshot, so verifying from here would mean shipping
		// the entire history across the network to do arithmetic the control
		// plane can do in place.
		var body struct {
			Revisions int64  `json:"revisions"`
			OK        bool   `json:"ok"`
			Break     string `json:"break"`
		}
		if callErr := r.do("GET", "/config/verify", nil, &body); callErr != nil {
			fmt.Fprintf(e.stderr, "nodary config verify: %v\n", callErr)
			return exitFor(callErr)
		}
		n, broken = body.Revisions, body.Break
		if !body.OK && broken == "" {
			broken = "the chain does not verify"
		}
	} else {
		db, ok := openConfigRead(e, "config verify", *dbPath)
		if !ok {
			return ExitFailure
		}
		defer db.Close()
		n, err = config.Verify(context.Background(), db.Read())
		if err != nil {
			broken = err.Error()
		}
	}

	if *format == "json" {
		doc := map[string]any{"revisions": n, "ok": broken == ""}
		if broken != "" {
			doc["break"] = broken
		}
		code := writeJSON(e, "config verify", doc)
		if broken != "" {
			return ExitFailure
		}
		return code
	}
	if broken != "" {
		fmt.Fprintf(e.stdout, "%d revisions verified, then: %s\n", n, broken)
		return ExitFailure
	}
	fmt.Fprintf(e.stdout, "%d revisions verified\n", n)
	return ExitOK
}

func cmdConfigDiff(e env, args []string) int {
	fs := newFlagSet(e, "config diff")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	server, credsPath := serverFlag(fs), credentialsFlag(fs)
	file := fs.String("f", "", "compare the live configuration against this file")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	r, code := remoteFor(e, "config diff", *server, *credsPath, *dbPath)
	if code >= 0 {
		return code
	}

	// **The comparison stays here even over --server.** config.Changes is a
	// pure function of two snapshots, so a diff endpoint would be a second
	// implementation of it reachable by one caller — and `-f FILE` compares
	// against a file on *this* machine, which the control plane cannot read.
	// What crosses the network is the snapshots.
	var db *store.DB
	if r == nil {
		var ok bool
		if db, ok = openConfigRead(e, "config diff", *dbPath); !ok {
			return ExitFailure
		}
		defer db.Close()
	}
	at := func(rev int64) (*config.Snapshot, bool) {
		if r != nil {
			s, err := remoteSnapshot(r, rev)
			if err != nil {
				fmt.Fprintf(e.stderr, "nodary config diff: %v\n", err)
				return nil, false
			}
			return s, true
		}
		return revisionAt(e, "config diff", db, rev)
	}

	var from, to *config.Snapshot
	var ok bool
	switch {
	case *file != "":
		if from, ok = at(0); !ok {
			return ExitFailure
		}
		body, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary config diff: %v\n", err)
			return ExitUsage
		}
		if to, err = config.DecodeTOML(body); err != nil {
			fmt.Fprintf(e.stderr, "nodary config diff: %v\n", err)
			return ExitUsage
		}
	case fs.NArg() == 2:
		a, err := strconv.ParseInt(fs.Arg(0), 10, 64)
		b, err2 := strconv.ParseInt(fs.Arg(1), 10, 64)
		if err != nil || err2 != nil {
			fmt.Fprintf(e.stderr, "nodary config diff: revisions are numbers\n")
			return ExitUsage
		}
		if from, ok = at(a); !ok {
			return ExitFailure
		}
		if to, ok = at(b); !ok {
			return ExitFailure
		}
	default:
		fmt.Fprintf(e.stderr, "nodary config diff: expected two revisions, or -f FILE\n")
		return ExitUsage
	}

	changes := config.Changes(from, to)
	if *format == "json" {
		return writeJSON(e, "config diff", map[string]any{"changes": changes})
	}
	if len(changes) == 0 {
		fmt.Fprintf(e.stdout, "no change\n")
		return ExitOK
	}
	for _, c := range changes {
		fmt.Fprintf(e.stdout, "%s\n", c)
	}
	return ExitOK
}

func cmdConfigApply(e env, args []string, forced string) int {
	fs := newFlagSet(e, "config apply")
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	file := fs.String("f", "", "the configuration to apply")
	prune := fs.Bool("prune", false, "delete objects the configuration does not mention")
	noSync := fs.Bool("no-sync", false, "do not re-render the data plane even if routes changed")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if *file == "" && forced == "" {
		fmt.Fprintf(e.stderr, "nodary config apply: -f FILE is required\n")
		return ExitUsage
	}

	source := forced
	if source == "" {
		body, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary config apply: %v\n", err)
			return ExitUsage
		}
		source = string(body)
	}
	want, err := config.DecodeTOML([]byte(source))
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary config apply: %v\n", err)
		return ExitUsage
	}
	return applySnapshot(e, "config apply", want, *prune, *noSync, cer, dbPath, keyPath, credsPath)
}

func cmdConfigRollback(e env, args []string) int {
	fs := newFlagSet(e, "config rollback")
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	prune := fs.Bool("prune", false, "delete objects the target revision does not mention")
	noSync := fs.Bool("no-sync", false, "do not re-render the data plane even if routes changed")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(e.stderr, "nodary config rollback: expected one revision number\n")
		return ExitUsage
	}
	seq, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil || seq < 1 {
		fmt.Fprintf(e.stderr, "nodary config rollback: %q is not a revision number\n", fs.Arg(0))
		return ExitUsage
	}

	path, _ := resolveDB(*dbPath)
	db, ok := openForReading(e, "config rollback", path)
	if !ok {
		return ExitFailure
	}
	target, err := config.Get(context.Background(), db.Read(), seq)
	db.Close()
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary config rollback: %v\n", err)
		return ExitFailure
	}
	return applySnapshot(e, "config rollback", target.Snapshot, *prune, *noSync, cer, dbPath, keyPath, credsPath)
}

// applySnapshot is the one path `apply` and `rollback` share, so a rollback
// cannot restore something different from what an export said was there.
func applySnapshot(e env, verb string, want *config.Snapshot, prune, noSync bool,
	cer ceremonyFlags, dbPath, keyPath, credsPath *string) int {

	s, ok := openSession(e, verb, *dbPath, *keyPath, *credsPath)
	if !ok {
		return ExitFailure
	}
	defer s.Close()

	var result config.Result
	rec, applied, code := s.attested(e, verb, change{
		action: "config.apply",
		render: func(ctx context.Context, tx *sql.Tx) (any, error) {
			// The change is rendered against live state, so an intent approved
			// against one configuration refuses to apply to another.
			have, err := config.Read(ctx, tx)
			if err != nil {
				return nil, err
			}
			return map[string]any{"changes": config.FilterChanges(config.Changes(have, want), prune), "prune": prune}, nil
		},
		apply: func(m audit.Mutation, _ any) error {
			if err := s.touch(m); err != nil {
				return err
			}
			var err error
			if result, err = config.Apply(context.Background(), m, s.now, want, config.Options{Prune: prune}); err != nil {
				return err
			}
			// R2-13: a rollback is itself a new revision. There is no branch
			// here for it — every apply records one, so history is append-only
			// by construction rather than by remembering.
			_, err = config.Record(context.Background(), m, s.now, s.who.Actor.ID, cerJustification(cer))
			return err
		},
	}, cer, "text")
	if !applied {
		return code
	}

	for _, c := range result.Changes {
		fmt.Fprintf(e.stdout, "%s\n", c)
	}
	if len(result.Changes) == 0 {
		fmt.Fprintf(e.stdout, "no change\n")
	}
	for _, o := range result.Orphans {
		fmt.Fprintf(e.stderr, "left in place, not in this configuration: %s\n", o)
	}
	if len(result.Orphans) > 0 {
		fmt.Fprintf(e.stderr, "pass --prune to delete them\n")
	}
	reportRecord(e, rec)
	autoSync(e, verb, result.Changes, noSync, dbPath)
	return ExitOK
}

// autoSync re-renders the data plane when the change moved what it serves.
//
// **Because the step that was separate was the step people forgot.** LiteLLM
// reads its routes from a file written by `gateway sync`, so applying a
// configuration and stopping there leaves a model that starts, becomes healthy,
// reports ready — and answers 404 to every client, because the data plane has
// never heard of it. That happened on the first end-to-end deployment here and
// the symptom named nothing: `/v1/models` was simply empty.
//
// It is what R3-14 will do properly, by making route membership live. Until
// then this is the cheap version, and it belongs on the verb that changes
// routes rather than in a sentence an operator has to remember.
//
// **Skipped when the database was named explicitly.** Then this is not the
// installed control plane — a copy, a test, a mirror pulled off another machine
// — and re-rendering /etc/nodary from it would point the running data plane at
// something else's routes. The command is printed instead.
func autoSync(e env, verb string, changes []string, noSync bool, dbPath *string) {
	if !movesTheDataPlane(changes) {
		return
	}
	_, explicit := resolveDB(*dbPath)
	if noSync || explicit {
		fmt.Fprintf(e.stderr,
			"\nRoutes moved. The data plane serves what `nodary gateway sync` last wrote:\n"+
				"  nodary gateway sync\n")
		return
	}
	fmt.Fprintf(e.stderr, "\nRoutes moved; re-rendering the data plane.\n")
	if code := syncGateway(e, *dbPath, "", "", false); code != ExitOK {
		// Not fatal: the configuration is applied and recorded either way, and
		// failing the verb here would say the apply did not happen.
		fmt.Fprintf(e.stderr,
			"nodary %s: the configuration is applied; the data plane is not updated.\n"+
				"  `nodary gateway sync` retries it.\n", verb)
	}
}

// movesTheDataPlane reports whether a change list touches what LiteLLM serves.
//
// Deployments count as well as routes: an api_base is a deployment's port, so
// moving a deployment to another node or port changes the rendering without
// any route line appearing at all.
func movesTheDataPlane(changes []string) bool {
	for _, c := range changes {
		if strings.Contains(c, " route ") || strings.Contains(c, " deployment ") {
			return true
		}
	}
	return false
}

func cerJustification(c ceremonyFlags) string {
	if c.justify == nil {
		return ""
	}
	return *c.justify
}
