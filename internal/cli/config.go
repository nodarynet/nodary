package cli

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"

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
	rev := fs.Int64("rev", 0, "show this revision instead of the live configuration")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	db, ok := openConfigRead(e, "config show", *dbPath)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	s, ok := revisionAt(e, "config show", db, *rev)
	if !ok {
		return ExitFailure
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
	out := fs.String("out", "", "write here instead of stdout")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	db, ok := openConfigRead(e, "config export", *dbPath)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	s, err := config.Read(context.Background(), db.Read())
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary config export: %v\n", err)
		return ExitFailure
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
	limit := fs.Int("limit", 50, "how many revisions to show")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	db, ok := openConfigRead(e, "config list", *dbPath)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	revs, err := config.List(context.Background(), db.Read(), *limit)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary config list: %v\n", err)
		return ExitFailure
	}
	if *format == "json" {
		out := make([]map[string]any, len(revs))
		for i, r := range revs {
			out[i] = map[string]any{"seq": r.Seq, "ts": r.TS.Format(audit.TimeFormat),
				"actor": r.Actor, "justification": r.Justification, "hash": r.Hash}
		}
		return writeJSON(e, "config list", out)
	}
	for _, r := range revs {
		fmt.Fprintf(e.stdout, "%d\t%s\t%s\t%s\n", r.Seq, r.TS.Format(audit.TimeFormat), r.Actor, r.Justification)
	}
	return ExitOK
}

func cmdConfigVerify(e env, args []string) int {
	fs := newFlagSet(e, "config verify")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	db, ok := openConfigRead(e, "config verify", *dbPath)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	n, err := config.Verify(context.Background(), db.Read())
	if *format == "json" {
		doc := map[string]any{"revisions": n, "ok": err == nil}
		if err != nil {
			doc["break"] = err.Error()
		}
		code := writeJSON(e, "config verify", doc)
		if err != nil {
			return ExitFailure
		}
		return code
	}
	if err != nil {
		fmt.Fprintf(e.stdout, "%d revisions verified, then: %v\n", n, err)
		return ExitFailure
	}
	fmt.Fprintf(e.stdout, "%d revisions verified\n", n)
	return ExitOK
}

func cmdConfigDiff(e env, args []string) int {
	fs := newFlagSet(e, "config diff")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	file := fs.String("f", "", "compare the live configuration against this file")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	db, ok := openConfigRead(e, "config diff", *dbPath)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	var from, to *config.Snapshot
	switch {
	case *file != "":
		if from, ok = revisionAt(e, "config diff", db, 0); !ok {
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
		if from, ok = revisionAt(e, "config diff", db, a); !ok {
			return ExitFailure
		}
		if to, ok = revisionAt(e, "config diff", db, b); !ok {
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
	return applySnapshot(e, "config apply", want, *prune, cer, dbPath, keyPath, credsPath)
}

func cmdConfigRollback(e env, args []string) int {
	fs := newFlagSet(e, "config rollback")
	dbPath, keyPath, credsPath := stateFlags(fs)
	cer := attestFlags(fs)
	prune := fs.Bool("prune", false, "delete objects the target revision does not mention")
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
	return applySnapshot(e, "config rollback", target.Snapshot, *prune, cer, dbPath, keyPath, credsPath)
}

// applySnapshot is the one path `apply` and `rollback` share, so a rollback
// cannot restore something different from what an export said was there.
func applySnapshot(e env, verb string, want *config.Snapshot, prune bool,
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
			return map[string]any{"changes": config.Changes(have, want), "prune": prune}, nil
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
	return ExitOK
}

func cerJustification(c ceremonyFlags) string {
	if c.justify == nil {
		return ""
	}
	return *c.justify
}
