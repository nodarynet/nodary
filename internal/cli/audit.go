package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/store"
)

func cmdAudit(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary audit: expected a subcommand (list, verify)\n")
		return ExitUsage
	}
	switch args[0] {
	case "list":
		return cmdAuditList(e, args[1:])
	case "verify":
		return cmdAuditVerify(e, args[1:])
	default:
		fmt.Fprintf(e.stderr, "nodary audit: unknown subcommand %q (want list or verify)\n", args[0])
		return ExitUsage
	}
}

// dbFlag registers --db and reports the resolved path along with whether the
// operator named it. The distinction matters: a database that is absent at the
// default location is an ordinary state for `verify --mirror` on a copy pulled
// off another machine, while one the operator named and that is not there is a
// mistake worth reporting.
func dbFlag(fs *flag.FlagSet) *string {
	return fs.String("db", "", "database path (default "+paths.Database()+")")
}

func resolveDB(flagValue string) (path string, explicit bool) {
	if flagValue != "" {
		return flagValue, true
	}
	return paths.Database(), false
}

// openForReading opens the database read-only. Inspecting a chain must not
// change the file being inspected, so this never migrates and never creates.
func openForReading(e env, verb, path string) (*store.DB, bool) {
	db, err := store.OpenReadOnly(context.Background(), path)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary audit %s: %v\n", verb, err)
		if errors.Is(err, store.ErrSchemaBehind) {
			fmt.Fprintf(e.stderr,
				"  a read-only command will not migrate a database underneath a reader.\n")
		}
		return nil, false
	}
	return db, true
}

func cmdAuditVerify(e env, args []string) int {
	fs := newFlagSet(e, "audit verify")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	mirror := fs.String("mirror", "", "also verify this JSONL file, with or without a database")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	path, explicit := resolveDB(*dbPath)
	report := verifyReport{}

	// With --mirror and no database at the default location, the file is
	// verified alone. That is the case an auditor is in when they check a copy
	// retrieved from a SIEM on a machine that never held the original.
	useDB := true
	if *mirror != "" && !explicit {
		if _, err := os.Stat(path); err != nil {
			useDB = false
		}
	}

	if useDB {
		db, ok := openForReading(e, "verify", path)
		if !ok {
			return ExitFailure
		}
		defer db.Close()

		res, err := audit.VerifyDB(context.Background(), db)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary audit verify: %v\n", err)
			return ExitFailure
		}
		report.Chain = newResultReport(res)

		if *mirror != "" {
			cmp, err := audit.Compare(context.Background(), db, *mirror)
			if err != nil {
				fmt.Fprintf(e.stderr, "nodary audit verify: %v\n", err)
				return ExitFailure
			}
			report.Comparison = &comparisonReport{
				Diverged: cmp.Diverged, Behind: cmp.Behind, Ahead: cmp.Ahead,
			}
		}
	}

	if *mirror != "" {
		res, err := audit.VerifyFile(*mirror)
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary audit verify: %v\n", err)
			return ExitFailure
		}
		r := newResultReport(res)
		r.Path = *mirror
		report.Mirror = r
	}

	report.OK = report.sound()
	if *format == "json" {
		enc := json.NewEncoder(e.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(e.stderr, "nodary audit verify: %v\n", err)
			return ExitFailure
		}
	} else {
		report.writeText(e.stdout)
	}

	if !report.OK {
		return ExitFailure
	}
	return ExitOK
}

// The report types are the --format json contract, so they are declared rather
// than assembled ad hoc. docs/specs/10-cli.md §4 makes that output a stable
// schema, not a rendering of whatever the internals happen to hold.
type verifyReport struct {
	OK         bool              `json:"ok"`
	Chain      *resultReport     `json:"chain,omitempty"`
	Mirror     *resultReport     `json:"mirror,omitempty"`
	Comparison *comparisonReport `json:"comparison,omitempty"`
}

type resultReport struct {
	Path     string          `json:"path,omitempty"`
	OK       bool            `json:"ok"`
	Records  int64           `json:"records"`
	FirstSeq int64           `json:"first_seq"`
	LastSeq  int64           `json:"last_seq"`
	Break    *problemReport  `json:"break"`
	Warnings []problemReport `json:"warnings"`
}

type problemReport struct {
	Seq    int64  `json:"seq"`
	Kind   string `json:"kind"`
	Detail string `json:"detail,omitempty"`
}

type comparisonReport struct {
	Diverged int64 `json:"diverged_at"`
	Behind   int64 `json:"behind"`
	Ahead    int64 `json:"ahead"`
}

func newResultReport(res audit.Result) *resultReport {
	r := &resultReport{
		OK: res.OK(), Records: res.Records,
		FirstSeq: res.FirstSeq, LastSeq: res.LastSeq,
		Warnings: []problemReport{},
	}
	if res.Break != nil {
		r.Break = &problemReport{Seq: res.Break.Seq, Kind: string(res.Break.Kind), Detail: res.Break.Detail}
	}
	for _, w := range res.Warnings {
		r.Warnings = append(r.Warnings, problemReport{Seq: w.Seq, Kind: string(w.Kind), Detail: w.Detail})
	}
	return r
}

// sound is false if anything verified failed, or if a mirror holds records the
// database does not — which means the two are not a pair.
func (v verifyReport) sound() bool {
	for _, r := range []*resultReport{v.Chain, v.Mirror} {
		if r != nil && !r.OK {
			return false
		}
	}
	if v.Comparison != nil && (v.Comparison.Diverged != 0 || v.Comparison.Ahead != 0) {
		return false
	}
	return true
}

func (v verifyReport) writeText(w interface{ Write([]byte) (int, error) }) {
	writeResult := func(label string, r *resultReport) {
		if r == nil {
			return
		}
		where := label
		if r.Path != "" {
			where = label + " " + r.Path
		}
		switch {
		case r.Break != nil:
			fmt.Fprintf(w, "%s: %s at seq %d\n", where, r.Break.Kind, r.Break.Seq)
			if r.Break.Detail != "" {
				fmt.Fprintf(w, "  %s\n", r.Break.Detail)
			}
			fmt.Fprintf(w, "  %d records verified before the break\n", r.Records)
		case r.Records == 0:
			fmt.Fprintf(w, "%s: empty\n", where)
		default:
			fmt.Fprintf(w, "%s: verified, %d records, seq %d–%d\n",
				where, r.Records, r.FirstSeq, r.LastSeq)
		}
		for _, warn := range r.Warnings {
			fmt.Fprintf(w, "  warning: seq %d: %s — %s\n", warn.Seq, warn.Kind, warn.Detail)
		}
	}

	writeResult("chain", v.Chain)
	writeResult("mirror", v.Mirror)

	if c := v.Comparison; c != nil {
		switch {
		case c.Diverged != 0:
			fmt.Fprintf(w, "comparison: the database and the mirror disagree from seq %d\n", c.Diverged)
		case c.Ahead != 0:
			fmt.Fprintf(w, "comparison: the mirror holds %d records the database does not\n", c.Ahead)
		case c.Behind != 0:
			fmt.Fprintf(w, "comparison: the mirror is %d records behind, which is ordinary — "+
				"delivery happens after the commit\n", c.Behind)
		default:
			fmt.Fprintf(w, "comparison: the mirror matches the database\n")
		}
	}
}

func cmdAuditList(e env, args []string) int {
	fs := newFlagSet(e, "audit list")
	format := formatFlag(fs)
	dbPath := dbFlag(fs)
	from := fs.String("from", "", "earliest record: a date (2006-01-02) or an RFC3339 instant")
	to := fs.String("to", "", "latest record; a bare date covers the whole day")
	actor := fs.String("actor", "", "match this actor id exactly")
	action := fs.String("action", "", "match this action, or the family when it ends in a dot")
	limit := fs.Int("limit", audit.DefaultLimit,
		fmt.Sprintf("records to return, at most %d", audit.MaxLimit))
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	filter, ok := buildFilter(e, "list", *from, *to, *actor, *action, *limit)
	if !ok {
		return ExitUsage
	}

	path, _ := resolveDB(*dbPath)
	db, ok := openForReading(e, "list", path)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	records, err := audit.List(context.Background(), db, filter)
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary audit list: %v\n", err)
		if errors.Is(err, audit.ErrBadFilter) {
			return ExitUsage
		}
		return ExitFailure
	}

	if *format == "json" {
		return writeRecordsJSON(e, "list", records)
	}
	writeRecordsText(e, records)
	return ExitOK
}

func buildFilter(e env, verb, from, to, actor, action string, limit int) (audit.Filter, bool) {
	f := audit.Filter{Actor: actor, Action: action, Limit: limit}
	var err error
	if f.From, err = audit.ParseBound(from, false); err != nil {
		fmt.Fprintf(e.stderr, "nodary audit %s: --from %v\n", verb, err)
		return f, false
	}
	if f.To, err = audit.ParseBound(to, true); err != nil {
		fmt.Fprintf(e.stderr, "nodary audit %s: --to %v\n", verb, err)
		return f, false
	}
	return f, true
}

// writeRecordsJSON emits each record as the object a sink delivers, inside a
// counted envelope. The envelope is indented for reading, so these are not the
// sink's exact bytes — `audit export --format jsonl` is what produces those,
// and is what an operator diffs against a shipped copy. What is guaranteed here
// is that the record objects are the same objects, built by the same code.
func writeRecordsJSON(e env, verb string, records []audit.Record) int {
	lines := make([]json.RawMessage, 0, len(records))
	for _, r := range records {
		line, err := r.Line()
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary audit %s: %v\n", verb, err)
			return ExitFailure
		}
		lines = append(lines, json.RawMessage(line))
	}
	enc := json.NewEncoder(e.stdout)
	enc.SetIndent("", "  ")
	out := struct {
		Count   int               `json:"count"`
		Records []json.RawMessage `json:"records"`
	}{len(lines), lines}
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(e.stderr, "nodary audit %s: %v\n", verb, err)
		return ExitFailure
	}
	return ExitOK
}

func writeRecordsText(e env, records []audit.Record) {
	if len(records) == 0 {
		fmt.Fprintln(e.stdout, "no audit records match")
		return
	}
	tw := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEQ\tTS\tACTOR\tACTION\tTARGET\tOUTCOME")
	for _, r := range records {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n",
			r.Seq, r.TS.Format(audit.TimeFormat), orDash(r.Actor.ID),
			r.Action, targetOf(r), r.Outcome)
	}
	tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func targetOf(r audit.Record) string {
	if r.Target == nil {
		return "-"
	}
	return r.Target.Kind + "/" + r.Target.ID
}
