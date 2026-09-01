package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/nodarynet/nodary/internal/audit"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/store"
)

func cmdAudit(e env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(e.stderr, "nodary audit: expected a subcommand (list, verify, export)\n")
		return ExitUsage
	}
	switch args[0] {
	case "list":
		return cmdAuditList(e, args[1:])
	case "verify":
		return cmdAuditVerify(e, args[1:])
	case "export":
		return cmdAuditExport(e, args[1:])
	default:
		fmt.Fprintf(e.stderr,
			"nodary audit: unknown subcommand %q (want list, verify or export)\n", args[0])
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
	anchorSpec := fs.String("anchor", "",
		"SEQ:HASH the mirror's first record must follow, for checking a fragment "+
			"against a chain this machine does not hold")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}
	anchor, ok := parseAnchor(e, *anchorSpec)
	if !ok {
		return ExitUsage
	}
	if anchor != nil && *mirror == "" {
		fmt.Fprintf(e.stderr, "nodary audit verify: --anchor applies to --mirror, which was not given\n")
		return ExitUsage
	}

	path, explicit := resolveDB(*dbPath)
	report := verifyReport{}
	// The judgement is audit's; this function only renders it. The CLI and the
	// HTTP API have to reach the same answer by the same route.
	var assessment audit.Assessment
	var chain *store.DB

	// With --mirror and no database at the default location, the file is
	// verified alone. That is the case an auditor is in when they check a copy
	// retrieved from a SIEM on a machine that never held the original.
	useDB := true
	if *mirror != "" && !explicit {
		switch _, err := os.Stat(path); {
		case errors.Is(err, os.ErrNotExist):
			useDB = false
		case err != nil:
			// Anything else — a permission error on a 0700 data directory, an
			// I/O error, a dangling symlink — is not "there is no database
			// here". Swallowing it skipped the authoritative chain and still
			// printed ok:true and exit 0, and because chain is omitempty the
			// output did not even show that it had been skipped: a false
			// all-clear, from the one command whose job is not to give one.
			fmt.Fprintf(e.stderr, "nodary audit verify: reading %s: %v\n", path, err)
			return ExitFailure
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
		assessment.Chain = &res

		chain = db
	}

	if *mirror != "" {
		// An anchor the operator supplied wins over the database: they are
		// asserting what this fragment should follow, and checking it against
		// the same machine's own chain would answer a different question.
		var res audit.Result
		var err error
		if anchor != nil {
			res, err = audit.VerifyFile(*mirror, anchor)
		} else {
			res, err = audit.VerifyMirror(context.Background(), chain, *mirror)
		}
		if err != nil {
			fmt.Fprintf(e.stderr, "nodary audit verify: %v\n", err)
			return ExitFailure
		}
		r := newResultReport(res)
		r.Path = *mirror
		report.Mirror = r
		assessment.Mirror = &res

		// Compared only once the mirror has been read as a chain. Comparing
		// first meant one unreadable line — a truncated final append is the
		// ordinary way a copy pulled from a SIEM is damaged — aborted the whole
		// command with a bare error, threw away the database report that had
		// already been computed, and under --format json wrote nothing at all
		// to stdout. VerifyFile reports the same input as a break at a named
		// path and line, which is the answer the operator asked for.
		if chain != nil && res.OK() {
			cmp, err := audit.Compare(context.Background(), chain, *mirror)
			if err != nil {
				fmt.Fprintf(e.stderr, "nodary audit verify: %v\n", err)
				return ExitFailure
			}
			assessment.Comparison = &cmp
			report.Comparison = &comparisonReport{
				Diverged: cmp.Diverged, Behind: cmp.Behind, Ahead: cmp.Ahead,
			}
			if cmp.Installs != nil {
				report.Comparison.Installs = cmp.Installs.String()
			}
		}
	}

	report.OK = assessment.OK()
	report.comparable = assessment.Comparable()
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
	// comparable is audit's judgement, carried through for rendering only. It
	// is not part of the --format json schema.
	comparable bool `json:"-"`

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
	// Fragment and Anchored are what stop "verified" meaning two things. A
	// fragment proves its own records consistent; anchored means it also joins
	// a chain that was known independently.
	Fragment bool `json:"fragment"`
	Anchored bool `json:"anchored"`
}

type problemReport struct {
	Seq    int64  `json:"seq"`
	Kind   string `json:"kind"`
	Detail string `json:"detail,omitempty"`
}

type comparisonReport struct {
	// Installs is set when the two are not one chain at all, and it makes every
	// other field here meaningless.
	Installs string `json:"installs,omitempty"`
	Diverged int64  `json:"diverged_at"`
	Behind   int64  `json:"behind"`
	Ahead    int64  `json:"ahead"`
}

func newResultReport(res audit.Result) *resultReport {
	r := &resultReport{
		OK: res.OK(), Records: res.Records,
		FirstSeq: res.FirstSeq, LastSeq: res.LastSeq,
		Warnings: []problemReport{},
		Fragment: res.Fragment, Anchored: res.Anchored,
	}
	if res.Break != nil {
		r.Break = &problemReport{Seq: res.Break.Seq, Kind: string(res.Break.Kind), Detail: res.Break.Detail}
	}
	for _, w := range res.Warnings {
		r.Warnings = append(r.Warnings, problemReport{Seq: w.Seq, Kind: string(w.Kind), Detail: w.Detail})
	}
	return r
}

// verified and failed are nil-safe, and say which of the two questions is being
// asked: "did this verify" is not the negation of "did this fail" when the
// result is absent because that half was not checked at all.

func (v verifyReport) writeText(w io.Writer) {
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
		case r.Fragment && r.Anchored:
			fmt.Fprintf(w, "%s: verified as a fragment, %d records, seq %d–%d, joined to seq %d\n",
				where, r.Records, r.FirstSeq, r.LastSeq, r.FirstSeq-1)
		case r.Fragment:
			// Said differently from a whole chain on purpose. A fragment is an
			// ordinary artefact — `export --from-seq` and a rotated sink file
			// are both fragments — but it proves strictly less, and reporting
			// the two in the same words would be the useful half of a lie.
			fmt.Fprintf(w, "%s: verified as a fragment, %d records, seq %d–%d\n",
				where, r.Records, r.FirstSeq, r.LastSeq)
			fmt.Fprintf(w, "  it starts at seq %d, so nothing in it shows what came before;\n"+
				"  pass --anchor %d:HASH to check that it joins a chain you know\n",
				r.FirstSeq, r.FirstSeq-1)
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

	// A comparison is only meaningful between two chains that verified. Saying
	// "the mirror matches the database" underneath "record altered at seq 3"
	// reads as a contradiction, and it is: what matched was the hash each side
	// recorded at that sequence, not the record the mirror actually holds.
	if c := v.Comparison; c != nil && v.comparable {
		switch {
		case c.Installs != "":
			fmt.Fprintf(w, "comparison: these are not the same chain — %s\n", c.Installs)
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
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	if !checkFormat(e, *format) {
		return ExitUsage
	}

	if *limit < 1 || *limit > audit.MaxLimit {
		// Checked here rather than left to Filter, whose Unlimited sentinel is
		// -1 and is tested before its range guard: --limit -1 was the one
		// negative value that returned the entire chain, at exit 0, past the
		// cap this flag's own help advertises.
		fmt.Fprintf(e.stderr, "nodary audit list: --limit %d is outside 1–%d\n", *limit, audit.MaxLimit)
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
		fmt.Fprintf(e.stderr, "nodary audit %s: --from: %v\n", verb, err)
		return f, false
	}
	if f.To, err = audit.ParseBound(to, true); err != nil {
		fmt.Fprintf(e.stderr, "nodary audit %s: --to: %v\n", verb, err)
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
	// Off, or the encoder rewrites <, > and & inside the canonical bytes as
	// \u003c and friends — so `audit list --format json` printed a record that
	// did not read the same as the one `audit export --format jsonl` and the
	// sink emit for the same seq. internal/canonical does not use encoding/json
	// for output for exactly this reason.
	enc.SetEscapeHTML(false)
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

func cmdAuditExport(e env, args []string) int {
	fs := newFlagSet(e, "audit export")
	// Not formatFlag: on this verb the value is the export encoding, per
	// docs/specs/09-api.md §1, not docs/specs/10-cli.md §2's rendering style.
	format := fs.String("format", audit.FormatJSONL,
		"export encoding: jsonl is byte-identical to what a sink delivered; "+
			"csv is for a spreadsheet and defuses formula cells with a leading apostrophe")
	dbPath := dbFlag(fs)
	from := fs.String("from", "", "earliest record: a date (2006-01-02) or an RFC3339 instant")
	to := fs.String("to", "", "latest record; a bare date covers the whole day")
	fromSeq := fs.Int64("from-seq", 0, "start at this sequence number, to resume a destination that fell behind")
	if code := parseFlags(e, fs, args); code >= 0 {
		return code
	}
	switch *format {
	case audit.FormatJSONL, audit.FormatCSV:
	default:
		// Named explicitly, because the global flag table advertises text,
		// json and yaml and this is the one verb where they do not apply.
		fmt.Fprintf(e.stderr,
			"nodary audit export: --format %q is not an export encoding (want jsonl or csv)\n", *format)
		return ExitUsage
	}

	filter, ok := buildFilter(e, "export", *from, *to, "", "", audit.Unlimited)
	if !ok {
		return ExitUsage
	}
	if *fromSeq < 0 {
		fmt.Fprintf(e.stderr, "nodary audit export: --from-seq %d is not a sequence number\n", *fromSeq)
		return ExitUsage
	}
	filter.FromSeq = *fromSeq

	path, _ := resolveDB(*dbPath)
	db, ok := openForReading(e, "export", path)
	if !ok {
		return ExitFailure
	}
	defer db.Close()

	var err error
	if *format == audit.FormatCSV {
		_, err = audit.ExportCSV(context.Background(), db, filter, e.stdout)
	} else {
		_, err = audit.ExportJSONL(context.Background(), db, filter, e.stdout)
	}
	if err != nil {
		fmt.Fprintf(e.stderr, "nodary audit export: %v\n", err)
		if errors.Is(err, audit.ErrBadFilter) {
			return ExitUsage
		}
		return ExitFailure
	}
	return ExitOK
}

// parseAnchor reads SEQ:HASH.
func parseAnchor(e env, spec string) (*audit.Anchor, bool) {
	if spec == "" {
		return nil, true
	}
	seqText, hash, found := strings.Cut(spec, ":")
	if !found {
		fmt.Fprintf(e.stderr, "nodary audit verify: --anchor %q is not SEQ:HASH\n", spec)
		return nil, false
	}
	seq, err := strconv.ParseInt(seqText, 10, 64)
	if err != nil || seq < 0 {
		fmt.Fprintf(e.stderr, "nodary audit verify: --anchor %q has no usable sequence number\n", spec)
		return nil, false
	}
	if seq == 0 {
		// Anchoring to "nothing" is anchoring to genesis, and saying so beats
		// silently accepting a hash that can never match.
		if hash != audit.GenesisPrevHash {
			fmt.Fprintf(e.stderr,
				"nodary audit verify: --anchor seq 0 is the start of a chain, whose hash is 64 zeros\n")
			return nil, false
		}
		return &audit.Anchor{Seq: 0, Hash: hash}, true
	}
	if !isHex64(hash) {
		fmt.Fprintf(e.stderr,
			"nodary audit verify: --anchor %q has no usable hash (want 64 lowercase hex characters)\n", spec)
		return nil, false
	}
	return &audit.Anchor{Seq: seq, Hash: hash}, true
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
