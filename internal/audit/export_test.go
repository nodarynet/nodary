package audit

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The property that makes an export trustworthy: it is the same bytes the sink
// delivered, so an operator can diff an export against a copy shipped off-box
// and get an empty result when nothing is wrong.
func TestJSONLExportIsByteIdenticalToTheMirror(t *testing.T) {
	db, mirror := chainOf(t, 8)

	var out bytes.Buffer
	n, err := ExportJSONL(context.Background(), db, Filter{}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if n != 8 {
		t.Errorf("exported %d records, want 8", n)
	}

	want, err := os.ReadFile(mirror)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != string(want) {
		t.Errorf("export and mirror differ\n export %q\n mirror %q", out.String(), want)
	}
}

// An export with no explicit limit must not stop at the listing default.
// Silently truncating evidence is worse than a long file.
func TestExportIsNotBoundedByTheListingDefault(t *testing.T) {
	db := openDB(t)
	l := New(db, NewDelivery(nil, Warn, io.Discard), WithClock(fixedClock))
	const n = DefaultLimit + 7
	for i := range n {
		if _, err := l.Act(context.Background(), request(fmt.Sprintf("a.%d", i)),
			func(m Mutation) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}

	var out bytes.Buffer
	got, err := ExportJSONL(context.Background(), db, Filter{}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if got != n {
		t.Errorf("exported %d records, want %d", got, n)
	}
}

// A chain reads forwards, and a JSONL export is meant to be verifiable as it
// stands.
func TestExportIsAscendingAndVerifiesAsAChain(t *testing.T) {
	db, _ := chainOf(t, 6)

	path := filepath.Join(t.TempDir(), "export.jsonl")
	fh, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExportJSONL(context.Background(), db, Filter{}, fh); err != nil {
		t.Fatal(err)
	}
	fh.Close()

	res, err := VerifyFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.Records != 6 || res.FirstSeq != 1 {
		t.Errorf("an export did not verify as a chain: %+v break=%v", res, res.Break)
	}
}

// --from-seq is how a destination that fell behind catches up.
func TestExportResumesFromASequence(t *testing.T) {
	db, _ := chainOf(t, 9)

	var out bytes.Buffer
	n, err := ExportJSONL(context.Background(), db, Filter{FromSeq: 7}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("exported %d records, want 3", n)
	}
	if !strings.Contains(out.String(), `"seq":7`) || strings.Contains(out.String(), `"seq":6`) {
		t.Errorf("resume started in the wrong place:\n%s", out.String())
	}
}

func TestCSVExportHasTheTableColumns(t *testing.T) {
	db, _ := chainOf(t, 4)

	var out bytes.Buffer
	n, err := ExportCSV(context.Background(), db, Filter{}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Errorf("exported %d records, want 4", n)
	}

	rows, err := csv.NewReader(bytes.NewReader(out.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("the export is not valid CSV: %v", err)
	}
	if len(rows) != 5 {
		t.Fatalf("%d rows, want a header and 4 records", len(rows))
	}
	if fmt.Sprint(rows[0]) != fmt.Sprint(columnNames) {
		t.Errorf("header = %v\n  want %v", rows[0], columnNames)
	}
	for i, row := range rows[1:] {
		if len(row) != len(columnNames) {
			t.Fatalf("row %d has %d fields, want %d", i, len(row), len(columnNames))
		}
	}

	// Ascending, and the values land under their own headings.
	index := map[string]int{}
	for i, name := range rows[0] {
		index[name] = i
	}
	if rows[1][index["seq"]] != "1" {
		t.Errorf("first row seq = %q, want 1", rows[1][index["seq"]])
	}
	if got := rows[1][index["outcome"]]; got != string(OutcomeSuccess) {
		t.Errorf("outcome column holds %q", got)
	}
	if got := rows[1][index["prev_hash"]]; got != GenesisPrevHash {
		t.Errorf("prev_hash column holds %q", got)
	}
	if got := rows[1][index["action"]]; got != "thing.add.0" {
		t.Errorf("action column holds %q", got)
	}
}

// A comma, a quote and a newline in a field must survive RFC 4180 quoting, or
// a justification an operator typed would shift every later column.
func TestCSVQuotesAwkwardValues(t *testing.T) {
	db := openDB(t)
	l := New(db, NewDelivery(nil, Warn, io.Discard), WithClock(fixedClock))
	awkward := "he said \"drain it\", then\nleft for the day"
	req := request("node.drain")
	req.Justification = awkward
	if _, err := l.Act(context.Background(), req, func(m Mutation) error { return nil }); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if _, err := ExportCSV(context.Background(), db, Filter{}, &out); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(out.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("the export is not valid CSV: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d rows, want a header and one record", len(rows))
	}
	index := map[string]int{}
	for i, name := range rows[0] {
		index[name] = i
	}
	if got := rows[1][index["justification"]]; got != awkward {
		t.Errorf("justification survived as %q, want %q", got, awkward)
	}
	if got := rows[1][index["outcome"]]; got != string(OutcomeSuccess) {
		t.Errorf("the columns shifted: outcome holds %q", got)
	}
}

// Filters apply to an export the same way they apply to a listing.
func TestExportFilters(t *testing.T) {
	db := varied(t)

	var out bytes.Buffer
	n, err := ExportJSONL(context.Background(), db, Filter{Action: "model."}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Errorf("exported %d records, want the 4 in the model family", n)
	}
}
