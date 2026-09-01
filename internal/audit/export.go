package audit

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"

	"github.com/nodarynet/nodary/internal/store"
)

// Export formats. docs/specs/09-api.md §1 specifies these values on this
// endpoint; they are not docs/specs/10-cli.md §2's global text|json|yaml,
// because here the value is the export encoding rather than a rendering style.
const (
	FormatJSONL = "jsonl"
	FormatCSV   = "csv"
)

// ExportJSONL writes one canonical record per line.
//
// The bytes are identical to what a sink delivered for the same records, which
// is what lets an operator diff an export against a copy shipped off-box and
// get an empty result when nothing is wrong.
func ExportJSONL(ctx context.Context, db *store.DB, f Filter, w io.Writer) (int64, error) {
	// Buffered, like the CSV writer already is. The caller passes os.Stdout, so
	// this was one write(2) per record for a whole-chain export — and
	// canonical.Encode returns a slice whose len equals its cap, so appending
	// the newline reallocated and copied every line rather than amortising.
	bw := bufio.NewWriter(w)
	var n int64
	err := Walk(ctx, db, exportOrder(f), func(r Record) error {
		line, err := r.Line()
		if err != nil {
			return err
		}
		if _, err := bw.Write(line); err != nil {
			return err
		}
		if err := bw.WriteByte('\n'); err != nil {
			return err
		}
		n++
		return nil
	})
	if ferr := bw.Flush(); err == nil {
		err = ferr
	}
	return n, err
}

// ExportCSV writes the rows as stored, with a header.
//
// The columns are the table's columns rather than the record's nested shape: an
// export a spreadsheet opens is worth more than one that re-nests, and JSONL is
// there for anything that needs structure.
//
// CSV cannot distinguish an empty string from null, and does not need to: an
// unset optional is null everywhere in this package and no field has a
// meaningful empty value, so an empty cell means unset with no ambiguity.
func ExportCSV(ctx context.Context, db *store.DB, f Filter, w io.Writer) (int64, error) {
	cw := csv.NewWriter(w)
	if err := cw.Write(columnNames); err != nil {
		return 0, err
	}

	var n int64
	err := Walk(ctx, db, exportOrder(f), func(r Record) error {
		row, err := r.row()
		if err != nil {
			return err
		}
		if err := cw.Write(row); err != nil {
			return err
		}
		n++
		return nil
	})
	// Flushed on both paths. csv.Writer buffers, so returning early on a Walk
	// error dropped the header and every row it had already accepted — stdout
	// got nothing at all for a small export, or a file severed mid-row for a
	// large one, while n went on claiming the rows had been written.
	cw.Flush()
	if err != nil {
		return n, err
	}
	return n, cw.Error()
}

// exportOrder forces the traversal an export needs: forwards, and complete.
//
// A chain reads forwards, and a listing's default cap would silently truncate
// evidence — an export that quietly stops at 50 records is worse than a long
// file. A caller that sets its own limit keeps it.
func exportOrder(f Filter) Filter {
	f.Ascending = true
	if f.Limit == 0 {
		f.Limit = Unlimited
	}
	return f
}

// row renders the record as its stored columns, in columnNames order.
func (r Record) row() ([]string, error) {
	detail, err := r.detailJSON()
	if err != nil {
		return nil, err
	}
	targetKind, targetID := r.targetFields()
	row := []string{
		fmt.Sprint(r.Seq), fmt.Sprint(r.V), r.Install, r.TS.UTC().Format(TimeFormat),
		r.Actor.ID, r.Actor.Method, r.Actor.Session,
		r.Source.IP, r.Source.Version,
		r.Action, targetKind, targetID,
		r.IntentHash, r.Justification, string(r.Outcome), string(detail),
		r.PrevHash, r.Hash,
	}
	if len(row) != len(columnNames) {
		// Unreachable unless columnNames changed without this function, which
		// is exactly the mistake that puts data under the wrong heading.
		return nil, fmt.Errorf("export has %d values for %d columns", len(row), len(columnNames))
	}
	return row, nil
}
