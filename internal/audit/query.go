package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nodarynet/nodary/internal/store"
)

// Listing limits, from docs/specs/09-api.md §2.
const (
	DefaultLimit = 50
	MaxLimit     = 500
	// Unlimited returns every match. An export uses it: truncating evidence
	// silently is worse than a long file.
	Unlimited = -1
)

// Filter selects records. Every field is optional; the zero Filter is
// "everything, newest first, up to DefaultLimit".
type Filter struct {
	// From and To are ts values in TimeFormat. The column is fixed-width UTC,
	// so lexicographic order is chronological order and these are plain string
	// comparisons against an indexed column rather than date arithmetic.
	From, To string
	// Actor matches actor_id exactly.
	Actor string
	// Action matches exactly, or as a prefix when it ends in a dot, so
	// "model." selects the whole family.
	Action string
	// FromSeq selects records at or after a sequence number. It is how a
	// destination that fell behind catches up.
	FromSeq int64
	// Limit caps the result: zero means DefaultLimit, Unlimited means every
	// match. Anything above MaxLimit is an error rather than a silent clamp,
	// because a caller that asked for 5000 records and got 500 has been given a
	// wrong answer quietly.
	Limit int
	// Ascending walks oldest-first. Listings are descending
	// (docs/specs/09-api.md §2); an export is ascending, because a chain reads
	// forwards.
	Ascending bool
}

// ErrBadFilter is returned for a filter that cannot be honoured.
var ErrBadFilter = fmt.Errorf("audit filter is not valid")

// ParseBound reads a --from or --to value: a date, or a full RFC3339 instant.
//
// A bare date as an upper bound covers the whole day. `--to 2026-08-31`
// meaning "up to midnight that morning" would silently drop everything that
// happened on the day the operator named, which is the wrong answer to the
// question they asked.
func ParseBound(s string, upper bool) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		if upper {
			t = t.Add(24*time.Hour - time.Millisecond)
		}
		return t.UTC().Format(TimeFormat), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "", fmt.Errorf("%w: %q is neither a date (2006-01-02) nor an RFC3339 instant", ErrBadFilter, s)
	}
	return t.UTC().Truncate(time.Millisecond).Format(TimeFormat), nil
}

// where builds the filter's SQL. Values are bound, never interpolated.
func (f Filter) where() (string, []any) {
	var clauses []string
	var args []any

	if f.From != "" {
		clauses, args = append(clauses, "ts >= ?"), append(args, f.From)
	}
	if f.To != "" {
		clauses, args = append(clauses, "ts <= ?"), append(args, f.To)
	}
	if f.FromSeq > 0 {
		clauses, args = append(clauses, "seq >= ?"), append(args, f.FromSeq)
	}
	if f.Actor != "" {
		clauses, args = append(clauses, "actor_id = ?"), append(args, f.Actor)
	}
	if f.Action != "" {
		if upper, ok := prefixBound(f.Action); ok {
			// A range rather than LIKE: it uses the index, and it sidesteps
			// escaping % and _ in an action name entirely.
			clauses = append(clauses, "action >= ? AND action < ?")
			args = append(args, f.Action, upper)
		} else {
			clauses, args = append(clauses, "action = ?"), append(args, f.Action)
		}
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// prefixBound returns the exclusive upper bound of a dotted action prefix.
func prefixBound(action string) (string, bool) {
	if !strings.HasSuffix(action, ".") {
		return "", false
	}
	b := []byte(action)
	b[len(b)-1]++ // '.' becomes '/', the next byte value
	return string(b), true
}

// limit resolves the row cap, or reports that there is none.
func (f Filter) limit() (n int, bounded bool, err error) {
	switch {
	case f.Limit == Unlimited:
		return 0, false, nil
	case f.Limit == 0:
		return DefaultLimit, true, nil
	case f.Limit < 0 || f.Limit > MaxLimit:
		return 0, false, fmt.Errorf("%w: limit %d is outside 1–%d", ErrBadFilter, f.Limit, MaxLimit)
	}
	return f.Limit, true, nil
}

// List returns matching records, newest first unless the filter says otherwise.
func List(ctx context.Context, db *store.DB, f Filter) ([]Record, error) {
	var out []Record
	err := Walk(ctx, db, f, func(r Record) error {
		out = append(out, r)
		return nil
	})
	return out, err
}

// Walk streams matching records to fn.
//
// Streaming rather than returning a slice is what lets an export run over a
// chain larger than memory; List is the convenience on top for a bounded
// listing.
func Walk(ctx context.Context, db *store.DB, f Filter, fn func(Record) error) error {
	n, bounded, err := f.limit()
	if err != nil {
		return err
	}
	where, args := f.where()
	order := " ORDER BY seq DESC"
	if f.Ascending {
		order = " ORDER BY seq ASC"
	}

	query := `SELECT ` + columns + ` FROM audit` + where + order
	if bounded {
		query += " LIMIT ?"
		args = append(args, n)
	}

	rows, err := db.Read().QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("reading audit records: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return err
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}
