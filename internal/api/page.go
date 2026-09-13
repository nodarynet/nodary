package api

import (
	"net/http"
	"strconv"
	"strings"
)

// docs/specs/09-api.md §2: "List endpoints take limit (default 50, max 500) and
// cursor. Responses carry next_cursor when more remain."
const (
	DefaultLimit = 50
	MaxLimit     = 500
)

// page is one request's slice of a listing.
type page struct {
	limit  int
	cursor string
}

// readPage parses limit and cursor.
//
// **A limit above the maximum is an error, not a silent clamp** — the rule
// audit.Filter already states: a caller that asked for 5000 records and was
// handed 500 has been given a wrong answer quietly, and will page through the
// wrong number of them without ever learning why.
func readPage(r *http.Request) (page, error) {
	p := page{limit: DefaultLimit, cursor: strings.TrimSpace(r.URL.Query().Get("cursor"))}
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return p, nil
	}
	n, err := strconv.Atoi(raw)
	switch {
	case err != nil || n < 1:
		return p, badRequest("limit is a positive whole number, not %q", raw)
	case n > MaxLimit:
		return p, badRequest("limit is at most %d, and you asked for %d", MaxLimit, n)
	}
	p.limit = n
	return p, nil
}

// seq reads a cursor that is a sequence number, for the listings ordered by one.
func (p page) seq() (int64, error) {
	if p.cursor == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(p.cursor, 10, 64)
	if err != nil || n < 1 {
		return 0, badRequest("cursor is the sequence number a page ended at, not %q", p.cursor)
	}
	return n, nil
}

// paginate returns one page of an ascending, key-ordered slice, and the cursor
// a caller sends to continue.
//
// **Keyed, not offset-based.** Every listing this serves is already ordered by
// its own key in SQL, and a cursor that is the last key returned stays correct
// when rows are inserted or removed between pages — where an offset silently
// skips or repeats a row. That matters most exactly where paging matters most.
//
// An empty next cursor means the listing is exhausted, which is what lets a
// client stop without a second request that returns nothing.
func paginate[T any](items []T, p page, key func(T) string) ([]T, string) {
	if p.cursor != "" {
		i := 0
		for i < len(items) && key(items[i]) <= p.cursor {
			i++
		}
		items = items[i:]
	}
	if len(items) > p.limit {
		return items[:p.limit], key(items[p.limit-1])
	}
	return items, ""
}

// listBody renders a page in the one shape 09 §2 describes.
func listBody(name string, items any, next string) map[string]any {
	body := map[string]any{name: items}
	if next != "" {
		body["next_cursor"] = next
	}
	return body
}

// paginateDesc is paginate for a listing ordered newest-first.
//
// Tokens are ordered by creation time descending, which is how a person reads
// them, and changing that order to suit the paginator would be the tail wagging
// the dog. So the cursor walks the other way: a page continues at the first key
// strictly below the one it ended on.
func paginateDesc[T any](items []T, p page, key func(T) string) ([]T, string) {
	if p.cursor != "" {
		i := 0
		for i < len(items) && key(items[i]) >= p.cursor {
			i++
		}
		items = items[i:]
	}
	if len(items) > p.limit {
		return items[:p.limit], key(items[p.limit-1])
	}
	return items, ""
}
