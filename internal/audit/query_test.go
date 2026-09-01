package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/store"
)

// varied writes records spread across actors, actions and days.
func varied(t *testing.T) *store.DB {
	t.Helper()
	db := openDB(t)
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	l := New(db, NewDelivery(nil, Warn, io.Discard), WithClock(func() time.Time { return at }))

	for i, spec := range []struct {
		actor, action string
		day           int
	}{
		{"root", "model.enable", 29},
		{"usr_a", "model.disable", 29},
		{"usr_a", "node.approve", 30},
		{"root", "model.restart", 30},
		{"usr_b", "token.revoke", 31},
		{"usr_a", "model.enable", 31},
	} {
		at = time.Date(2026, 8, spec.day, 12, 0, i, 0, time.UTC)
		req := request(spec.action)
		req.Actor.ID = spec.actor
		if _, err := l.Act(context.Background(), req, func(m Mutation) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func seqs(records []Record) []int64 {
	out := make([]int64, 0, len(records))
	for _, r := range records {
		out = append(out, r.Seq)
	}
	return out
}

func TestListIsNewestFirst(t *testing.T) {
	db := varied(t)
	got, err := List(context.Background(), db, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	want := []int64{6, 5, 4, 3, 2, 1}
	if fmt.Sprint(seqs(got)) != fmt.Sprint(want) {
		t.Errorf("seqs = %v, want %v", seqs(got), want)
	}
}

func TestListFilters(t *testing.T) {
	db := varied(t)
	for name, tc := range map[string]struct {
		filter Filter
		want   []int64
	}{
		"by actor":         {Filter{Actor: "usr_a"}, []int64{6, 3, 2}},
		"by exact action":  {Filter{Action: "model.enable"}, []int64{6, 1}},
		"by action family": {Filter{Action: "model."}, []int64{6, 4, 2, 1}},
		"from a date":      {Filter{From: mustBound(t, "2026-08-31", false)}, []int64{6, 5}},
		"to a date":        {Filter{To: mustBound(t, "2026-08-29", true)}, []int64{2, 1}},
		"a single day":     {Filter{From: mustBound(t, "2026-08-30", false), To: mustBound(t, "2026-08-30", true)}, []int64{4, 3}},
		"from a sequence":  {Filter{FromSeq: 5}, []int64{6, 5}},
		"actor and family": {Filter{Actor: "usr_a", Action: "model."}, []int64{6, 2}},
		"nothing matches":  {Filter{Actor: "nobody"}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := List(context.Background(), db, tc.filter)
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(seqs(got)) != fmt.Sprint(tc.want) {
				t.Errorf("seqs = %v, want %v", seqs(got), tc.want)
			}
		})
	}
}

// A bare date as an upper bound covers the whole day. Meaning "up to midnight
// that morning" would silently drop everything that happened on the day the
// operator named.
func TestParseBoundCoversTheWholeDay(t *testing.T) {
	from, err := ParseBound("2026-08-31", false)
	if err != nil {
		t.Fatal(err)
	}
	to, err := ParseBound("2026-08-31", true)
	if err != nil {
		t.Fatal(err)
	}
	if from != "2026-08-31T00:00:00.000Z" {
		t.Errorf("from = %q", from)
	}
	if to != "2026-08-31T23:59:59.999Z" {
		t.Errorf("to = %q", to)
	}

	// A full instant is normalised to UTC and to the column's precision.
	got, err := ParseBound("2026-08-31T12:00:00.9994+02:00", false)
	if err != nil {
		t.Fatal(err)
	}
	if got != "2026-08-31T10:00:00.999Z" {
		t.Errorf("instant = %q, want it normalised to UTC milliseconds", got)
	}

	if _, err := ParseBound("last tuesday", false); !errors.Is(err, ErrBadFilter) {
		t.Errorf("error = %v, want ErrBadFilter", err)
	}
	if got, err := ParseBound("", false); got != "" || err != nil {
		t.Errorf("an empty bound should be no bound, got %q %v", got, err)
	}
}

func TestListLimits(t *testing.T) {
	db := varied(t)

	got, err := List(context.Background(), db, Filter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Seq != 6 {
		t.Errorf("seqs = %v, want the two newest", seqs(got))
	}

	// Above the maximum is an error, not a silent clamp: a caller that asked
	// for 5000 and got 500 has been given a wrong answer quietly.
	if _, err := List(context.Background(), db, Filter{Limit: MaxLimit + 1}); !errors.Is(err, ErrBadFilter) {
		t.Errorf("error = %v, want ErrBadFilter", err)
	}
	if _, err := List(context.Background(), db, Filter{Limit: -7}); !errors.Is(err, ErrBadFilter) {
		t.Errorf("error = %v, want ErrBadFilter", err)
	}
}

// The default bound exists so a listing cannot accidentally stream a whole
// chain; an export has to be able to.
func TestDefaultLimitBoundsAListingAndUnlimitedDoesNot(t *testing.T) {
	db := openDB(t)
	l := New(db, NewDelivery(nil, Warn, io.Discard), WithClock(fixedClock))
	for i := range DefaultLimit + 5 {
		if _, err := l.Act(context.Background(), request(fmt.Sprintf("a.%d", i)),
			func(m Mutation) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}

	got, err := List(context.Background(), db, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != DefaultLimit {
		t.Errorf("default listing returned %d, want %d", len(got), DefaultLimit)
	}

	all, err := List(context.Background(), db, Filter{Limit: Unlimited, Ascending: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != DefaultLimit+5 {
		t.Errorf("unlimited returned %d, want %d", len(all), DefaultLimit+5)
	}
	if all[0].Seq != 1 {
		t.Errorf("ascending should start at seq 1, got %d", all[0].Seq)
	}
}

// Action matching is literal, and the prefix form is a range rather than a
// LIKE. The two look equivalent until the prefix contains a LIKE wildcard, or
// until case comes up: SQLite's LIKE is case-insensitive for ASCII by default,
// and treats _ as "any one character". Both would silently widen the filter,
// and a filter that quietly returns more than it was asked for is worse than
// one that errors.
func TestActionMatchingIsLiteral(t *testing.T) {
	db := openDB(t)
	l := New(db, NewDelivery(nil, Warn, io.Discard), WithClock(fixedClock))
	for _, action := range []string{
		"model.enable",
		"model%enable",  // a wildcard in an exact match
		"model_enable",  // and the single-character one
		"MODEL.disable", // LIKE would fold this into the model. family
		"node_pool.drain",
		"nodeXpool.drain", // only _ as a wildcard reaches this from node_pool.
	} {
		if _, err := l.Act(context.Background(), request(action),
			func(m Mutation) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}

	for action, want := range map[string][]string{
		"model.enable": {"model.enable"},
		"model%enable": {"model%enable"},
		"model_enable": {"model_enable"},
		"model.":       {"model.enable"},
		"node_pool.":   {"node_pool.drain"},
		"MODEL.":       {"MODEL.disable"},
	} {
		got, err := List(context.Background(), db, Filter{Action: action})
		if err != nil {
			t.Fatal(err)
		}
		var actions []string
		for _, r := range got {
			actions = append(actions, r.Action)
		}
		if fmt.Sprint(actions) != fmt.Sprint(want) {
			t.Errorf("action %q matched %v, want %v", action, actions, want)
		}
	}
}

func mustBound(t *testing.T, s string, upper bool) string {
	t.Helper()
	b, err := ParseBound(s, upper)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
