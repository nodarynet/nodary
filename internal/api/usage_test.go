package api_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/observed"
)

// meter writes metering rows the way the gateway does, through the same
// function, so the test cannot record a shape the product could not.
func (f *fixture) meter(t *testing.T, user, model, node string, n int) {
	t.Helper()
	var id string
	if err := f.db.Read().QueryRow(`SELECT id FROM user WHERE name = ?`, user).Scan(&id); err != nil {
		t.Fatalf("looking up %s: %v", user, err)
	}
	for i := range n {
		if err := observed.RecordUsage(context.Background(), f.db, observed.Usage{
			TS: time.Now().Add(-time.Duration(i) * time.Minute), UserID: id,
			Route: model, ModelID: model, NodeName: node,
			PromptTokens: 10, CompletionTokens: 5, Status: 200,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func usageRows(doc map[string]any) []any {
	rows, _ := doc["usage"].([]any)
	return rows
}

// R2-32. The reader is internal/metering, which `nodary usage show` also calls,
// so the two front ends cannot report different totals for one question.
func TestUsageIsReportedAndGrouped(t *testing.T) {
	f := newFixture(t)
	f.addUser("gina", "operator")
	f.addUser("hank", "operator")
	f.meter(t, "gina", "acme/tiny", "gpu-01", 3)
	f.meter(t, "hank", "acme/tiny", "gpu-02", 1)

	code, doc := f.do("GET", "/usage?group_by=user", f.admin, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, doc)
	}
	rows := usageRows(doc)
	if len(rows) != 2 {
		t.Fatalf("%d groups, want 2: %v", len(rows), doc)
	}
	// Busiest first.
	first, _ := rows[0].(map[string]any)
	if first["requests"] != float64(3) {
		t.Errorf("first group has %v requests, want the busiest: %v", first["requests"], rows)
	}
	if first["prompt_tokens"] != float64(30) {
		t.Errorf("prompt tokens = %v, want 30 summed", first["prompt_tokens"])
	}

	// And grouping by node answers a different question from the same rows.
	_, byNode := f.do("GET", "/usage?group_by=node", f.admin, nil, nil)
	if got := len(usageRows(byNode)); got != 2 {
		t.Errorf("%d nodes, want 2: %v", got, byNode)
	}

	// docs/adr/0006: counts only, never content. There is no column for it, so
	// this is a guard on the rendering rather than on the schema.
	for _, raw := range rows {
		row, _ := raw.(map[string]any)
		for k := range row {
			switch k {
			case "subject", "requests", "prompt_tokens", "completion_tokens":
			default:
				t.Errorf("a usage row carries %q, which is not a count", k)
			}
		}
	}
}

func TestAnUnknownGroupByIsRefused(t *testing.T) {
	f := newFixture(t)
	if code, doc := f.do("GET", "/usage?group_by=prompt", f.admin, nil, nil); code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: %v", code, doc)
	}
}

// **Every authenticated caller reads usage, including other people's**, and
// that is docs/specs/07-identity-audit.md §1's table as written: `state.read`
// and `usage.read.self` are both granted to RoleViewer, the lowest role, so
// there is no line separating "mine" from "everyone's" for a handler to
// enforce. Pinned rather than assumed, so that when a `usage.read.all` is added
// this test is what says the behavior changed.
func TestEveryAuthenticatedCallerCanReadUsage(t *testing.T) {
	f := newFixture(t)
	f.addUser("gina", "viewer")
	f.addUser("hank", "operator")
	f.meter(t, "gina", "acme/tiny", "gpu-01", 2)
	f.meter(t, "hank", "acme/tiny", "gpu-01", 5)

	_, minted, _ := f.mintToken("gina", "")
	viewer := secretOf(minted)
	if viewer == "" {
		t.Fatalf("no token: %v", minted)
	}

	code, doc := f.do("GET", "/usage?group_by=user", viewer, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, doc)
	}
	if got := len(usageRows(doc)); got != 2 {
		t.Errorf("a viewer saw %d groups, want both — §1 draws no line here: %v", got, doc)
	}

	// Unauthenticated is still refused, which is the line that does exist.
	if code, doc := f.do("GET", "/usage", "", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: %v", code, doc)
	}
}

// The ungrouped listing has one row per request and no bound, so it pages. A
// grouped report is bounded by how many subjects exist and is returned whole —
// truncating it would hide its tail while looking complete.
func TestTheUngroupedListingPagesAndAGroupedReportDoesNot(t *testing.T) {
	f := newFixture(t)
	f.addUser("gina", "operator")
	f.meter(t, "gina", "acme/tiny", "gpu-01", 7)

	code, doc := f.do("GET", "/usage?limit=3", f.admin, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, doc)
	}
	if got := len(usageRows(doc)); got != 3 {
		t.Fatalf("%d rows, want the 3 asked for: %v", got, doc)
	}
	next, _ := doc["next_cursor"].(string)
	if next == "" {
		t.Fatal("no cursor with four rows remaining")
	}

	seen := map[string]bool{}
	for _, raw := range usageRows(doc) {
		seen[fmt.Sprint(raw.(map[string]any)["subject"])] = true
	}
	_, page2 := f.do("GET", "/usage?limit=3&cursor="+next, f.admin, nil, nil)
	for _, raw := range usageRows(page2) {
		if s := fmt.Sprint(raw.(map[string]any)["subject"]); seen[s] {
			t.Errorf("page two repeats %s", s)
		}
	}

	// The grouped report ignores the limit and returns every group.
	_, grouped := f.do("GET", "/usage?group_by=user&limit=1", f.admin, nil, nil)
	if _, more := grouped["next_cursor"]; more {
		t.Error("a grouped report offered a cursor it cannot honor")
	}
	if got := len(usageRows(grouped)); got != 1 {
		t.Errorf("%d groups, want the one user: %v", got, grouped)
	}
}
