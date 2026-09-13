package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
)

// doFull is do, plus the response headers — which is where a version travels.
func (f *fixture) doFull(method, path, token string, body any, headers map[string]string) (int, map[string]any, http.Header) {
	f.t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			f.t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, f.srv.URL+api.Prefix+path, rdr)
	if err != nil {
		f.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return resp.StatusCode, doc, resp.Header
}

// etagOf reads a config-backed object and returns the version it was at.
func (f *fixture) etagOf(path string) string {
	f.t.Helper()
	code, doc, h := f.doFull("GET", path, f.admin, nil, nil)
	if code != http.StatusOK {
		f.t.Fatalf("GET %s: %d %v", path, code, doc)
	}
	tag := h.Get("ETag")
	if tag == "" {
		f.t.Fatalf("GET %s carries no ETag, so a client has no version to send back", path)
	}
	return tag
}

// putLimit is a small config-backed mutation: it records a revision, which is
// what every config-backed object is versioned by.
func (f *fixture) putLimit(rpm int, headers map[string]string) (int, map[string]any) {
	f.t.Helper()
	h := map[string]string{api.HeaderJustify: "setting a limit"}
	for k, v := range headers {
		h[k] = v
	}
	code, doc, _ := f.doFull("PUT", "/limits/role/operator", f.admin,
		map[string]any{"subject_kind": "role", "subject_id": "operator", "rpm": rpm}, h)
	return code, doc
}

// 09 §2: list and show endpoints on versioned objects carry the version.
func TestConfigBackedReadsCarryTheirRevision(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"/models", "/deployments", "/routes", "/limits"} {
		if tag := f.etagOf(path); !strings.HasPrefix(tag, `"`) {
			t.Errorf("GET %s: ETag = %q, want it quoted", path, tag)
		}
	}
}

// The whole point: two administrators cannot silently overwrite one another.
func TestAStaleIfMatchIsRefusedWithAConflict(t *testing.T) {
	f := newFixture(t)

	// Alice reads the limits and gets the version she saw.
	was := f.etagOf("/limits")

	// Bob changes something in between.
	if code, doc := f.putLimit(100, nil); code != http.StatusOK {
		t.Fatalf("the first write failed: %d %v", code, doc)
	}

	// Alice writes against what she read, and is refused rather than silently
	// dropping Bob's change on the floor.
	code, doc := f.putLimit(200, map[string]string{api.HeaderIfMatch: was})
	if code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %v", code, doc)
	}
	body, _ := doc["error"].(map[string]any)
	if body["code"] != "revision_changed" {
		t.Errorf("code = %v, want revision_changed: %v", body["code"], doc)
	}
	// And the message says what to do about it.
	if msg, _ := body["message"].(string); !strings.Contains(msg, "re-read") {
		t.Errorf("message does not say how to recover: %q", msg)
	}

	// Re-read and try again: it goes through.
	if code, doc := f.putLimit(200, map[string]string{api.HeaderIfMatch: f.etagOf("/limits")}); code != http.StatusOK {
		t.Fatalf("the retry after re-reading failed: %d %v", code, doc)
	}
}

// 09 §2 makes If-Match something endpoints *accept*, not demand. A client that
// never read the object has nothing to have raced with.
func TestIfMatchIsOptional(t *testing.T) {
	f := newFixture(t)
	if code, doc := f.putLimit(50, nil); code != http.StatusOK {
		t.Fatalf("a write with no If-Match was refused: %d %v", code, doc)
	}
	// RFC 9110's "*" means "as long as it exists".
	if code, doc := f.putLimit(60, map[string]string{api.HeaderIfMatch: "*"}); code != http.StatusOK {
		t.Fatalf(`If-Match: * was refused: %d %v`, code, doc)
	}
	// A client that pulled the number out of the JSON rather than echoing the
	// quoted header is being reasonable too.
	bare := strings.Trim(f.etagOf("/limits"), `"`)
	if code, doc := f.putLimit(70, map[string]string{api.HeaderIfMatch: bare}); code != http.StatusOK {
		t.Fatalf("an unquoted revision was refused: %d %v", code, doc)
	}
}

// A refused mutation must change nothing, including the revision chain: a 409
// that still advanced the version would make the next retry fail too.
func TestAConflictWritesNothing(t *testing.T) {
	f := newFixture(t)
	if code, _ := f.putLimit(100, nil); code != http.StatusOK {
		t.Fatal("setup write failed")
	}
	before := f.etagOf("/limits")

	// Stale by construction: 0 is where the chain stands before any revision.
	if code, _ := f.putLimit(200, map[string]string{api.HeaderIfMatch: `"0"`}); code != http.StatusConflict {
		t.Fatalf("expected a conflict, got %d", code)
	}
	if after := f.etagOf("/limits"); after != before {
		t.Errorf("a refused write moved the revision from %s to %s", before, after)
	}
}

// --- pagination (R2-21) ------------------------------------------------------

// A page is a slice plus the cursor to continue from, and walking the pages has
// to produce every record exactly once.
func TestPagingTheAuditChainVisitsEveryRecordOnce(t *testing.T) {
	f := newFixture(t)
	for i := range 12 {
		if code, doc := f.putLimit(i+1, nil); code != http.StatusOK {
			t.Fatalf("write %d: %d %v", i, code, doc)
		}
	}

	seen := map[float64]bool{}
	cursor, pages := "", 0
	for {
		path := "/audit?limit=5"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		code, doc, _ := f.doFull("GET", path, f.admin, nil, nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s: %d %v", path, code, doc)
		}
		records, _ := doc["records"].([]any)
		if len(records) > 5 {
			t.Fatalf("a page of %d records was returned for limit=5", len(records))
		}
		for _, raw := range records {
			rec, _ := raw.(map[string]any)
			seq, _ := rec["seq"].(float64)
			if seen[seq] {
				t.Fatalf("seq %v appeared on two pages", seq)
			}
			seen[seq] = true
		}
		next, _ := doc["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
		if pages++; pages > 20 {
			t.Fatal("paging did not terminate")
		}
	}
	if len(seen) < 12 {
		t.Errorf("walked %d records over %d pages, want at least the 12 writes", len(seen), pages+1)
	}
	// The last page must not carry a cursor, or a client makes one more request
	// to be told there is nothing.
	if pages == 0 {
		t.Error("the whole chain came back in one page; the limit was not applied")
	}
}

func TestPagingASnapshotListing(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"alpha", "beta", "gamma"} {
		if code, doc, _ := f.doFull("PUT", "/limits/user/"+name, f.admin,
			map[string]any{"subject_kind": "user", "subject_id": name, "rpm": 10},
			map[string]string{api.HeaderJustify: "seeding"}); code != http.StatusOK {
			t.Fatalf("seeding %s: %d %v", name, code, doc)
		}
	}

	code, doc, _ := f.doFull("GET", "/limits?limit=2", f.admin, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, doc)
	}
	first, _ := doc["limits"].([]any)
	if len(first) != 2 {
		t.Fatalf("first page has %d entries, want 2: %v", len(first), doc)
	}
	next, _ := doc["next_cursor"].(string)
	if next == "" {
		t.Fatal("no next_cursor with more remaining")
	}

	code, doc, _ = f.doFull("GET", "/limits?limit=2&cursor="+next, f.admin, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, doc)
	}
	second, _ := doc["limits"].([]any)
	if len(second) != 1 {
		t.Errorf("second page has %d entries, want the remaining 1: %v", len(second), doc)
	}
	if _, more := doc["next_cursor"]; more {
		t.Error("the last page carries a cursor, so a client makes one request too many")
	}
	// And the pages do not overlap.
	if len(second) == 1 && len(first) == 2 {
		id := func(v any) any { return v.(map[string]any)["subject_id"] }
		if id(second[0]) == id(first[0]) || id(second[0]) == id(first[1]) {
			t.Errorf("page two repeats page one: %v then %v", first, second)
		}
	}
}

// A limit above the maximum is an error, not a silent clamp: a caller that
// asked for 5000 and got 500 has been given a wrong answer quietly.
func TestAnOversizeLimitIsRefused(t *testing.T) {
	f := newFixture(t)
	for _, q := range []string{"limit=5000", "limit=0", "limit=-1", "limit=many"} {
		code, doc, _ := f.doFull("GET", "/models?"+q, f.admin, nil, nil)
		if code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400: %v", q, code, doc)
		}
	}
	// And the documented maximum is accepted.
	if code, doc, _ := f.doFull("GET", "/models?limit=500", f.admin, nil, nil); code != http.StatusOK {
		t.Errorf("limit=500 was refused: %d %v", code, doc)
	}
}
