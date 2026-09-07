package observed

import (
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/nodarynet/nodary/internal/store"
)

// R3-15's structural half.
//
// internal/gateway's canary test proves that today's code does not write a
// prompt anywhere. This proves something the canary cannot: that there is
// nowhere to write one. docs/adr/0006-cui-boundary-and-fips.md makes "nodary
// records that a request happened, never what it said" a *structural*
// guarantee, and a guarantee that depends on every future author remembering it
// is not structural.
//
// So the field set is pinned. Adding `Prompt`, `Completion`, `Messages` or
// anything else that could hold content fails here, and the failure names the
// decision rather than the test.
func TestTheUsageRecordIsClosed(t *testing.T) {
	want := []string{
		"TS", "UserID", "TokenID", "Route", "ModelID", "DeploymentID", "NodeName",
		"RequestID", "PromptTokens", "CompletionTokens", "Latency", "Status",
		"Streamed", "Partial",
	}
	var got []string
	rt := reflect.TypeOf(Usage{})
	for i := 0; i < rt.NumField(); i++ {
		got = append(got, rt.Field(i).Name)
	}
	slices.Sort(got)
	sorted := append([]string(nil), want...)
	slices.Sort(sorted)

	if !reflect.DeepEqual(got, sorted) {
		t.Errorf("the usage record's fields changed.\n got: %v\nwant: %v\n\n"+
			"If a field was added to hold request or response content, that is the thing "+
			"docs/adr/0006-cui-boundary-and-fips.md says cannot exist: nodary records that a "+
			"request happened, never what it said. If it is a new counter or identifier, add "+
			"it to this list and to the column list below.", got, sorted)
	}
}

// And the same for the table, because a column is where content would actually
// land. The schema and the struct are two halves of one closed record, and a
// column with no field is a column something could still write to.
func TestTheUsageTableIsClosed(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	rows, err := db.Read().QueryContext(ctx, `SELECT name FROM pragma_table_info('usage')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		got = append(got, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"id", "ts", "user_id", "token_id", "route", "model_id", "deployment_id",
		"node_name", "request_id", "prompt_tokens", "completion_tokens",
		"latency_ms", "status", "streamed", "partial",
	}
	slices.Sort(got)
	slices.Sort(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the usage table's columns changed.\n got: %v\nwant: %v\n\n"+
			"0006_fleet.sql: there is no column for request or response content, and there is "+
			"not going to be one.", got, want)
	}
}

// The row round-trips, so the closed schema is also a working one.
func TestUsageRoundTrips(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "nodary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	u := Usage{
		TS: time.Now(), Route: "acme/tiny", ModelID: "acme/tiny",
		RequestID: "req_1", PromptTokens: 11, CompletionTokens: 7,
		Latency: 250 * time.Millisecond, Status: 200, Streamed: true, Partial: true,
	}
	if err := RecordUsage(ctx, db, u); err != nil {
		t.Fatal(err)
	}

	var prompt, completion, latency int64
	var status, streamed, partial int
	if err := db.Read().QueryRowContext(ctx,
		`SELECT prompt_tokens, completion_tokens, latency_ms, status, streamed, partial FROM usage`).
		Scan(&prompt, &completion, &latency, &status, &streamed, &partial); err != nil {
		t.Fatal(err)
	}
	if prompt != 11 || completion != 7 || latency != 250 || status != 200 {
		t.Errorf("row = %d/%d %dms %d", prompt, completion, latency, status)
	}
	if streamed != 1 || partial != 1 {
		t.Errorf("streamed=%d partial=%d, want both set", streamed, partial)
	}
}
