package api_test

import (
	"database/sql"
	"net/http"
	"testing"

	"github.com/nodarynet/nodary/internal/api"
)

// R2-26's remaining endpoint. The core has existed since R4-06; what was
// missing was the HTTP surface for it.
//
// **It could not have been added by wiring a route alone.** The API carried its
// own copy of the rules about which columns move with a node's state, and that
// copy wrote `state` by itself for anything that was not an approval — so a
// revoke would have failed 0006_fleet.sql's CHECK pairing `departed` with a
// `departed_at`. This is the test that would have caught it.
func TestRevokingANodeOverTheAPIRecordsWhenItLeft(t *testing.T) {
	f := newFixture(t)
	f.join("gpu-01")
	if code, doc := f.do(http.MethodPost, "/nodes/gpu-01/approve", f.admin, nil,
		map[string]string{api.HeaderJustify: "a GPU host for the team"}); code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, doc)
	}

	code, doc := f.do(http.MethodPost, "/nodes/gpu-01/revoke", f.admin, nil,
		map[string]string{api.HeaderJustify: "the machine is being returned"})
	if code != http.StatusOK {
		t.Fatalf("revoke: %d %v", code, doc)
	}

	var state string
	var departed sql.NullString
	if err := f.db.Read().QueryRow(
		`SELECT state, departed_at FROM node WHERE name = 'gpu-01'`).Scan(&state, &departed); err != nil {
		t.Fatal(err)
	}
	if state != "departed" {
		t.Errorf("state = %q, want departed", state)
	}
	if !departed.Valid || departed.String == "" {
		t.Error("departed_at was not recorded, so the row cannot be read back as history")
	}
}

// The preview is what core.Act hashes into intent_hash, so it is the agreement.
// Both front ends render it from one function now; this pins that it still
// carries the terms.
func TestARevokePreviewCarriesTheNodesOwnTerms(t *testing.T) {
	f := newFixture(t)
	f.join("gpu-01")

	code, doc := f.do(http.MethodPost, "/nodes/gpu-01/revoke?dry_run=true", f.admin, nil,
		map[string]string{api.HeaderJustify: "checking"})
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, doc)
	}
	change, _ := doc["change"].(map[string]any)
	for _, k := range []string{"node", "from", "to", "offer", "constraints"} {
		if _, ok := change[k]; !ok {
			t.Errorf("the preview does not carry %s: %v", k, change)
		}
	}
	if change["to"] != "departed" {
		t.Errorf("to = %v, want departed", change["to"])
	}
	// A dry run changes nothing.
	var state string
	if err := f.db.Read().QueryRow(`SELECT state FROM node WHERE name = 'gpu-01'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state == "departed" {
		t.Error("a dry run revoked the node")
	}
}

// Revoking a node that does not exist is a refusal naming it, not a 500.
func TestRevokingAnUnknownNodeIsRefused(t *testing.T) {
	f := newFixture(t)
	code, doc := f.do(http.MethodPost, "/nodes/nowhere/revoke", f.admin, nil,
		map[string]string{api.HeaderJustify: "checking"})
	if code == http.StatusOK || code == http.StatusInternalServerError {
		t.Fatalf("status = %d: %v", code, doc)
	}
}

// Drain is an operator's to do — it takes work off a machine without ending its
// membership. Ejecting a node from the fleet is the node-lifecycle authority
// docs/specs/07-identity-audit.md §1 gives an admin, and revoke is that
// authority exercised in the other direction.
func TestAnOperatorMayDrainANodeButNotRevokeIt(t *testing.T) {
	f := newFixture(t)
	f.join("gpu-01")
	if code, doc := f.do(http.MethodPost, "/nodes/gpu-01/approve", f.admin, nil,
		map[string]string{api.HeaderJustify: "a GPU host"}); code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, doc)
	}

	f.addUser("erin", "operator")
	_, minted, _ := f.mintToken("erin", "")
	operator := secretOf(minted)
	if operator == "" {
		t.Fatalf("no token for erin: %v", minted)
	}

	if code, doc := f.do(http.MethodPost, "/nodes/gpu-01/drain", operator, nil,
		map[string]string{api.HeaderJustify: "taking work off it"}); code != http.StatusOK {
		t.Fatalf("an operator could not drain: %d %v", code, doc)
	}
	code, doc := f.do(http.MethodPost, "/nodes/gpu-01/revoke", operator, nil,
		map[string]string{api.HeaderJustify: "ejecting it"})
	if code != http.StatusForbidden {
		t.Fatalf("an operator revoked a node: %d %v", code, doc)
	}
}
