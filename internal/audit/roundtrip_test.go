package audit

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// A record survives being written and read back, field for field.
//
// The failure this exists for is quiet in the worst way. Record had a marshaler
// and no unmarshaler, so encoding/json matched untagged fields by name on the
// way back: `action`, `seq` and `hash` returned, and `intent_hash` and
// `prev_hash` — the two whose names have two words — came back empty. A copy of
// the chain read from the API therefore had no links between its records and no
// binding between an approved preview and what was applied, while looking
// complete. An empty prev_hash does not read as "incomplete export"; it reads
// as tampering.
//
// Held by round trip rather than by listing the fields twice: the comparison is
// the marshaled form, so a member added to members() and forgotten in
// UnmarshalJSON fails here without anybody remembering to extend a list.
func TestARecordSurvivesBeingReadBack(t *testing.T) {
	full := Record{
		V: 1, Install: "ins_abc", Seq: 42,
		TS:            time.Date(2026, 9, 14, 4, 42, 48, 575_000_000, time.UTC),
		Actor:         Actor{ID: "usr_1", Method: "token", Session: "tok_1"},
		Source:        Source{IP: "10.0.0.1", Version: "2.0.0"},
		Action:        "node.approve",
		Target:        &Target{Kind: "node", ID: "gpu-01"},
		IntentHash:    "fa487a87c964ff0d",
		Justification: "approving over the network",
		Outcome:       OutcomeSuccess,
		Detail:        map[string]any{"request_id": "req_1", "revision": "1"},
		PrevHash:      "54ffbba9ce30bfe9",
		Hash:          "811a6e4cd38a2d82",
	}
	// Every exported field carries a distinct non-zero value, so the comparison
	// below actually exercises all of them. Reflective rather than written out,
	// because a field added to Record and left zero here would make this test
	// pass while covering nothing.
	v := reflect.ValueOf(full)
	for i := range v.NumField() {
		if v.Field(i).IsZero() {
			t.Fatalf("Record.%s is zero in this fixture, so the round trip does not test it",
				v.Type().Field(i).Name)
		}
	}

	first, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var back Record
	if err := json.Unmarshal(first, &back); err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("a record does not survive a round trip:\n  out %s\n  in  %s", first, second)
	}

	// And the hash still verifies over what came back, which is the property
	// the whole chain rests on: a record read from the network must be
	// checkable without trusting the reader.
	if got, err := back.Compute(); err != nil {
		t.Fatal(err)
	} else if want, _ := full.Compute(); got != want {
		t.Errorf("the hash preimage changed in transit: %s, want %s", got, want)
	}
}
