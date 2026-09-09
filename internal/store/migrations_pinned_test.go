package store

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestAnAppliedMigrationNeverChanges is the guard a spelling sweep walked
// straight through.
//
// A migration is content-addressed: Migrate records each file's checksum when it
// applies it, and refuses to run again against a database whose recorded
// checksum differs. That is the right behavior — an applied migration describes
// what a live database actually did, and editing one makes the record a
// fiction.
//
// **Nothing caught it at build time**, because every test builds a fresh
// database, and a fresh database records whatever checksum is embedded. The
// failure surfaced only on a real installation, as
//
//	migration checksum does not match the applied schema: 0005_evidence applied
//	as 0b70f77c…, embedded copy is 5d024240…
//
// after a tree-wide edit corrected two words in a comment inside it. A comment
// is enough; the file is hashed whole.
//
// So the checksums are pinned here. Adding a migration adds a line, which is a
// deliberate and reviewable act. Editing one that already exists fails, which is
// the point: the fix is a new migration, never a changed one.
func TestAnAppliedMigrationNeverChanges(t *testing.T) {
	pinned := map[string]string{}
	body, err := os.ReadFile("testdata/migrations.sha256")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			t.Fatalf("testdata/migrations.sha256 is not `sha256sum` output: %q", line)
		}
		pinned[f[1]] = f[0]
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		raw, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		got := hex.EncodeToString(sum[:])
		switch want, ok := pinned[name]; {
		case !ok:
			t.Errorf("%s is not pinned. If it is new, add this line to "+
				"internal/store/testdata/migrations.sha256:\n\t%s  %s", name, got, name)
		case want != got:
			t.Errorf("%s changed: %s, pinned %s.\n"+
				"An applied migration describes what live databases already did. "+
				"Correct it with a NEW migration, never by editing this one — a comment counts, "+
				"because the file is hashed whole.", name, short(got), short(want))
		}
		delete(pinned, name)
	}
	for name := range pinned {
		t.Errorf("%s is pinned and no longer exists; a migration is never removed", name)
	}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}
