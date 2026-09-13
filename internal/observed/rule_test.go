package observed

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// writable is every table this package may write, and why each one is an
// observation rather than a decision.
//
// The package comment states the rule — "it writes only what a machine reported
// about itself" — and until this test the rule was prose. The comment even says
// each statement names its columns explicitly "so it can be reviewed against the
// rule above by reading it", which is a control performed by whoever remembers
// to perform it. This package is precisely where a new write gets added: it is
// the one directory `TestNothingBypassesTheSeam` exempts from the audit gate,
// so a function added here is outside the chain by construction, and `audit` is
// one table name away.
var writable = map[string]string{
	"usage":              "one inference request, as the gateway saw it happen",
	"token":              "last_used_at only — when a credential was presented, never whether it may be",
	"node":               "inventory and liveness as the node reported them",
	"deployment":         "the unit states an agent observed, never what was asked for",
	"staging":            "how far a transfer got",
	"refusal":            "what an agent refused to run, and why it refused",
	"stage_reset":        "consuming a request the control plane made; making the request is a decision and is audited",
	"deployment_restart": "the same, for a restart request",
}

// decided are columns that carry a person's decision even on a table this
// package may otherwise write. The package comment names the first by hand:
// *"not `node.state`, not approval"*.
var decided = map[string][]string{
	"node":       {"state", "approved_by", "approved_at", "departed_at"},
	"deployment": {"backend", "params_json", "extra_args_json", "disabled"},
	"token":      {"revoked_at", "user_id", "kind", "expires_at"},
}

// doUpdate strips the `DO UPDATE SET` of an upsert, which belongs to the INSERT
// before it and would otherwise read as an UPDATE of a table called "set".
var doUpdate = regexp.MustCompile(`(?is)\bON\s+CONFLICT\b.*?\bDO\s+UPDATE\s+SET\b`)

var writes = regexp.MustCompile(`(?is)\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+([a-z_][a-z0-9_]*)`)

// sourceOfThisPackage is every non-test .go file beside this one.
func sourceOfThisPackage(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		out[name] = string(body)
	}
	if len(out) == 0 {
		t.Fatal("read no source for this package")
	}
	return out
}

func TestThisPackageWritesNoTableThatHoldsADecision(t *testing.T) {
	for name, body := range sourceOfThisPackage(t) {
		for _, m := range writes.FindAllStringSubmatch(doUpdate.ReplaceAllString(body, ""), -1) {
			table := strings.ToLower(m[2])
			if _, ok := writable[table]; ok {
				continue
			}
			t.Errorf("%s writes %s, which is not an observation this package may record.\n"+
				"  Everything a person decides goes through audit.Log.Act. If %s really is "+
				"something a machine reported about itself, say so in writable; otherwise the "+
				"write belongs in the chain.", name, table, table)
		}
	}
}

// The `audit` table by name, because it is the one whose absence the package's
// whole existence depends on, and a failure that named it only as "not in the
// allowlist" would under-describe what had happened.
func TestTheAuditChainIsNotWritableFromHere(t *testing.T) {
	if reason, ok := writable["audit"]; ok {
		t.Fatalf("audit is in the allowlist (%q). This package is exempt from the seam that "+
			"forces every write through audit.Log.Act, so an audit write from here is an "+
			"unattributed record in a chain whose whole claim is attribution.", reason)
	}
	for name, body := range sourceOfThisPackage(t) {
		for _, m := range writes.FindAllStringSubmatch(doUpdate.ReplaceAllString(body, ""), -1) {
			if strings.ToLower(m[2]) == "audit" {
				t.Errorf("%s writes the audit table directly", name)
			}
		}
	}
}

// A table may be writable and still have columns that are not. `node` is the
// example the package comment gives: liveness is an observation, and `state` is
// an approval somebody made.
func TestNoWriteHereSetsAColumnSomebodyDecided(t *testing.T) {
	// `UPDATE <table> SET <columns> WHERE`, and the upsert form, which does set
	// columns and is the one place DO UPDATE SET must not be stripped.
	sets := regexp.MustCompile(`(?is)\bUPDATE\s+([a-z_][a-z0-9_]*)\s+SET\s+(.*?)\bWHERE\b`)
	upserts := regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+([a-z_][a-z0-9_]*)\b.*?\bDO\s+UPDATE\s+SET\s+(.*?)(?:\bWHERE\b|` + "`" + `)`)

	for name, body := range sourceOfThisPackage(t) {
		for _, re := range []*regexp.Regexp{sets, upserts} {
			for _, m := range re.FindAllStringSubmatch(body, -1) {
				table := strings.ToLower(m[1])
				assigned := m[2]
				for _, col := range decided[table] {
					if regexp.MustCompile(`(?i)\b` + col + `\s*=`).MatchString(assigned) {
						t.Errorf("%s sets %s.%s, which is a decision and belongs in the chain:\n  %s",
							name, table, col, strings.Join(strings.Fields(assigned), " "))
					}
				}
			}
		}
	}
}

// The allowlist is not allowed to rot into a list of every table. If a write is
// removed, its entry goes with it — otherwise the next person reads a permission
// that nothing exercises as precedent for adding one.
func TestEveryAllowedTableIsActuallyWritten(t *testing.T) {
	seen := map[string]bool{}
	for _, body := range sourceOfThisPackage(t) {
		for _, m := range writes.FindAllStringSubmatch(doUpdate.ReplaceAllString(body, ""), -1) {
			seen[strings.ToLower(m[2])] = true
		}
	}
	var stale []string
	for table := range writable {
		if !seen[table] {
			stale = append(stale, table)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("writable permits %v, and nothing here writes them. Remove the entries: an "+
			"unused permission reads as precedent.", stale)
	}
}
