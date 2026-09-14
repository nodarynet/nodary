package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An adoption review grepped for enforcement sites and found eleven of sixteen
// settings with none, which is the right measurement and the wrong conclusion
// for two of them: `require_signed_artifacts` and `egress_default` are refused
// at parse if set to anything else, and the mechanisms behind them run
// unconditionally. Nothing reads those fields because nothing needs to.
//
// The rest were genuinely unenforced and have been enforced one task at a time
// since -- `token_max_ttl_days` by R1-37, `allow_custom_backends` by R6-07 --
// which leaves three that can vary with nothing acting on them. That is the
// number the display has to carry, and the arithmetic here is the point: these
// counts move only when somebody deliberately moves them.
func TestEverySettingSaysWhetherAnythingActsOnIt(t *testing.T) {
	var enforcedN, invariantN int
	for _, f := range fields {
		switch {
		case f.standing == enforced:
			enforcedN++
		case strings.HasPrefix(f.standing, invariant):
			invariantN++
		case strings.HasPrefix(f.standing, pending):
			// docs/plans/mvp.md §3: a stub nobody numbered is scope nobody
			// agreed to. The same rule, applied to a setting.
			task := strings.TrimPrefix(f.standing, pending)
			if !isTaskNumber(task) {
				t.Errorf("%s is not enforced and names %q rather than a task", f.name, task)
			}
		default:
			t.Errorf("%s carries an unrecognized standing %q", f.name, f.standing)
		}
	}
	if got := len(Unenforced()); got != 3 {
		t.Errorf("%d settings are unenforced, the display and the README say 3: %v", got, Unenforced())
	}
	if enforcedN != 11 || invariantN != 2 {
		t.Errorf("enforced = %d, invariant = %d; want 11 and 2", enforcedN, invariantN)
	}
}

// isTaskNumber matches R4-32 and the like.
func isTaskNumber(s string) bool {
	n, ok := strings.CutPrefix(s, "R")
	if !ok {
		return false
	}
	milestone, task, ok := strings.Cut(n, "-")
	return ok && len(milestone) == 1 && digits(milestone) && len(task) == 2 && digits(task)
}

func digits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// Whatever the text renderer marks, the JSON form marks too. `policy show
// --format json` is what gets scripted and what gets pasted into a system
// security plan, so a caveat it does not carry is a caveat nobody sees.
func TestTheMarkingSurvivesEveryRendering(t *testing.T) {
	p, _, err := Builtin("regulated")
	if err != nil {
		t.Fatal(err)
	}
	standing, lines := Standing(), Describe(p)
	if len(standing) != 5 {
		t.Errorf("Standing() carries %d annotations, want 5 (3 unenforced + 2 invariants)", len(standing))
	}
	for name, note := range standing {
		var found bool
		for _, l := range lines {
			if strings.HasPrefix(l, name+" ") && strings.Contains(l, note) {
				found = true
			}
		}
		if !found {
			t.Errorf("Describe does not carry %s's standing %q", name, note)
		}
	}
	// And an enforced setting is displayed with no caveat at all.
	for _, l := range lines {
		if strings.HasPrefix(l, "require_totp ") && strings.Contains(l, "(") {
			t.Errorf("require_totp is enforced and should carry no annotation: %q", l)
		}
	}
}

// The administering guide states the count in prose, and prose goes stale in
// exactly the way a marked setting must not: a reader is told four settings are
// unenforced, counts six in `policy show`, and now distrusts both. Pinned here
// rather than in the guide's own package because this is where the number is
// decided.
func TestTheGuideSaysHowManySettingsAreUnmarked(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "site", "administering.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%s of\nits sixteen settings are marked today", spellOut(len(Unenforced())))
	if !strings.Contains(string(body), want) {
		t.Errorf("the administering guide does not say %q; %d settings are unenforced: %v",
			want, len(Unenforced()), Unenforced())
	}
}

func spellOut(n int) string {
	words := []string{"Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight",
		"Nine", "Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen"}
	if n < len(words) {
		return words[n]
	}
	return fmt.Sprint(n)
}
