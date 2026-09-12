package policy

import (
	"strings"
	"testing"
)

// An adoption review grepped for enforcement sites and found eleven of sixteen
// settings with none, which is the right measurement and the wrong conclusion
// for two of them: `require_signed_artifacts` and `egress_default` are refused
// at parse if set to anything else, and the mechanisms behind them run
// unconditionally. Nothing reads those fields because nothing needs to.
//
// A third, `token_max_ttl_days`, was genuinely unenforced and is now enforced
// (R1-37), which leaves eight that can vary with nothing acting on them. That
// is the number the display has to carry, and the arithmetic here is the point:
// these counts move only when somebody deliberately moves them.
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
	if got := len(Unenforced()); got != 8 {
		t.Errorf("%d settings are unenforced, the display and the README say 8: %v", got, Unenforced())
	}
	if enforcedN != 6 || invariantN != 2 {
		t.Errorf("enforced = %d, invariant = %d; want 6 and 2", enforcedN, invariantN)
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
	if len(standing) != 10 {
		t.Errorf("Standing() carries %d annotations, want 10 (8 unenforced + 2 invariants)", len(standing))
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
