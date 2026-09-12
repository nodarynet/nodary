package policy

import (
	"fmt"
	"slices"
	"strings"
)

// Change is one setting that differs between two profiles.
type Change struct {
	Setting string
	From    string
	To      string
	// Loosens reports whether the candidate permits something the active
	// profile did not, or keeps evidence for less time.
	Loosens bool
}

func (c Change) String() string {
	s := fmt.Sprintf("%s: %s -> %s", c.Setting, c.From, c.To)
	if c.Loosens {
		s += "  (loosens)"
	}
	return s
}

// field is one comparable setting. Keeping the direction of "looser" beside the
// value it belongs to is what stops the two drifting apart: a new setting adds
// one row and cannot be added without saying which way is looser.
//
// standing carries the same idea one step further. A profile is read as a list
// of controls, so a setting nothing acts on has to say so where it is displayed
// — an operator cannot tell a ceiling from a label by looking at the number. It
// is the stub discipline in docs/plans/mvp.md §3 applied to a setting rather
// than a verb: what is not in force names the task that will put it there.
type field struct {
	name    string
	show    func(Profile) string
	loosens func(a, b Profile) bool
	// standing is empty when something outside this package acts on the
	// setting, and otherwise says what its status actually is.
	standing string
}

// The three things a setting's standing can be. Anything enforced carries no
// annotation, because an unmarked row is the common case and the display is
// already dense.
const (
	// enforced: something outside this package reads the setting and acts on
	// it. Spelled rather than left blank so that every row states its standing
	// and a new one cannot be added without choosing.
	enforced = ""
	// pending: the setting can vary, the feature it governs exists or is
	// coming, and nothing reads it yet. Always followed by a task number.
	pending = "not enforced · "
	// invariant: the setting cannot vary — Profile.validate refuses every
	// other value — and the mechanism implements that one value
	// unconditionally. Nothing reads the field because nothing needs to.
	invariant = "invariant · "
)

// requireLoosens: a `require_` switch loosens when it stops requiring.
func requireLoosens(get func(Profile) bool) func(a, b Profile) bool {
	return func(a, b Profile) bool { return get(a) && !get(b) }
}

// allowLoosens: an `allow_` switch loosens when it starts allowing.
func allowLoosens(get func(Profile) bool) func(a, b Profile) bool {
	return func(a, b Profile) bool { return !get(a) && get(b) }
}

func lowerLoosens(get func(Profile) int) func(a, b Profile) bool {
	return func(a, b Profile) bool { return get(b) < get(a) }
}

func higherLoosens(get func(Profile) int) func(a, b Profile) bool {
	return func(a, b Profile) bool { return get(b) > get(a) }
}

func showBool(get func(Profile) bool) func(Profile) string {
	return func(p Profile) string {
		if get(p) {
			return "true"
		}
		return "false"
	}
}

func showInt(get func(Profile) int) func(Profile) string {
	return func(p Profile) string { return fmt.Sprint(get(p)) }
}

// showList takes the label for the empty case, because empty means opposite
// things either side: an empty allowlist permits every origin, an empty
// denylist refuses none.
func showList(get func(Profile) []string, whenEmpty string) func(Profile) string {
	return func(p Profile) string {
		v := get(p)
		if len(v) == 0 {
			return "[] (" + whenEmpty + ")"
		}
		return "[" + strings.Join(v, ", ") + "]"
	}
}

// fields is every setting a profile carries. A setting missing here would
// silently never appear in a diff, which is the failure `policy diff` exists to
// prevent, so the test asserts the count against the struct.
//
// The fourth column is what acts on the setting. It is here rather than in a
// document because a list kept somewhere else goes stale silently, and the test
// that pins it makes the honest answer the cheap one: a new setting has to
// declare whether anything reads it.
var fields = []field{
	{"require_totp", showBool(func(p Profile) bool { return p.RequireTOTP }), requireLoosens(func(p Profile) bool { return p.RequireTOTP }), enforced},
	{"require_justification", showBool(func(p Profile) bool { return p.RequireJustification }), requireLoosens(func(p Profile) bool { return p.RequireJustification }), enforced},
	{"min_justification_length", showInt(func(p Profile) int { return p.MinJustificationLength }), lowerLoosens(func(p Profile) int { return p.MinJustificationLength }), enforced},
	{"require_signed_artifacts", showBool(func(p Profile) bool { return p.RequireSignedArtifacts }), requireLoosens(func(p Profile) bool { return p.RequireSignedArtifacts }), invariant + "refused if false; digests are checked unconditionally"},
	{"allow_unattended_tokens", showBool(func(p Profile) bool { return p.AllowUnattendedTokens }), allowLoosens(func(p Profile) bool { return p.AllowUnattendedTokens }), enforced},
	{"allow_custom_backends", showBool(func(p Profile) bool { return p.AllowCustomBackends }), allowLoosens(func(p Profile) bool { return p.AllowCustomBackends }), pending + "R6-07"},
	{"allow_derived_images", showBool(func(p Profile) bool { return p.AllowDerivedImages }), allowLoosens(func(p Profile) bool { return p.AllowDerivedImages }), pending + "R6-08"},
	{"require_pinned_derives", showBool(func(p Profile) bool { return p.RequirePinnedDerives }), requireLoosens(func(p Profile) bool { return p.RequirePinnedDerives }), pending + "R6-11"},
	{"egress_default", func(p Profile) string { return p.EgressDefault }, func(a, b Profile) bool { return false }, invariant + `refused if not "deny"; isolation is unconditional`},
	{"model_origin_allowlist", showList(func(p Profile) []string { return p.ModelOriginAllowlist }, "any origin"), allowlistLoosens, pending + "R4-32"},
	{"model_origin_denylist", showList(func(p Profile) []string { return p.ModelOriginDenylist }, "none denied"), denylistLoosens, pending + "R4-32"},
	{"require_model_manifest", showBool(func(p Profile) bool { return p.RequireModelManifest }), requireLoosens(func(p Profile) bool { return p.RequireModelManifest }), pending + "R4-31"},
	{"audit_retention_days", showInt(func(p Profile) int { return p.AuditRetentionDays }), lowerLoosens(func(p Profile) int { return p.AuditRetentionDays }), pending + "R2-14"},
	{"usage_retention_days", showInt(func(p Profile) int { return p.UsageRetentionDays }), lowerLoosens(func(p Profile) int { return p.UsageRetentionDays }), pending + "R3-13"},
	{"session_ttl_minutes", showInt(func(p Profile) int { return p.SessionTTLMinutes }), higherLoosens(func(p Profile) int { return p.SessionTTLMinutes }), enforced},
	{"token_max_ttl_days", showInt(func(p Profile) int { return p.TokenMaxTTLDays }), higherLoosens(func(p Profile) int { return p.TokenMaxTTLDays }), enforced},
}

// An empty allowlist means any origin, so emptying one is the loosest move
// available and filling one in is a tightening.
func allowlistLoosens(a, b Profile) bool {
	if len(b.ModelOriginAllowlist) == 0 {
		return len(a.ModelOriginAllowlist) > 0
	}
	if len(a.ModelOriginAllowlist) == 0 {
		return false
	}
	return addsAny(a.ModelOriginAllowlist, b.ModelOriginAllowlist)
}

// A denylist loosens when something stops being denied.
func denylistLoosens(a, b Profile) bool {
	return addsAny(b.ModelOriginDenylist, a.ModelOriginDenylist)
}

// addsAny reports whether to contains an entry from is missing.
func addsAny(from, to []string) bool {
	for _, v := range to {
		if !slices.Contains(from, v) {
			return true
		}
	}
	return false
}

// Diff reports every setting that differs, and which of them loosen.
//
// docs/specs/07-identity-audit.md §4: loosening is permitted; doing it silently
// is not.
func Diff(active, candidate Profile) []Change {
	var out []Change
	for _, f := range fields {
		from, to := f.show(active), f.show(candidate)
		if from == to {
			continue
		}
		out = append(out, Change{Setting: f.name, From: from, To: to, Loosens: f.loosens(active, candidate)})
	}
	return out
}

// Loosens reports whether any change in a diff relaxes the posture.
func Loosens(changes []Change) bool {
	return slices.ContainsFunc(changes, func(c Change) bool { return c.Loosens })
}

// Describe renders every setting, in the order docs/specs/07-identity-audit.md
// §4 presents them.
//
// It walks the same table Diff does, so a setting cannot appear in one and be
// missing from the other.
//
// A setting nothing acts on is marked. The alternative — showing sixteen
// numbers and letting the reader assume all sixteen are in force — is how a
// system security plan ends up citing a control that is a label, which is worse
// for the person who wrote it down than having no tool at all.
func Describe(p Profile) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = fmt.Sprintf("%-24s %-28s", f.name, f.show(p))
		if f.standing != "" {
			out[i] += "(" + f.standing + ")"
		}
		out[i] = strings.TrimRight(out[i], " ")
	}
	return out
}

// Standing reports what acts on each setting, keyed by setting name, for
// callers that render the profile themselves. An absent key means enforced.
//
// `policy show --format json` is read by scripts and by whoever assembles an
// SSP, and a caveat only the text renderer carries is a caveat that does not
// reach them.
// Unenforced names the settings nothing acts on yet, in display order.
//
// Narrower than Standing: an invariant is annotated but is in force, so
// counting it as unenforced would understate the product in the other
// direction.
func Unenforced() []string {
	var out []string
	for _, f := range fields {
		if strings.HasPrefix(f.standing, pending) {
			out = append(out, f.name)
		}
	}
	return out
}

func Standing() map[string]string {
	out := map[string]string{}
	for _, f := range fields {
		if f.standing != "" {
			out[f.name] = f.standing
		}
	}
	return out
}
