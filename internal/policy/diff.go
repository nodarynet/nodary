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
type field struct {
	name    string
	show    func(Profile) string
	loosens func(a, b Profile) bool
}

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
var fields = []field{
	{"require_totp", showBool(func(p Profile) bool { return p.RequireTOTP }), requireLoosens(func(p Profile) bool { return p.RequireTOTP })},
	{"require_justification", showBool(func(p Profile) bool { return p.RequireJustification }), requireLoosens(func(p Profile) bool { return p.RequireJustification })},
	{"min_justification_length", showInt(func(p Profile) int { return p.MinJustificationLength }), lowerLoosens(func(p Profile) int { return p.MinJustificationLength })},
	{"require_signed_artifacts", showBool(func(p Profile) bool { return p.RequireSignedArtifacts }), requireLoosens(func(p Profile) bool { return p.RequireSignedArtifacts })},
	{"allow_unattended_tokens", showBool(func(p Profile) bool { return p.AllowUnattendedTokens }), allowLoosens(func(p Profile) bool { return p.AllowUnattendedTokens })},
	{"allow_custom_backends", showBool(func(p Profile) bool { return p.AllowCustomBackends }), allowLoosens(func(p Profile) bool { return p.AllowCustomBackends })},
	{"allow_derived_images", showBool(func(p Profile) bool { return p.AllowDerivedImages }), allowLoosens(func(p Profile) bool { return p.AllowDerivedImages })},
	{"require_pinned_derives", showBool(func(p Profile) bool { return p.RequirePinnedDerives }), requireLoosens(func(p Profile) bool { return p.RequirePinnedDerives })},
	{"egress_default", func(p Profile) string { return p.EgressDefault }, func(a, b Profile) bool { return false }},
	{"model_origin_allowlist", showList(func(p Profile) []string { return p.ModelOriginAllowlist }, "any origin"), allowlistLoosens},
	{"model_origin_denylist", showList(func(p Profile) []string { return p.ModelOriginDenylist }, "none denied"), denylistLoosens},
	{"require_model_manifest", showBool(func(p Profile) bool { return p.RequireModelManifest }), requireLoosens(func(p Profile) bool { return p.RequireModelManifest })},
	{"audit_retention_days", showInt(func(p Profile) int { return p.AuditRetentionDays }), lowerLoosens(func(p Profile) int { return p.AuditRetentionDays })},
	{"usage_retention_days", showInt(func(p Profile) int { return p.UsageRetentionDays }), lowerLoosens(func(p Profile) int { return p.UsageRetentionDays })},
	{"session_ttl_minutes", showInt(func(p Profile) int { return p.SessionTTLMinutes }), higherLoosens(func(p Profile) int { return p.SessionTTLMinutes })},
	{"token_max_ttl_days", showInt(func(p Profile) int { return p.TokenMaxTTLDays }), higherLoosens(func(p Profile) int { return p.TokenMaxTTLDays })},
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
func Describe(p Profile) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = fmt.Sprintf("%-24s %s", f.name, f.show(p))
	}
	return out
}
