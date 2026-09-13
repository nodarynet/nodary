package policy

import (
	"errors"
	"fmt"
	"strings"
)

// ErrOriginDenied is a model whose provenance the active profile refuses.
var ErrOriginDenied = errors.New("model origin denied by policy")

// DeniesOrigin reports why a profile refuses a model's provenance, or nil.
//
// docs/specs/05-catalog.md §2 checks both `origin_org` and `origin_country`
// against the same two lists, so an entry is whichever of the two an operator
// wrote — "CN" and "google" both work, and neither list has a format.
//
// **Case-insensitive, and that is not a nicety.** A denylist of ["CN"] that a
// `--origin-country cn` slipped past would be a control anybody defeats by
// holding shift, which is worse than no control because it reads as one.
//
// **The denylist wins.** An origin on both lists is denied: a profile that
// contradicts itself should fail closed, and an operator who wrote an origin
// into a denylist expressed the more specific intent.
//
// **An undeclared origin fails a non-empty allowlist.** Otherwise the whole
// control is bypassed by leaving the flag off, which is the easiest thing in
// the world to do by accident and the easiest to do on purpose.
func (p Profile) DeniesOrigin(org, country string) error {
	org, country = strings.TrimSpace(org), strings.TrimSpace(country)

	for _, denied := range p.ModelOriginDenylist {
		if matches(denied, org, country) {
			return fmt.Errorf("%w: %q is on %s's denylist", ErrOriginDenied, denied, p.Name)
		}
	}
	if len(p.ModelOriginAllowlist) == 0 {
		return nil // docs/specs/07-identity-audit.md §4: empty means any origin
	}

	if org == "" && country == "" {
		return fmt.Errorf("%w: %s allows only %s, and this model declares no origin — "+
			"pass --origin-org and --origin-country",
			ErrOriginDenied, p.Name, strings.Join(p.ModelOriginAllowlist, ", "))
	}
	for _, allowed := range p.ModelOriginAllowlist {
		if matches(allowed, org, country) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s allows only %s, and this model declares %s",
		ErrOriginDenied, p.Name, strings.Join(p.ModelOriginAllowlist, ", "), describeOrigin(org, country))
}

// matches reports whether a list entry names either half of an origin. An empty
// half matches nothing: a model that declares no country is not thereby from
// every country, nor from none in particular.
func matches(entry, org, country string) bool {
	if entry = strings.TrimSpace(entry); entry == "" {
		return false
	}
	return (org != "" && strings.EqualFold(entry, org)) ||
		(country != "" && strings.EqualFold(entry, country))
}

// describeOrigin renders what a model claims, for a refusal that has to be
// actionable without the reader going to look the entry up.
func describeOrigin(org, country string) string {
	switch {
	case org != "" && country != "":
		return fmt.Sprintf("%s (%s)", org, country)
	case org != "":
		return "org " + org
	default:
		return "country " + country
	}
}
