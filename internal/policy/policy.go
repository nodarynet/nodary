// Package policy parses and validates the policy profile that decides how much
// ceremony a mutation requires and how long evidence is kept.
//
// A profile is one reviewable object (docs/specs/07-identity-audit.md §4). That
// is why parsing is strict: a key nobody reads is a constraint an operator
// believes is in force, and the whole value of the object is that reading it
// tells you the posture. Unknown keys are refused rather than ignored.
//
// What a profile adjusts is ceremony and retention. It never decides whether a
// record exists.
package policy

import (
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed profiles/*.toml
var profiles embed.FS

// ErrInvalid is returned for every profile that will not load. Callers
// distinguish the reason by the message; the CLI maps all of them to the same
// exit code, because "this profile is not usable" is one outcome.
var ErrInvalid = errors.New("invalid policy profile")

// Profile is the whole posture. Every field maps to a key in
// docs/specs/07-identity-audit.md §4, and there are no fields that do not.
type Profile struct {
	Name string `toml:"name"`

	RequireTOTP            bool `toml:"require_totp"`
	RequireJustification   bool `toml:"require_justification"`
	MinJustificationLength int  `toml:"min_justification_length"`
	RequireSignedArtifacts bool `toml:"require_signed_artifacts"`
	AllowUnattendedTokens  bool `toml:"allow_unattended_tokens"`
	AllowCustomBackends    bool `toml:"allow_custom_backends"`
	AllowDerivedImages     bool `toml:"allow_derived_images"`
	RequirePinnedDerives   bool `toml:"require_pinned_derives"`

	EgressDefault        string   `toml:"egress_default"`
	ModelOriginAllowlist []string `toml:"model_origin_allowlist"`
	ModelOriginDenylist  []string `toml:"model_origin_denylist"`
	RequireModelManifest bool     `toml:"require_model_manifest"`

	AuditRetentionDays int `toml:"audit_retention_days"`
	UsageRetentionDays int `toml:"usage_retention_days"`
	SessionTTLMinutes  int `toml:"session_ttl_minutes"`
	TokenMaxTTLDays    int `toml:"token_max_ttl_days"`
}

type document struct {
	Policy Profile `toml:"policy"`
}

// notSettings are the properties a profile cannot turn off, keyed by the name
// somebody would plausibly reach for when trying.
//
// They have no fields above, so they would already fail as unknown keys. The
// generic message would be "unknown key", which is a poor answer to somebody
// who just tried to disable the audit chain: it reads as a typo rather than as
// a refusal. docs/specs/07-identity-audit.md §4 lists five such properties;
// intent_hash, digest pinning and the chain itself are here because they are
// not expressible, while require_signed_artifacts and egress_default are real
// keys checked in validate below.
var notSettings = map[string]string{
	"audit_chain":       "the audit chain is not a setting: no profile disables it",
	"require_audit":     "the audit chain is not a setting: no profile disables it",
	"audit_enabled":     "the audit chain is not a setting: no profile disables it",
	"intent_hash":       "intent_hash binding is not a setting: no profile disables it",
	"require_intent":    "intent_hash binding is not a setting: no profile disables it",
	"digest_pinning":    "component digest pinning is not a setting: no profile disables it",
	"pinned_components": "component digest pinning is not a setting: no profile disables it",
	"egress_isolation":  "egress isolation is not a setting: use egress_default, which must stay \"deny\"",
}

// Parse reads a profile and refuses anything it does not fully understand.
func Parse(src []byte) (Profile, error) {
	var doc document
	md, err := toml.Decode(string(src), &doc)
	if err != nil {
		return Profile{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}

	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
			// The leaf is what an operator typed; match on it so
			// "policy.audit_chain" and "audit_chain" both explain themselves.
			leaf := k[len(k)-1]
			if why, ok := notSettings[leaf]; ok {
				return Profile{}, fmt.Errorf("%w: %s", ErrInvalid, why)
			}
		}
		sort.Strings(keys)
		return Profile{}, fmt.Errorf("%w: unknown %s %s — a profile is reviewed by reading it, so a key nobody applies is refused rather than ignored",
			ErrInvalid, plural("key", len(keys)), strings.Join(keys, ", "))
	}

	p := doc.Policy
	if err := p.validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// validate enforces the invariants no profile may turn off, and the ranges that
// would otherwise be nonsense.
func (p Profile) validate() error {
	switch {
	case strings.TrimSpace(p.Name) == "":
		return fmt.Errorf("%w: name is required — a profile is cited in audit records by name", ErrInvalid)

	// docs/specs/07-identity-audit.md §4: the two invariants a plausible
	// profile could actually contain, as opposed to the three that have no key.
	case !p.RequireSignedArtifacts:
		return fmt.Errorf("%w: require_signed_artifacts cannot be false — signature and digest verification is not a posture", ErrInvalid)
	case p.EgressDefault != "deny":
		return fmt.Errorf("%w: egress_default must be \"deny\", not %q — egress isolation for serving deployments is not a posture", ErrInvalid, p.EgressDefault)

	case p.MinJustificationLength < 0:
		return fmt.Errorf("%w: min_justification_length cannot be negative", ErrInvalid)
	case p.AuditRetentionDays < 1:
		return fmt.Errorf("%w: audit_retention_days must be at least 1", ErrInvalid)
	case p.UsageRetentionDays < 1:
		return fmt.Errorf("%w: usage_retention_days must be at least 1", ErrInvalid)
	case p.SessionTTLMinutes < 1:
		return fmt.Errorf("%w: session_ttl_minutes must be at least 1", ErrInvalid)
	case p.TokenMaxTTLDays < 1:
		return fmt.Errorf("%w: token_max_ttl_days must be at least 1", ErrInvalid)
	}
	for _, o := range append(append([]string{}, p.ModelOriginAllowlist...), p.ModelOriginDenylist...) {
		if strings.TrimSpace(o) == "" {
			return fmt.Errorf("%w: a model origin cannot be blank", ErrInvalid)
		}
	}
	return nil
}

// Builtin returns one of the profiles shipped in the binary.
//
// docs/specs/07-identity-audit.md §4 makes `default` the profile a fresh
// install runs, because a first-run experience that demands a TOTP code before
// a user exists converts nobody.
func Builtin(name string) (Profile, []byte, error) {
	src, err := profiles.ReadFile("profiles/" + name + ".toml")
	if err != nil {
		return Profile{}, nil, fmt.Errorf("%w: no built-in profile %q (have %s)",
			ErrInvalid, name, strings.Join(BuiltinNames(), ", "))
	}
	p, err := Parse(src)
	if err != nil {
		return Profile{}, nil, err
	}
	return p, src, nil
}

// BuiltinNames lists the shipped profiles, in the order they are presented.
func BuiltinNames() []string { return []string{"default", "regulated"} }

// Default is the profile a fresh install runs.
const Default = "default"

func plural(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
