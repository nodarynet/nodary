package policy

import (
	"errors"
	"strings"
	"testing"
)

func profile(allow, deny []string) Profile {
	return Profile{Name: "test", ModelOriginAllowlist: allow, ModelOriginDenylist: deny}
}

func TestDeniesOrigin(t *testing.T) {
	for _, c := range []struct {
		name     string
		p        Profile
		org      string
		country  string
		denied   bool
		mentions string
	}{
		{"no lists allows anything", profile(nil, nil), "google", "US", false, ""},
		{"no lists allows an undeclared origin", profile(nil, nil), "", "", false, ""},

		{"a denied country", profile(nil, []string{"CN"}), "acme", "CN", true, "denylist"},
		{"a denied org", profile(nil, []string{"acme"}), "acme", "US", true, "denylist"},
		{"an unlisted origin passes a denylist", profile(nil, []string{"CN"}), "google", "US", false, ""},

		// A control anybody defeats by holding shift is worse than no control,
		// because it reads as one.
		{"case does not defeat a denylist", profile(nil, []string{"CN"}), "", "cn", true, "denylist"},
		{"case does not defeat an allowlist", profile([]string{"US"}, nil), "", "us", false, ""},
		{"surrounding space does not defeat a denylist", profile(nil, []string{" CN "}), "", "CN", true, "denylist"},

		{"an allowlisted country", profile([]string{"US", "GB"}, nil), "google", "US", false, ""},
		{"an allowlisted org", profile([]string{"google"}, nil), "google", "IE", false, ""},
		{"an origin outside the allowlist", profile([]string{"US"}, nil), "acme", "CN", true, "acme (CN)"},

		// Leaving the flag off is the easiest bypass in the world to reach for.
		{"an undeclared origin fails an allowlist", profile([]string{"US"}, nil), "", "", true, "declares no origin"},

		// A profile that contradicts itself fails closed.
		{"the denylist wins over the allowlist", profile([]string{"CN"}, []string{"CN"}), "", "CN", true, "denylist"},

		// An empty half is not a wildcard.
		{"an empty country does not match an entry", profile(nil, []string{"CN"}), "google", "", false, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.p.DeniesOrigin(c.org, c.country)
			if c.denied != (err != nil) {
				t.Fatalf("DeniesOrigin(%q, %q) = %v, denied should be %t", c.org, c.country, err, c.denied)
			}
			if err == nil {
				return
			}
			if !errors.Is(err, ErrOriginDenied) {
				t.Errorf("error does not wrap ErrOriginDenied: %v", err)
			}
			if !strings.Contains(err.Error(), c.mentions) {
				t.Errorf("refusal does not say %q: %v", c.mentions, err)
			}
		})
	}
}

// The refusal has to be actionable on its own: an operator reading it in an
// audit record months later has neither the profile nor the command in front
// of them.
func TestARefusalNamesTheProfileAndWhatItAllows(t *testing.T) {
	err := profile([]string{"US", "GB"}, nil).DeniesOrigin("acme", "CN")
	for _, want := range []string{"test", "US, GB", "acme (CN)"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
}
