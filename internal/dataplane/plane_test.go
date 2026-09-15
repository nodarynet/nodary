package dataplane

import (
	"errors"
	"strings"
	"testing"
)

// Every install that predates the selector runs LiteLLM, so an absent
// `data_plane` key has to describe what is actually on the host rather than
// what a later release would prefer. Getting this backwards would move a
// running control plane onto a different data plane on the upgrade that
// introduced the key, without anybody asking for it.
func TestAnUnstatedPlaneIsTheOneEveryInstallAlreadyRuns(t *testing.T) {
	for _, in := range []string{"", "   ", "\n"} {
		p, err := Select(in)
		if err != nil {
			t.Fatalf("Select(%q): %v", in, err)
		}
		if p.Name != LiteLLM.Name {
			t.Errorf("Select(%q) = %q, want %q", in, p.Name, LiteLLM.Name)
		}
	}
	if Default().Name != LiteLLM.Name {
		t.Errorf("Default() = %q, want %q", Default().Name, LiteLLM.Name)
	}
}

// A name this build does not have is refused, not fallen back from. Falling
// back would start one data plane on a host whose operator wrote down another,
// and the symptom — inference works, just not with the retry, fallback or
// logging posture they chose — names nothing.
func TestAPlaneThisBuildDoesNotHaveIsRefusedByName(t *testing.T) {
	_, err := Select("vllm-direct")
	if !errors.Is(err, ErrUnknownPlane) {
		t.Fatalf("err = %v, want ErrUnknownPlane", err)
	}
	if !strings.Contains(err.Error(), "vllm-direct") {
		t.Errorf("the refusal does not name what was asked for: %v", err)
	}
	for _, have := range Names() {
		if !strings.Contains(err.Error(), have) {
			t.Errorf("the refusal does not name %q, which this build does have: %v", have, err)
		}
	}
}

// Every field is load-bearing somewhere — a plane with no unit installs
// nothing, one with no assertion writes an unchecked compliance surface — and
// a value half filled in fails a long way from here, on a host.
func TestEveryPlaneIsCompletelyDescribed(t *testing.T) {
	for _, p := range All() {
		for _, f := range []struct {
			name string
			set  bool
		}{
			{"Name", p.Name != ""},
			{"Component", p.Component != ""},
			{"Unit", strings.HasSuffix(p.Unit, ".service")},
			{"UnitBody", strings.Contains(p.UnitBody, "[Service]")},
			{"ConfigFile", p.ConfigFile != ""},
			{"EnvFile", p.EnvFile != ""},
			{"ImageVar", strings.HasPrefix(p.ImageVar, "NODARY_")},
			{"AppliedName", p.AppliedName != ""},
			{"ServedHeader", p.ServedHeader != ""},
			{"Render", p.Render != nil},
			{"Assert", p.Assert != nil},
		} {
			if !f.set {
				t.Errorf("plane %q: %s is not set", p.Name, f.name)
			}
		}
		// The unit has to expand the variable the pin is written under, or the
		// image an upgrade moves is not the image systemd starts.
		if !strings.Contains(p.UnitBody, "${"+p.ImageVar+"}") {
			t.Errorf("plane %q: the unit does not expand %s", p.Name, p.ImageVar)
		}
		// And it has to read the file that pin is written into.
		if !strings.Contains(p.UnitBody, p.EnvFile) {
			t.Errorf("plane %q: the unit does not load %s", p.Name, p.EnvFile)
		}
		// What Render produces must satisfy Assert. They are a pair: the
		// assertion exists because a renderer that dropped a pinned setting
		// would otherwise be indistinguishable from one that did not.
		if err := p.Assert(p.Render(Config{MasterKey: "k"})); err != nil {
			t.Errorf("plane %q renders something its own assertion refuses: %v", p.Name, err)
		}
	}
}

// Two planes sharing a file, a unit or a marker is how a host that switched
// ends up with one plane reading the other's configuration — or skipping a
// restart because the marker it compares against was written by something else.
func TestNoTwoPlanesShareAName(t *testing.T) {
	seen := map[string]string{}
	for _, p := range All() {
		for _, v := range []string{p.Name, p.Unit, p.ConfigFile, p.EnvFile, p.ImageVar, p.AppliedName} {
			if other, ok := seen[v]; ok {
				t.Errorf("%q is used by both %s and %s", v, other, p.Name)
			}
			seen[v] = p.Name
		}
	}
}
