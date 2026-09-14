package backend

import (
	"errors"
	"strings"
	"testing"
)

func recipe(t *testing.T, index string, steps ...string) Derive {
	t.Helper()
	quoted := make([]string, len(steps))
	for i, s := range steps {
		quoted[i] = `"` + s + `"`
	}
	src := `
[backend]
name     = "vllm-fips"
inherits = "vllm"

[backend.derive]
from      = "vllm/vllm-openai@sha256:61fc8a896b0a4fbbbdc063bc4b0dbc25ce98e02b5050c24aeb7830ac02039b14"
steps     = [` + strings.Join(quoted, ", ") + `]
` + index + `
timeout_s = 1800
`
	d, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	return *d.Backend.Derive
}

const anIndex = `index_url = "https://pypi.internal/simple"`

// §5's own example, which is the shape a regulated site is meant to write.
func TestThePinnedFormOfTheSpecsExampleIsAccepted(t *testing.T) {
	for _, step := range []string{
		"pip install --no-cache-dir opencv-python-headless==4.12.0.88",
		"pip3 install opencv-python-headless==4.12.0.88",
		"uv pip install opencv-python-headless==4.12.0.88",
		"apt-get install -y libssl3=3.0.11-1~deb12u2",
		"apk add openssl=3.1.4-r5",
		// Installs nothing, so it has no version to name. §5 requires an
		// exact version of *install* steps.
		"python -c pass",
		"ldconfig",
		// A flag's separate value is not a package.
		"pip install --index-url https://pypi.internal/simple numpy==2.1.0",
	} {
		if err := recipe(t, anIndex, step).Pinned(); err != nil {
			t.Errorf("%q was refused: %v", step, err)
		}
	}
}

// The property the flag exists for: a recipe that floats produces a different
// image next month, so the record R6-10 writes would attest an artifact nobody
// can rebuild.
func TestAnUnpinnedInstallIsRefused(t *testing.T) {
	for _, step := range []string{
		"pip install opencv-python-headless",
		"pip install --no-cache-dir numpy",
		"apt-get install -y libssl3",
		"apk add openssl",
		// The documented second spelling of pip. A gate that missed it would
		// be a gate with a way around it written in pip's own manual.
		"python -m pip install numpy",
		"python3 -m pip install numpy",
	} {
		err := recipe(t, anIndex, step).Pinned()
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%q was accepted as pinned", step)
			continue
		}
		if !strings.Contains(err.Error(), step) {
			t.Errorf("%q: the refusal does not name the step: %v", step, err)
		}
	}
}

// A gate that silently passes what it does not understand reports compliance it
// has not established.
func TestAStepThisBuildCannotCheckIsRefusedRatherThanPassed(t *testing.T) {
	for _, step := range []string{
		"curl -o /tmp/patch.tgz https://internal/patch.tgz",
		"wget https://internal/patch.tgz",
		"git clone https://internal/thing.git",
		"dnf install -y openssl",
		"npm install left-pad@1.3.0",
		"pip install -r requirements.txt",
		"pip install -e /src/thing",
	} {
		err := recipe(t, anIndex, step).Pinned()
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%q passed a gate that cannot check it", step)
			continue
		}
		// The reason matters as much as the refusal: an operator has to know
		// whether to pin something or to do it a different way.
		if !strings.Contains(err.Error(), "cannot") {
			t.Errorf("%q: the refusal does not say it could not be checked: %v", step, err)
		}
	}
}

// "index_url set" is half of what §5's policy row asks for. Without it a build
// resolves against whatever the container's default index is.
func TestAnIndexIsRequired(t *testing.T) {
	err := recipe(t, "", "pip install numpy==2.1.0").Pinned()
	if !errors.Is(err, ErrInvalid) {
		t.Fatal("a recipe with no index satisfied require_pinned_derives")
	}
	if !strings.Contains(err.Error(), "index_url") {
		t.Errorf("the refusal does not name the field: %v", err)
	}
}
