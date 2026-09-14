package backend

import (
	"errors"
	"strings"
	"testing"
)

// fipsDerive is §5's own example: the case derived images exist for.
const fipsDerive = `
[backend]
name     = "vllm-fips"
inherits = "vllm"

[backend.derive]
from      = "vllm/vllm-openai@sha256:61fc8a896b0a4fbbbdc063bc4b0dbc25ce98e02b5050c24aeb7830ac02039b14"
steps     = ["pip install --no-cache-dir opencv-python-headless==4.12.0.88"]
index_url = "https://pypi.internal/simple"
timeout_s = 1800
`

func TestTheSpecsOwnDeriveParses(t *testing.T) {
	d, err := Parse([]byte(fipsDerive))
	if err != nil {
		t.Fatalf("§5's example does not parse: %v", err)
	}
	if d.Backend.Inherits != "vllm" || d.Backend.Derive == nil {
		t.Fatalf("not read as a derive: %+v", d.Backend)
	}
	if got := d.Backend.Derive.TimeoutS; got != 1800 {
		t.Errorf("timeout_s = %d", got)
	}
}

// The property R6-08 is for: a derive changes an image and nothing else, so a
// deployment of the derive is configured exactly as one of its parent is.
func TestADeriveInheritsEverythingButTheImage(t *testing.T) {
	parent, err := Get("vllm")
	if err != nil {
		t.Fatal(err)
	}
	child, err := Parse([]byte(fipsDerive))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Inherit(parent, child)
	if err != nil {
		t.Fatal(err)
	}

	if got.Backend.Name != "vllm-fips" {
		t.Errorf("name = %q", got.Backend.Name)
	}
	for _, c := range []struct{ what, want, have string }{
		{"api", parent.Backend.API, got.Backend.API},
		{"weights_layout", parent.Backend.WeightsLayout, got.Backend.WeightsLayout},
		{"mount_path", parent.Backend.MountPath, got.Backend.MountPath},
		{"probe.health", parent.Backend.Probe.Health, got.Backend.Probe.Health},
		{"args.model_path", parent.Backend.Args["model_path"], got.Backend.Args["model_path"]},
		{"args.tensor_parallel", parent.Backend.Args["tensor_parallel"], got.Backend.Args["tensor_parallel"]},
	} {
		if c.want == "" || c.have != c.want {
			t.Errorf("%s = %q, want the parent's %q", c.what, c.have, c.want)
		}
	}
	if got.Backend.ContainerPort != parent.Backend.ContainerPort {
		t.Errorf("container_port = %d", got.Backend.ContainerPort)
	}

	// **The image is cleared, not inherited.** Naming the base here would let a
	// deployment start on the uncorrected image — exactly what the derive
	// exists to prevent, reached by inheriting one field too many.
	if got.Backend.ImageDefault != "" {
		t.Errorf("image_default = %q; the served image is what the build produces",
			got.Backend.ImageDefault)
	}
	if got.Backend.Derive == nil || got.Backend.Derive.From != child.Backend.Derive.From {
		t.Error("the recipe did not survive inheritance")
	}
}

// A tag is refused for the reason the component manifest refuses one: a build
// whose input can change underneath it produces a record that means nothing.
func TestABaseImageMustBeDigestPinned(t *testing.T) {
	for _, from := range []string{
		"vllm/vllm-openai:v0.28.0",
		"vllm/vllm-openai",
		"vllm/vllm-openai@sha256:tooshort",
		"vllm/vllm-openai@md5:61fc8a896b0a4fbbbdc063bc4b0dbc25ce98e02b5050c24aeb7830ac02039b14",
	} {
		src := strings.Replace(fipsDerive,
			"vllm/vllm-openai@sha256:61fc8a896b0a4fbbbdc063bc4b0dbc25ce98e02b5050c24aeb7830ac02039b14",
			from, 1)
		if _, err := Parse([]byte(src)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q was accepted as a base image", from)
		}
	}
}

// Steps are an argv, not a shell. A pipe or a redirection would reach the
// program as an argument instead of doing what it looks like — a build that
// succeeds having done something other than what was written.
func TestAStepThatReadsLikeShellIsRefused(t *testing.T) {
	for _, step := range []string{
		"pip install foo | tee /tmp/log",
		"pip install foo && pip install bar",
		"sh -c 'pip install foo'",
		"pip install foo > /dev/null",
		"pip install $(cat req.txt)",
		"pip install `cat req.txt`",
		"pip install foo; rm -rf /",
	} {
		src := strings.Replace(fipsDerive,
			`"pip install --no-cache-dir opencv-python-headless==4.12.0.88"`,
			`"`+strings.ReplaceAll(step, `"`, `\"`)+`"`, 1)
		_, err := Parse([]byte(src))
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%q was accepted as a step", step)
			continue
		}
		if !strings.Contains(err.Error(), "argv, not a") {
			t.Errorf("%q: the refusal does not say why: %v", step, err)
		}
	}
}

// "The blast radius is an image and nothing else" is only true if a derive
// cannot set the things that would widen it. Refused rather than ignored: an
// operator who writes `args` and sees it accepted believes it took effect.
func TestADeriveMayNotIntroduceANewVocabulary(t *testing.T) {
	for what, extra := range map[string]string{
		"api":            `api = "triton"`,
		"weights_layout": `weights_layout = "single-file"`,
		"mount_path":     `mount_path = "/somewhere"`,
		"container_port": `container_port = 9999`,
		"image_default":  `image_default = "somewhere/else:latest"`,
		"args":           "[backend.args]\nmodel_path = \"--model {v}\"",
		"extra":          "[backend.extra]\nthing = \"--thing {v}\"",
		"probe":          "[backend.probe]\nhealth = \"/nope\"\nready = \"/nope\"\nready_timeout_s = 1",
		"capabilities":   "[backend.capabilities]\ntensor_parallel = true",
		"env":            "[backend.env]\nFOO = \"bar\"",
	} {
		src := fipsDerive + "\n" + extra + "\n"
		// The [backend] table has to stay contiguous for the scalar cases.
		if !strings.HasPrefix(extra, "[") {
			src = strings.Replace(fipsDerive, `inherits = "vllm"`,
				"inherits = \"vllm\"\n"+extra, 1)
		}
		_, err := Parse([]byte(src))
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("a derive setting %s was accepted", what)
			continue
		}
		if !strings.Contains(err.Error(), "may not set") {
			t.Errorf("%s: wrong refusal: %v", what, err)
		}
	}
}

// A derive with no steps is a copy of its base under a second name, and one
// with no recipe is a second name for its parent. Both are descriptors somebody
// wrote believing they did something.
func TestADeriveThatChangesNothingIsRefused(t *testing.T) {
	noSteps := strings.Replace(fipsDerive,
		`steps     = ["pip install --no-cache-dir opencv-python-headless==4.12.0.88"]`,
		`steps     = []`, 1)
	if _, err := Parse([]byte(noSteps)); !errors.Is(err, ErrInvalid) {
		t.Error("a derive with no steps was accepted")
	}

	noRecipe := "[backend]\nname = \"vllm-fips\"\ninherits = \"vllm\"\n"
	err := func() error { _, e := Parse([]byte(noRecipe)); return e }()
	if !errors.Is(err, ErrInvalid) {
		t.Error("`inherits` with no [backend.derive] was accepted")
	} else if !strings.Contains(err.Error(), "another name for vllm") {
		t.Errorf("the refusal does not say what it would be: %v", err)
	}
}

// A ceiling, for prepare.timeout_s's reason: without one a wedged build is
// indistinguishable from a slow one, forever.
func TestADeriveNeedsATimeout(t *testing.T) {
	for _, v := range []string{"timeout_s = 0", "timeout_s = -1"} {
		src := strings.Replace(fipsDerive, "timeout_s = 1800", v, 1)
		if _, err := Parse([]byte(src)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q was accepted", v)
		}
	}
}

// §5 says a derive varies a *built-in*. A chain would make "what does this
// backend do" a walk rather than a lookup, with no cycle detection anywhere.
func TestADeriveOfADeriveIsRefused(t *testing.T) {
	first, err := Parse([]byte(fipsDerive))
	if err != nil {
		t.Fatal(err)
	}
	second := strings.Replace(strings.Replace(fipsDerive,
		`name     = "vllm-fips"`, `name     = "vllm-fips-two"`, 1),
		`inherits = "vllm"`, `inherits = "vllm-fips"`, 1)
	child, err := Parse([]byte(second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inherit(first, child); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a derive of a derive resolved: %v", err)
	}

	// And inheriting itself, which is the one-step version of the same thing.
	selfish := strings.Replace(fipsDerive, `inherits = "vllm"`, `inherits = "vllm-fips"`, 1)
	if _, err := Parse([]byte(selfish)); !errors.Is(err, ErrInvalid) {
		t.Error("a derive that inherits itself was accepted")
	}
}

// Inherit is given a parent by name elsewhere; a mismatch is a caller bug that
// would otherwise produce a descriptor claiming a lineage it does not have.
func TestInheritRefusesTheWrongParent(t *testing.T) {
	sglang, err := Get("sglang")
	if err != nil {
		t.Fatal(err)
	}
	child, err := Parse([]byte(fipsDerive))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inherit(sglang, child); !errors.Is(err, ErrInvalid) {
		t.Error("a derive of vllm resolved against sglang")
	}
}
