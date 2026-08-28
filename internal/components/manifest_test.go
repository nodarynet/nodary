package components

import (
	"strings"
	"testing"
)

// TestEmbeddedManifestIsValid is the guard that matters: the manifest shipped
// in this binary must satisfy every structural rule install-time verification
// assumes. A regression here is a broken release, not a broken test.
func TestEmbeddedManifestIsValid(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if errs := m.Validate(); len(errs) > 0 {
		for _, e := range errs {
			t.Errorf("validate: %v", e)
		}
	}
	if len(m.Components) == 0 {
		t.Fatal("embedded manifest has no components")
	}
	if m.NodaryVersion == "" {
		t.Error("embedded manifest has no nodary_version")
	}
}

// Install-time components must build for both Linux platforms nodary
// supports; a half-populated one would install on amd64 and mysteriously fail
// on arm64.
//
// Backends are exempt: upstream genuinely ships some model-server images for
// amd64 only, and the manifest records what exists rather than what we would
// prefer to exist.
func TestEmbeddedManifestCoversSupportedPlatforms(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, c := range m.Components {
		if c.Group == GroupBackend {
			continue
		}
		for _, p := range []string{"linux/amd64", "linux/arm64"} {
			if _, ok := c.Platforms[p]; !ok {
				t.Errorf("component %s missing platform %s", c.Name, p)
			}
		}
	}
}

// Backends must never appear in a --components selection: they are gigabytes
// each and are chosen by which models a site enables.
func TestSelectExcludesBackends(t *testing.T) {
	m, _ := Load()
	if len(m.Backends()) == 0 {
		t.Fatal("no backends in the manifest to test against")
	}
	for _, spec := range []string{"all", "minimal", ""} {
		got, err := m.Select(RoleNode, spec)
		if err != nil {
			t.Fatalf("select %q: %v", spec, err)
		}
		for _, c := range got {
			if c.Group == GroupBackend {
				t.Errorf("--components %q selected backend %s", spec, c.Name)
			}
		}
	}
}

func TestSelectBackends(t *testing.T) {
	m, _ := Load()

	none, err := m.SelectBackends("")
	if err != nil || len(none) != 0 {
		t.Errorf("empty spec should select nothing, got %d (%v)", len(none), err)
	}

	all, err := m.SelectBackends("all")
	if err != nil {
		t.Fatalf("select all backends: %v", err)
	}
	if len(all) != len(m.Backends()) {
		t.Errorf("all selected %d of %d backends", len(all), len(m.Backends()))
	}

	one, err := m.SelectBackends("vllm")
	if err != nil {
		t.Fatalf("select vllm: %v", err)
	}
	if len(one) != 1 || one[0].Name != "vllm" {
		t.Errorf("expected exactly vllm, got %v", one)
	}

	// An unknown backend must list what is available rather than just refusing.
	_, err = m.SelectBackends("nonesuch")
	if err == nil {
		t.Fatal("expected an error for an unknown backend")
	}
	if !strings.Contains(err.Error(), "have:") {
		t.Errorf("error should list available backends, got: %v", err)
	}
}

// Every backend image in the manifest should correspond to a descriptor nodary
// actually ships, or it is dead weight in the mirror.
func TestBackendsAreDigestPinned(t *testing.T) {
	m, _ := Load()
	for _, c := range m.Backends() {
		if c.Kind != KindImage {
			t.Errorf("backend %s is kind %q, want image", c.Name, c.Kind)
		}
		for plat, a := range c.Platforms {
			if !strings.Contains(a.Image, "@sha256:") {
				t.Errorf("backend %s [%s] is not digest-pinned", c.Name, plat)
			}
		}
	}
}

func TestValidateRejectsUnpinnedImage(t *testing.T) {
	m := &Manifest{Schema: SchemaVersion, Components: []Component{{
		Name: "x", Version: "1", Kind: KindImage, Roles: []Role{RoleServer}, Group: GroupCore,
		Platforms: map[string]Artifact{"linux/amd64": {Image: "prom/prometheus:latest"}},
	}}}
	errs := m.Validate()
	if len(errs) == 0 {
		t.Fatal("expected an error for a tag-only image reference")
	}
	if !strings.Contains(errs[0].Error(), "digest-pinned") {
		t.Errorf("error should name the missing pin, got: %v", errs[0])
	}
}

func TestValidateRejectsBadDigestAndScheme(t *testing.T) {
	cases := map[string]Artifact{
		"short digest": {URL: "https://example.com/x.tgz", SHA256: "abc"},
		"http url":     {URL: "http://example.com/x.tgz", SHA256: strings.Repeat("a", 64)},
		"missing url":  {SHA256: strings.Repeat("a", 64)},
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			m := &Manifest{Schema: SchemaVersion, Components: []Component{{
				Name: "x", Version: "1", Kind: KindArchive, Roles: []Role{RoleNode},
				Group: GroupRuntime, Platforms: map[string]Artifact{"linux/amd64": a},
			}}}
			if errs := m.Validate(); len(errs) == 0 {
				t.Error("expected a validation error")
			}
		})
	}
}

func TestValidateRejectsDuplicateNames(t *testing.T) {
	c := Component{
		Name: "dup", Version: "1", Kind: KindBinary, Roles: []Role{RoleNode}, Group: GroupRuntime,
		Platforms: map[string]Artifact{"linux/amd64": {
			URL: "https://example.com/x", SHA256: strings.Repeat("b", 64)}},
	}
	m := &Manifest{Schema: SchemaVersion, Components: []Component{c, c}}
	found := false
	for _, e := range m.Validate() {
		if strings.Contains(e.Error(), "duplicate") {
			found = true
		}
	}
	if !found {
		t.Error("expected a duplicate-name error")
	}
}

func TestSelect(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	all, err := m.Select(RoleServer, "all")
	if err != nil {
		t.Fatalf("select all: %v", err)
	}
	minimal, err := m.Select(RoleServer, "minimal")
	if err != nil {
		t.Fatalf("select minimal: %v", err)
	}
	if len(minimal) >= len(all) {
		t.Errorf("minimal (%d) should be a strict subset of all (%d)", len(minimal), len(all))
	}
	if len(minimal) == 0 {
		t.Error("minimal server selection is empty")
	}

	// An empty spec must behave as minimal rather than as everything: an
	// install that quietly pulls observability nobody asked for is a surprise.
	def, err := m.Select(RoleServer, "")
	if err != nil {
		t.Fatalf("select default: %v", err)
	}
	if len(def) != len(minimal) {
		t.Errorf("empty spec selected %d, minimal selects %d", len(def), len(minimal))
	}

	// Every selection must be role-appropriate.
	for _, c := range all {
		if !c.HasRole(RoleServer) {
			t.Errorf("component %s selected for server but lacks the role", c.Name)
		}
	}
}

func TestSelectByGroupAndName(t *testing.T) {
	m, _ := Load()

	byGroup, err := m.Select(RoleNode, "runtime")
	if err != nil {
		t.Fatalf("select runtime: %v", err)
	}
	if len(byGroup) == 0 {
		t.Fatal("runtime group is empty for the node role")
	}
	for _, c := range byGroup {
		if c.Group != GroupRuntime {
			t.Errorf("%s is in group %s, not runtime", c.Name, c.Group)
		}
	}

	byName, err := m.Select(RoleNode, "runc")
	if err != nil {
		t.Fatalf("select runc: %v", err)
	}
	if len(byName) != 1 || byName[0].Name != "runc" {
		t.Errorf("expected exactly runc, got %v", byName)
	}
}

func TestSelectUnknownIsAnError(t *testing.T) {
	m, _ := Load()
	if _, err := m.Select(RoleServer, "nonesuch"); err == nil {
		t.Error("expected an error for an unknown component name")
	}
}

func TestParseRejectsWrongSchema(t *testing.T) {
	_, err := parse([]byte(`{"schema": 99, "nodary_version": "0.0.1", "components": []}`))
	if err == nil {
		t.Fatal("expected an error for an unrecognised schema version")
	}
	if !strings.Contains(err.Error(), "schema") {
		t.Errorf("error should name the schema, got: %v", err)
	}
}

// A field an older binary does not understand must be an error, not a silent
// omission: half-applying a newer manifest is worse than refusing it.
func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := parse([]byte(`{"schema": 1, "nodary_version": "0.0.1", "components": [], "surprise": true}`))
	if err == nil {
		t.Fatal("expected an error for an unknown top-level field")
	}
}
