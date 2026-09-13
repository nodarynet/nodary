package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// originPolicy applies a profile that differs from `default` only in its origin
// lists, so a test exercises provenance without also having to satisfy
// `regulated`'s TOTP and justification ceremony.
func (a *appliance) originPolicy(t *testing.T, allow, deny string) {
	t.Helper()
	body := `[policy]
name = "origins"
require_totp             = false
require_justification    = false
min_justification_length = 0
require_signed_artifacts = true
allow_unattended_tokens  = true
allow_custom_backends    = true
allow_derived_images     = true
require_pinned_derives   = false
egress_default           = "deny"
model_origin_allowlist   = ` + allow + `
model_origin_denylist    = ` + deny + `
require_model_manifest   = false
audit_retention_days     = 365
usage_retention_days     = 90
session_ttl_minutes      = 10080
token_max_ttl_days       = 3650
`
	path := filepath.Join(t.TempDir(), "origins.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := a.run("policy", "apply", path, "--yes", "--justify",
		"setting the origin lists for this test"); code != ExitOK {
		t.Fatalf("policy apply: exit %d: %s", code, stderr)
	}
}

// registerable is a node and a model directory with weights in it, which is the
// least a `model register` needs before provenance is the interesting part.
func (a *appliance) registerable(t *testing.T) string {
	t.Helper()
	a.enrolled("fractal")
	a.addUser("alice", "operator")
	models := t.TempDir()
	dir := filepath.Join(models, "acme--tiny")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tiny-q4_k_m.gguf"), []byte("GGUF, allegedly"), 0o644); err != nil {
		t.Fatal(err)
	}
	return models
}

func (a *appliance) register(t *testing.T, models string, extra ...string) (int, string) {
	t.Helper()
	args := append([]string{"model", "register", "acme/tiny",
		"--node", "fractal", "--models-dir", models, "--port", "8001",
		"--backend", "llama-cpp", "--yes", "--justify", "registering a model"}, extra...)
	code, _, stderr := a.run(args...)
	return code, stderr
}

// docs/specs/05-catalog.md §2: rejected at registration, and the rejection
// written to the chain with the actor and the attempted origin. A refusal that
// left no record would make the control unprovable, which is the whole point of
// having it here rather than in tribal knowledge.
func TestADeniedOriginIsRefusedAtRegistrationAndRecorded(t *testing.T) {
	a := newAppliance(t)
	models := a.registerable(t)
	a.originPolicy(t, "[]", `["CN"]`)

	code, stderr := a.register(t, models, "--origin-org", "acme", "--origin-country", "CN")
	if code == ExitOK {
		t.Fatalf("a denied origin registered: %s", stderr)
	}
	if !strings.Contains(stderr, "denylist") {
		t.Errorf("the refusal does not say why: %s", stderr)
	}

	detail := a.scalar(t, `SELECT detail_json FROM audit WHERE outcome = 'failure' ORDER BY seq DESC LIMIT 1`)
	for _, want := range []string{"denied_origin_country", "CN", "acme/tiny"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the record does not carry %q: %s", want, detail)
		}
	}
	if n := a.scalar(t, `SELECT count(*) FROM model`); n != "0" {
		t.Errorf("%s models in the catalog, want none", n)
	}
}

// Holding shift is not a way past a control.
func TestCaseDoesNotGetPastTheDenylist(t *testing.T) {
	a := newAppliance(t)
	models := a.registerable(t)
	a.originPolicy(t, "[]", `["CN"]`)

	if code, stderr := a.register(t, models, "--origin-country", "cn"); code == ExitOK {
		t.Fatalf("a lowercased denied origin registered: %s", stderr)
	}
}

// The bypass that needs no cleverness at all: leave the flag off.
func TestAnUndeclaredOriginDoesNotSatisfyAnAllowlist(t *testing.T) {
	a := newAppliance(t)
	models := a.registerable(t)
	a.originPolicy(t, `["US"]`, "[]")

	code, stderr := a.register(t, models)
	if code == ExitOK {
		t.Fatalf("a model declaring no origin registered under an allowlist: %s", stderr)
	}
	if !strings.Contains(stderr, "declares no origin") {
		t.Errorf("the refusal does not name the cause: %s", stderr)
	}
}

func TestAnAllowedOriginRegisters(t *testing.T) {
	a := newAppliance(t)
	models := a.registerable(t)
	a.originPolicy(t, `["US", "GB"]`, `["CN"]`)

	if code, stderr := a.register(t, models, "--origin-org", "acme", "--origin-country", "US"); code != ExitOK {
		t.Fatalf("an allowed origin was refused: %s", stderr)
	}
	if got := a.scalar(t, `SELECT origin_country FROM model WHERE id = 'acme/tiny'`); got != "US" {
		t.Errorf("origin_country = %q, want US", got)
	}
	if got := a.scalar(t, `SELECT license FROM model WHERE id = 'acme/tiny'`); got != "" {
		t.Errorf("license = %q, want it unset when the flag is absent", got)
	}
}

// docs/specs/11-failure-modes.md: a model whose origin *becomes* denied has its
// deployments **flagged, not stopped**. Refusing every later document that
// merely restates the model would stop them by another road — the operator
// could change nothing else in the fleet until they deleted it.
func TestTighteningPolicyDoesNotStopAModelAlreadyRegistered(t *testing.T) {
	a := newAppliance(t)
	models := a.registerable(t)
	a.originPolicy(t, "[]", "[]")

	doc := filepath.Join(t.TempDir(), "register.toml")
	if code, _, stderr := a.run("model", "register", "acme/tiny",
		"--node", "fractal", "--models-dir", models, "--port", "8001",
		"--backend", "llama-cpp", "--origin-org", "acme", "--origin-country", "CN",
		"-o", doc, "--yes", "--justify", "writing the document"); code != ExitOK {
		t.Fatalf("register -o: %d %s", code, stderr)
	}
	if code, _, stderr := a.run("config", "apply", "-f", doc, "--yes", "--justify",
		"registering while the origin is allowed"); code != ExitOK {
		t.Fatalf("the first apply failed: %s", stderr)
	}

	a.originPolicy(t, "[]", `["CN"]`)

	// The same document again, now that its origin is denied.
	if code, _, stderr := a.run("config", "apply", "-f", doc, "--yes", "--justify",
		"an unrelated change that happens to restate the model"); code != ExitOK {
		t.Fatalf("tightening policy stopped an existing model: %s", stderr)
	}

	// But moving it to a denied origin is a registration, and is refused.
	if code, stderr := a.register(t, models, "--origin-org", "other", "--origin-country", "CN"); code == ExitOK {
		t.Fatalf("changing a model's origin to a denied one was allowed: %s", stderr)
	}
}
