package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Main(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersionText(t *testing.T) {
	code, stdout, _ := run(t, "version")
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d", code, ExitOK)
	}
	if !strings.HasPrefix(stdout, "nodary ") {
		t.Errorf("stdout should start with the program name, got %q", stdout)
	}
	if !strings.Contains(stdout, "platform") {
		t.Error("version output should name the platform")
	}
}

func TestVersionJSONIsStableAndCleanOnStdout(t *testing.T) {
	code, stdout, stderr := run(t, "version", "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if stderr != "" {
		t.Errorf("--format json must leave stderr empty, got %q", stderr)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	for _, k := range []string{"version", "platform", "go"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q in %v", k, got)
		}
	}
}

// Planned-but-unimplemented verbs must be distinguishable from typos: the
// first is a wait, the second is a bug report.
func TestPlannedVerbsFailAsUnimplementedNotUnknown(t *testing.T) {
	for _, verb := range []string{"server", "node", "doctor", "policy", "bundle"} {
		t.Run(verb, func(t *testing.T) {
			code, stdout, stderr := run(t, verb)
			if code != ExitFailure {
				t.Errorf("exit = %d, want %d", code, ExitFailure)
			}
			if !strings.Contains(stderr, "not implemented") {
				t.Errorf("stderr should say not implemented, got %q", stderr)
			}
			if strings.Contains(stderr, "unknown command") {
				t.Error("a specified verb must not be reported as unknown")
			}
			if stdout != "" {
				t.Errorf("errors belong on stderr, stdout had %q", stdout)
			}
		})
	}
}

func TestUnknownVerbIsUsageError(t *testing.T) {
	code, _, stderr := run(t, "nonesuch")
	if code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("stderr should name the problem, got %q", stderr)
	}
}

func TestNoArgsIsUsageError(t *testing.T) {
	if code, _, _ := run(t); code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
}

func TestHelpSucceeds(t *testing.T) {
	code, stdout, _ := run(t, "help")
	if code != ExitOK {
		t.Errorf("exit = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout, "components") {
		t.Error("help should list implemented commands")
	}
}

func TestBadFormatIsUsageError(t *testing.T) {
	code, _, stderr := run(t, "version", "--format", "xml")
	if code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "xml") {
		t.Errorf("error should quote the bad value, got %q", stderr)
	}
}

func TestComponentsListText(t *testing.T) {
	code, stdout, _ := run(t, "components", "list", "--platform", "linux/amd64")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stdout, "COMPONENT") {
		t.Error("expected a table header")
	}
	if !strings.Contains(stdout, "containerd") {
		t.Error("expected containerd in the manifest listing")
	}
}

func TestComponentsListJSON(t *testing.T) {
	code, stdout, stderr := run(t, "components", "list", "--platform", "all", "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	if stderr != "" {
		t.Errorf("--format json must leave stderr empty, got %q", stderr)
	}

	var got struct {
		NodaryVersion string `json:"nodary_version"`
		Components    []struct {
			Name      string                       `json:"name"`
			Kind      string                       `json:"kind"`
			Platforms map[string]map[string]string `json:"platforms"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if len(got.Components) == 0 {
		t.Fatal("no components listed")
	}

	// The listing is the operator's view of what will be fetched, so every
	// entry must actually carry a pin.
	for _, c := range got.Components {
		for plat, a := range c.Platforms {
			if c.Kind == "image" {
				if !strings.Contains(a["image"], "@sha256:") {
					t.Errorf("%s [%s]: image is not digest-pinned", c.Name, plat)
				}
				continue
			}
			if len(a["sha256"]) != 64 {
				t.Errorf("%s [%s]: missing or malformed sha256", c.Name, plat)
			}
		}
	}
}

func TestComponentsListUnknownPlatform(t *testing.T) {
	code, _, stderr := run(t, "components", "list", "--platform", "plan9/386")
	if code != ExitFailure {
		t.Errorf("exit = %d, want %d", code, ExitFailure)
	}
	if !strings.Contains(stderr, "plan9/386") {
		t.Errorf("error should quote the platform, got %q", stderr)
	}
}

func TestComponentsVerifyOfflineNeedsNoNetwork(t *testing.T) {
	code, stdout, _ := run(t, "components", "verify", "--offline")
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(stdout, "skipped") {
		t.Error("offline verification should report skips")
	}
}

func TestComponentsSubcommandErrors(t *testing.T) {
	if code, _, _ := run(t, "components"); code != ExitUsage {
		t.Errorf("bare `components` exit = %d, want %d", code, ExitUsage)
	}
	if code, _, _ := run(t, "components", "nonesuch"); code != ExitUsage {
		t.Errorf("unknown subcommand exit = %d, want %d", code, ExitUsage)
	}
}
