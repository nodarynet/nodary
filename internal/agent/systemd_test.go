package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fake host proves the loop's logic. This proves the boundary: that the
// verbs the loop builds are ones systemd accepts, that `is-active` and
// `list-units` answer the way the loop reads them, and that an unquoted
// ${NODARY_ARGS} splits into separate arguments — which is the assumption
// internal/agent/plan.go's refusal of whitespace in extra_args rests on.
//
// It runs against the *user* manager, which can start a unit without root, and
// against a stub unit rather than the shipped template. What that costs is
// stated at each point rather than glossed: the shipped template's contents are
// asserted elsewhere, and what a user manager cannot do is called out below.
//
// Skipped rather than failed where there is no user manager: a CI container
// often has no session bus, and a test that cannot run is not a failure.
func TestAgainstRealSystemd(t *testing.T) {
	sd := needSystemd(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	h := RealHost(filepath.Join(dir, "units"), filepath.Join(dir, "etc"))
	h.UserScope = true

	// A stub, and not the shipped template: that one runs /usr/local/bin/nerdctl,
	// which R5-04 places and this host does not have. What is under test here is
	// systemd's half of the contract — template instantiation with %i, the
	// EnvironmentFile being read, and the verbs — so the stub keeps exactly
	// those and drops the container runtime.
	unit := `[Unit]
Description=nodary model deployment %i

[Service]
Type=simple
EnvironmentFile=` + h.ConfigDir + `/deployments/%i.env
ExecStart=/usr/bin/env sleep ${NODARY_ARGS}
`
	installUnit(t, sd, TemplateName, unit)
	name := UnitName("systemdtest")
	t.Cleanup(func() { _, _ = h.systemctl(context.Background(), "stop", name) })

	if out, err := h.systemctl(ctx, "daemon-reload"); err != nil {
		t.Fatalf("daemon-reload: %v: %s", err, out)
	}

	u := Unit{Deployment: "systemdtest",
		EnvPath: filepath.Join(h.ConfigDir, "deployments", "systemdtest.env"),
		Env:     []EnvVar{{"NODARY_ARGS", "300"}}}
	if _, err := writeEnvFile(u); err != nil {
		t.Fatal(err)
	}

	if out, err := h.systemctl(ctx, "start", name); err != nil {
		t.Fatalf("start: %v: %s\n%s", err, out, h.LogTail(ctx, name, 20))
	}
	if !h.isActive(ctx, name) {
		t.Fatalf("the unit is not active: %s", h.LogTail(ctx, name, 20))
	}

	// The listing the loop uses to decide what to stop has to find it, with the
	// exact flags and glob the loop passes.
	running, err := h.runningInstances(ctx)
	if err != nil {
		t.Fatalf("runningInstances: %v", err)
	}
	if !hasUnit(running, name) {
		t.Errorf("list-units returned %v, want the running instance", running)
	}

	if out, err := h.systemctl(ctx, "stop", name); err != nil {
		t.Fatalf("stop: %v: %s", err, out)
	}
	if h.isActive(ctx, name) {
		t.Error("the unit is still active after stop")
	}
}

// `$FOO` splits at whitespace into separate arguments; `${FOO}` is one
// argument, never split. The unit template depends on both behaviours — the
// argument list must split, an image reference must not — and this asserts each
// against real systemd rather than against the documentation.
//
// It is here because assuming it was wrong. docs/specs/03-agent.md §6 had
// `${NODARY_ARGS}`, which hands a model server its entire argv as one string;
// it exits on an unrecognised argument, and the failure surfaces on a GPU host
// as a container that will not start. This test is what found it, and it is
// what stops the braces coming back.
func TestSystemdSplitsBareVariablesAndNotBracedOnes(t *testing.T) {
	sd := needSystemd(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	h := RealHost(filepath.Join(dir, "units"), filepath.Join(dir, "etc"))
	h.UserScope = true

	// touch creates one file per argument, so three words in one variable
	// either produce three files or one file whose name holds the spaces.
	for _, tc := range []struct {
		what   string
		expand string
		split  bool
	}{
		{"bare", "$NODARY_ARGS", true},
		{"braced", "${NODARY_ARGS}", false},
	} {
		out := filepath.Join(dir, tc.what)
		if err := os.MkdirAll(out, 0o755); err != nil {
			t.Fatal(err)
		}
		unit := "[Unit]\nDescription=nodary argv " + tc.what + "\n\n" +
			"[Service]\nType=oneshot\nEnvironmentFile=" + h.ConfigDir + "/deployments/%i.env\n" +
			"ExecStart=/usr/bin/touch " + tc.expand + "\n"
		service := "nodary-argv" + tc.what + "@" + tc.what + ".service"
		installUnit(t, sd, "nodary-argv"+tc.what+"@.service", unit)
		t.Cleanup(func() { _, _ = h.systemctl(context.Background(), "stop", service) })

		u := Unit{Deployment: tc.what,
			EnvPath: filepath.Join(h.ConfigDir, "deployments", tc.what+".env"),
			Env: []EnvVar{{"NODARY_ARGS", strings.Join([]string{
				filepath.Join(out, "one"), filepath.Join(out, "two"), filepath.Join(out, "three")}, " ")}}}
		if _, err := writeEnvFile(u); err != nil {
			t.Fatal(err)
		}
		if o, err := h.systemctl(ctx, "daemon-reload"); err != nil {
			t.Fatalf("daemon-reload: %v: %s", err, o)
		}
		// The braced form is *expected* to fail here: touch cannot create a
		// file whose name is three paths joined by spaces.
		_, startErr := h.systemctl(ctx, "start", service)

		var made []string
		entries, _ := os.ReadDir(out)
		for _, e := range entries {
			made = append(made, e.Name())
		}
		if tc.split {
			if startErr != nil {
				t.Fatalf("%s: start: %v\n%s", tc.what, startErr, h.LogTail(ctx, service, 20))
			}
			if len(made) != 3 {
				t.Errorf("%s: created %v, want three separate arguments", tc.what, made)
			}
			continue
		}
		for _, name := range made {
			if strings.Contains(name, " ") {
				t.Errorf("braced: systemd split nothing but produced %q; the assumption behind "+
					"the unbraced form in the template has changed", name)
			}
		}
		if len(made) == 3 {
			t.Error("braced ${NODARY_ARGS} split into arguments; the template no longer needs " +
				"the unbraced form, and docs/specs/03-agent.md §6 should be revisited")
		}
	}
}

// needSystemd skips unless a usable user manager is present.
//
// What a user manager cannot show, said plainly rather than left implied: it is
// delegated cpu, memory and pids and has no network controller, so
// IPAddressDeny= is inert there — which is exactly the spike's finding and the
// reason docs/specs/03-agent.md §5 does not treat it as the egress control.
// Nothing under test here depends on it.
func needSystemd(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("-short")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		t.Skip("systemctl is not installed")
	}
	out, err := exec.Command("systemctl", "--user", "is-system-running").CombinedOutput()
	state := strings.TrimSpace(string(out))
	if err != nil && state != "degraded" && state != "running" {
		t.Skipf("no usable systemd user manager: %s", state)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	dir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("cannot write user units: %v", err)
	}
	return dir
}

func installUnit(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err == nil {
		t.Skipf("%s already exists; refusing to overwrite it", path)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Remove(path)
		_, _ = exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput()
	})
}

func hasUnit(all []string, want string) bool {
	for _, s := range all {
		if s == want {
			return true
		}
	}
	return false
}
