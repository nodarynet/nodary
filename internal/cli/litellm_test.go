package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/gateway"
	"github.com/nodarynet/nodary/internal/install"
)

// install runs a staged, offline `server install` into the appliance's tree.
func stagedInstall(t *testing.T, a *appliance) (int, string) {
	t.Helper()
	code, _, stderr := runWithStdin(t, "", "server", "install",
		"--root", a.dir, "--offline", "--db", a.db, "--secret-key", a.key,
		"--config", filepath.Join(a.dir, "server.toml"),
		"--user", "", "--skip-preflight", "--bind", "127.0.0.1:18443")
	return code, stderr
}

// TestTheMasterKeySurvivesAReinstall is the bug this shape invites.
//
// The same key has to appear in two files — `gateway.env`, which systemd hands
// to the gateway, and `litellm.yaml`, which is the only credential LiteLLM
// accepts. A re-run that generated a fresh one would leave the two disagreeing,
// and the symptom is every inference request failing upstream on a control
// plane whose install just reported success.
func TestTheMasterKeySurvivesAReinstall(t *testing.T) {
	a := newAppliance(t)
	if code, stderr := stagedInstall(t, a); code != ExitOK {
		t.Fatalf("server install: exit %d, %s", code, stderr)
	}
	first := readKey(t, a.dir)

	if code, stderr := stagedInstall(t, a); code != ExitOK {
		t.Fatalf("re-running the install: exit %d, %s", code, stderr)
	}
	if second := readKey(t, a.dir); second != first {
		t.Errorf("the master key changed on a re-run: %q then %q", first, second)
	}

	// And the two files agree, which is the property the key exists for.
	conf, err := os.ReadFile(filepath.Join(a.dir, "litellm.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), first) {
		t.Error("litellm.yaml does not carry the key the gateway was given")
	}
}

func readKey(t *testing.T, dir string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, "gateway.env"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(body)), "NODARY_MASTER_KEY="))
}

// TestTheDataPlaneConfigurationPinsLoggingOff is the compliance surface.
//
// docs/plans/pivot-cmmc.md makes LiteLLM one: inside a CUI boundary a
// configuration that failed to pin request logging off is an incident, not a
// nuisance, and one that reached the disk would be in force the moment systemd
// started the unit. So the install asserts before it writes, using the same
// function the gateway uses before it proxies.
func TestTheDataPlaneConfigurationPinsLoggingOff(t *testing.T) {
	a := newAppliance(t)
	if code, stderr := stagedInstall(t, a); code != ExitOK {
		t.Fatalf("server install: exit %d, %s", code, stderr)
	}
	body, err := os.ReadFile(filepath.Join(a.dir, "litellm.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.AssertLoggingOff(body); err != nil {
		t.Errorf("the installed configuration does not pin logging off: %v", err)
	}
	// A fresh control plane has no deployments, and that is an ordinary state
	// rather than a broken one — LiteLLM refuses a configuration with no
	// model_list at all, so the empty list has to be written explicitly.
	if !strings.Contains(string(body), "model_list:") {
		t.Error("no model_list; LiteLLM refuses a configuration without one")
	}
}

// TestTheLiteLLMImageIsPinnedByDigest keeps a tag out of the unit.
//
// A tag is a name somebody can move. The manifest pins bytes, and the whole
// point of pinning is that what runs is what the manifest was written against.
func TestTheLiteLLMImageIsPinnedByDigest(t *testing.T) {
	a := newAppliance(t)
	if code, stderr := stagedInstall(t, a); code != ExitOK {
		t.Fatalf("server install: exit %d, %s", code, stderr)
	}
	body, err := os.ReadFile(filepath.Join(a.dir, "litellm.env"))
	if err != nil {
		t.Fatal(err)
	}
	ref := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(body)), "NODARY_LITELLM_IMAGE="))
	if !strings.Contains(ref, "@sha256:") {
		t.Errorf("the image is not pinned by digest: %q", ref)
	}

	m, err := components.Load()
	if err != nil {
		t.Fatal(err)
	}
	want, err := imageFor(m, "litellm", "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	if ref != want {
		t.Errorf("the unit would run %q, the manifest pins %q", ref, want)
	}

	// A component the manifest does not carry is an error, not an empty string
	// that would render a unit running whatever `nerdctl` resolves.
	if _, err := imageFor(m, "nosuchthing", "linux/amd64"); err == nil {
		t.Error("an unknown component resolved to an image")
	}
}

// TestServerStatusReportsTheFingerprintTheInstallPrinted closes a gap that only
// shows up on the second node.
//
// The pin was printed once, by `server install`, and by nothing else — while
// every node that ever enrolls needs it. Recovering it meant re-running the
// install, which mints a fresh setup link and join token and retires the
// outstanding ones, or reaching for `openssl x509 -outform DER | sha256sum`.
// Asked for, on a real box, halfway through enrolling a node.
func TestServerStatusReportsTheFingerprintTheInstallPrinted(t *testing.T) {
	a := newAppliance(t)
	code, printed, stderr := runWithStdin(t, "", "server", "install",
		"--root", a.dir, "--offline", "--db", a.db, "--secret-key", a.key,
		"--config", filepath.Join(a.dir, "server.toml"),
		"--user", "", "--skip-preflight", "--bind", "127.0.0.1:18443")
	if code != ExitOK {
		t.Fatalf("server install: exit %d, %s", code, stderr)
	}
	// Last line of stdout: the install's step reports share the stream, which is
	// why scripts/verify-privileged.sh takes it with `tail -1`.
	lines := strings.Split(strings.TrimSpace(printed), "\n")
	want := strings.TrimSpace(lines[len(lines)-1])
	if !strings.HasPrefix(want, "sha256:") {
		t.Fatalf("the install did not print a fingerprint: %q", want)
	}

	code, out, stderr := runWithStdin(t, "", "server", "status",
		"--config", filepath.Join(a.dir, "server.toml"), "--db", a.db)
	if code != ExitOK {
		t.Fatalf("server status: exit %d, %s", code, stderr)
	}
	if !strings.Contains(out, want) {
		t.Errorf("status does not report the pin the install printed (%s):\n%s", want, out)
	}
}

// TestEveryUnitTheInstallWritesIsAlsoStarted is the gap that produced a silent
// dead end.
//
// `WriteUnits` wrote nodary-gateway.service and the start list did not name it,
// so the inference API was installed, enabled by nobody, and listening nowhere.
// The first completion attempt got **no response at all** and no usage row —
// a failure with no error anywhere, because no request ever reached anything.
//
// Written against the same source the install uses, so a unit added to a role
// later cannot quietly go unstarted.
func TestEveryUnitTheInstallWritesIsAlsoStarted(t *testing.T) {
	for _, role := range []string{"server", "node"} {
		written := install.Units(role)
		started := startedUnits(role)
		for name := range written {
			if !slices.Contains(started, name) {
				t.Errorf("%s install writes %s and never starts it; it would be installed "+
					"and listening nowhere", role, name)
			}
		}
		for _, name := range started {
			if _, ok := written[name]; !ok {
				t.Errorf("%s install starts %s and never writes it", role, name)
			}
		}
	}
}
