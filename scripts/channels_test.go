package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// R5-20 and R5-21: the two wrapper channels resolve per-platform artifacts, and
// each has its own way of quietly doing nothing on a platform it does not
// cover. npm installs `optionalDependencies` silently, so an unsupported host
// gets the shim and no binary; pip picks whatever wheel matches, so an
// imprecise tag installs a broken entry point instead of reporting no
// distribution. Both failures look like a working install until the first run.

func repoFile(t *testing.T, parts ...string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join(append([]string{".."}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// runShim executes the npm launcher with process.platform and process.arch
// forced, which is the only way to ask what it does on a host this test is not
// running on.
func runShim(t *testing.T, platform, arch string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("no node on this host")
	}
	shim := repoFile(t, "packaging", "npm", "nodary", "bin", "nodary.js")
	harness := filepath.Join(t.TempDir(), "harness.js")
	body := `Object.defineProperty(process, "platform", {value: ` + quote(platform) + `});
Object.defineProperty(process, "arch", {value: ` + quote(arch) + `});
process.exit = (code) => { throw new Error("exit:" + code); };
try { require(` + quote(shim) + `); } catch (e) { process.stderr.write(String(e.message) + "\n"); }
`
	if err := os.WriteFile(harness, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("node", harness).CombinedOutput()
	return string(out), err
}

func quote(s string) string { return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"` }

// R5-21: a native Windows install fails at resolution, by name. npm will
// happily install the shim there and resolve no platform package at all.
func TestTheNpmShimNamesAnUnsupportedPlatform(t *testing.T) {
	out, _ := runShim(t, "win32", "x64")
	if !strings.Contains(out, "unsupported platform win32-x64") {
		t.Errorf("the shim does not name the platform:\n%s", out)
	}
	// And it says what is supported, because the next question is always that.
	if !strings.Contains(out, "linux-x64") {
		t.Errorf("the refusal does not list what is supported:\n%s", out)
	}
	// It must not fall through to executing something.
	if strings.Contains(out, "could not execute") {
		t.Errorf("the shim tried to run a binary on an unsupported platform:\n%s", out)
	}
}

// R5-20's npm half: a supported platform whose package is absent is a different
// failure from an unsupported one, and telling them apart is the difference
// between "reinstall" and "nodary does not run here".
func TestTheNpmShimTellsAMissingPackageFromAnUnsupportedOne(t *testing.T) {
	out, _ := runShim(t, "linux", "x64")
	if !strings.Contains(out, "nodary-linux-x64 is not installed") {
		t.Errorf("a missing platform package was not named:\n%s", out)
	}
	if !strings.Contains(out, "--include=optional") {
		t.Errorf("the refusal does not say how to fix it:\n%s", out)
	}
	if strings.Contains(out, "unsupported platform") {
		t.Errorf("a supported platform was reported as unsupported:\n%s", out)
	}
}

// R5-20's pip half: the wheel tags are what make `pip install nodary` say "no
// matching distribution" rather than installing something that cannot run. A
// generic tag — py3-none-any — would match everywhere, which is the bug.
func TestTheWheelTagsAreSpecificEnoughToRefuse(t *testing.T) {
	body, err := os.ReadFile(repoFile(t, "packaging", "pypi", "build_wheels.py"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if strings.Contains(src, "py3-none-any") {
		t.Error("a wheel tagged `any` matches every platform, including the ones with no binary")
	}
	// Both libc flavors, or Alpine falls through to an sdist that does not
	// exist and reports a build error instead of an unsupported platform.
	for _, tag := range []string{
		"manylinux2014_x86_64", "musllinux_1_2_x86_64",
		"manylinux2014_aarch64", "musllinux_1_2_aarch64",
		"macosx_10_12_x86_64", "macosx_11_0_arm64",
	} {
		if !strings.Contains(src, tag) {
			t.Errorf("no wheel is tagged %s", tag)
		}
	}
	// R5-21 again: nothing is built for Windows, so there is nothing for pip to
	// match and the message comes from pip itself.
	for _, tag := range []string{"win_amd64", "win32"} {
		if strings.Contains(src, tag) {
			t.Errorf("a %s wheel is built for a platform nodary does not support", tag)
		}
	}
}
