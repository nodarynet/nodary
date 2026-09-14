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

// R5-26: the shipped binary is the FIPS build, and it is the *only* build.
//
// ADR 0004's decision is "one shipped artifact"; ADR 0006 §2 says that artifact
// runs the validated module. Both are invisible to `goreleaser check`, which
// validates the schema and has nothing to say about which env a build carries —
// so dropping GOFIPS140 in a refactor would produce a perfectly valid
// configuration that silently ships a different binary than the ADRs describe.
func TestTheShippedBinaryIsTheFIPSBuild(t *testing.T) {
	body, err := os.ReadFile(repoFile(t, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	if !strings.Contains(src, "GOFIPS140=v1.0.0") {
		t.Error("the release build does not set GOFIPS140: the shipped binary would not be " +
			"the FIPS build ADR 0006 §2 says ships")
	}
	// One build, not two. A second `- id:` under builds: would mean a channel
	// has to choose, which is the thing ADR 0004 exists to prevent.
	builds := src[strings.Index(src, "\nbuilds:"):]
	builds = builds[:strings.Index(builds, "\narchives:")]
	if n := strings.Count(builds, "\n  - id:"); n != 1 {
		t.Errorf("builds: declares %d artifacts, want 1 — ADR 0004 ships one binary and "+
			"every channel carries the same object", n)
	}
	// `only` is not shipped: it refuses HMAC-SHA-1 by panicking inside
	// hmac.New, on TOTP's path, inside an audited mutation (ADR 0006 §2).
	if strings.Contains(src, "fips140=only") {
		t.Error("the release build enables fips140=only, which panics on TOTP's HMAC-SHA-1")
	}
}

// R5-23: the Homebrew channel is a macOS cask, and two of its properties are
// invisible to `goreleaser check` — which validates the schema and has nothing
// to say about whether the values make sense together.
//
// String assertions rather than a YAML parse: this module has no YAML
// dependency, and adding one to check four lines of release configuration would
// cost more than it proves.
func TestTheHomebrewChannelIsACaskInTheRightPlace(t *testing.T) {
	body, err := os.ReadFile(repoFile(t, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)

	// `brews` is deprecated and goes away at the next major. Its return would
	// pass `check` with a warning CI is configured to tolerate.
	if strings.Contains(src, "\nbrews:") {
		t.Error("the deprecated `brews` block is back; goreleaser removes it at the next major")
	}
	if !strings.Contains(src, "\nhomebrew_casks:") {
		t.Fatal("no homebrew_casks block: the Homebrew channel is gone entirely")
	}

	// **A cask published into Formula/ installs from nowhere.** `brew install
	// --cask nodarynet/tap/nodary` looks in Casks/, so the wrong directory is a
	// 404 for every macOS operator and a valid configuration to goreleaser.
	casks := src[strings.Index(src, "\nhomebrew_casks:"):]
	if !strings.Contains(casks, "directory: Casks") {
		t.Error("the cask is not published into Casks/, so `brew install --cask` would 404")
	}

	// The release artifacts are not codesigned or notarized, so Gatekeeper
	// quarantines what the cask downloads and macOS refuses to run it — with a
	// dialog about a damaged file, which reads as a corrupt download. Losing
	// this hook breaks every macOS install and nothing here would fail.
	if !strings.Contains(casks, "com.apple.quarantine") {
		t.Error("no quarantine-clearing hook: Gatekeeper would refuse the binary on first run")
	}
}

// **An `-X` against a package the binary does not link is silently ignored.**
// Measured while wiring R5-16: `-X …/internal/release.TrustedKey=…` produced a
// binary still carrying the placeholder, because nothing imported the package
// yet, and goreleaser reported success. A release built that way ships a
// binary that cannot verify a manifest revision or an upgrade, and the refusal
// reads like a bug rather than a missing secret.
//
// Both keys also carried comments claiming they were "stamped in at release
// with -ldflags" while nothing stamped either, which is how this went unnoticed.
func TestEveryStampedPackageIsActuallyLinkedIn(t *testing.T) {
	body, err := os.ReadFile(repoFile(t, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var stamped []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "- -X github.com/nodarynet/nodary/")
		if !ok {
			continue
		}
		pkg, _, _ := strings.Cut(rest, ".")
		stamped = append(stamped, "github.com/nodarynet/nodary/"+pkg)
	}
	if len(stamped) == 0 {
		t.Fatal("no -X ldflags at all: the version and both trust anchors would be placeholders")
	}

	out, err := exec.Command("go", "list", "-deps", repoFile(t, "./cmd/nodary")).Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	linked := map[string]bool{}
	for _, p := range strings.Split(string(out), "\n") {
		linked[strings.TrimSpace(p)] = true
	}
	for _, pkg := range stamped {
		if !linked[pkg] {
			t.Errorf("%s is stamped with -X but nothing links it in, so the value is "+
				"silently dropped and the build ships its placeholder", pkg)
		}
	}
}
