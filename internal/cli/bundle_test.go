package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/bundle"
	"github.com/nodarynet/nodary/internal/components"
)

// A cache somebody changed after `components fetch` verified it must not reach
// a bundle: nothing will check it again until it is on a machine with no
// network, which is the worst place to find out.
//
// Driven through the verb rather than the package, because the selection is
// half of what could go wrong — `--components cni-plugins` names a node
// component, and a bundle that resolved it per role rather than per site would
// answer "unknown component" for a name the manifest plainly holds.
func TestACacheThatDoesNotMatchTheManifestIsNotBundled(t *testing.T) {
	plat := "linux/amd64"
	m, err := components.Load()
	if err != nil {
		t.Fatal(err)
	}
	// One real component, so the digests under test are the ones this build
	// actually pins rather than something the test made up.
	var pick components.Component
	for _, c := range m.ForPlatform(plat) {
		if c.Kind != components.KindImage && c.Platforms[plat].SHA256 != "" {
			pick = c
			break
		}
	}
	if pick.Name == "" {
		t.Skip("this build pins no fetchable component for " + plat)
	}

	// A cache holding bytes that hash to what the manifest pins is not
	// something a test can conjure, so this asserts the refusal instead: a
	// cache whose contents are wrong must never reach a bundle.
	cache := t.TempDir()
	if err := os.WriteFile(filepath.Join(cache, components.ArtifactName(pick, plat)),
		[]byte("not the pinned bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "site.tar")
	code, _, stderr := run(t, "bundle", "create", "--platform", plat,
		"--components", pick.Name, "--dir", cache, "-o", out)
	if code == ExitOK {
		t.Fatal("a cache that does not match the manifest was bundled")
	}
	if !strings.Contains(stderr, "does not match") {
		t.Errorf("the refusal does not name the mismatch: %s", stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a refused create left a file an operator would ship")
	}
}

// `bundle show` answers the question an operator has about a file somebody
// handed them, without extracting forty gigabytes to find out.
func TestBundleShowReadsTheHeaderOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "site.tar")
	if err := os.WriteFile(path, []byte("this is not a tar"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, "bundle", "show", path)
	if code == ExitOK {
		t.Fatal("a file that is not a bundle was shown")
	}
	if !strings.Contains(stderr, "not a nodary bundle") {
		t.Errorf("the refusal is not specific: %s", stderr)
	}
}

// --format json is a schema a script reads, so the keys are the words the
// bundle's own manifest uses.
func TestBundleShowJSONCarriesTheManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "site.tar")
	made, err := bundle.Create(t.Context(), bundle.CreateOptions{
		Out: path, Platform: "linux/amd64", Dist: t.TempDir(), NodaryVersion: "0.0.1-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(made.Components) != 0 {
		t.Fatalf("the fixture bundled something: %+v", made)
	}
	code, stdout, stderr := run(t, "bundle", "show", path, "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	for _, key := range []string{"schema", "nodary_version", "platform", "created_at"} {
		if _, ok := got[key]; !ok {
			t.Errorf("--format json is missing %q: %s", key, stdout)
		}
	}
}

// A bundle carries a site, so a name is resolved against every role rather
// than against each one: `cni-plugins` is a node component and asking the
// server role about it answers "unknown", which is true of that role and false
// of the site.
func TestBundleCreateResolvesAgainstTheWholeSite(t *testing.T) {
	m, err := components.Load()
	if err != nil {
		t.Fatal(err)
	}
	// Any component that belongs to exactly one role is the case under test.
	var oneRole string
	for _, c := range m.ForPlatform("linux/amd64") {
		if c.Kind != components.KindImage && len(c.Roles) == 1 {
			oneRole = c.Name
			break
		}
	}
	if oneRole == "" {
		t.Skip("every component in this build carries both roles")
	}

	// It will fail on the empty cache, which is the point: it has to get past
	// selection to reach the cache at all.
	code, _, stderr := run(t, "bundle", "create", "--platform", "linux/amd64",
		"--components", oneRole, "--dir", t.TempDir(),
		"-o", filepath.Join(t.TempDir(), "site.tar"))
	if code == ExitOK {
		t.Fatal("an empty cache produced a bundle")
	}
	if strings.Contains(stderr, "unknown component") {
		t.Errorf("%s belongs to one role and was reported unknown, so a bundle cannot carry "+
			"a site's node components: %s", oneRole, stderr)
	}
	if !strings.Contains(stderr, "not in the cache") {
		t.Errorf("the refusal should be about the cache, not selection: %s", stderr)
	}
}

// A revision arriving without its signature is unreadable at the far end:
// `advisory check` refuses one and offers no unsigned mode. Discovering that on
// the air-gapped machine is the exact failure this whole verb exists to avoid,
// so it is refused where the operator can still do something about it.
func TestAFeedWithNoSignatureIsNotBundled(t *testing.T) {
	dir := t.TempDir()
	feed := filepath.Join(dir, "advisories.toml")
	if err := os.WriteFile(feed, []byte("revision = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "site.tar")
	code, _, stderr := run(t, "bundle", "create", "--platform", "linux/amd64",
		"--components", "minimal", "--dir", t.TempDir(), "--feed", feed, "-o", out)
	if code == ExitOK {
		t.Fatal("an unsigned feed was bundled")
	}
	if !strings.Contains(stderr, "no signature") {
		t.Errorf("the refusal does not name the missing signature: %s", stderr)
	}
}

// A --feed the operator named and that is not there is a mistake worth saying
// so about. An *absent default* is not: a site with no subscription has no
// feed, and its bundles are ordinary rather than broken.
func TestAFeedIsOnlyDemandedWhenItWasAskedFor(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nowhere.toml")
	_, _, stderr := run(t, "bundle", "create", "--platform", "linux/amd64",
		"--components", "minimal", "--dir", t.TempDir(), "--feed", missing,
		"-o", filepath.Join(t.TempDir(), "site.tar"))
	if !strings.Contains(stderr, "nowhere.toml") {
		t.Errorf("a named feed that is absent was not reported: %s", stderr)
	}

	// Without the flag the run gets as far as the cache, which is where an
	// empty one stops it — so selection and the feed both got out of the way.
	_, _, stderr = run(t, "bundle", "create", "--platform", "linux/amd64",
		"--components", "minimal", "--dir", t.TempDir(),
		"-o", filepath.Join(t.TempDir(), "site.tar"))
	if strings.Contains(stderr, "advisories.toml") {
		t.Errorf("a bundle demanded a feed nobody asked it to carry: %s", stderr)
	}
}

// The recurring case, and the one that decides whether an offline site stays
// current: the gigabytes are installed once and a feed revision arrives every
// month. If receiving revision 13 meant re-carrying every container image, a
// site simply would not do it.
func TestAFeedOnlyBundleRoundTripsThroughTheVerb(t *testing.T) {
	dir := t.TempDir()
	feed := filepath.Join(dir, "advisories.toml")
	body := []byte("revision = 12\nstatement = \"a report, not a warranty\"\n")
	if err := os.WriteFile(feed, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(feed+".minisig", []byte("untrusted comment: sig\nRWQf\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "feed.tar")
	code, _, stderr := run(t, "bundle", "create", "--platform", "linux/amd64",
		"--components", "none", "--feed", feed, "-o", out)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}

	// It is in the archive, not merely in the manifest: `bundle open` counts
	// members and refuses a bundle that names more than it carries.
	conf := t.TempDir()
	code, stdout, stderr := run(t, "bundle", "open", "--dir", t.TempDir(),
		"--config-dir", conf, out)
	if code != ExitOK {
		t.Fatalf("open exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "placed") {
		t.Errorf("the feed was not reported as placed:\n%s", stdout)
	}
	got, err := os.ReadFile(filepath.Join(conf, "advisories.toml"))
	if err != nil {
		t.Fatalf("the feed did not land: %v", err)
	}
	// Byte for byte: the detached signature is over these exact bytes.
	if string(got) != string(body) {
		t.Errorf("the feed changed in transit:\n%q\n%q", body, got)
	}
	if _, err := os.Stat(filepath.Join(conf, "advisories.toml.minisig")); err != nil {
		t.Errorf("the signature did not land: %v", err)
	}
}

// A bundle with nothing in it at all is a mistake worth naming, and stays one.
func TestABundleWithNothingSelectedIsRefused(t *testing.T) {
	code, _, stderr := run(t, "bundle", "create", "--platform", "linux/amd64",
		"--components", "none", "-o", filepath.Join(t.TempDir(), "empty.tar"))
	if code == ExitOK {
		t.Fatal("an empty bundle was written")
	}
	if !strings.Contains(stderr, "nothing selected") {
		t.Errorf("wrong refusal: %s", stderr)
	}
}
