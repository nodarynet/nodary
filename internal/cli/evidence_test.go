package cli

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nodarynet/nodary/ee/license"
	"github.com/nodarynet/nodary/internal/minisign"

	_ "modernc.org/sqlite"
)

// licensed gives the appliance a valid licence, signed by a key this test
// generated and pointed the binary at.
func (a *appliance) licensed(expires time.Time, features ...string) {
	a.t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		a.t.Fatal(err)
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		a.t.Fatal(err)
	}
	key := minisign.PublicKey{ID: id, Key: pub}

	quoted := make([]string, len(features))
	for i, f := range features {
		quoted[i] = `"` + f + `"`
	}
	src := "[license]\ncustomer = \"Test Manufacturing Inc\"\nissued = \"2026-01-01T00:00:00Z\"\n" +
		"expires = \"" + expires.UTC().Format(time.RFC3339) + "\"\n" +
		"features = [" + strings.Join(quoted, ", ") + "]\n"

	path := filepath.Join(a.dir, "nodary.license")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		a.t.Fatal(err)
	}
	if err := os.WriteFile(path+".minisig",
		[]byte(minisign.Sign(priv, id, []byte(src), "nodary licence")), 0o600); err != nil {
		a.t.Fatal(err)
	}

	previous := license.TrustedKey
	license.TrustedKey = minisign.EncodePublicKey(key)
	a.t.Cleanup(func() { license.TrustedKey = previous })
	a.licPriv, a.licID = priv, id

	if code, _, stderr := a.run("license", "apply", path); code != ExitOK {
		a.t.Fatalf("applying a licence: %d %s", code, stderr)
	}
}

// R9-03: an unlicensed install carries the verb and explains what it would
// produce. The commercial surface is discoverable, never hidden.
func TestUnlicensedExportNamesEveryMemberAndWritesNothing(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	out := filepath.Join(a.dir, "bundle.tar.gz")

	code, stdout, stderr := a.run("evidence", "export", "--out", out)
	if code != ExitPolicy {
		t.Errorf("exit = %d, want %d", code, ExitPolicy)
	}
	if stdout != "" {
		t.Errorf("an unlicensed export wrote to stdout: %q", stdout)
	}
	for _, m := range []string{"chain.jsonl", "verify.txt", "manifest.json.minisig", "controls.json"} {
		if !strings.Contains(stderr, m) {
			t.Errorf("the refusal does not name %s:\n%s", m, stderr)
		}
	}
	// And it must say the free path still exists.
	if !strings.Contains(stderr, "audit export") {
		t.Errorf("the refusal does not point at the free export:\n%s", stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("an unlicensed export wrote a file")
	}
}

// R9-05 through R9-09 and R9-12: the bundle, and the property that makes it
// worth money — it verifies with the stock tools and no nodary.
func TestBundleVerifiesWithSha256sumAndMinisignAlone(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	a.addUser("bob", "operator")
	a.licensed(time.Now().AddDate(1, 0, 0), license.FeatureEvidence)

	out := filepath.Join(a.dir, "bundle.tar.gz")
	code, stdout, stderr := a.run("evidence", "export", "--out", out)
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0: %s", code, stderr)
	}
	if strings.TrimSpace(stdout) != out {
		t.Errorf("stdout should be the path alone, got %q", stdout)
	}

	dir := t.TempDir()
	members := extractBundle(t, out, dir)

	// The chain must actually carry the records. Without this the two checks
	// below pass just as well on an empty segment, which is how a bound that
	// silently excluded everything went unnoticed once already.
	if n := strings.Count(members["chain.jsonl"], "\n"); n < 3 {
		t.Errorf("chain.jsonl holds %d records, want at least the three this test made:\n%s",
			n, members["chain.jsonl"])
	}

	// Every member 13 §2 names is present, including the ones with no producer.
	for _, want := range []string{
		"chain.jsonl", "verify.txt", "controls.json", "controls.md",
		"revisions.jsonl", "nodes.json", "identity.jsonl", "remediation.jsonl",
		"manifest.json", "manifest.json.minisig", "manifest.sha256",
		"nodary-evidence.pub", "README.txt",
	} {
		if _, ok := members[want]; !ok {
			t.Errorf("the bundle has no %s", want)
		}
	}

	// Step 1 of the documented procedure.
	if o, err := runIn(dir, "sha256sum", "-c", "manifest.sha256"); err != nil {
		t.Errorf("sha256sum -c failed:\n%s", o)
	}
	// Step 2, with the tool an assessor actually has.
	if _, err := exec.LookPath("minisign"); err != nil {
		t.Skip("minisign is not installed; the signature half is unverified in this run")
	}
	o, err := runIn(dir, "minisign", "-Vm", "manifest.json", "-p", "nodary-evidence.pub")
	if err != nil {
		t.Fatalf("minisign refused the bundle:\n%s", o)
	}
	if !strings.Contains(o, "Signature and comment signature verified") {
		t.Errorf("minisign did not confirm both signatures:\n%s", o)
	}

	// An edited member has to fail. Without this the two checks above pass on a
	// bundle that proves nothing.
	if err := os.WriteFile(filepath.Join(dir, "chain.jsonl"),
		[]byte(members["chain.jsonl"]+"tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if o, err := runIn(dir, "sha256sum", "-c", "manifest.sha256"); err == nil {
		t.Errorf("an edited member passed sha256sum:\n%s", o)
	}
}

// R9-08: the segment carries the anchor that joins it to the chain, and the
// verification says so in words an assessor can act on.
func TestVerifyTxtReportsTheChainAndHowToCheckItIndependently(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	a.licensed(time.Now().AddDate(1, 0, 0), license.FeatureEvidence)

	out := filepath.Join(a.dir, "bundle.tar.gz")
	if code, _, stderr := a.run("evidence", "export", "--out", out); code != ExitOK {
		t.Fatalf("export: %d %s", code, stderr)
	}
	members := extractBundle(t, out, t.TempDir())

	verify := members["verify.txt"]
	if !strings.Contains(verify, "RESULT: verified") {
		t.Errorf("the chain did not verify:\n%s", verify)
	}
	for _, want := range []string{"sha256sum -c manifest.sha256", "minisign -Vm manifest.json", "prev_hash"} {
		if !strings.Contains(verify, want) {
			t.Errorf("verify.txt does not tell the reader how to check %q:\n%s", want, verify)
		}
	}

	// The identity member carries the lifecycle and no secret.
	if !strings.Contains(members["identity.jsonl"], `"kind":"user"`) {
		t.Errorf("identity.jsonl has no users:\n%s", members["identity.jsonl"])
	}
}

// R9-10 and R9-13: a member with no claims says so, in its own schema, rather
// than being absent or — worse — guessing.
func TestUnmappedAndPendingMembersSayWhatTheyAre(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	a.licensed(time.Now().AddDate(1, 0, 0), license.FeatureEvidence)

	out := filepath.Join(a.dir, "bundle.tar.gz")
	if code, _, stderr := a.run("evidence", "export", "--out", out); code != ExitOK {
		t.Fatalf("export: %d %s", code, stderr)
	}
	members := extractBundle(t, out, t.TempDir())

	var controls struct {
		Status  string `json:"status"`
		Entries []struct {
			Practice string `json:"practice"`
			Status   string `json:"status"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(members["controls.json"]), &controls); err != nil {
		t.Fatalf("controls.json is not JSON: %v", err)
	}
	if controls.Status != "unmapped" {
		t.Errorf("controls.json claims status %q", controls.Status)
	}
	for _, e := range controls.Entries {
		if e.Practice != "" {
			t.Errorf("an entry claims practice %q before the mapping was transcribed", e.Practice)
		}
	}
	// The markdown a human reads has to carry the same warning, because that is
	// the one that gets pasted somewhere.
	if !strings.Contains(members["controls.md"], "worse than one that is absent") {
		t.Errorf("controls.md does not warn against using it:\n%s", members["controls.md"])
	}

	for _, m := range []string{"revisions.jsonl", "remediation.jsonl", "nodes.json"} {
		if !strings.Contains(members[m], `"status": "pending"`) &&
			!strings.Contains(members[m], `"status":"pending"`) {
			t.Errorf("%s does not say it is pending:\n%s", m, members[m])
		}
	}
}

// R9-04, the property a careful buyer tests first: an expired licence stops new
// bundles and touches nothing that already exists.
func TestAnExpiredLicenceNeverMakesEvidenceUnreadable(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	a.licensed(time.Now().AddDate(1, 0, 0), license.FeatureEvidence)

	out := filepath.Join(a.dir, "bundle.tar.gz")
	if code, _, stderr := a.run("evidence", "export", "--out", out); code != ExitOK {
		t.Fatalf("export: %d %s", code, stderr)
	}

	// Replace the licence with one that ran out yesterday.
	a.licensedExpired()

	// The bundle already written still verifies, with no nodary involved.
	dir := t.TempDir()
	extractBundle(t, out, dir)
	if o, err := runIn(dir, "sha256sum", "-c", "manifest.sha256"); err != nil {
		t.Errorf("an existing bundle stopped verifying after expiry:\n%s", o)
	}

	// The free path is untouched.
	if code, stdout, stderr := a.run("audit", "export", "--format", "jsonl"); code != ExitOK {
		t.Errorf("audit export broke under an expired licence: %d %s", code, stderr)
	} else if !strings.Contains(stdout, `"seq"`) {
		t.Errorf("audit export produced nothing:\n%s", stdout)
	}
	if code, _, stderr := a.run("audit", "verify"); code != ExitOK {
		t.Errorf("audit verify broke under an expired licence: %d %s", code, stderr)
	}

	// Only the new export is refused, and it says why.
	code, _, stderr := a.run("evidence", "export", "--out", filepath.Join(a.dir, "second.tar.gz"))
	if code != ExitPolicy {
		t.Errorf("exit = %d, want %d", code, ExitPolicy)
	}
	if !strings.Contains(stderr, "expired") {
		t.Errorf("the refusal does not say the licence expired:\n%s", stderr)
	}
}

// licensedExpired replaces the applied licence with one that has already run
// out, signed by the same key so the signature is still good.
//
// The row is written directly because `license apply` refuses an expired
// licence, and rightly: accepting one would record a grant that was never in
// force. Expiry is a state an install reaches by time passing, not by an act,
// and this is the only way to reach it without waiting.
func (a *appliance) licensedExpired() {
	a.t.Helper()
	if a.licPriv == nil {
		a.t.Fatal("licensed() has not run")
	}
	src := "[license]\ncustomer = \"Test Manufacturing Inc\"\nissued = \"2020-01-01T00:00:00Z\"\n" +
		"expires = \"2021-01-01T00:00:00Z\"\nfeatures = [\"evidence\"]\n"
	sig := minisign.Sign(a.licPriv, a.licID, []byte(src), "nodary licence")

	db, err := sql.Open("sqlite", a.db)
	if err != nil {
		a.t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE license SET source = ?, signature = ? WHERE singleton = 1`,
		src, sig); err != nil {
		a.t.Fatalf("expiring the licence: %v", err)
	}
}

// execSQL runs a statement straight against the database, for states a test
// cannot reach through a verb — an agent's heartbeat, or a tamper.
func (a *appliance) execSQL(stmt string) {
	a.t.Helper()
	db, err := sql.Open("sqlite", a.db)
	if err != nil {
		a.t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(stmt); err != nil {
		a.t.Fatalf("exec %q: %v", stmt, err)
	}
}

func extractBundle(t *testing.T, path, into string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("the bundle is not gzip: %v", err)
	}
	out := map[string]string{}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading the tar: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(into, h.Name), body, 0o600); err != nil {
			t.Fatal(err)
		}
		out[h.Name] = string(body)
	}
	return out
}

func runIn(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	o, err := cmd.CombinedOutput()
	return string(o), err
}
