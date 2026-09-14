package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/minisign"
)

// signedRevision writes a manifest revision and its signature, and points this
// build's trust at the key that signed it.
func signedRevision(t *testing.T, revision int, mutate func(map[string]any)) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var id [8]byte
	copy(id[:], []byte("manifest"))
	previous := components.TrustedKey
	components.TrustedKey = minisign.EncodePublicKey(minisign.PublicKey{ID: id, Key: pub})
	t.Cleanup(func() { components.TrustedKey = previous })

	var doc map[string]any
	if err := json.Unmarshal(components.Document(), &doc); err != nil {
		t.Fatal(err)
	}
	doc["revision"] = revision
	if mutate != nil {
		mutate(doc)
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "components.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	sig := minisign.Sign(priv, id, body, "nodary component manifest revision")
	if err := os.WriteFile(path+".minisig", []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func embeddedRevision(t *testing.T) int {
	t.Helper()
	m, err := components.Load()
	if err != nil {
		t.Fatal(err)
	}
	return m.Revision
}

// R5-27's deliverable, and ADR 0007's reason for it: a customer takes a
// component fix on their own timeline rather than waiting for us to tag. The
// act is audited, so *which* manifest a fleet runs has a person against it.
func TestApplyingARevisionIsAnAuditedActThatTakesEffect(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	want := embeddedRevision(t) + 4
	path := signedRevision(t, want, nil)
	conf := t.TempDir()

	code, _, stderr := a.run("components", "apply", path, "--config-dir", conf,
		"--yes", "--justify", "taking the containerd fix ahead of the next release")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}

	// It is in the chain, which is what makes the running manifest attributable
	// rather than inferred from a version string.
	code, stdout, _ := a.run("audit", "list", "--format", "json")
	if code != ExitOK || !strings.Contains(stdout, "components.apply") {
		t.Errorf("the apply is not in the chain:\n%s", stdout)
	}

	// And it is what resolution now returns.
	// Through the bare runner: `components show` reads a file and the embedded
	// manifest, and needs no control plane at all.
	code, stdout, stderr = run(t, "components", "show", "--config-dir", conf, "--format", "json")
	if code != ExitOK {
		t.Fatalf("show: %s", stderr)
	}
	var out struct {
		Source struct {
			Revision int  `json:"revision"`
			Applied  bool `json:"applied"`
			Floor    int  `json:"floor"`
		} `json:"source"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("%v: %s", err, stdout)
	}
	if !out.Source.Applied || out.Source.Revision != want {
		t.Errorf("the revision is not in force: %+v", out.Source)
	}
	if out.Source.Floor != embeddedRevision(t) {
		t.Errorf("the floor moved: %+v", out.Source)
	}
}

// Nothing is written and nothing is recorded until the signature checks out. A
// chain record for a revision that was never applied is a false statement about
// the fleet.
func TestATamperedRevisionIsNeverAppliedOrRecorded(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	path := signedRevision(t, embeddedRevision(t)+4, nil)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body, ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := t.TempDir()

	code, _, stderr := a.run("components", "apply", path, "--config-dir", conf,
		"--yes", "--justify", "this should not land")
	if code == ExitOK {
		t.Fatal("a tampered revision was applied")
	}
	// ADR 0007's sharp edge, named where somebody will hit it: stock minisign
	// defaults to a prehashed signature this build refuses.
	if !strings.Contains(stderr, "-S -l") {
		t.Errorf("the refusal does not name the flag: %s", stderr)
	}
	if _, err := os.Stat(filepath.Join(conf, components.RevisionName)); !os.IsNotExist(err) {
		t.Error("a refused revision was written anyway")
	}
	code, stdout, _ := a.run("audit", "list", "--format", "json")
	if code == ExitOK && strings.Contains(stdout, "components.apply") {
		t.Errorf("a refused revision reached the chain:\n%s", stdout)
	}
}

// Ignored, not rejected: an offline site replaying a bundle it already opened
// should keep working rather than fail closed on something that is not an
// attack.
func TestAStaleRevisionIsAcceptedAsANoOp(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	path := signedRevision(t, embeddedRevision(t), nil)
	conf := t.TempDir()

	code, _, stderr := a.run("components", "apply", path, "--config-dir", conf,
		"--yes", "--justify", "replaying last quarter's bundle")
	if code != ExitOK {
		t.Fatalf("a stale revision failed the install: %d %s", code, stderr)
	}
	if !strings.Contains(stderr, "nothing applied") {
		t.Errorf("the no-op was not reported: %s", stderr)
	}
	if _, err := os.Stat(filepath.Join(conf, components.RevisionName)); !os.IsNotExist(err) {
		t.Error("a stale revision was installed")
	}
}

// A revision that pins nothing is well-formed and is not a manifest. Validate
// walks the components and finds nothing wrong with none of them, so this
// verified and superseded the floor until it was refused explicitly — leaving a
// fleet pinning nothing at all.
func TestARevisionThatPinsNothingIsRefused(t *testing.T) {
	a := newAppliance(t)
	a.addUser("alice", "admin")
	path := signedRevision(t, embeddedRevision(t)+4, func(doc map[string]any) {
		doc["components"] = []any{}
	})

	code, _, stderr := a.run("components", "apply", path, "--config-dir", t.TempDir(),
		"--yes", "--justify", "this must not land")
	if code == ExitOK {
		t.Fatal("a manifest pinning nothing replaced one that pins everything")
	}
	if !strings.Contains(stderr, "pins no components") {
		t.Errorf("the refusal does not say what is wrong: %s", stderr)
	}
}

// The seam. Every verb that resolves a component reaches the manifest through
// loadManifest, so an applied revision has to supersede the floor *there* —
// otherwise `components apply` writes a file that changes what `components
// show` says and nothing about what the fleet actually installs.
func TestAnAppliedRevisionIsWhatTheFetchingVerbsResolve(t *testing.T) {
	conf := t.TempDir()
	previous := configDir
	configDir = conf
	t.Cleanup(func() { configDir = previous })

	// A version string is the cheapest observable difference between the floor
	// and the revision, and `components list` prints it.
	const marked = "9.9.9-from-the-revision"
	path := signedRevision(t, embeddedRevision(t)+5, func(doc map[string]any) {
		list := doc["components"].([]any)
		list[0].(map[string]any)["version"] = marked
	})
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(path + ".minisig")
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		components.RevisionName: body, components.RevisionSig: sig,
	} {
		if err := os.WriteFile(filepath.Join(conf, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	code, stdout, stderr := run(t, "components", "list")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, marked) {
		t.Errorf("a fetching verb is still resolving the floor:\n%s", stdout)
	}
}
