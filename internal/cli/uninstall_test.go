package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nodarynet/nodary/internal/components"
	"github.com/nodarynet/nodary/internal/dataplane"
	"github.com/nodarynet/nodary/internal/install"
)

// installedTree stages what an install leaves on disk, for whichever roles are
// named, so an uninstall can be run against it without a live systemd.
func installedTree(t *testing.T, roles ...string) string {
	t.Helper()
	root := t.TempDir()
	etc := filepath.Join(root, "etc", "nodary")
	units := filepath.Join(root, install.DefaultUnitDir)
	for _, d := range []string{etc, units,
		filepath.Join(root, "opt", "nodary", "0.0.1"),
		filepath.Join(root, install.DefaultBinDir),
		filepath.Join(root, "var", "lib", "nodary", "models", "hub"),
		filepath.Join(root, "var", "log", "nodary"),
		filepath.Join(root, "usr", "bin"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range roles {
		switch role {
		case "server":
			write(filepath.Join(etc, "server.toml"), "bind = \"0.0.0.0:8443\"\n")
			// The database and the key that unseals it are the control plane's
			// alone; a GPU node has neither, which is why uninstalling one
			// needs no --purge.
			write(filepath.Join(root, "var", "lib", "nodary", "nodary.db"), "database")
			write(filepath.Join(etc, "secret.key"), "key")
		case "node":
			write(filepath.Join(etc, "agent.toml"), "server = \"https://127.0.0.1:8443\"\n"+
				"name = \"fractal\"\nca_fingerprint = \"sha256:"+strings.Repeat("a", 64)+"\"\n")
		}
		for name, body := range install.Units(role, dataplane.LiteLLM) {
			write(filepath.Join(units, name), body)
		}
	}

	write(filepath.Join(root, "opt", "nodary", "0.0.1", "nodary"), "binary")
	write(filepath.Join(root, install.DefaultBinDir, "nodary"), "link")
	write(filepath.Join(root, "var", "lib", "nodary", "models", "hub", "weights"), "tensors")
	write(filepath.Join(root, "var", "log", "nodary", "audit.jsonl"), "{}")

	// Two components: one nodary placed, one it found already there. Only the
	// first may ever be removed.
	write(filepath.Join(root, "usr", "bin", "containerd"), "theirs")
	write(filepath.Join(root, "usr", "bin", "nerdctl"), "ours")
	record, err := json.Marshal(components.Ownership{
		NodaryVersion: "0.0.1",
		Components: []components.Owned{
			{Component: "containerd", Path: "/usr/bin/containerd", Placed: false},
			{Component: "nerdctl", Path: "/usr/bin/nerdctl", Placed: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(etc, components.OwnershipFile), string(record))
	return root
}

func there(t *testing.T, parts ...string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(parts...))
	return err == nil
}

func TestUninstallingANodeLeavesStateAndWeights(t *testing.T) {
	root := installedTree(t, "node")

	code, stdout, stderr := run(t, "uninstall", "--root", root, "--force")
	if code != ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, stderr, stdout)
	}

	for _, gone := range [][]string{
		{root, "etc", "nodary"},
		{root, "opt", "nodary"},
		{root, install.DefaultBinDir, "nodary"},
		{root, install.DefaultUnitDir, "nodary-agent.service"},
		{root, "usr", "bin", "nerdctl"},
	} {
		if there(t, gone...) {
			t.Errorf("%s survived the uninstall", filepath.Join(gone...))
		}
	}
	// dev/specs/01-install.md §10: the default keeps state and weights.
	for _, kept := range [][]string{
		{root, "var", "lib", "nodary", "models", "hub", "weights"},
		{root, "var", "log", "nodary", "audit.jsonl"},
		// Found, not placed. A host is rarely only a nodary node, and removing
		// what an operator installed takes down whatever else uses it.
		{root, "usr", "bin", "containerd"},
	} {
		if !there(t, kept...) {
			t.Errorf("%s was removed and should not have been", filepath.Join(kept...))
		}
	}
	// The half it cannot do.
	if !strings.Contains(stderr, "nodary node revoke fractal") {
		t.Errorf("uninstalling a node does not name the server-side half: %s", stderr)
	}
}

// Without --purge the database survives in /var/lib/nodary while /etc/nodary —
// and secret.key with it — is removed either way, leaving a database nothing
// can ever unseal. That is refusable in advance rather than discoverable later.
func TestUninstallingAControlPlaneNeedsPurge(t *testing.T) {
	root := installedTree(t, "server")

	code, _, stderr := run(t, "uninstall", "--root", root, "--force")
	if code == ExitOK {
		t.Fatalf("a control plane uninstalled without --purge")
	}
	for _, want := range []string{"--purge", "secret.key", "backup create"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not mention %q: %s", want, stderr)
		}
	}
	if !there(t, root, "etc", "nodary", "secret.key") {
		t.Error("a refused uninstall removed something")
	}
}

// The weights sit inside the data directory by default, and --purge-models
// exists because they are the most expensive thing on the machine. Purging
// state must not take them by accident.
func TestPurgeKeepsWeightsUnlessPurgeModels(t *testing.T) {
	root := installedTree(t, "server", "node")

	if code, _, stderr := run(t, "uninstall", "--root", root, "--force", "--purge"); code != ExitOK {
		t.Fatalf("exit: %s", stderr)
	}
	if there(t, root, "var", "lib", "nodary", "nodary.db") {
		t.Error("--purge kept the database")
	}
	if there(t, root, "var", "log", "nodary", "audit.jsonl") {
		t.Error("--purge kept the logs")
	}
	if !there(t, root, "var", "lib", "nodary", "models", "hub", "weights") {
		t.Error("--purge deleted the weights; that is what --purge-models is for")
	}

	root2 := installedTree(t, "server", "node")
	if code, _, stderr := run(t, "uninstall", "--root", root2, "--force",
		"--purge", "--purge-models"); code != ExitOK {
		t.Fatalf("exit: %s", stderr)
	}
	if there(t, root2, "var", "lib", "nodary", "models", "hub", "weights") {
		t.Error("--purge-models kept the weights")
	}
}

// A unit an operator wrote is not nodary's to delete, however its name reads —
// the same rule components.Owned.Placed states for binaries.
func TestAUnitNodaryDidNotWriteIsLeftAlone(t *testing.T) {
	root := installedTree(t, "node")
	theirs := filepath.Join(root, install.DefaultUnitDir, "containerd.service")
	if err := os.WriteFile(theirs, []byte("[Unit]\nDescription=theirs\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := run(t, "uninstall", "--root", root, "--force")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !there(t, theirs) {
		t.Error("removed a unit nodary did not write")
	}
	if !strings.Contains(stdout, "not written by nodary") {
		t.Errorf("leaving it alone was not reported: %s", stdout)
	}
	// And the ones it did write still went.
	if there(t, root, install.DefaultUnitDir, "nodary-agent.service") {
		t.Error("nodary-agent.service survived")
	}
}

// A single box is both roles, which is the pilot topology. One verb has to
// handle it, because an operator should not have to know which halves they have.
func TestUninstallHandlesAHostThatIsBothRoles(t *testing.T) {
	root := installedTree(t, "server", "node")

	code, stdout, stderr := run(t, "uninstall", "--root", root, "--force", "--purge", "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var out struct {
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("%v: %s", err, stdout)
	}
	if len(out.Roles) != 2 {
		t.Errorf("roles = %v, want both", out.Roles)
	}
	for _, unit := range []string{"nodary-server.service", "nodary-agent.service",
		"nodary-gateway.service", "nodary-prune.timer"} {
		if there(t, root, install.DefaultUnitDir, unit) {
			t.Errorf("%s survived", unit)
		}
	}
}

// Rerunning after a failure has to finish the job, not report nothing to do.
func TestUninstallFinishesAHalfDoneOne(t *testing.T) {
	root := installedTree(t, "node")
	if err := os.RemoveAll(filepath.Join(root, "etc", "nodary")); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := run(t, "uninstall", "--root", root, "--force")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if there(t, root, "opt", "nodary") {
		t.Error("the binaries a half-finished uninstall left behind are still there")
	}
}
