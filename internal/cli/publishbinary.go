package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/nodarynet/nodary/internal/api"
	"github.com/nodarynet/nodary/internal/install"
	"github.com/nodarynet/nodary/internal/paths"
	"github.com/nodarynet/nodary/internal/release"
)

// BinarySig is the release signature kept beside an installed binary.
//
// install.sh downloads it to verify what it is about to install and, as of
// R5-16, keeps it instead of discarding it with the temporary directory. A
// signature nobody retained is one a node can never be shown.
const BinarySig = "nodary.minisig"

// publishBinary copies this host's own binary and its release signature into
// the mirror, so a node with no egress can fetch and verify an upgrade
// (dev/specs/03-agent.md §1, R5-16).
//
// **It verifies before it publishes.** A control plane that served a binary it
// could not itself check would be asking every node to trust bytes on its word
// — which is the one thing dev/plans/R5a-components-and-units.md §1 says
// neither side does. Verifying here also means the failure lands on the machine
// with an operator on it, rather than on twenty nodes at once.
//
// Absent inputs are reported and skipped rather than failing the upgrade: a
// host whose install.sh predates this has no signature to copy, and the rest of
// the upgrade is still correct and still worth doing.
func publishBinary(dataDir, optDir, version, platform string) install.Step {
	step := install.Step{Name: "mirror: binary"}

	if !release.Trusted() {
		step.Detail = "skipped: this build carries a placeholder release key, so nothing it " +
			"published could be verified by a node"
		return step
	}
	src := filepath.Join(optDir, version, "nodary")
	sig := filepath.Join(optDir, version, BinarySig)

	sigBody, err := os.ReadFile(sig)
	if errors.Is(err, os.ErrNotExist) {
		step.Detail = "skipped: no release signature beside " + src +
			"; reinstall with install.sh to keep one"
		return step
	}
	if err != nil {
		step.Detail = err.Error()
		return step
	}
	if err := release.VerifyFile(src, string(sigBody)); err != nil {
		// Not published, and loudly. The alternative is a mirror serving
		// something this host already knows does not check out.
		step.Detail = "NOT published: " + err.Error()
		return step
	}

	name := fmt.Sprintf("nodary-%s-%s", version, platform)
	dist := api.DistDir(dataDir)
	if err := os.MkdirAll(dist, paths.ModeDataDir); err != nil {
		step.Detail = err.Error()
		return step
	}
	if err := copyFile(src, filepath.Join(dist, name), 0o755); err != nil {
		step.Detail = err.Error()
		return step
	}
	if err := os.WriteFile(filepath.Join(dist, name+".minisig"), sigBody, 0o644); err != nil {
		step.Detail = err.Error()
		return step
	}
	step.Changed = true
	step.Detail = name + " (verified against the release key)"
	return step
}

// copyFile writes through a temporary name and renames, so the mirror never
// serves a half-written binary — the same reason internal/derive exports an
// image that way.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".nodary-publish-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}
