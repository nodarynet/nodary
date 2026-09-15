// Package release is the trust anchor for a nodary binary.
//
// **A node cannot reach a release, and must not take one on trust.**
// dev/specs/03-agent.md §1 gives GPU hosts no egress, so a node that upgrades
// itself is handed a binary by its control plane (R5-16). Every other artifact
// a node receives is checked against something the node already holds — a
// component against its own embedded manifest, a certificate against its pinned
// CA — which is what "neither side trusts the other's word" means in
// dev/plans/R5a-components-and-units.md §1.
//
// The binary is the artifact where that property matters most and is hardest to
// keep, because the binary is what performs every other check. A compromised
// control plane can already dictate argv, images and models, so the capability
// is not new; what would be lost is the node's ability to *detect* it about the
// one artifact whose job is detection. So the release signature travels with
// the binary and the node verifies it here.
package release

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/nodarynet/nodary/internal/minisign"
)

// TrustedKey is the release signing key this build verifies binaries against.
//
// **Its own key**, separate from the component manifest's and the advisory
// feed's, for the reason ADR 0005 §3 gives: one key for several purposes puts
// whichever pipeline can reach it in the position of minting the others.
//
// Stamped in at release with `-ldflags -X`. While it holds the placeholder,
// nothing verifies and self-upgrade refuses — the same posture install.sh takes
// when its own `NODARY_PUBKEY` is still `REPLACE_AT_RELEASE_TIME`, and for the
// same reason: a development copy must not be able to install anything.
var TrustedKey = placeholderKey

const placeholderKey = "PLACEHOLDER-NOT-A-REAL-KEY"

// ErrUnverified is a binary whose signature did not check out — including the
// case where this build has no key to check it with.
var ErrUnverified = errors.New("the binary does not verify against the release key")

// Trusted reports whether this build carries a real key.
//
// Exposed so a caller can refuse *before* downloading a few tens of megabytes
// it is going to throw away, and say why.
func Trusted() bool { return !strings.Contains(TrustedKey, "PLACEHOLDER") }

// Verify checks a binary against its detached minisign signature.
//
// The signature file's contents rather than a path, because the caller fetched
// it over the same connection as the binary and there is no reason for this to
// know about a filesystem.
func Verify(binary []byte, signature string) error {
	if !Trusted() {
		return fmt.Errorf("%w: %w — this build carries a placeholder release key, so it "+
			"cannot check what it was handed", ErrUnverified, minisign.ErrPlaceholder)
	}
	pub, err := minisign.ParsePublicKey(TrustedKey)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	if _, err := minisign.Verify(pub, binary, signature); err != nil {
		return fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	return nil
}

// VerifyFile is Verify against a binary on disk.
func VerifyFile(path, signature string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return Verify(body, signature)
}
