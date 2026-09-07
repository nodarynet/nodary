// Package minisign verifies detached minisign signatures.
//
// It exists because nothing in the tree verified a signature in Go: every check
// was shell calling openssl or the minisign binary, and docs/adr/0007 needs the
// component manifest verified inside the binary once it stops being embedded in
// it. The same verifier checks a licence key and the advisory feed.
//
// # Only the legacy algorithm
//
// Minisign has two: `Ed` signs the message with Ed25519, and `ED` signs a
// BLAKE2b-512 digest of it. This package implements the first and refuses the
// second, deliberately. BLAKE2b is not in the standard library and is not
// FIPS-approved, so accepting `ED` would put a non-approved hash on the path
// that decides what a node installs — inside the boundary docs/adr/0006 exists
// to defend.
//
// **`Ed` is not what minisign produces by default.** Measured against minisign
// 0.11: a bare `minisign -S` writes a prehashed `ED` signature, and `-l` is
// what asks for the legacy format. Anything this package must verify has to be
// signed `minisign -S -l`, and the refusal below says so — the failure
// otherwise arrives as "signature does not verify" against a signature that is
// perfectly good.
//
// # Wire format
//
//	public key:  untrusted comment line, then base64( "Ed" || keyID[8] || pub[32] )
//	signature:   untrusted comment line
//	             base64( alg[2] || keyID[8] || sig[64] )
//	             "trusted comment: ..." line
//	             base64( globalSig[64] ) over sig || trustedComment
//
// The trusted comment is only trustworthy because of that last line: it is
// covered by a second signature, which is what stops a signature being lifted
// from one artifact onto another that claims to be something else.
package minisign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Errors a caller distinguishes. Everything else is a malformed input.
var (
	ErrPrehashed   = errors.New("prehashed signature: sign with `minisign -S -l`, which is not the default")
	ErrWrongKey    = errors.New("signature was made by a different key")
	ErrBadSig      = errors.New("signature does not verify")
	ErrMalformed   = errors.New("malformed minisign data")
	ErrPlaceholder = errors.New("this build carries a placeholder key and cannot verify anything")
)

const (
	algLegacy    = "Ed"
	algPrehashed = "ED"
	keyIDLen     = 8
	sigLen       = ed25519.SignatureSize
)

// PublicKey is a parsed minisign public key.
type PublicKey struct {
	ID  [keyIDLen]byte
	Key ed25519.PublicKey
}

// ParsePublicKey reads the two-line public key file minisign writes, or just
// its payload line.
func ParsePublicKey(s string) (PublicKey, error) {
	lines := contentLines(s)
	if len(lines) == 0 {
		return PublicKey{}, fmt.Errorf("%w: the public key is empty", ErrMalformed)
	}
	// The payload is the last content line; the first is an untrusted comment
	// when the file has one.
	raw, err := base64.StdEncoding.DecodeString(lines[len(lines)-1])
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: the public key is not base64: %v", ErrMalformed, err)
	}
	if want := 2 + keyIDLen + ed25519.PublicKeySize; len(raw) != want {
		return PublicKey{}, fmt.Errorf("%w: public key is %d bytes, want %d", ErrMalformed, len(raw), want)
	}
	if alg := string(raw[:2]); alg != algLegacy {
		return PublicKey{}, fmt.Errorf("%w: unsupported public key algorithm %q", ErrMalformed, alg)
	}
	var k PublicKey
	copy(k.ID[:], raw[2:2+keyIDLen])
	k.Key = ed25519.PublicKey(raw[2+keyIDLen:])
	return k, nil
}

// Signature is a parsed detached signature.
type Signature struct {
	ID             [keyIDLen]byte
	Sig            []byte
	TrustedComment string
	GlobalSig      []byte
}

// ParseSignature reads a .minisig file.
func ParseSignature(s string) (Signature, error) {
	lines := contentLines(s)
	if len(lines) < 4 {
		return Signature{}, fmt.Errorf("%w: a signature file has four lines, this has %d", ErrMalformed, len(lines))
	}
	raw, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil {
		return Signature{}, fmt.Errorf("%w: the signature is not base64: %v", ErrMalformed, err)
	}
	if want := 2 + keyIDLen + sigLen; len(raw) != want {
		return Signature{}, fmt.Errorf("%w: signature is %d bytes, want %d", ErrMalformed, len(raw), want)
	}
	switch alg := string(raw[:2]); alg {
	case algLegacy:
	case algPrehashed:
		return Signature{}, ErrPrehashed
	default:
		return Signature{}, fmt.Errorf("%w: unknown signature algorithm %q", ErrMalformed, alg)
	}

	tc, ok := strings.CutPrefix(lines[2], "trusted comment: ")
	if !ok {
		return Signature{}, fmt.Errorf("%w: the third line is not a trusted comment", ErrMalformed)
	}
	global, err := base64.StdEncoding.DecodeString(lines[3])
	if err != nil || len(global) != sigLen {
		return Signature{}, fmt.Errorf("%w: the global signature is not %d base64 bytes", ErrMalformed, sigLen)
	}

	var sig Signature
	copy(sig.ID[:], raw[2:2+keyIDLen])
	sig.Sig = raw[2+keyIDLen:]
	sig.TrustedComment = tc
	sig.GlobalSig = global
	return sig, nil
}

// Verify checks a detached signature over msg.
//
// The trusted comment is checked too, and a failure there is as fatal as a
// failure on the message: a comment that is not covered by a signature is
// attacker-controlled text sitting inside something a human will read.
func Verify(pub PublicKey, msg []byte, sigFile string) (Signature, error) {
	sig, err := ParseSignature(sigFile)
	if err != nil {
		return Signature{}, err
	}
	if !bytes.Equal(sig.ID[:], pub.ID[:]) {
		return Signature{}, fmt.Errorf("%w: signed by %x, this build trusts %x",
			ErrWrongKey, sig.ID, pub.ID)
	}
	if !ed25519.Verify(pub.Key, msg, sig.Sig) {
		return Signature{}, ErrBadSig
	}
	if !ed25519.Verify(pub.Key, append(append([]byte{}, sig.Sig...), sig.TrustedComment...), sig.GlobalSig) {
		return Signature{}, fmt.Errorf("%w: the trusted comment is not covered by the signature", ErrBadSig)
	}
	return sig, nil
}

// Sign produces a detached signature. It is here rather than in a test because
// an install signs its own evidence bundle (docs/specs/13-evidence.md §2).
func Sign(priv ed25519.PrivateKey, id [keyIDLen]byte, msg []byte, trustedComment string) string {
	sig := ed25519.Sign(priv, msg)
	line := append(append([]byte(algLegacy), id[:]...), sig...)
	global := ed25519.Sign(priv, append(append([]byte{}, sig...), trustedComment...))
	return fmt.Sprintf("untrusted comment: signature from nodary\n%s\ntrusted comment: %s\n%s\n",
		base64.StdEncoding.EncodeToString(line), trustedComment,
		base64.StdEncoding.EncodeToString(global))
}

// EncodePublicKey renders a public key in the file form minisign -V accepts,
// so an assessor can check a bundle with the stock tool.
func EncodePublicKey(k PublicKey) string {
	raw := append(append([]byte(algLegacy), k.ID[:]...), k.Key...)
	return fmt.Sprintf("untrusted comment: minisign public key %X\n%s\n",
		k.ID, base64.StdEncoding.EncodeToString(raw))
}

func contentLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
