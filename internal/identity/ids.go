package identity

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// idAlphabet is RFC 4648 base32 without padding, lowercased.
//
// Base32 rather than hex because it says the same thing in fewer characters,
// and lowercase because these appear in audit records, log lines and command
// arguments, where a mixed-case identifier is one transcription error away from
// a support ticket. Nothing decodes an id, so the alphabet only has to be
// unambiguous to read.
var idAlphabet = base32.StdEncoding.WithPadding(base32.NoPadding)

// idBytes is 10, so an id is 16 characters carrying 80 bits. These are not
// secrets — they identify a row, and the secret is the token — so the bound
// that matters is collision, not guessing, and 80 bits puts that out of reach.
const idBytes = 10

// newID mints a prefixed identifier. The prefix is what makes an id
// self-describing in an audit record's target_id, where the kind and the
// identity are separate columns and only one of them is quoted in a report.
func newID(prefix string) (string, error) {
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating an identifier: %w", err)
	}
	return prefix + strings.ToLower(idAlphabet.EncodeToString(b)), nil
}
