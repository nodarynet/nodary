package canonical

import (
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// hexDigits is deliberately lowercase. RFC 8785 §3.2.2.2 requires lowercase
// hexadecimal in \uXXXX escapes; an uppercase hex digit changes
// the hash of every record carrying a control character, and would do so
// silently.
const hexDigits = "0123456789abcdef"

// writeString appends the JCS serialisation of s.
//
// RFC 8785 §3.2.2.2 names seven short escapes and requires everything else
// printable to be emitted literally. In particular the forward slash is NOT
// escaped, and neither is any non-ASCII character — encoding/json escapes
// <, > and & by default, which is why this does not use it.
func writeString(b *strings.Builder, s string) error {
	if !utf8.ValidString(s) {
		return errInvalidUTF8
	}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[r>>4])
				b.WriteByte(hexDigits[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return nil
}

// lessUTF16 reports whether a sorts before b by UTF-16 code unit, which is what
// RFC 8785 §3.2.3 specifies for property names.
//
// This is not the same as Go's native string comparison. Above U+FFFF a
// character encodes as a surrogate pair whose first unit lies in D800..DBFF, so
// it sorts *below* U+E000..U+FFFF; in UTF-8 byte order the same character sorts
// *above*. Sorting keys with `<` would therefore disagree with every conforming
// JCS implementation on any object mixing the two ranges.
//
// The comparison is over the decoded string, not its escaped form (§3.2.3).
func lessUTF16(a, b string) bool {
	au := utf16.Encode([]rune(a))
	bu := utf16.Encode([]rune(b))
	for i := 0; i < len(au) && i < len(bu); i++ {
		if au[i] != bu[i] {
			return au[i] < bu[i]
		}
	}
	return len(au) < len(bu)
}

// checkSurrogateEscapes rejects unpaired \uD800-\uDFFF escapes in raw JSON.
//
// This cannot be done after decoding: encoding/json silently substitutes U+FFFD
// for a lone surrogate, so by the time a Go string exists the evidence is gone
// and the value hashes differently from every other implementation. RFC 8785
// §3.2.2.2 requires terminating with an error, because the alternative is
// broken signatures.
//
// Escapes appear only inside string literals in valid JSON, and the caller has
// already established that the document parses, so a lexical scan is enough.
func checkSurrogateEscapes(data []byte) error {
	for i := 0; i+1 < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		if data[i+1] == '\\' {
			// An escaped backslash: skip both so `\\uD800` reads as a
			// literal backslash followed by text, not as an escape.
			i++
			continue
		}
		if data[i+1] != 'u' || i+5 >= len(data) {
			continue
		}
		hi, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 32)
		if err != nil {
			continue // malformed; the JSON parser reports it
		}
		switch {
		case hi >= 0xDC00 && hi <= 0xDFFF:
			// A trailing surrogate with no leading one before it.
			return errLoneSurrogate
		case hi >= 0xD800 && hi <= 0xDBFF:
			// Must be followed immediately by a trailing surrogate escape.
			j := i + 6
			if j+5 >= len(data) || data[j] != '\\' || data[j+1] != 'u' {
				return errLoneSurrogate
			}
			lo, err := strconv.ParseUint(string(data[j+2:j+6]), 16, 32)
			if err != nil || lo < 0xDC00 || lo > 0xDFFF {
				return errLoneSurrogate
			}
			i = j + 5
		}
	}
	return nil
}
