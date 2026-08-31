// Package canonical implements RFC 8785 (JSON Canonicalization Scheme).
//
// Every hash in nodary is taken over the bytes this package produces: the audit
// chain's `hash` and `prev_hash` (docs/specs/07-identity-audit.md §3), the
// `intent_hash` binding an approved preview to what was applied (§2), and the
// configuration revision chain (docs/specs/08-data-model.md §2). Changing these
// bytes after records exist would invalidate history that was never tampered
// with, so the output is a frozen contract rather than an implementation
// detail.
//
// It does not use encoding/json for output. Go 1.27 ships both encoding/json
// and encoding/json/v2, and they disagree on the same input — v1 escapes <, >
// and & into \u003c, \u003e and \u0026, v2 does not. v1 also sorts map keys by UTF-8
// byte order where RFC 8785 §3.2.3 requires UTF-16 order, encodes struct fields
// in declaration order rather than sorted order, and silently substitutes
// U+FFFD for invalid UTF-8 instead of reporting it. Any of those would bind the
// audit chain to standard-library behaviour that is actively diverging.
//
// Conformance: on every input this package accepts, its output is byte-identical
// to any conforming JCS implementation. It accepts less than JCS does — see
// ErrIntegerTooLarge — and never differs on what it accepts.
package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// Rejections. Each names a case where a canonical form would otherwise be
// ambiguous, lossy, or silently different from another implementation's.
var (
	// ErrNotFinite is returned for NaN and ±Inf, which JSON cannot represent.
	ErrNotFinite = errors.New("value is not a finite number")

	// ErrIntegerTooLarge is returned for an integer no IEEE-754 double holds
	// exactly.
	//
	// This is an exactness test rather than a magnitude one: 10^17 exceeds
	// 2^53 and is still exact, and rejecting it would make the encoder refuse
	// to read back its own output for the input 1e17. RFC 8785 §3.1 requires
	// every number be expressible as a double, so a conforming implementation
	// given 2^53+1 emits 9007199254740992 — it rounds. Refusing beats silently
	// losing precision in a value someone will later be held to, which is what
	// RFC 7493 §2.2 recommends for interoperable JSON.
	ErrIntegerTooLarge = errors.New("integer is not exactly representable as a double")

	// ErrLoneSurrogate is returned for an unpaired \uD800-\uDFFF escape.
	// RFC 8785 §3.2.2.2 requires terminating rather than substituting, since
	// the alternative is a signature that verifies for one party and not
	// another.
	ErrLoneSurrogate = errors.New("unpaired surrogate escape")

	// ErrDuplicateKey is returned for an object with a repeated member name.
	// RFC 8259 leaves the outcome to the parser, so there is no single
	// canonical form for such an object.
	ErrDuplicateKey = errors.New("duplicate object key")

	// ErrInvalidUTF8 is returned for a string that is not well-formed UTF-8.
	ErrInvalidUTF8 = errors.New("string is not valid UTF-8")

	// ErrUnsupportedType is returned by Encode for a Go value outside the
	// closed domain it accepts.
	ErrUnsupportedType = errors.New("type is outside the canonical value domain")
)

// Unexported aliases keep the internal call sites terse.
var (
	errNotFinite       = ErrNotFinite
	errIntegerTooLarge = ErrIntegerTooLarge
	errLoneSurrogate   = ErrLoneSurrogate
	errDuplicateKey    = ErrDuplicateKey
	errInvalidUTF8     = ErrInvalidUTF8
)

// PathError reports where in the document a rejection occurred, so a refusal
// says which field is at fault rather than only that the record is unencodable.
type PathError struct {
	Path string
	Err  error
}

func (e *PathError) Error() string {
	if e.Path == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %v", e.Path, e.Err)
}

func (e *PathError) Unwrap() error { return e.Err }

func at(path string, err error) error {
	if err == nil {
		return nil
	}
	var pe *PathError
	if errors.As(err, &pe) {
		return err // already located, keep the innermost position
	}
	return &PathError{Path: path, Err: err}
}

// EncodeJSON returns the canonical form of an existing JSON document.
func EncodeJSON(data []byte) ([]byte, error) {
	// Checked against the raw bytes, because both conditions are unobservable
	// after encoding/json has decoded them: it replaces invalid UTF-8 and lone
	// surrogates alike with U+FFFD.
	if !utf8.Valid(data) {
		return nil, ErrInvalidUTF8
	}
	v, err := parse(data)
	if err != nil {
		return nil, err
	}
	if err := checkSurrogateEscapes(data); err != nil {
		return nil, err
	}
	return marshal(v)
}

// Encode returns the canonical form of a Go value.
//
// It accepts a closed domain — booleans, strings, nil, the integer kinds,
// float64, json.Number, slices and arrays, maps with string keys, structs with
// plain `json:"name"` tags, and pointers to any of those. Everything else is
// ErrUnsupportedType.
//
// The domain is closed on purpose. Routing through json.Marshal would inherit
// omitempty, json.Marshaler, time.Time and []byte-to-base64 behaviour wholesale
// and would make the invalid-UTF-8 rule unreachable, since v1 substitutes
// U+FFFD rather than erroring. An unencodable value is better as a loud refusal
// than as a quietly different set of bytes.
func Encode(v any) ([]byte, error) {
	iv, err := fromGo(v, "")
	if err != nil {
		return nil, err
	}
	return marshal(iv)
}

// Hash returns the SHA-256 of the canonical form.
func Hash(v any) ([32]byte, error) {
	b, err := Encode(v)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// HashHex returns the SHA-256 of the canonical form as lowercase hex, which is
// the form the schema stores for hash, prev_hash and intent_hash.
func HashHex(v any) (string, error) {
	sum, err := Hash(v)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum[:]), nil
}

// HashJSON is HashHex for an existing JSON document.
func HashJSON(data []byte) (string, error) {
	b, err := EncodeJSON(data)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// marshal serialises the intermediate representation. Both entry points funnel
// through it, which is what keeps them from drifting apart.
func marshal(v any) ([]byte, error) {
	var b strings.Builder
	if err := encodeValue(&b, v, ""); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func encodeValue(b *strings.Builder, v any, path string) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		if err := writeString(b, t); err != nil {
			return at(path, err)
		}
	case int64:
		s, err := formatInt(t)
		if err != nil {
			return at(path, err)
		}
		b.WriteString(s)
	case uint64:
		s, err := formatUint(t)
		if err != nil {
			return at(path, err)
		}
		b.WriteString(s)
	case float64:
		s, err := formatNumber(t)
		if err != nil {
			return at(path, err)
		}
		b.WriteString(s)
	case json.Number:
		s, err := formatJSONNumber(t)
		if err != nil {
			return at(path, err)
		}
		b.WriteString(s)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encodeValue(b, e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// RFC 8785 §3.2.3: by UTF-16 code unit, over the decoded name.
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })

		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeString(b, k); err != nil {
				return at(path+"."+k, err)
			}
			b.WriteByte(':')
			if err := encodeValue(b, t[k], path+"."+k); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return at(path, fmt.Errorf("%w: %T", ErrUnsupportedType, v))
	}
	return nil
}

// formatJSONNumber renders a number taken from a JSON document.
//
// An integer literal is range-checked against 2^53 before anything else: a
// float64 conversion would silently round it, which is the precision loss
// ErrIntegerTooLarge exists to prevent.
func formatJSONNumber(n json.Number) (string, error) {
	s := n.String()
	if !strings.ContainsAny(s, ".eE") {
		return formatIntLiteral(s)
	}
	f, err := n.Float64()
	if err != nil {
		return "", errNotFinite
	}
	return formatNumber(f)
}
