package canonical

import (
	"math"
	"math/big"
	"strconv"
	"strings"
)

// exactFloat64 reports whether the integer i is representable as an IEEE-754
// double with no loss.
//
// This is an exactness test, not a magnitude test, and the difference is
// load-bearing. 2^53 is the largest integer below which *every* integer is
// representable, but plenty of larger ones still are: 10^17 is 5^17 * 2^17, and
// 5^17 fits in 53 bits. An earlier magnitude check rejected exactly those, which
// meant ES6 formatting could emit 100000000000000000 for the input 1e17 and then
// refuse to read its own output back — found by FuzzEncodeJSON in under a
// second. Producing a canonical form that cannot be re-canonicalised would break
// `audit verify`, which re-hashes stored records to check the chain.
func exactFloat64(i *big.Int) (float64, bool) {
	f, acc := new(big.Float).SetInt(i).Float64()
	return f, acc == big.Exact
}

// smallEnoughForExactInt is 2^53: at or below it every integer is exact, so the
// big.Int path can be skipped.
const smallEnoughForExactInt = 1 << 53

// formatNumber renders f the way ECMAScript's Number::toString does, which is
// what RFC 8785 §3.2.2.3 requires.
//
// Go's own formatting is close but not identical — strconv picks between %e and
// %f on different thresholds than ECMAScript does — so the exponent rules are
// applied here rather than delegated. Getting this wrong changes hashes for
// some values and not others, which is why it carries the JCS number suite as
// a test.
func formatNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errNotFinite
	}
	// Covers -0, which ECMAScript renders as "0" rather than "-0".
	if f == 0 {
		return "0", nil
	}

	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}

	// Shortest round-trip form, always scientific: "d.ddde±dd" or "de±dd".
	// The mantissa carries no trailing zeros at precision -1, which is what
	// makes it the digit string ECMAScript calls s.
	e := strconv.AppendFloat(nil, f, 'e', -1, 64)
	mant, expPart, _ := strings.Cut(string(e), "e")
	exp10, err := strconv.Atoi(expPart)
	if err != nil {
		return "", errNotFinite
	}

	digits := strings.Replace(mant, ".", "", 1)

	// ECMAScript defines k, n and s such that s has k digits and
	// s × 10^(n-k) == f. The scientific mantissa gives s directly, and
	// n is one more than the decimal exponent.
	k := len(digits)
	n := exp10 + 1

	var b strings.Builder
	b.WriteString(sign)
	switch {
	case k <= n && n <= 21:
		// Integral, no exponent needed: 100, 1e20 spelled out.
		b.WriteString(digits)
		b.WriteString(strings.Repeat("0", n-k))
	case 0 < n && n <= 21:
		// Decimal point inside the digits: 1.5
		b.WriteString(digits[:n])
		b.WriteByte('.')
		b.WriteString(digits[n:])
	case -6 < n && n <= 0:
		// Leading zeros rather than an exponent: 0.1, 0.000001
		b.WriteString("0.")
		b.WriteString(strings.Repeat("0", -n))
		b.WriteString(digits)
	default:
		// Exponential. ECMAScript always signs the exponent: 1e+21, 1e-7.
		if k == 1 {
			b.WriteString(digits)
		} else {
			b.WriteString(digits[:1])
			b.WriteByte('.')
			b.WriteString(digits[1:])
		}
		b.WriteByte('e')
		if n-1 >= 0 {
			b.WriteByte('+')
		} else {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(abs(n - 1)))
	}
	return b.String(), nil
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// formatInt renders an integer, refusing one a double cannot hold exactly.
//
// RFC 8785 §3.1 requires every number be expressible as a double, so a
// conforming implementation handed 2^53+1 emits 9007199254740992 — it rounds.
// nodary refuses instead: silently losing precision in a value someone will
// later be held to is the wrong failure for an audit record. On every input we
// do accept, our bytes match any conforming implementation.
func formatInt(i int64) (string, error) {
	if i <= smallEnoughForExactInt && i >= -smallEnoughForExactInt {
		return formatNumber(float64(i))
	}
	f, ok := exactFloat64(big.NewInt(i))
	if !ok {
		return "", errIntegerTooLarge
	}
	return formatNumber(f)
}

func formatUint(u uint64) (string, error) {
	if u <= smallEnoughForExactInt {
		return formatNumber(float64(u))
	}
	f, ok := exactFloat64(new(big.Int).SetUint64(u))
	if !ok {
		return "", errIntegerTooLarge
	}
	return formatNumber(f)
}

// formatIntLiteral renders an integer taken verbatim from a JSON document,
// where the value may exceed int64 entirely.
func formatIntLiteral(lit string) (string, error) {
	i, ok := new(big.Int).SetString(lit, 10)
	if !ok {
		return "", errNotFinite
	}
	f, exact := exactFloat64(i)
	if !exact {
		return "", errIntegerTooLarge
	}
	return formatNumber(f)
}
