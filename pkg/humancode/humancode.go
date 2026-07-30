// Package humancode generates and normalizes short secrets meant to be
// read aloud, written on paper, and typed in by hand -- the server's setup
// token and its registration invite codes.
//
// It is deliberately NOT the same encoding as an account id (pkg/address,
// Bech32m with a checksum). An address is long-lived, appears everywhere,
// and benefits from a checksum catching a typo before anything is sent. A
// code here is short-lived, entered once, and verified against the server
// on the spot -- so the server's own "that code isn't valid" answer plays
// the role a checksum would, and the encoding stays as short as possible.
package humancode

import (
	"crypto/rand"
	"fmt"
	"strings"
	"unicode"
)

// Alphabet is Crockford's Base32 alphabet: it excludes I, L, O and U --
// the first three because they are easily confused with 1, 1 and 0, the
// last so a random code cannot spell something unfortunate. Its size
// (32 = 2^5) means each symbol carries exactly 5 bits with no modulo bias.
const Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Generate returns a code of symbols random symbols from [Alphabet], using
// exactly 5 random bits each. symbols must be positive and no more than 12,
// which is all the accumulator below can hold (12 * 5 = 60 bits).
func Generate(symbols int) (string, error) {
	if symbols <= 0 || symbols > 12 {
		return "", fmt.Errorf("humancode: symbols must be between 1 and 12, got %d", symbols)
	}

	raw := make([]byte, (symbols*5+7)/8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("humancode: reading random bytes: %w", err)
	}

	var acc uint64
	for _, b := range raw {
		acc = acc<<8 | uint64(b)
	}

	buf := make([]byte, symbols)
	for i := symbols - 1; i >= 0; i-- {
		buf[i] = Alphabet[acc&0x1f]
		acc >>= 5
	}
	return string(buf), nil
}

// Normalize turns whatever a human actually typed into the canonical form
// used for hashing and comparison. It is intentionally forgiving, because
// every one of these variations is the *same* code as far as the person
// entering it is concerned:
//
//   - case is ignored ("abcd" == "ABCD");
//   - cosmetic separators and whitespace are dropped, so the grouped form a
//     code is displayed in ("ABCD-EFGH-JKMN") matches the compact form a QR
//     carries, and a code split across a line break still works;
//   - the letters [Alphabet] deliberately omits are folded onto the digits
//     they get mistaken for: I and L become 1, O becomes 0. This is
//     unambiguous precisely *because* those letters can never occur in a
//     generated code -- seeing one can only mean a misread digit.
//
// U is left alone: it is excluded from the alphabet too, but there is no
// digit it plausibly stands for, so a code containing one simply will not
// match rather than being silently rewritten into a different code.
func Normalize(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for _, c := range s {
		switch c {
		case '-', '_', ' ', '\t', '\n', '\r':
			continue
		}
		switch upper := unicode.ToUpper(c); upper {
		case 'I', 'L':
			sb.WriteRune('1')
		case 'O':
			sb.WriteRune('0')
		default:
			sb.WriteRune(upper)
		}
	}
	return sb.String()
}

// Format groups an already-normalized code for display, inserting a hyphen
// every group symbols ("ABCDEFGHJKMN" with group 4 gives
// "ABCD-EFGH-JKMN"). Purely cosmetic: [Normalize] strips the result back to
// what Format was given, so a code may be shown grouped and typed either
// way. group <= 0 returns code unchanged.
func Format(code string, group int) string {
	if group <= 0 || len(code) <= group {
		return code
	}
	var sb strings.Builder
	sb.Grow(len(code) + len(code)/group)
	for i, c := range code {
		if i > 0 && i%group == 0 {
			sb.WriteByte('-')
		}
		sb.WriteRune(c)
	}
	return sb.String()
}
