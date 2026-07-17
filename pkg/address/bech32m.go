// Package address implements Freizone's self-certifying account addressing
// scheme: a bech32m-derived identifier computed from the SHA-256 hash of an
// account's root Ed25519 public key.
package address

import (
	"errors"
	"strings"
)

// charset is the BIP-350 bech32/bech32m character set.
const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32mConst is the BIP-350 checksum XOR constant (distinct from the
// original bech32 constant of 1).
const bech32mConst = 0x2bc830a3

var generator = [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

// polymod computes the bech32 checksum polynomial over a sequence of 5-bit
// values, per BIP-173/BIP-350.
func polymod(values []int) int {
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
}

// hrpExpand expands a human-readable part into the value sequence used for
// checksum computation, per BIP-173.
func hrpExpand(hrp string) []int {
	ret := make([]int, 0, len(hrp)*2+1)
	for _, c := range hrp {
		ret = append(ret, int(c)>>5)
	}
	ret = append(ret, 0)
	for _, c := range hrp {
		ret = append(ret, int(c)&31)
	}
	return ret
}

// verifyChecksum reports whether data (which includes a trailing 6-group
// checksum) is a valid bech32m sequence for hrp.
func verifyChecksum(hrp string, data []int) bool {
	values := append(hrpExpand(hrp), data...)
	return polymod(values) == bech32mConst
}

// createChecksum computes the 6-group bech32m checksum for hrp and data.
func createChecksum(hrp string, data []int) []int {
	values := append(hrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := polymod(values) ^ bech32mConst
	checksum := make([]int, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = (mod >> uint(5*(5-i))) & 31
	}
	return checksum
}

// EncodeBech32m encodes hrp and a sequence of 5-bit values (0-31, without a
// checksum) into a full bech32m string "hrp1<data><checksum>".
func EncodeBech32m(hrp string, data []int) (string, error) {
	for _, c := range hrp {
		if c < 33 || c > 126 {
			return "", errors.New("bech32m: invalid character in human-readable part")
		}
	}
	for _, v := range data {
		if v < 0 || v > 31 {
			return "", errors.New("bech32m: data value out of range")
		}
	}

	combined := append(append([]int{}, data...), createChecksum(hrp, data)...)

	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, v := range combined {
		sb.WriteByte(charset[v])
	}

	result := sb.String()
	if len(result) > 90 {
		return "", errors.New("bech32m: encoded string exceeds maximum length of 90")
	}
	return result, nil
}

// DecodeBech32m decodes a bech32m string, verifies its checksum, and returns
// the human-readable part and the data values (with the checksum stripped).
func DecodeBech32m(s string) (hrp string, data []int, err error) {
	if len(s) < 8 || len(s) > 90 {
		return "", nil, errors.New("bech32m: invalid length")
	}

	lower := strings.ToLower(s)
	upper := strings.ToUpper(s)
	if s != lower && s != upper {
		return "", nil, errors.New("bech32m: mixed case is not allowed")
	}
	s = lower

	pos := strings.LastIndex(s, "1")
	if pos < 1 || pos+7 > len(s) {
		return "", nil, errors.New("bech32m: invalid separator position")
	}

	hrp = s[:pos]
	for _, c := range hrp {
		if c < 33 || c > 126 {
			return "", nil, errors.New("bech32m: invalid character in human-readable part")
		}
	}

	dataPart := s[pos+1:]
	values := make([]int, len(dataPart))
	for i, c := range dataPart {
		idx := strings.IndexRune(charset, c)
		if idx < 0 {
			return "", nil, errors.New("bech32m: invalid data character")
		}
		values[i] = idx
	}

	if !verifyChecksum(hrp, values) {
		return "", nil, errors.New("bech32m: invalid checksum")
	}

	return hrp, values[:len(values)-6], nil
}
