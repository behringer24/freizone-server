package address

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// CurrentVersion is the only address version currently supported: SHA-256
// root-key hash, bech32m checksum.
const CurrentVersion = 0

const (
	hashGroupCount     = 14 // 70 bits of truncated hash, 5 bits per group
	payloadGroupCount  = 1 + hashGroupCount
	checksumGroupCount = 6
	idLength           = payloadGroupCount + checksumGroupCount // 21 chars

	// PrefixLength is the number of leading characters of an id that a
	// server enforces unique among its own accounts (see docs/PROTOCOL.md's
	// id-prefix uniqueness note): the version marker plus 4 real characters
	// of entropy. Matches FormatForDisplay's first group size exactly.
	PrefixLength = 5
)

// domainSeparationTag is used only as checksum input (per BIP-350's hrp
// role); it is never part of the resulting address string. It exists so a
// Freizone address can never be mistaken for (or collide with) an unrelated
// bech32m string that happens to use a real hrp.
const domainSeparationTag = "frz"

// DeriveID computes the self-certifying account address for a root public
// key: bech32m(SHA-256(rootPubKey) truncated to 70 bits, prefixed with a
// 5-bit version marker), with no human-readable prefix or separator -- a
// plain 21-character string (15 payload + 6 checksum).
func DeriveID(rootPubKey ed25519.PublicKey) (string, error) {
	if len(rootPubKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("address: root public key must be %d bytes, got %d", ed25519.PublicKeySize, len(rootPubKey))
	}

	hash := sha256.Sum256(rootPubKey)
	hashGroups := leadingBitGroups(hash[:], hashGroupCount, 5)

	payload := make([]int, 0, payloadGroupCount)
	payload = append(payload, CurrentVersion)
	payload = append(payload, hashGroups...)

	checksum := createChecksum(domainSeparationTag, payload)
	all := append(payload, checksum...)

	var sb strings.Builder
	sb.Grow(idLength)
	for _, v := range all {
		sb.WriteByte(charset[v])
	}
	return sb.String(), nil
}

// Verify reports whether id is the correct, self-certifying address for
// rootPubKey.
func Verify(id string, rootPubKey ed25519.PublicKey) (bool, error) {
	normalized, err := Normalize(id)
	if err != nil {
		return false, err
	}
	expected, err := DeriveID(rootPubKey)
	if err != nil {
		return false, err
	}
	return normalized == expected, nil
}

// StripSeparators removes cosmetic dashes/whitespace and lowercases id,
// without validating its length or checksum. Shared by Normalize (which
// additionally enforces the full 21-character form) and any caller that
// also needs to recognize the shorter, unchecksummed PrefixLength form.
func StripSeparators(id string) string {
	var sb strings.Builder
	for _, c := range id {
		switch c {
		case '-', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(unicode.ToLower(c))
	}
	return sb.String()
}

// ValidCharset reports whether every character in s belongs to the bech32m
// charset -- useful for validating a short id-prefix, which (unlike a full
// id) carries no checksum of its own to catch typos.
func ValidCharset(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune(charset, c) {
			return false
		}
	}
	return true
}

// Normalize strips cosmetic separators/whitespace, lowercases, and validates
// an address's length, character set, and checksum -- without needing the
// corresponding public key. It returns the canonical 21-character form.
func Normalize(id string) (string, error) {
	normalized := StripSeparators(id)

	if len(normalized) != idLength {
		return "", fmt.Errorf("address: id must be %d characters (excluding separators), got %d", idLength, len(normalized))
	}

	values := make([]int, idLength)
	for i, c := range normalized {
		idx := strings.IndexRune(charset, c)
		if idx < 0 {
			return "", fmt.Errorf("address: invalid character %q in id", c)
		}
		values[i] = idx
	}

	if !verifyChecksum(domainSeparationTag, values) {
		return "", errors.New("address: invalid checksum")
	}

	return normalized, nil
}

// FormatForDisplay inserts hyphens every 5 characters for readability. It is
// purely cosmetic: the canonical form used in storage, URLs, and comparisons
// has no separators. 5 (not 4) is deliberate: the first char is always the
// version marker (see CurrentVersion), so a 5-char first group carries 4
// real characters of entropy -- and happens to split the 15-char payload
// into exactly 3 even groups, leaving only the 6-char checksum tail uneven.
func FormatForDisplay(id string) string {
	var sb strings.Builder
	for i, c := range id {
		if i > 0 && i%5 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteRune(c)
	}
	return sb.String()
}

// leadingBitGroups reads the leading numGroups*groupSize bits from data
// (MSB-first) and splits them into numGroups values of groupSize bits each,
// discarding any remaining bits. Unlike a general-purpose bit-packing
// conversion, it does not validate that the discarded trailing bits are
// zero -- here they are genuine truncated hash entropy, not padding.
func leadingBitGroups(data []byte, numGroups, groupSize int) []int {
	maxAcc := (1 << uint(8+groupSize-1)) - 1
	mask := (1 << uint(groupSize)) - 1

	groups := make([]int, 0, numGroups)
	acc := 0
	bits := 0
	for _, b := range data {
		if len(groups) >= numGroups {
			break
		}
		acc = ((acc << 8) | int(b)) & maxAcc
		bits += 8
		for bits >= groupSize && len(groups) < numGroups {
			bits -= groupSize
			groups = append(groups, (acc>>uint(bits))&mask)
		}
	}
	return groups
}
