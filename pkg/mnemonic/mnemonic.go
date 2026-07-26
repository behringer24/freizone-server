// Package mnemonic encodes a 32-byte seed as a 24-word BIP-39 recovery
// phrase and decodes it back. It is used to back up and restore a Freizone
// identity root key: the seed is the Ed25519 root private key's seed
// (ed25519.PrivateKey.Seed()), and account_id == hash(root_pubkey), so
// restoring the seed restores the exact same account (see pkg/address).
//
// Only BIP-39's entropy<->words mapping is used, not its PBKDF2 seed
// derivation: the 32-byte value *is* the entropy. That keeps the phrase
// interoperable with standard BIP-39 word tooling (offline validation,
// autocomplete) while encoding exactly the bytes needed to rebuild the key.
//
// For 256-bit entropy the checksum is 8 bits, giving 264 bits == 24 words of
// 11 bits each.
package mnemonic

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"strings"
)

//go:embed english.txt
var englishList string

const (
	// SeedSize is the entropy length this package encodes: 256 bits.
	SeedSize = 32
	// WordCount is the resulting phrase length: (256 + 8 checksum) / 11.
	WordCount = 24
	// WordlistSize is the number of words in the BIP-39 English list.
	WordlistSize = 2048

	bitsPerWord  = 11
	checksumBits = SeedSize * 8 / 32 // 8 bits for 256-bit entropy
	totalBits    = SeedSize*8 + checksumBits
)

var (
	// ErrSeedSize is returned by Encode for a seed that is not SeedSize bytes.
	ErrSeedSize = fmt.Errorf("mnemonic: seed must be %d bytes", SeedSize)
	// ErrWordCount is returned by Decode for a phrase that is not WordCount words.
	ErrWordCount = fmt.Errorf("mnemonic: phrase must be %d words", WordCount)
	// ErrUnknownWord is returned by Decode when a word is not in the list.
	ErrUnknownWord = errors.New("mnemonic: unknown word")
	// ErrChecksum is returned by Decode when the phrase's checksum does not match.
	ErrChecksum = errors.New("mnemonic: invalid checksum")
)

var (
	wordList  []string
	wordIndex map[string]int
)

func init() {
	wordList = strings.Fields(englishList)
	if len(wordList) != WordlistSize {
		panic(fmt.Sprintf("mnemonic: embedded wordlist must have %d entries, got %d", WordlistSize, len(wordList)))
	}
	wordIndex = make(map[string]int, len(wordList))
	for i, w := range wordList {
		wordIndex[w] = i
	}
}

// Encode turns a 32-byte seed into a 24-word BIP-39 phrase.
func Encode(seed []byte) ([]string, error) {
	if len(seed) != SeedSize {
		return nil, ErrSeedSize
	}
	sum := sha256.Sum256(seed)

	// entropy (256 bits) followed by the checksum byte (first 8 bits of the
	// hash) == 264 bits; checksumBits==8 for a 256-bit seed, so appending a
	// whole byte is exact.
	buf := make([]byte, 0, SeedSize+1)
	buf = append(buf, seed...)
	buf = append(buf, sum[0])

	words := make([]string, WordCount)
	for i := range words {
		words[i] = wordList[readBits(buf, i*bitsPerWord, bitsPerWord)]
	}
	return words, nil
}

// EncodeString is Encode with the words joined by single spaces.
func EncodeString(seed []byte) (string, error) {
	words, err := Encode(seed)
	if err != nil {
		return "", err
	}
	return strings.Join(words, " "), nil
}

// Decode validates a 24-word phrase and returns the 32-byte seed it encodes.
// Words are matched case-insensitively and trimmed of surrounding whitespace.
func Decode(words []string) ([]byte, error) {
	if len(words) != WordCount {
		return nil, ErrWordCount
	}

	buf := make([]byte, SeedSize+1)
	for i, w := range words {
		idx, ok := wordIndex[strings.ToLower(strings.TrimSpace(w))]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownWord, w)
		}
		writeBits(buf, i*bitsPerWord, bitsPerWord, idx)
	}

	seed := make([]byte, SeedSize)
	copy(seed, buf[:SeedSize])
	if sum := sha256.Sum256(seed); buf[SeedSize] != sum[0] {
		return nil, ErrChecksum
	}
	return seed, nil
}

// DecodeString splits a phrase on whitespace and decodes it (see Decode).
func DecodeString(phrase string) ([]byte, error) {
	return Decode(strings.Fields(phrase))
}

// Wordlist returns a copy of the 2048-word BIP-39 English list, for a client
// to drive word autocomplete/validation locally.
func Wordlist() []string {
	out := make([]string, len(wordList))
	copy(out, wordList)
	return out
}

// ValidWord reports whether w is in the wordlist (case-insensitive).
func ValidWord(w string) bool {
	_, ok := wordIndex[strings.ToLower(strings.TrimSpace(w))]
	return ok
}

// readBits reads n bits at bit offset off from b, MSB-first.
func readBits(b []byte, off, n int) int {
	v := 0
	for i := 0; i < n; i++ {
		pos := off + i
		bit := (b[pos/8] >> uint(7-pos%8)) & 1
		v = v<<1 | int(bit)
	}
	return v
}

// writeBits writes the low n bits of val at bit offset off into b, MSB-first.
func writeBits(b []byte, off, n, val int) {
	for i := 0; i < n; i++ {
		if (val>>uint(n-1-i))&1 == 1 {
			pos := off + i
			b[pos/8] |= 1 << uint(7-pos%8)
		}
	}
}
