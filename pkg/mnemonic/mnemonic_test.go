package mnemonic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// knownVectors are canonical BIP-39 256-bit test vectors (Trezor/BIP-39
// reference set): the 32-byte entropy is used directly as our seed.
var knownVectors = []struct {
	seedHex string
	phrase  string
}{
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
	},
	{
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
	},
	{
		"8080808080808080808080808080808080808080808080808080808080808080",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
	},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestKnownVectors(t *testing.T) {
	for _, v := range knownVectors {
		seed := mustHex(t, v.seedHex)

		got, err := EncodeString(seed)
		if err != nil {
			t.Fatalf("Encode(%s): %v", v.seedHex, err)
		}
		if got != v.phrase {
			t.Errorf("Encode(%s)\n got  %q\n want %q", v.seedHex, got, v.phrase)
		}

		back, err := DecodeString(v.phrase)
		if err != nil {
			t.Fatalf("Decode(%q): %v", v.phrase, err)
		}
		if !bytes.Equal(back, seed) {
			t.Errorf("Decode(%q) = %x, want %s", v.phrase, back, v.seedHex)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	// Deterministic pseudo-random seeds: seed_n = SHA-256("frz" || n).
	for n := 0; n < 512; n++ {
		h := sha256.Sum256([]byte{'f', 'r', 'z', byte(n), byte(n >> 8)})
		seed := h[:]

		words, err := Encode(seed)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if len(words) != WordCount {
			t.Fatalf("Encode: got %d words, want %d", len(words), WordCount)
		}
		back, err := Decode(words)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if !bytes.Equal(back, seed) {
			t.Fatalf("round-trip mismatch: %x -> %x", seed, back)
		}
	}
}

func TestDecodeRejectsBadChecksum(t *testing.T) {
	// All-zero entropy's valid last word is "art"; any other final word that
	// keeps the entropy bits but flips the checksum must be rejected. "abandon"
	// (index 0) as the 24th word gives entropy still zero but checksum 0 != art.
	phrase := strings.Repeat("abandon ", 24)
	_, err := DecodeString(phrase)
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("got %v, want ErrChecksum", err)
	}
}

func TestDecodeRejectsUnknownWord(t *testing.T) {
	valid := knownVectors[0].phrase
	words := strings.Fields(valid)
	words[5] = "notaword"
	_, err := Decode(words)
	if !errors.Is(err, ErrUnknownWord) {
		t.Fatalf("got %v, want ErrUnknownWord", err)
	}
}

func TestDecodeRejectsWrongLength(t *testing.T) {
	_, err := Decode([]string{"abandon", "abandon"})
	if !errors.Is(err, ErrWordCount) {
		t.Fatalf("got %v, want ErrWordCount", err)
	}
}

func TestEncodeRejectsWrongSeedSize(t *testing.T) {
	_, err := Encode(make([]byte, 16))
	if !errors.Is(err, ErrSeedSize) {
		t.Fatalf("got %v, want ErrSeedSize", err)
	}
}

func TestDecodeCaseAndSpaceInsensitive(t *testing.T) {
	seed := mustHex(t, knownVectors[0].seedHex)
	messy := "  ABANDON  Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ART "
	back, err := DecodeString(messy)
	if err != nil {
		t.Fatalf("Decode(messy): %v", err)
	}
	if !bytes.Equal(back, seed) {
		t.Errorf("Decode(messy) = %x, want %s", back, knownVectors[0].seedHex)
	}
}

func TestWordlist(t *testing.T) {
	wl := Wordlist()
	if len(wl) != WordlistSize {
		t.Fatalf("Wordlist size %d, want %d", len(wl), WordlistSize)
	}
	if !ValidWord("abandon") || !ValidWord("ZOO") || ValidWord("notaword") {
		t.Fatal("ValidWord disagrees with wordlist")
	}
}
