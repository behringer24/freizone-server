package address

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func mustKey(t *testing.T, seed byte) ed25519.PublicKey {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey)
}

func TestDeriveIDLengthAndCharset(t *testing.T) {
	id, err := DeriveID(mustKey(t, 1))
	if err != nil {
		t.Fatalf("DeriveID() error = %v", err)
	}
	if len(id) != idLength {
		t.Fatalf("len(id) = %d, want %d", len(id), idLength)
	}
	for _, c := range id {
		if !strings.ContainsRune(charset, c) {
			t.Errorf("id contains character %q outside bech32m charset", c)
		}
	}
}

func TestDeriveIDDeterministic(t *testing.T) {
	key := mustKey(t, 7)
	id1, err := DeriveID(key)
	if err != nil {
		t.Fatalf("DeriveID() error = %v", err)
	}
	id2, err := DeriveID(key)
	if err != nil {
		t.Fatalf("DeriveID() error = %v", err)
	}
	if id1 != id2 {
		t.Errorf("DeriveID is not deterministic: %q != %q", id1, id2)
	}
}

func TestDeriveIDDifferentKeysDifferentIDs(t *testing.T) {
	id1, _ := DeriveID(mustKey(t, 1))
	id2, _ := DeriveID(mustKey(t, 2))
	if id1 == id2 {
		t.Errorf("expected different ids for different keys, both were %q", id1)
	}
}

func TestDeriveIDRejectsWrongKeySize(t *testing.T) {
	if _, err := DeriveID(ed25519.PublicKey([]byte{1, 2, 3})); err == nil {
		t.Error("expected error for undersized public key")
	}
}

func TestVerify(t *testing.T) {
	key := mustKey(t, 3)
	id, err := DeriveID(key)
	if err != nil {
		t.Fatalf("DeriveID() error = %v", err)
	}

	ok, err := Verify(id, key)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !ok {
		t.Error("Verify() = false, want true for the key that produced this id")
	}

	otherKey := mustKey(t, 4)
	ok, err = Verify(id, otherKey)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if ok {
		t.Error("Verify() = true, want false for a different key")
	}
}

func TestVerifyWithDisplayFormatting(t *testing.T) {
	key := mustKey(t, 5)
	id, _ := DeriveID(key)
	displayed := FormatForDisplay(id)
	if displayed == id {
		t.Fatalf("FormatForDisplay did not add separators: %q", displayed)
	}

	ok, err := Verify(strings.ToUpper(displayed), key)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !ok {
		t.Error("Verify() should accept a dash-formatted, uppercased id")
	}
}

func TestNormalizeRejectsBadLength(t *testing.T) {
	if _, err := Normalize("abcd"); err == nil {
		t.Error("expected error for too-short id")
	}
}

func TestNormalizeRejectsInvalidCharacter(t *testing.T) {
	key := mustKey(t, 6)
	id, _ := DeriveID(key)
	tampered := "1" + id[1:] // '1' is excluded from the bech32 charset
	if _, err := Normalize(tampered); err == nil {
		t.Error("expected error for id containing an invalid character")
	}
}

func TestNormalizeRejectsBadChecksum(t *testing.T) {
	key := mustKey(t, 8)
	id, _ := DeriveID(key)

	// Flip the last payload character to something else valid-charset-wise,
	// which should break the checksum.
	last := id[idLength-1]
	replacement := byte('q')
	if last == replacement {
		replacement = 'p'
	}
	tampered := id[:idLength-1] + string(replacement)

	if _, err := Normalize(tampered); err == nil {
		t.Errorf("expected checksum error for tampered id %q", tampered)
	}
}

func TestLeadingBitGroupsAllZero(t *testing.T) {
	data := make([]byte, 9)
	groups := leadingBitGroups(data, 14, 5)
	if len(groups) != 14 {
		t.Fatalf("len(groups) = %d, want 14", len(groups))
	}
	for i, g := range groups {
		if g != 0 {
			t.Errorf("groups[%d] = %d, want 0", i, g)
		}
	}
}

func TestLeadingBitGroupsAllOnes(t *testing.T) {
	data := make([]byte, 9)
	for i := range data {
		data[i] = 0xFF
	}
	groups := leadingBitGroups(data, 14, 5)
	if len(groups) != 14 {
		t.Fatalf("len(groups) = %d, want 14", len(groups))
	}
	for i, g := range groups {
		if g != 31 {
			t.Errorf("groups[%d] = %d, want 31", i, g)
		}
	}
}

func TestLeadingBitGroupsKnownPattern(t *testing.T) {
	// 0b10110_00101 -> groups [0b10110, 0b00101] = [22, 5]
	data := []byte{0b10110001, 0b01000000}
	groups := leadingBitGroups(data, 2, 5)
	want := []int{22, 5}
	if len(groups) != len(want) {
		t.Fatalf("len(groups) = %d, want %d", len(groups), len(want))
	}
	for i := range want {
		if groups[i] != want[i] {
			t.Errorf("groups[%d] = %d, want %d", i, groups[i], want[i])
		}
	}
}
