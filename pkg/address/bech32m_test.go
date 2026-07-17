package address

import "testing"

// Official BIP-350 test vectors.
// Source: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

func TestDecodeBech32mValidVectors(t *testing.T) {
	valid := []string{
		"A1LQFN3A",
		"a1lqfn3a",
		"an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
		"abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
		"11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
		"split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
		"?1v759aa",
	}

	for _, s := range valid {
		if _, _, err := DecodeBech32m(s); err != nil {
			t.Errorf("DecodeBech32m(%q) unexpected error: %v", s, err)
		}
	}
}

func TestDecodeBech32mInvalidVectors(t *testing.T) {
	invalid := map[string]string{
		string(rune(0x20)) + "1xj0phk": "HRP character out of range",
		string(rune(0x7F)) + "1g6xzxy": "HRP character out of range",
		string(rune(0x80)) + "1vctc34": "HRP character out of range",
		"an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4": "overall max length exceeded",
		"qyrz8wqd2c9m":  "no separator character",
		"1qyrz8wqd2c9m": "empty HRP",
		"y1b0jsk6g":     "invalid data character",
		"lt1igcx5c0":    "invalid data character",
		"in1muywd":      "too short checksum",
		"mm1crxm3i":     "invalid character in checksum",
		"au1s5cgom":     "invalid character in checksum",
		"M1VUXWEZ":      "checksum calculated with uppercase form of HRP",
		"16plkw9":       "empty HRP",
		"1p2gdwpf":      "empty HRP",
	}

	for s, reason := range invalid {
		if _, _, err := DecodeBech32m(s); err == nil {
			t.Errorf("DecodeBech32m(%q) expected error (%s), got none", s, reason)
		}
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	data := []int{0, 1, 2, 3, 4, 5, 31, 30, 29}
	s, err := EncodeBech32m("frz", data)
	if err != nil {
		t.Fatalf("EncodeBech32m() error = %v", err)
	}

	hrp, decoded, err := DecodeBech32m(s)
	if err != nil {
		t.Fatalf("DecodeBech32m(%q) error = %v", s, err)
	}
	if hrp != "frz" {
		t.Errorf("hrp = %q, want frz", hrp)
	}
	if len(decoded) != len(data) {
		t.Fatalf("decoded length = %d, want %d", len(decoded), len(data))
	}
	for i := range data {
		if decoded[i] != data[i] {
			t.Errorf("decoded[%d] = %d, want %d", i, decoded[i], data[i])
		}
	}
}

func TestEncodeRejectsInvalidData(t *testing.T) {
	if _, err := EncodeBech32m("frz", []int{32}); err == nil {
		t.Error("expected error for out-of-range data value")
	}
}

func TestDecodeRejectsTamperedChecksum(t *testing.T) {
	s, err := EncodeBech32m("frz", []int{1, 2, 3})
	if err != nil {
		t.Fatalf("EncodeBech32m() error = %v", err)
	}
	tampered := s[:len(s)-1] + string(charsetOtherChar(s[len(s)-1]))
	if _, _, err := DecodeBech32m(tampered); err == nil {
		t.Errorf("expected checksum error decoding tampered string %q", tampered)
	}
}

func charsetOtherChar(c byte) byte {
	for i := 0; i < len(charset); i++ {
		if charset[i] != c {
			return charset[i]
		}
	}
	panic("unreachable")
}
