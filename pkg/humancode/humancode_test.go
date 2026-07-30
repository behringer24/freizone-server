package humancode

import (
	"strings"
	"testing"
)

func TestGenerateLengthAndCharset(t *testing.T) {
	for _, symbols := range []int{1, 8, 12} {
		code, err := Generate(symbols)
		if err != nil {
			t.Fatalf("Generate(%d): %v", symbols, err)
		}
		if len(code) != symbols {
			t.Errorf("Generate(%d) = %q, want %d symbols", symbols, code, symbols)
		}
		for _, c := range code {
			if !strings.ContainsRune(Alphabet, c) {
				t.Errorf("Generate(%d) = %q contains %q, which is outside the alphabet", symbols, code, c)
			}
		}
	}
}

func TestGenerateRejectsOutOfRange(t *testing.T) {
	// 12 symbols is the accumulator's ceiling (60 bits); asking for more
	// would silently produce a biased or truncated code.
	for _, symbols := range []int{0, -1, 13} {
		if _, err := Generate(symbols); err == nil {
			t.Errorf("Generate(%d) succeeded, want an error", symbols)
		}
	}
}

func TestGenerateIsNotConstant(t *testing.T) {
	first, err := Generate(12)
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		next, err := Generate(12)
		if err != nil {
			t.Fatal(err)
		}
		if next != first {
			return
		}
	}
	t.Fatalf("Generate(12) returned %q 21 times in a row", first)
}

func TestNormalize(t *testing.T) {
	const canonical = "ABCD1234JKMN"
	// Every one of these is the same code as far as the person typing is
	// concerned, so all of them must normalize to the same string.
	for _, in := range []string{
		canonical,
		"abcd1234jkmn",
		"ABCD-1234-JKMN",
		"abcd-1234-jkmn",
		"ABCD 1234 JKMN",
		"ABCD_1234_JKMN",
		" ABCD-1234-JKMN\n",
		"ABCD-1234-\tJKMN",
		// I/L misread as 1, O misread as 0 -- unambiguous, since the
		// alphabet cannot produce those letters in the first place.
		"ABCDI234JKMN",
		"ABCDl234JKMN",
		"ABCD1234JKMN",
	} {
		if got := Normalize(in); got != canonical {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, canonical)
		}
	}

	// O folds to zero.
	if got := Normalize("OOO"); got != "000" {
		t.Errorf(`Normalize("OOO") = %q, want "000"`, got)
	}
	// U has no digit it plausibly stands for, so it is left as-is and will
	// simply fail to match rather than being rewritten into another code.
	if got := Normalize("UUU"); got != "UUU" {
		t.Errorf(`Normalize("UUU") = %q, want "UUU"`, got)
	}
}

func TestNormalizeIsIdempotent(t *testing.T) {
	once := Normalize("abcd-1234-jkmn")
	if twice := Normalize(once); twice != once {
		t.Errorf("Normalize is not idempotent: %q then %q", once, twice)
	}
}

func TestFormat(t *testing.T) {
	cases := []struct {
		code  string
		group int
		want  string
	}{
		{"ABCDEFGHJKMN", 4, "ABCD-EFGH-JKMN"},
		{"ABCDEFGH", 4, "ABCD-EFGH"},
		{"ABCD", 4, "ABCD"}, // exactly one group: no trailing hyphen
		{"ABC", 4, "ABC"},   // shorter than a group
		{"ABCDE", 4, "ABCD-E"},
		{"ABCDEFGHJKMN", 0, "ABCDEFGHJKMN"},
		{"", 4, ""},
	}
	for _, c := range cases {
		if got := Format(c.code, c.group); got != c.want {
			t.Errorf("Format(%q, %d) = %q, want %q", c.code, c.group, got, c.want)
		}
	}
}

func TestFormatRoundTripsThroughNormalize(t *testing.T) {
	// The property the whole scheme rests on: a code may be displayed
	// grouped and typed back in either form.
	code, err := Generate(12)
	if err != nil {
		t.Fatal(err)
	}
	if got := Normalize(Format(code, 4)); got != code {
		t.Errorf("Normalize(Format(%q)) = %q, want the original", code, got)
	}
}
