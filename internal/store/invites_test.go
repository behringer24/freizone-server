package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/pkg/humancode"
)

func TestCreateAndConsumeInviteCode(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	mustCreateAccount(t, db, "admin1")

	code, err := CreateInviteCode(db, "admin1", nil, now)
	if err != nil {
		t.Fatalf("CreateInviteCode() error = %v", err)
	}
	if code == "" {
		t.Fatal("CreateInviteCode() returned empty code")
	}

	mustCreateAccount(t, db, "newuser")
	if err := ConsumeInviteCode(db, code, "newuser", now); err != nil {
		t.Fatalf("ConsumeInviteCode() error = %v", err)
	}

	inv, err := GetInviteCode(db, code)
	if err != nil {
		t.Fatalf("GetInviteCode() error = %v", err)
	}
	if inv.UsedAt == nil || inv.UsedByAccountID == nil || *inv.UsedByAccountID != "newuser" {
		t.Errorf("invite code not marked used correctly: %+v", inv)
	}
}

func TestConsumeInviteCodeNotFound(t *testing.T) {
	db := newTestDB(t)
	if err := ConsumeInviteCode(db, "does-not-exist", "newuser", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("ConsumeInviteCode() error = %v, want ErrNotFound", err)
	}
}

func TestConsumeInviteCodeAlreadyUsed(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	mustCreateAccount(t, db, "admin1")
	mustCreateAccount(t, db, "user1")
	mustCreateAccount(t, db, "user2")

	code, err := CreateInviteCode(db, "admin1", nil, now)
	if err != nil {
		t.Fatalf("CreateInviteCode() error = %v", err)
	}
	if err := ConsumeInviteCode(db, code, "user1", now); err != nil {
		t.Fatalf("first ConsumeInviteCode() error = %v", err)
	}
	if err := ConsumeInviteCode(db, code, "user2", now); !errors.Is(err, ErrInviteAlreadyUsed) {
		t.Errorf("second ConsumeInviteCode() error = %v, want ErrInviteAlreadyUsed", err)
	}
}

func TestConsumeInviteCodeExpired(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	mustCreateAccount(t, db, "admin1")
	mustCreateAccount(t, db, "user1")

	expiresAt := now.Add(-time.Hour)
	code, err := CreateInviteCode(db, "admin1", &expiresAt, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("CreateInviteCode() error = %v", err)
	}

	if err := ConsumeInviteCode(db, code, "user1", now); !errors.Is(err, ErrInviteExpired) {
		t.Errorf("ConsumeInviteCode() error = %v, want ErrInviteExpired", err)
	}
}

func TestConsumeInviteCodeNotYetExpired(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	mustCreateAccount(t, db, "admin1")
	mustCreateAccount(t, db, "user1")

	expiresAt := now.Add(time.Hour)
	code, err := CreateInviteCode(db, "admin1", &expiresAt, now)
	if err != nil {
		t.Fatalf("CreateInviteCode() error = %v", err)
	}

	if err := ConsumeInviteCode(db, code, "user1", now); err != nil {
		t.Errorf("ConsumeInviteCode() error = %v, want nil for a not-yet-expired code", err)
	}
}

func TestCreateInviteCodeFormatIsShortAndGrouped(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "admin1")

	code, err := CreateInviteCode(db, "admin1", nil, time.Now())
	if err != nil {
		t.Fatalf("CreateInviteCode() error = %v", err)
	}

	// "ABCD-EFGH-JKMN": 12 symbols in groups of 4. The whole point of the
	// format is that it can be read aloud and typed by hand.
	if want := humancode.Format(humancode.Normalize(code), inviteCodeGroup); code != want {
		t.Errorf("CreateInviteCode() = %q, want it grouped as %q", code, want)
	}
	stripped := humancode.Normalize(code)
	if len(stripped) != inviteCodeSymbols {
		t.Errorf("code %q has %d symbols, want %d", code, len(stripped), inviteCodeSymbols)
	}
	for _, c := range stripped {
		if !strings.ContainsRune(humancode.Alphabet, c) {
			t.Errorf("code %q contains %q, which is outside the alphabet", code, c)
		}
	}
}

func TestInviteCodePlaintextIsNeverStored(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "admin1")

	code, err := CreateInviteCode(db, "admin1", nil, time.Now())
	if err != nil {
		t.Fatalf("CreateInviteCode() error = %v", err)
	}

	// A leaked database must not yield a working invite, so nothing
	// resembling the code itself may appear in the row.
	var stored string
	if err := db.QueryRow(`SELECT code_hash FROM invite_codes`).Scan(&stored); err != nil {
		t.Fatalf("reading code_hash: %v", err)
	}
	if stored == code || stored == humancode.Normalize(code) {
		t.Errorf("code_hash %q is the code itself, want a hash", stored)
	}
	if len(stored) != 64 {
		t.Errorf("code_hash %q is %d chars, want a 64-char sha256 hex digest", stored, len(stored))
	}
}

func TestConsumeInviteCodeIsForgivingAboutHowItWasTyped(t *testing.T) {
	// Every variation a person might plausibly produce from the same printed
	// or spoken code has to redeem it: case, the grouping hyphens, stray
	// whitespace, and the letters the alphabet omits standing in for digits.
	variants := []struct {
		name   string
		mangle func(string) string
	}{
		{"as issued", func(c string) string { return c }},
		{"lowercased", strings.ToLower},
		{"without hyphens", func(c string) string { return strings.ReplaceAll(c, "-", "") }},
		{"lowercased without hyphens", func(c string) string {
			return strings.ToLower(strings.ReplaceAll(c, "-", ""))
		}},
		{"spaces instead of hyphens", func(c string) string { return strings.ReplaceAll(c, "-", " ") }},
		{"surrounded by whitespace", func(c string) string { return "  " + c + "\n" }},
		{"O typed for zero", func(c string) string { return strings.ReplaceAll(c, "0", "O") }},
		{"I typed for one", func(c string) string { return strings.ReplaceAll(c, "1", "I") }},
		{"l typed for one", func(c string) string { return strings.ReplaceAll(c, "1", "l") }},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			db := newTestDB(t)
			now := time.Now()
			mustCreateAccount(t, db, "admin1")
			mustCreateAccount(t, db, "newbie")

			code, err := CreateInviteCode(db, "admin1", nil, now)
			if err != nil {
				t.Fatalf("CreateInviteCode() error = %v", err)
			}
			if err := ConsumeInviteCode(db, v.mangle(code), "newbie", now); err != nil {
				t.Errorf("ConsumeInviteCode(%q) error = %v, want it accepted", v.mangle(code), err)
			}
		})
	}
}

func TestConsumeInviteCodeStillRejectsAWrongCode(t *testing.T) {
	// The forgiving normalization must not become "anything goes": a code
	// that differs by a real symbol is still wrong.
	db := newTestDB(t)
	now := time.Now()
	mustCreateAccount(t, db, "admin1")
	mustCreateAccount(t, db, "newbie")

	if _, err := CreateInviteCode(db, "admin1", nil, now); err != nil {
		t.Fatalf("CreateInviteCode() error = %v", err)
	}
	if err := ConsumeInviteCode(db, "ZZZZ-ZZZZ-ZZZZ", "newbie", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("ConsumeInviteCode(wrong code) error = %v, want ErrNotFound", err)
	}
}
