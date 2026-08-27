package store

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/pkg/humancode"
)

// TestDeleteAccountClearsSetupTokenClaimant is the regression guard for the
// undeletable-bootstrap-admin bug (audit L3): the setup_tokens FK on the
// claimant account must SET NULL on delete, not block it. Before migration
// 0015 this DeleteAccount failed the foreign-key constraint.
func TestDeleteAccountClearsSetupTokenClaimant(t *testing.T) {
	db := newTestDB(t)

	token, created, err := InitSetupToken(db, time.Now())
	if err != nil || !created {
		t.Fatalf("InitSetupToken() = %q, created=%v, err=%v", token, created, err)
	}
	mustCreateAccount(t, db, "admin")
	if err := ClaimSetupToken(db, token, "admin", time.Now()); err != nil {
		t.Fatalf("ClaimSetupToken() error = %v", err)
	}

	// The claimant account must be deletable despite the setup_tokens reference.
	if err := DeleteAccount(db, "admin"); err != nil {
		t.Fatalf("DeleteAccount() error = %v (setup_tokens FK must not block it)", err)
	}

	// The historical token row survives, with the claimant cleared to NULL.
	var claimant sql.NullString
	if err := db.QueryRow(`SELECT used_by_account_id FROM setup_tokens WHERE id = 1`).Scan(&claimant); err != nil {
		t.Fatalf("querying setup_tokens after delete: %v", err)
	}
	if claimant.Valid {
		t.Errorf("used_by_account_id = %q after claimant deleted, want NULL", claimant.String)
	}
}

func TestInitSetupTokenGeneratesOnce(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()

	token, created, err := InitSetupToken(db, now)
	if err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}
	if !created {
		t.Error("created = false on first call, want true")
	}
	if token == "" {
		t.Error("token is empty on first call")
	}

	token2, created2, err := InitSetupToken(db, now)
	if err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}
	if created2 {
		t.Error("created = true on second call, want false")
	}
	if token2 != "" {
		t.Error("expected empty token on second call (plaintext not recoverable)")
	}
}

func TestClaimSetupToken(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()

	token, _, err := InitSetupToken(db, now)
	if err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}

	if err := CreateAccount(db, testAccount("admin1", true)); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	if err := ClaimSetupToken(db, token, "admin1", now); err != nil {
		t.Fatalf("ClaimSetupToken() error = %v", err)
	}

	claimed, err := SetupTokenClaimed(db)
	if err != nil {
		t.Fatalf("SetupTokenClaimed() error = %v", err)
	}
	if !claimed {
		t.Error("SetupTokenClaimed() = false after a successful claim")
	}
}

func TestClaimSetupTokenRejectsWrongToken(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()

	if _, _, err := InitSetupToken(db, now); err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}

	if err := ClaimSetupToken(db, "wrong-token", "admin1", now); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("ClaimSetupToken() error = %v, want ErrInvalidToken", err)
	}
}

func TestGenerateSetupTokenFormat(t *testing.T) {
	token, err := generateSetupToken()
	if err != nil {
		t.Fatalf("generateSetupToken() error = %v", err)
	}
	if len(token) != setupTokenSymbols {
		t.Errorf("len(token) = %d, want %d", len(token), setupTokenSymbols)
	}
	for _, c := range token {
		if !strings.ContainsRune(humancode.Alphabet, c) {
			t.Errorf("token %q contains character %q outside humancode.Alphabet", token, c)
		}
	}
}

func TestClaimSetupTokenToleratesDashesAndLowercase(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()

	token, _, err := InitSetupToken(db, now)
	if err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}
	if err := CreateAccount(db, testAccount("admin1", true)); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	mid := len(token) / 2
	dashed := strings.ToLower(token[:mid] + "-" + token[mid:])
	if err := ClaimSetupToken(db, dashed, "admin1", now); err != nil {
		t.Fatalf("ClaimSetupToken(%q) error = %v, want nil", dashed, err)
	}
}

func TestClaimSetupTokenLocksOutAfterMaxAttempts(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()

	token, _, err := InitSetupToken(db, now)
	if err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}
	if err := CreateAccount(db, testAccount("admin1", true)); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	for i := 0; i < MaxSetupTokenAttempts; i++ {
		if err := ClaimSetupToken(db, "wrong-token", "admin1", now); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("attempt %d: ClaimSetupToken() error = %v, want ErrInvalidToken", i, err)
		}
		// ClaimSetupToken deliberately doesn't record the failed attempt
		// itself (see its doc comment) -- callers sharing a transaction
		// with other work must do this separately, against a DBTX that
		// commits independently of that transaction.
		if err := RecordFailedSetupTokenAttempt(db); err != nil {
			t.Fatalf("attempt %d: RecordFailedSetupTokenAttempt() error = %v", i, err)
		}
	}

	// The lockout threshold is now reached -- even the correct token must
	// be rejected, and the operator must reset instead.
	if err := ClaimSetupToken(db, token, "admin1", now); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("ClaimSetupToken() with correct token after lockout error = %v, want ErrInvalidToken", err)
	}
}

func TestClaimSetupTokenRejectsReuse(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()

	token, _, err := InitSetupToken(db, now)
	if err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}
	if err := CreateAccount(db, testAccount("admin1", true)); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	if err := ClaimSetupToken(db, token, "admin1", now); err != nil {
		t.Fatalf("first ClaimSetupToken() error = %v", err)
	}

	// A distinct fake id with a different first-5-char prefix from "admin1"
	// -- reusing an "adminN" pattern here would collide with the new
	// id_prefix uniqueness constraint, which isn't what this test is about.
	if err := CreateAccount(db, testAccount("second-admin", true)); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	if err := ClaimSetupToken(db, token, "second-admin", now); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("second ClaimSetupToken() error = %v, want ErrInvalidToken", err)
	}
}

func TestResetSetupToken(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()

	token1, _, err := InitSetupToken(db, now)
	if err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}

	if err := ResetSetupToken(db); err != nil {
		t.Fatalf("ResetSetupToken() error = %v", err)
	}

	token2, created, err := InitSetupToken(db, now)
	if err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}
	if !created {
		t.Error("created = false after reset, want true")
	}
	if token1 == token2 {
		t.Error("expected a fresh token after reset")
	}
}
