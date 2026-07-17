package store

import (
	"errors"
	"testing"
	"time"
)

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

	if err := CreateAccount(db, testAccount("admin2", true)); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	if err := ClaimSetupToken(db, token, "admin2", now); !errors.Is(err, ErrInvalidToken) {
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
