package store

import (
	"errors"
	"testing"
	"time"
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
