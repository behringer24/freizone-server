package store

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func testAccount(id string, isAdmin bool) Account {
	pub, _, _ := ed25519.GenerateKey(nil)
	return Account{
		ID:            id,
		RootPubKey:    pub,
		VersionMarker: 0,
		Status:        AccountStatusActive,
		IsAdmin:       isAdmin,
		CreatedAt:     time.Now(),
	}
}

func TestCreateAndGetAccount(t *testing.T) {
	db := newTestDB(t)
	acc := testAccount("acct1", false)

	if err := CreateAccount(db, acc); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	got, err := GetAccount(db, "acct1")
	if err != nil {
		t.Fatalf("GetAccount() error = %v", err)
	}
	if got.ID != acc.ID || !got.RootPubKey.Equal(acc.RootPubKey) || got.IsAdmin != acc.IsAdmin {
		t.Errorf("GetAccount() = %+v, want to match %+v", got, acc)
	}
}

func TestCreateAccountRejectsDuplicateID(t *testing.T) {
	db := newTestDB(t)
	acc := testAccount("acct-dup", false)

	if err := CreateAccount(db, acc); err != nil {
		t.Fatalf("first CreateAccount() error = %v", err)
	}
	err := CreateAccount(db, acc)
	if !errors.Is(err, ErrConflict) {
		t.Errorf("second CreateAccount() error = %v, want ErrConflict", err)
	}
}

func TestGetAccountNotFound(t *testing.T) {
	db := newTestDB(t)
	_, err := GetAccount(db, "does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetAccount() error = %v, want ErrNotFound", err)
	}
}

func TestAnyAdminExists(t *testing.T) {
	db := newTestDB(t)

	exists, err := AnyAdminExists(db)
	if err != nil {
		t.Fatalf("AnyAdminExists() error = %v", err)
	}
	if exists {
		t.Error("AnyAdminExists() = true before any admin was created")
	}

	if err := CreateAccount(db, testAccount("admin1", true)); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	exists, err = AnyAdminExists(db)
	if err != nil {
		t.Fatalf("AnyAdminExists() error = %v", err)
	}
	if !exists {
		t.Error("AnyAdminExists() = false after an admin was created")
	}
}
