package store

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func testAccount(id string, isAdmin bool) Account {
	pub, _, _ := ed25519.GenerateKey(nil)
	role := RoleUser
	if isAdmin {
		role = RoleAdmin
	}
	return Account{
		ID:            id,
		RootPubKey:    pub,
		VersionMarker: 0,
		Status:        AccountStatusActive,
		Role:          role,
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
	if got.ID != acc.ID || !got.RootPubKey.Equal(acc.RootPubKey) || got.Role != acc.Role {
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

func TestCreateAccountRejectsSamePrefixDifferentID(t *testing.T) {
	db := newTestDB(t)
	if err := CreateAccount(db, testAccount("qsame-first-account", false)); err != nil {
		t.Fatalf("first CreateAccount() error = %v", err)
	}

	// Different id, but the same first 5 characters -- must be rejected
	// distinctly from an exact-duplicate id, since the caller's fix here is
	// "generate a fresh identity", not "you already have this account".
	err := CreateAccount(db, testAccount("qsame-second-account", false))
	if !errors.Is(err, ErrIDPrefixConflict) {
		t.Errorf("CreateAccount() with colliding prefix error = %v, want ErrIDPrefixConflict", err)
	}
	if errors.Is(err, ErrConflict) {
		t.Errorf("CreateAccount() with colliding prefix should not also be ErrConflict, got %v", err)
	}
}

func TestGetAccountNotFound(t *testing.T) {
	db := newTestDB(t)
	_, err := GetAccount(db, "does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetAccount() error = %v, want ErrNotFound", err)
	}
}

func TestCountActiveAdmins(t *testing.T) {
	db := newTestDB(t)

	count, err := CountActiveAdmins(db)
	if err != nil {
		t.Fatalf("CountActiveAdmins() error = %v", err)
	}
	if count != 0 {
		t.Errorf("CountActiveAdmins() = %d before any admin was created, want 0", count)
	}

	if err := CreateAccount(db, testAccount("admin1", true)); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	count, err = CountActiveAdmins(db)
	if err != nil {
		t.Fatalf("CountActiveAdmins() error = %v", err)
	}
	if count != 1 {
		t.Errorf("CountActiveAdmins() = %d after one admin was created, want 1", count)
	}

	if err := SetAccountStatus(db, "admin1", AccountStatusDisabled); err != nil {
		t.Fatalf("SetAccountStatus() error = %v", err)
	}
	count, err = CountActiveAdmins(db)
	if err != nil {
		t.Fatalf("CountActiveAdmins() error = %v", err)
	}
	if count != 0 {
		t.Errorf("CountActiveAdmins() = %d after the only admin was blocked, want 0", count)
	}
}

func TestSetAccountRole(t *testing.T) {
	db := newTestDB(t)
	if err := CreateAccount(db, testAccount("acct1", false)); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	if err := SetAccountRole(db, "acct1", RoleModerator); err != nil {
		t.Fatalf("SetAccountRole() error = %v", err)
	}
	got, err := GetAccount(db, "acct1")
	if err != nil {
		t.Fatalf("GetAccount() error = %v", err)
	}
	if got.Role != RoleModerator {
		t.Errorf("Role = %q, want %q", got.Role, RoleModerator)
	}

	if err := SetAccountRole(db, "does-not-exist", RoleAdmin); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetAccountRole() on unknown account error = %v, want ErrNotFound", err)
	}
}

func TestSetAccountStatus(t *testing.T) {
	db := newTestDB(t)
	if err := CreateAccount(db, testAccount("acct1", false)); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	if err := SetAccountStatus(db, "acct1", AccountStatusDisabled); err != nil {
		t.Fatalf("SetAccountStatus() error = %v", err)
	}
	got, err := GetAccount(db, "acct1")
	if err != nil {
		t.Fatalf("GetAccount() error = %v", err)
	}
	if got.Status != AccountStatusDisabled {
		t.Errorf("Status = %q, want %q", got.Status, AccountStatusDisabled)
	}

	if err := SetAccountStatus(db, "does-not-exist", AccountStatusActive); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetAccountStatus() on unknown account error = %v, want ErrNotFound", err)
	}
}

func TestDeleteAccount(t *testing.T) {
	db := newTestDB(t)
	if err := CreateAccount(db, testAccount("acct1", false)); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	if err := DeleteAccount(db, "acct1"); err != nil {
		t.Fatalf("DeleteAccount() error = %v", err)
	}
	if _, err := GetAccount(db, "acct1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetAccount() after delete error = %v, want ErrNotFound", err)
	}

	if err := DeleteAccount(db, "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteAccount() on unknown account error = %v, want ErrNotFound", err)
	}
}

func TestListAccounts(t *testing.T) {
	db := newTestDB(t)
	if err := CreateAccount(db, testAccount("acct1", false)); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	if err := CreateAccount(db, testAccount("acct2", true)); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	accounts, err := ListAccounts(db)
	if err != nil {
		t.Fatalf("ListAccounts() error = %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("ListAccounts() returned %d accounts, want 2", len(accounts))
	}
	if accounts[0].ID != "acct1" || accounts[1].ID != "acct2" {
		t.Errorf("ListAccounts() order = [%s, %s], want [acct1, acct2] (oldest first)", accounts[0].ID, accounts[1].ID)
	}
	if accounts[1].Role != RoleAdmin {
		t.Errorf("accounts[1].Role = %q, want %q", accounts[1].Role, RoleAdmin)
	}
}
