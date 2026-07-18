package store

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func testDevice(accountID, deviceID string) Device {
	pub, _, _ := ed25519.GenerateKey(nil)
	return Device{
		DeviceID:      deviceID,
		AccountID:     accountID,
		DevicePubKey:  pub,
		CertIssuedAt:  time.Now(),
		CertSignature: []byte{1, 2, 3, 4},
		Status:        DeviceStatusActive,
		CreatedAt:     time.Now(),
	}
}

func mustCreateAccount(t *testing.T, db DBTX, id string) {
	t.Helper()
	if err := CreateAccount(db, testAccount(id, false)); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
}

func TestCreateAndGetDevice(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	dev := testDevice("acct1", "device1")

	if err := CreateDevice(db, dev); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	got, err := GetDevice(db, "device1")
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if got.DeviceID != dev.DeviceID || got.AccountID != dev.AccountID || got.Status != DeviceStatusActive {
		t.Errorf("GetDevice() = %+v, want to match %+v", got, dev)
	}
	if got.RevokedAt != nil {
		t.Errorf("RevokedAt = %v, want nil", got.RevokedAt)
	}
}

func TestCreateDeviceRejectsDuplicateID(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	dev := testDevice("acct1", "device-dup")

	if err := CreateDevice(db, dev); err != nil {
		t.Fatalf("first CreateDevice() error = %v", err)
	}
	err := CreateDevice(db, dev)
	if !errors.Is(err, ErrConflict) {
		t.Errorf("second CreateDevice() error = %v, want ErrConflict", err)
	}
}

func TestGetDeviceNotFound(t *testing.T) {
	db := newTestDB(t)
	if _, err := GetDevice(db, "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetDevice() error = %v, want ErrNotFound", err)
	}
}

func TestListDevicesByAccount(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	mustCreateAccount(t, db, "acct2")

	if err := CreateDevice(db, testDevice("acct1", "d1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	if err := CreateDevice(db, testDevice("acct1", "d2")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	if err := CreateDevice(db, testDevice("acct2", "d3")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	devices, err := ListDevicesByAccount(db, "acct1")
	if err != nil {
		t.Fatalf("ListDevicesByAccount() error = %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("len(devices) = %d, want 2", len(devices))
	}
}

func TestRevokeDevice(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	if err := RevokeDevice(db, "device1", time.Now()); err != nil {
		t.Fatalf("RevokeDevice() error = %v", err)
	}

	got, err := GetDevice(db, "device1")
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if got.Status != DeviceStatusRevoked {
		t.Errorf("Status = %q, want %q", got.Status, DeviceStatusRevoked)
	}
	if got.RevokedAt == nil {
		t.Error("RevokedAt = nil, want non-nil after revocation")
	}
}

func TestRevokeDeviceNotFoundOrAlreadyRevoked(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	if err := RevokeDevice(db, "does-not-exist", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("RevokeDevice() on unknown device error = %v, want ErrNotFound", err)
	}

	if err := RevokeDevice(db, "device1", time.Now()); err != nil {
		t.Fatalf("first RevokeDevice() error = %v", err)
	}
	if err := RevokeDevice(db, "device1", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("RevokeDevice() on already-revoked device error = %v, want ErrNotFound", err)
	}
}

func TestSetDevicePushSubscription(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	got, err := GetDevice(db, "device1")
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if got.Push != nil {
		t.Errorf("Push = %v, want nil before it's ever set", got.Push)
	}

	sub := &PushSubscription{Endpoint: "https://push.example.org/wake/abc123", P256dh: "p256dh-value", Auth: "auth-value"}
	if err := SetDevicePushSubscription(db, "device1", sub); err != nil {
		t.Fatalf("SetDevicePushSubscription() error = %v", err)
	}
	got, err = GetDevice(db, "device1")
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if got.Push == nil || *got.Push != *sub {
		t.Errorf("Push = %v, want %v", got.Push, sub)
	}

	if err := SetDevicePushSubscription(db, "device1", nil); err != nil {
		t.Fatalf("SetDevicePushSubscription(nil) error = %v", err)
	}
	got, err = GetDevice(db, "device1")
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if got.Push != nil {
		t.Errorf("Push = %v, want nil after clearing", got.Push)
	}

	if err := SetDevicePushSubscription(db, "does-not-exist", sub); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetDevicePushSubscription() on unknown device error = %v, want ErrNotFound", err)
	}
}
