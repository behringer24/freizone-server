package store

import (
	"errors"
	"testing"
	"time"
)

func TestUpsertAndGetDHIdentity(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	pubKey := []byte("0123456789012345678901234567890x")[:32]
	signature := []byte{1, 2, 3, 4}
	issuedAt := time.Now().Truncate(time.Second)

	if err := UpsertDHIdentity(db, "device1", pubKey, signature, issuedAt); err != nil {
		t.Fatalf("UpsertDHIdentity() error = %v", err)
	}

	got, err := GetDevice(db, "device1")
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if string(got.DHIdentityPubKey) != string(pubKey) {
		t.Errorf("DHIdentityPubKey = %x, want %x", got.DHIdentityPubKey, pubKey)
	}
	if string(got.DHIdentitySignature) != string(signature) {
		t.Errorf("DHIdentitySignature = %x, want %x", got.DHIdentitySignature, signature)
	}
	if got.DHIdentityIssuedAt == nil || !got.DHIdentityIssuedAt.Equal(issuedAt) {
		t.Errorf("DHIdentityIssuedAt = %v, want %v", got.DHIdentityIssuedAt, issuedAt)
	}
}

func TestUpsertDHIdentityNotFound(t *testing.T) {
	db := newTestDB(t)
	err := UpsertDHIdentity(db, "no-such-device", []byte("x"), []byte("y"), time.Now())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("UpsertDHIdentity() error = %v, want ErrNotFound", err)
	}
}

func TestGetDeviceWithoutDHIdentity(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	got, err := GetDevice(db, "device1")
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if got.DHIdentityPubKey != nil {
		t.Errorf("DHIdentityPubKey = %x, want nil before any upload", got.DHIdentityPubKey)
	}
}

func TestUpsertSignedPrekeyReplacesPrevious(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	now := time.Now().Truncate(time.Second)
	first := SignedPrekey{DeviceID: "device1", KeyID: 1, PubKey: []byte("pub1"), Signature: []byte("sig1"), IssuedAt: now, CreatedAt: now}
	if err := UpsertSignedPrekey(db, first); err != nil {
		t.Fatalf("UpsertSignedPrekey() error = %v", err)
	}

	got, err := GetSignedPrekey(db, "device1")
	if err != nil {
		t.Fatalf("GetSignedPrekey() error = %v", err)
	}
	if got.KeyID != 1 || string(got.PubKey) != "pub1" {
		t.Errorf("got %+v, want key_id=1 pubkey=pub1", got)
	}

	second := SignedPrekey{DeviceID: "device1", KeyID: 2, PubKey: []byte("pub2"), Signature: []byte("sig2"), IssuedAt: now, CreatedAt: now}
	if err := UpsertSignedPrekey(db, second); err != nil {
		t.Fatalf("UpsertSignedPrekey() (replace) error = %v", err)
	}

	got, err = GetSignedPrekey(db, "device1")
	if err != nil {
		t.Fatalf("GetSignedPrekey() error = %v", err)
	}
	if got.KeyID != 2 || string(got.PubKey) != "pub2" {
		t.Errorf("got %+v, want key_id=2 pubkey=pub2 after replace", got)
	}
}

func TestGetSignedPrekeyNotFound(t *testing.T) {
	db := newTestDB(t)
	if _, err := GetSignedPrekey(db, "no-such-device"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetSignedPrekey() error = %v, want ErrNotFound", err)
	}
}

func TestAddAndClaimOneTimePrekeys(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	now := time.Now()
	keys := []OneTimePrekeyInput{
		{KeyID: 1, PubKey: []byte("otpk1")},
		{KeyID: 2, PubKey: []byte("otpk2")},
	}
	if err := AddOneTimePrekeys(db, "device1", keys, now); err != nil {
		t.Fatalf("AddOneTimePrekeys() error = %v", err)
	}

	claimed1, err := ClaimOneTimePrekey(db, "device1")
	if err != nil {
		t.Fatalf("ClaimOneTimePrekey() error = %v", err)
	}
	if claimed1 == nil {
		t.Fatal("ClaimOneTimePrekey() = nil, want a claimed key")
	}
	if claimed1.KeyID != 1 || string(claimed1.PubKey) != "otpk1" {
		t.Errorf("claimed1 = %+v, want key_id=1 pubkey=otpk1 (FIFO order)", claimed1)
	}

	claimed2, err := ClaimOneTimePrekey(db, "device1")
	if err != nil {
		t.Fatalf("ClaimOneTimePrekey() error = %v", err)
	}
	if claimed2 == nil || claimed2.KeyID != 2 {
		t.Errorf("claimed2 = %+v, want key_id=2", claimed2)
	}

	claimed3, err := ClaimOneTimePrekey(db, "device1")
	if err != nil {
		t.Fatalf("ClaimOneTimePrekey() error = %v", err)
	}
	if claimed3 != nil {
		t.Errorf("claimed3 = %+v, want nil once the pool is empty", claimed3)
	}
}

func TestCountOneTimePrekeys(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	if count, err := CountOneTimePrekeys(db, "device1"); err != nil || count != 0 {
		t.Fatalf("CountOneTimePrekeys() = (%d, %v), want (0, nil) before any upload", count, err)
	}

	keys := []OneTimePrekeyInput{
		{KeyID: 1, PubKey: []byte("otpk1")},
		{KeyID: 2, PubKey: []byte("otpk2")},
		{KeyID: 3, PubKey: []byte("otpk3")},
	}
	if err := AddOneTimePrekeys(db, "device1", keys, time.Now()); err != nil {
		t.Fatalf("AddOneTimePrekeys() error = %v", err)
	}
	if count, err := CountOneTimePrekeys(db, "device1"); err != nil || count != 3 {
		t.Fatalf("CountOneTimePrekeys() = (%d, %v), want (3, nil) after upload", count, err)
	}

	if _, err := ClaimOneTimePrekey(db, "device1"); err != nil {
		t.Fatalf("ClaimOneTimePrekey() error = %v", err)
	}
	if count, err := CountOneTimePrekeys(db, "device1"); err != nil || count != 2 {
		t.Fatalf("CountOneTimePrekeys() = (%d, %v), want (2, nil) after one claim", count, err)
	}
}

func TestClaimOneTimePrekeyNeverHandsOutTheSameKeyTwice(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	if err := AddOneTimePrekeys(db, "device1", []OneTimePrekeyInput{{KeyID: 1, PubKey: []byte("otpk1")}}, time.Now()); err != nil {
		t.Fatalf("AddOneTimePrekeys() error = %v", err)
	}

	type result struct {
		claimed *ClaimedOneTimePrekey
		err     error
	}
	results := make(chan result, 5)
	for i := 0; i < 5; i++ {
		go func() {
			c, err := ClaimOneTimePrekey(db, "device1")
			results <- result{c, err}
		}()
	}

	nonNil := 0
	for i := 0; i < 5; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("ClaimOneTimePrekey() error = %v", r.err)
		}
		if r.claimed != nil {
			nonNil++
		}
	}
	if nonNil != 1 {
		t.Errorf("exactly one concurrent claim should have succeeded, got %d", nonNil)
	}
}
