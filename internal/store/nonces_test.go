package store

import (
	"testing"
	"time"
)

func TestRecordNonceRejectsReplay(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	expires := now.Add(5 * time.Minute)

	ok, err := RecordNonce(db, "device1", "nonce1", now, expires)
	if err != nil {
		t.Fatalf("RecordNonce() error = %v", err)
	}
	if !ok {
		t.Error("RecordNonce() = false on first use, want true")
	}

	ok, err = RecordNonce(db, "device1", "nonce1", now, expires)
	if err != nil {
		t.Fatalf("RecordNonce() error = %v", err)
	}
	if ok {
		t.Error("RecordNonce() = true on replay, want false")
	}
}

func TestRecordNonceDistinctPerDevice(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	expires := now.Add(5 * time.Minute)

	ok1, err := RecordNonce(db, "device1", "nonceA", now, expires)
	if err != nil {
		t.Fatalf("RecordNonce() error = %v", err)
	}
	ok2, err := RecordNonce(db, "device2", "nonceA", now, expires)
	if err != nil {
		t.Fatalf("RecordNonce() error = %v", err)
	}
	if !ok1 || !ok2 {
		t.Errorf("expected the same nonce value to be usable independently per device, got ok1=%v ok2=%v", ok1, ok2)
	}
}

func TestPurgeExpiredNonces(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()

	if _, err := RecordNonce(db, "device1", "expired", now.Add(-time.Hour), now.Add(-time.Minute)); err != nil {
		t.Fatalf("RecordNonce() error = %v", err)
	}
	if _, err := RecordNonce(db, "device1", "fresh", now, now.Add(time.Hour)); err != nil {
		t.Fatalf("RecordNonce() error = %v", err)
	}

	purged, err := PurgeExpiredNonces(db, now)
	if err != nil {
		t.Fatalf("PurgeExpiredNonces() error = %v", err)
	}
	if purged != 1 {
		t.Errorf("purged = %d, want 1", purged)
	}

	// The fresh nonce should still be usable as "already recorded".
	ok, err := RecordNonce(db, "device1", "fresh", now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("RecordNonce() error = %v", err)
	}
	if ok {
		t.Error("expected fresh nonce to still be recorded (replay) after purge")
	}
}
