package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

func testBlob(id, recipientDeviceID string, size int64) Blob {
	now := time.Now()
	return Blob{
		BlobID:            id,
		RecipientDeviceID: recipientDeviceID,
		SizeBytes:         size,
		CreatedAt:         now,
		ExpiresAt:         now.Add(14 * 24 * time.Hour),
	}
}

func blobTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	return db
}

func TestCreateAndGetBlob(t *testing.T) {
	db := blobTestDB(t)

	if err := CreateBlob(db, testBlob("blob1", "device1", 1234)); err != nil {
		t.Fatalf("CreateBlob() error = %v", err)
	}

	got, err := GetBlobForDevice(db, "blob1", "device1")
	if err != nil {
		t.Fatalf("GetBlobForDevice() error = %v", err)
	}
	if got.BlobID != "blob1" || got.RecipientDeviceID != "device1" || got.SizeBytes != 1234 {
		t.Errorf("got %+v, want blob1/device1/1234", got)
	}
}

func TestCreateBlobRejectsDuplicateID(t *testing.T) {
	db := blobTestDB(t)
	if err := CreateBlob(db, testBlob("blob1", "device1", 10)); err != nil {
		t.Fatalf("CreateBlob() error = %v", err)
	}
	if err := CreateBlob(db, testBlob("blob1", "device1", 10)); !errors.Is(err, ErrConflict) {
		t.Errorf("error = %v, want ErrConflict", err)
	}
}

func TestGetBlobForForeignDeviceIsNotFound(t *testing.T) {
	db := blobTestDB(t)
	if err := CreateDevice(db, testDevice("acct1", "device2")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	if err := CreateBlob(db, testBlob("blob1", "device1", 10)); err != nil {
		t.Fatalf("CreateBlob() error = %v", err)
	}

	// "Not yours" must be indistinguishable from "doesn't exist", so a
	// caller can't probe which blob ids are real.
	if _, err := GetBlobForDevice(db, "blob1", "device2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound for another device's blob", err)
	}
	if _, err := GetBlobForDevice(db, "no-such-blob", "device1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound for an unknown blob", err)
	}
}

func TestBlobUsageCountsAndSums(t *testing.T) {
	db := blobTestDB(t)

	count, total, err := BlobUsage(db, "device1")
	if err != nil {
		t.Fatalf("BlobUsage() error = %v", err)
	}
	// SUM over no rows is NULL in SQLite -- must surface as 0, not an error.
	if count != 0 || total != 0 {
		t.Errorf("empty usage = (%d, %d), want (0, 0)", count, total)
	}

	if err := CreateBlob(db, testBlob("blob1", "device1", 100)); err != nil {
		t.Fatalf("CreateBlob() error = %v", err)
	}
	if err := CreateBlob(db, testBlob("blob2", "device1", 250)); err != nil {
		t.Fatalf("CreateBlob() error = %v", err)
	}

	count, total, err = BlobUsage(db, "device1")
	if err != nil {
		t.Fatalf("BlobUsage() error = %v", err)
	}
	if count != 2 || total != 350 {
		t.Errorf("usage = (%d, %d), want (2, 350)", count, total)
	}
}

func TestBlobUsageIsPerDevice(t *testing.T) {
	db := blobTestDB(t)
	if err := CreateDevice(db, testDevice("acct1", "device2")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	if err := CreateBlob(db, testBlob("blob1", "device1", 100)); err != nil {
		t.Fatalf("CreateBlob() error = %v", err)
	}

	count, total, err := BlobUsage(db, "device2")
	if err != nil {
		t.Fatalf("BlobUsage() error = %v", err)
	}
	if count != 0 || total != 0 {
		t.Errorf("device2 usage = (%d, %d), want (0, 0) -- quota must not be shared", count, total)
	}
}

func TestDeleteBlobForDevice(t *testing.T) {
	db := blobTestDB(t)
	if err := CreateDevice(db, testDevice("acct1", "device2")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	if err := CreateBlob(db, testBlob("blob1", "device1", 10)); err != nil {
		t.Fatalf("CreateBlob() error = %v", err)
	}

	// Another device must not be able to delete it.
	if err := DeleteBlobForDevice(db, "blob1", "device2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("cross-device delete error = %v, want ErrNotFound", err)
	}
	if err := DeleteBlobForDevice(db, "blob1", "device1"); err != nil {
		t.Fatalf("DeleteBlobForDevice() error = %v", err)
	}
	if _, err := GetBlobForDevice(db, "blob1", "device1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("blob still present after delete: %v", err)
	}
	if err := DeleteBlobForDevice(db, "blob1", "device1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete error = %v, want ErrNotFound", err)
	}
}

func TestListExpiredBlobsRespectsCutoffAndLimit(t *testing.T) {
	db := blobTestDB(t)
	now := time.Now()

	expired := testBlob("old1", "device1", 10)
	expired.ExpiresAt = now.Add(-time.Hour)
	expired2 := testBlob("old2", "device1", 10)
	expired2.ExpiresAt = now.Add(-2 * time.Hour)
	live := testBlob("fresh", "device1", 10)
	live.ExpiresAt = now.Add(time.Hour)
	for _, b := range []Blob{expired, expired2, live} {
		if err := CreateBlob(db, b); err != nil {
			t.Fatalf("CreateBlob(%s) error = %v", b.BlobID, err)
		}
	}

	got, err := ListExpiredBlobs(db, now, 10)
	if err != nil {
		t.Fatalf("ListExpiredBlobs() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d expired blobs, want 2", len(got))
	}
	for _, b := range got {
		if b.BlobID == "fresh" {
			t.Error("a blob that has not expired was listed")
		}
	}

	// Batched on purpose: each row owns a file to unlink, so the sweep must
	// be able to work in bounded chunks.
	limited, err := ListExpiredBlobs(db, now, 1)
	if err != nil {
		t.Fatalf("ListExpiredBlobs(limit 1) error = %v", err)
	}
	if len(limited) != 1 {
		t.Errorf("got %d blobs with limit 1, want 1", len(limited))
	}
}

func TestDeleteBlobByIDAndExists(t *testing.T) {
	db := blobTestDB(t)
	if err := CreateBlob(db, testBlob("blob1", "device1", 10)); err != nil {
		t.Fatalf("CreateBlob() error = %v", err)
	}

	exists, err := BlobIDExists(db, "blob1")
	if err != nil {
		t.Fatalf("BlobIDExists() error = %v", err)
	}
	if !exists {
		t.Error("BlobIDExists() = false for a stored blob")
	}

	if err := DeleteBlobByID(db, "blob1"); err != nil {
		t.Fatalf("DeleteBlobByID() error = %v", err)
	}
	exists, err = BlobIDExists(db, "blob1")
	if err != nil {
		t.Fatalf("BlobIDExists() error = %v", err)
	}
	if exists {
		t.Error("BlobIDExists() = true after deletion")
	}
}

func TestBlobsAreRemovedWithTheirDevice(t *testing.T) {
	db := blobTestDB(t)
	if err := CreateBlob(db, testBlob("blob1", "device1", 10)); err != nil {
		t.Fatalf("CreateBlob() error = %v", err)
	}

	// Undelivered blobs must not outlive the device they were for -- the
	// same cascade queued messages already rely on.
	if _, err := db.Exec(`DELETE FROM devices WHERE device_id = ?`, "device1"); err != nil {
		t.Fatalf("deleting device: %v", err)
	}

	exists, err := BlobIDExists(db, "blob1")
	if err != nil {
		t.Fatalf("BlobIDExists() error = %v", err)
	}
	if exists {
		t.Error("blob survived deletion of its recipient device")
	}
}
