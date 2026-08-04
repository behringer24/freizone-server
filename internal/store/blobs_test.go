package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

func testBlob(id string, size int64) Blob {
	now := time.Now()
	return Blob{
		BlobID:    id,
		SizeBytes: size,
		CreatedAt: now,
		ExpiresAt: now.Add(14 * 24 * time.Hour),
	}
}

func mustCreateBlob(t *testing.T, db DBTX, id string, size int64, recipients ...string) {
	t.Helper()
	if err := CreateBlob(db, testBlob(id, size), recipients); err != nil {
		t.Fatalf("CreateBlob(%s) error = %v", id, err)
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

	mustCreateBlob(t, db, "blob1", 1234, "device1")

	got, err := GetBlobForDevice(db, "blob1", "device1")
	if err != nil {
		t.Fatalf("GetBlobForDevice() error = %v", err)
	}
	if got.BlobID != "blob1" || got.SizeBytes != 1234 {
		t.Errorf("got %+v, want blob1/1234", got)
	}
}

func TestCreateBlobRejectsDuplicateID(t *testing.T) {
	db := blobTestDB(t)
	mustCreateBlob(t, db, "blob1", 10, "device1")
	if err := CreateBlob(db, testBlob("blob1", 10), []string{"device1"}); !errors.Is(err, ErrConflict) {
		t.Errorf("error = %v, want ErrConflict", err)
	}
}

// A blob with no recipient is unreachable and would occupy disk with nothing
// able to fetch it, so the store refuses to record one at all.
func TestCreateBlobRejectsAnEmptyRecipientList(t *testing.T) {
	db := blobTestDB(t)
	if err := CreateBlob(db, testBlob("blob1", 10), nil); err == nil {
		t.Error("CreateBlob() with no recipients succeeded, want an error")
	}
	exists, err := BlobIDExists(db, "blob1")
	if err != nil {
		t.Fatalf("BlobIDExists() error = %v", err)
	}
	if exists {
		t.Error("a recipientless blob was recorded anyway")
	}
}

func TestGetBlobForForeignDeviceIsNotFound(t *testing.T) {
	db := blobTestDB(t)
	if err := CreateDevice(db, testDevice("acct1", "device2")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	mustCreateBlob(t, db, "blob1", 10, "device1")

	// "Not yours" must be indistinguishable from "doesn't exist", so a
	// caller can't probe which blob ids are real.
	if _, err := GetBlobForDevice(db, "blob1", "device2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound for another device's blob", err)
	}
	if _, err := GetBlobForDevice(db, "no-such-blob", "device1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound for an unknown blob", err)
	}
}

// The SRV-18 shape: one stored object, several recipients, each of whom may
// fetch it -- which is what makes a group picture one upload per recipient
// server instead of one per member.
func TestBlobWithSeveralRecipientsIsFetchableByEach(t *testing.T) {
	db := blobTestDB(t)
	for _, id := range []string{"device2", "device3"} {
		if err := CreateDevice(db, testDevice("acct1", id)); err != nil {
			t.Fatalf("CreateDevice(%s) error = %v", id, err)
		}
	}
	mustCreateBlob(t, db, "blob1", 500, "device1", "device2")

	for _, deviceID := range []string{"device1", "device2"} {
		if _, err := GetBlobForDevice(db, "blob1", deviceID); err != nil {
			t.Errorf("GetBlobForDevice(%s) error = %v, want the blob", deviceID, err)
		}
	}
	// A device that was not named stays as unable to fetch it as before.
	if _, err := GetBlobForDevice(db, "blob1", "device3"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unnamed device error = %v, want ErrNotFound", err)
	}

	recipients, err := BlobRecipients(db, "blob1")
	if err != nil {
		t.Fatalf("BlobRecipients() error = %v", err)
	}
	if len(recipients) != 2 {
		t.Errorf("got %d recipients, want 2", len(recipients))
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

	mustCreateBlob(t, db, "blob1", 100, "device1")
	mustCreateBlob(t, db, "blob2", 250, "device1")

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
	mustCreateBlob(t, db, "blob1", 100, "device1")

	count, total, err := BlobUsage(db, "device2")
	if err != nil {
		t.Fatalf("BlobUsage() error = %v", err)
	}
	if count != 0 || total != 0 {
		t.Errorf("device2 usage = (%d, %d), want (0, 0) -- quota must not be shared", count, total)
	}
}

// A shared blob counts in full against every recipient. Charging a fraction
// would let a sender multiply one device's effective allowance simply by
// naming co-recipients.
func TestBlobUsageChargesEachRecipientInFull(t *testing.T) {
	db := blobTestDB(t)
	if err := CreateDevice(db, testDevice("acct1", "device2")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	mustCreateBlob(t, db, "blob1", 300, "device1", "device2")

	for _, deviceID := range []string{"device1", "device2"} {
		count, total, err := BlobUsage(db, deviceID)
		if err != nil {
			t.Fatalf("BlobUsage(%s) error = %v", deviceID, err)
		}
		if count != 1 || total != 300 {
			t.Errorf("%s usage = (%d, %d), want (1, 300)", deviceID, count, total)
		}
	}
}

func TestDeleteBlobForDevice(t *testing.T) {
	db := blobTestDB(t)
	if err := CreateDevice(db, testDevice("acct1", "device2")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	mustCreateBlob(t, db, "blob1", 10, "device1")

	// Another device must not be able to delete it.
	if _, err := DeleteBlobForDevice(db, "blob1", "device2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("cross-device delete error = %v, want ErrNotFound", err)
	}
	unreferenced, err := DeleteBlobForDevice(db, "blob1", "device1")
	if err != nil {
		t.Fatalf("DeleteBlobForDevice() error = %v", err)
	}
	if !unreferenced {
		t.Error("deleting the only recipient's claim left the blob referenced")
	}
	if _, err := GetBlobForDevice(db, "blob1", "device1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("blob still present after delete: %v", err)
	}
	if _, err := DeleteBlobForDevice(db, "blob1", "device1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete error = %v, want ErrNotFound", err)
	}
}

// One group member deleting their copy must not take the picture away from
// the rest: the file only goes with the last claim.
func TestDeleteBlobForDeviceKeepsItForTheOtherRecipients(t *testing.T) {
	db := blobTestDB(t)
	if err := CreateDevice(db, testDevice("acct1", "device2")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	mustCreateBlob(t, db, "blob1", 10, "device1", "device2")

	unreferenced, err := DeleteBlobForDevice(db, "blob1", "device1")
	if err != nil {
		t.Fatalf("DeleteBlobForDevice() error = %v", err)
	}
	if unreferenced {
		t.Error("blob reported unreferenced while another recipient still holds it")
	}
	if _, err := GetBlobForDevice(db, "blob1", "device2"); err != nil {
		t.Errorf("the remaining recipient lost access: %v", err)
	}

	unreferenced, err = DeleteBlobForDevice(db, "blob1", "device2")
	if err != nil {
		t.Fatalf("DeleteBlobForDevice() error = %v", err)
	}
	if !unreferenced {
		t.Error("blob still referenced after its last recipient deleted it")
	}
	exists, err := BlobIDExists(db, "blob1")
	if err != nil {
		t.Fatalf("BlobIDExists() error = %v", err)
	}
	if exists {
		t.Error("blob row survived its last recipient")
	}
}

func TestListExpiredBlobsRespectsCutoffAndLimit(t *testing.T) {
	db := blobTestDB(t)
	now := time.Now()

	expired := testBlob("old1", 10)
	expired.ExpiresAt = now.Add(-time.Hour)
	expired2 := testBlob("old2", 10)
	expired2.ExpiresAt = now.Add(-2 * time.Hour)
	live := testBlob("fresh", 10)
	live.ExpiresAt = now.Add(time.Hour)
	for _, b := range []Blob{expired, expired2, live} {
		if err := CreateBlob(db, b, []string{"device1"}); err != nil {
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
	mustCreateBlob(t, db, "blob1", 10, "device1")

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
	// The recipient rows must go with it, or the next blob to reuse the id
	// would inherit them.
	recipients, err := BlobRecipients(db, "blob1")
	if err != nil {
		t.Fatalf("BlobRecipients() error = %v", err)
	}
	if len(recipients) != 0 {
		t.Errorf("got %d recipient rows after deleting the blob, want 0", len(recipients))
	}
}

// A removed device takes its claims with it, exactly as it does its queued
// messages. Since SRV-18 that no longer necessarily removes the blob: the
// cascade cannot tell it took the last claim, so what is left behind is an
// unreferenced blob for the cleanup ticker.
func TestBlobClaimsAreRemovedWithTheirDevice(t *testing.T) {
	db := blobTestDB(t)
	if err := CreateDevice(db, testDevice("acct1", "device2")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	mustCreateBlob(t, db, "shared", 10, "device1", "device2")
	mustCreateBlob(t, db, "solo", 10, "device1")

	if _, err := db.Exec(`DELETE FROM devices WHERE device_id = ?`, "device1"); err != nil {
		t.Fatalf("deleting device: %v", err)
	}

	if _, err := GetBlobForDevice(db, "shared", "device1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a removed device kept its claim: %v", err)
	}
	if _, err := GetBlobForDevice(db, "shared", "device2"); err != nil {
		t.Errorf("the surviving recipient lost the shared blob: %v", err)
	}

	unreferenced, err := ListUnreferencedBlobs(db, 10)
	if err != nil {
		t.Fatalf("ListUnreferencedBlobs() error = %v", err)
	}
	if len(unreferenced) != 1 || unreferenced[0].BlobID != "solo" {
		t.Errorf("unreferenced = %+v, want only the blob whose last recipient was removed", unreferenced)
	}
}

func TestListUnreferencedBlobsRespectsLimit(t *testing.T) {
	db := blobTestDB(t)
	mustCreateBlob(t, db, "blob1", 10, "device1")
	mustCreateBlob(t, db, "blob2", 10, "device1")
	if _, err := db.Exec(`DELETE FROM blob_recipients`); err != nil {
		t.Fatalf("clearing recipients: %v", err)
	}

	got, err := ListUnreferencedBlobs(db, 1)
	if err != nil {
		t.Fatalf("ListUnreferencedBlobs() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d blobs with limit 1, want 1", len(got))
	}
}
