package store

import (
	"database/sql"
	"testing"
	"time"
)

// activityTestDB gives acct1 two devices and acct2 one, so the aggregation is
// exercised across devices and across accounts rather than in the degenerate
// one-of-each case where a wrong GROUP BY would still look right.
func activityTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	mustCreateAccount(t, db, "acct2")
	for accountID, deviceIDs := range map[string][]string{
		"acct1": {"device1", "device2"},
		"acct2": {"device3"},
	} {
		for _, deviceID := range deviceIDs {
			if err := CreateDevice(db, testDevice(accountID, deviceID)); err != nil {
				t.Fatalf("CreateDevice(%s) error = %v", deviceID, err)
			}
		}
	}
	return db
}

func mustCreateMessageAt(t *testing.T, db DBTX, id, recipientAccountID, recipientDeviceID string, sentAt time.Time) {
	t.Helper()
	msg := testMessage(id, recipientDeviceID)
	msg.RecipientAccountID = recipientAccountID
	msg.SentAt = sentAt
	msg.ExpiresAt = sentAt.Add(14 * 24 * time.Hour)
	if err := CreateMessage(db, msg); err != nil {
		t.Fatalf("CreateMessage(%s) error = %v", id, err)
	}
}

func TestAccountActivitySumsAcrossAnAccountsDevices(t *testing.T) {
	db := activityTestDB(t)
	oldest := time.Now().Add(-72 * time.Hour).UTC().Truncate(time.Second)
	newer := time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second)

	// Spread across both of acct1's devices: the summary is per account, and a
	// per-device query would report half of this.
	mustCreateMessageAt(t, db, "m1", "acct1", "device1", newer)
	mustCreateMessageAt(t, db, "m2", "acct1", "device2", oldest)
	mustCreateMessageAt(t, db, "m3", "acct2", "device3", newer)

	if err := CreateBlob(db, testBlob("blob1", 100), []string{"device1"}); err != nil {
		t.Fatalf("CreateBlob() error = %v", err)
	}
	if err := CreateBlob(db, testBlob("blob2", 250), []string{"device2"}); err != nil {
		t.Fatalf("CreateBlob() error = %v", err)
	}

	activity, err := AccountActivityByAccount(db)
	if err != nil {
		t.Fatalf("AccountActivityByAccount() error = %v", err)
	}

	one := activity["acct1"]
	if one.PendingMessages != 2 {
		t.Errorf("acct1 pending = %d, want 2", one.PendingMessages)
	}
	if !one.OldestPendingAt.Equal(oldest) {
		t.Errorf("acct1 oldest = %v, want %v -- the age of the *earliest* queued message is the abandonment signal", one.OldestPendingAt, oldest)
	}
	if one.BlobCount != 2 || one.BlobBytes != 350 {
		t.Errorf("acct1 blobs = (%d, %d), want (2, 350)", one.BlobCount, one.BlobBytes)
	}
	if one.DeviceCount != 2 {
		t.Errorf("acct1 devices = %d, want 2", one.DeviceCount)
	}

	two := activity["acct2"]
	if two.PendingMessages != 1 || two.BlobCount != 0 || two.BlobBytes != 0 || two.DeviceCount != 1 {
		t.Errorf("acct2 = %+v, want 1 pending / no blobs / 1 device", two)
	}
}

// The device count is the quota's multiplier, so it has to survive an account
// having no attachments at all -- an INNER JOIN here would drop the row and
// leave the usage figure with nothing to be measured against.
func TestAccountActivityReportsDevicesWithoutBlobs(t *testing.T) {
	db := activityTestDB(t)

	activity, err := AccountActivityByAccount(db)
	if err != nil {
		t.Fatalf("AccountActivityByAccount() error = %v", err)
	}
	if got := activity["acct1"].DeviceCount; got != 2 {
		t.Errorf("device count = %d, want 2", got)
	}
	if got := activity["acct1"].BlobBytes; got != 0 {
		t.Errorf("blob bytes = %d, want 0", got)
	}
}

// The blob join multiplies each device row by its blobs. COUNT(DISTINCT) on
// the device is what keeps a single device with three attachments from
// reporting itself three times over -- and inflating the quota it is measured
// against by the same factor.
func TestAccountActivityDeviceCountSurvivesTheBlobJoin(t *testing.T) {
	db := activityTestDB(t)
	for _, id := range []string{"blob1", "blob2", "blob3"} {
		if err := CreateBlob(db, testBlob(id, 10), []string{"device1"}); err != nil {
			t.Fatalf("CreateBlob(%s) error = %v", id, err)
		}
	}

	activity, err := AccountActivityByAccount(db)
	if err != nil {
		t.Fatalf("AccountActivityByAccount() error = %v", err)
	}
	if got := activity["acct1"].DeviceCount; got != 2 {
		t.Errorf("device count = %d, want 2", got)
	}
	if got := activity["acct1"].BlobCount; got != 3 {
		t.Errorf("blob count = %d, want 3", got)
	}
}

// An empty queue has no oldest message. Reporting the zero time instead would
// have a client render an age of two thousand years.
func TestAccountActivityLeavesOldestPendingZeroWhenTheQueueIsEmpty(t *testing.T) {
	db := activityTestDB(t)
	if err := CreateBlob(db, testBlob("blob1", 10), []string{"device1"}); err != nil {
		t.Fatalf("CreateBlob() error = %v", err)
	}

	activity, err := AccountActivityByAccount(db)
	if err != nil {
		t.Fatalf("AccountActivityByAccount() error = %v", err)
	}
	if !activity["acct1"].OldestPendingAt.IsZero() {
		t.Errorf("oldest = %v, want the zero time", activity["acct1"].OldestPendingAt)
	}
}

// A brand-new account with no devices yet is simply absent, and callers read
// that as the zero value rather than having to special-case it.
func TestAccountActivityOmitsAccountsWithNothingToReport(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")

	activity, err := AccountActivityByAccount(db)
	if err != nil {
		t.Fatalf("AccountActivityByAccount() error = %v", err)
	}
	if _, ok := activity["acct1"]; ok {
		t.Error("an account with no devices, messages or blobs should not appear")
	}
	if got := activity["acct1"]; got.PendingMessages != 0 || got.DeviceCount != 0 {
		t.Errorf("missing entry = %+v, want the zero value", got)
	}
}
