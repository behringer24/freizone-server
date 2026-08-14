package store

import (
	"testing"
	"time"
)

func TestComputeCurrentStatsAggregatesAcrossTables(t *testing.T) {
	db := newTestDB(t)
	// The single server_settings row (id=1), which GetFederationEnabled
	// reads, is created by InitRegistrationPolicy -- see settings_test.go.
	if err := InitRegistrationPolicy(db, "closed"); err != nil {
		t.Fatalf("InitRegistrationPolicy() error = %v", err)
	}
	mustCreateAccount(t, db, "acct1")
	mustCreateAccount(t, db, "acct2")
	if err := SetAccountStatus(db, "acct2", AccountStatusDisabled); err != nil {
		t.Fatalf("SetAccountStatus() error = %v", err)
	}
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	if err := CreateDevice(db, testDevice("acct1", "device2")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	mustCreateBlob(t, db, "blob1", 100, "device1")
	mustCreateBlob(t, db, "blob2", 250, "device2")
	if err := CreateMessage(db, testMessage("m1", "device1")); err != nil {
		t.Fatalf("CreateMessage() error = %v", err)
	}
	if err := BlockFederationSender(db, "some-remote-acct", "acct1", nil, time.Now()); err != nil {
		t.Fatalf("BlockFederationSender() error = %v", err)
	}

	s, err := ComputeCurrentStats(db)
	if err != nil {
		t.Fatalf("ComputeCurrentStats() error = %v", err)
	}

	if s.AccountCount != 2 {
		t.Errorf("AccountCount = %d, want 2", s.AccountCount)
	}
	if s.ActiveAccountCount != 1 {
		t.Errorf("ActiveAccountCount = %d, want 1 (acct2 was disabled)", s.ActiveAccountCount)
	}
	if s.DeviceCount != 2 {
		t.Errorf("DeviceCount = %d, want 2", s.DeviceCount)
	}
	if s.BlobCount != 2 || s.BlobBytes != 350 {
		t.Errorf("blobs = (%d, %d), want (2, 350)", s.BlobCount, s.BlobBytes)
	}
	if s.PendingMessageCount != 1 {
		t.Errorf("PendingMessageCount = %d, want 1", s.PendingMessageCount)
	}
	if s.FederationBlocklistCount != 1 {
		t.Errorf("FederationBlocklistCount = %d, want 1", s.FederationBlocklistCount)
	}
	// Never seeded via InitFederationEnabled in this test -- an unseeded
	// setting defaults to true (see GetFederationEnabled).
	if !s.FederationEnabled {
		t.Error("FederationEnabled = false, want true (unseeded default)")
	}
	// DiskFreeBytes/DiskTotalBytes/DBBytes are deliberately left at zero by
	// ComputeCurrentStats -- they come from the filesystem, not the database.
	if s.DBBytes != 0 || s.DiskFreeBytes != 0 || s.DiskTotalBytes != 0 {
		t.Errorf("filesystem fields = (%d, %d, %d), want all zero", s.DBBytes, s.DiskFreeBytes, s.DiskTotalBytes)
	}
}

// A brand-new database with nothing in it should report all zeros rather
// than erroring -- COUNT/SUM over an empty table is well-defined SQL, but
// it is worth pinning down that this package's aggregate queries agree.
func TestComputeCurrentStatsOnEmptyDatabase(t *testing.T) {
	db := newTestDB(t)
	if err := InitRegistrationPolicy(db, "closed"); err != nil {
		t.Fatalf("InitRegistrationPolicy() error = %v", err)
	}

	s, err := ComputeCurrentStats(db)
	if err != nil {
		t.Fatalf("ComputeCurrentStats() error = %v", err)
	}
	if s.AccountCount != 0 || s.DeviceCount != 0 || s.BlobCount != 0 || s.PendingMessageCount != 0 {
		t.Errorf("stats on empty db = %+v, want all zero", s)
	}
}

// The forecast's raw material: what expires when, and what arrived recently.
func TestBlobExpiryBucketsAndInflow(t *testing.T) {
	db := newTestDB(t)
	mustCreateAccount(t, db, "acct1")
	if err := CreateDevice(db, testDevice("acct1", "device1")); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	now := time.Now().UTC()
	// Two expiring the same day, one a day later, one already overdue: an
	// expired-but-unswept blob still occupies the disk, so it has to be
	// reported rather than dropped.
	blobs := []struct {
		id        string
		size      int64
		createdAt time.Time
		expiresAt time.Time
	}{
		{"blobA", 100, now, now.AddDate(0, 0, 5)},
		{"blobB", 250, now, now.AddDate(0, 0, 5)},
		{"blobC", 400, now.AddDate(0, 0, -1), now.AddDate(0, 0, 6)},
		{"blobOverdue", 30, now.AddDate(0, 0, -20), now.AddDate(0, 0, -2)},
	}
	for _, b := range blobs {
		if err := CreateBlob(db, Blob{
			BlobID: b.id, SizeBytes: b.size, CreatedAt: b.createdAt, ExpiresAt: b.expiresAt,
		}, []string{"device1"}); err != nil {
			t.Fatalf("CreateBlob(%s) error = %v", b.id, err)
		}
	}

	buckets, err := BlobExpiryBuckets(db)
	if err != nil {
		t.Fatalf("BlobExpiryBuckets() error = %v", err)
	}
	if len(buckets) != 3 {
		t.Fatalf("want a bucket per distinct expiry day (overdue included), got %d: %+v", len(buckets), buckets)
	}
	// Oldest first, so the overdue day leads.
	if buckets[0].Day != now.AddDate(0, 0, -2).Format("2006-01-02") || buckets[0].Bytes != 30 {
		t.Errorf("first bucket = %+v, want the overdue 30 bytes", buckets[0])
	}
	var total int64
	for _, b := range buckets {
		total += b.Bytes
	}
	if total != 780 {
		t.Errorf("buckets sum to %d, want every stored byte (780)", total)
	}
	// The two sharing a day are summed into one bucket, not listed twice.
	sameDay := now.AddDate(0, 0, 5).Format("2006-01-02")
	for _, b := range buckets {
		if b.Day == sameDay && (b.Bytes != 350 || b.Count != 2) {
			t.Errorf("bucket %s = (%d bytes, %d blobs), want (350, 2)", b.Day, b.Bytes, b.Count)
		}
	}

	// Inflow counts what was stored inside the window and nothing older.
	inflow, err := BlobBytesCreatedSince(db, now.AddDate(0, 0, -2))
	if err != nil {
		t.Fatalf("BlobBytesCreatedSince() error = %v", err)
	}
	if inflow != 750 {
		t.Errorf("inflow = %d, want 750 (the 20-day-old upload is outside the window)", inflow)
	}
}

func testStatsSnapshot(capturedAt time.Time) StatsSnapshot {
	return StatsSnapshot{
		CapturedAt:               capturedAt,
		AccountCount:             3,
		ActiveAccountCount:       2,
		DeviceCount:              4,
		BlobCount:                5,
		BlobBytes:                1024,
		DBBytes:                  4096,
		PendingMessageCount:      1,
		DiskFreeBytes:            1_000_000,
		DiskTotalBytes:           2_000_000,
		FederationEnabled:        true,
		FederationBlocklistCount: 0,
	}
}

func TestInsertAndStatsHistoryRoundTrip(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	want := testStatsSnapshot(now)
	if err := InsertStatsSnapshot(db, want); err != nil {
		t.Fatalf("InsertStatsSnapshot() error = %v", err)
	}

	history, err := StatsHistory(db, now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("StatsHistory() error = %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("len(history) = %d, want 1", len(history))
	}
	got := history[0]
	if !got.CapturedAt.Equal(want.CapturedAt) {
		t.Errorf("CapturedAt = %v, want %v", got.CapturedAt, want.CapturedAt)
	}
	if got.AccountCount != want.AccountCount || got.ActiveAccountCount != want.ActiveAccountCount ||
		got.DeviceCount != want.DeviceCount || got.BlobCount != want.BlobCount || got.BlobBytes != want.BlobBytes ||
		got.DBBytes != want.DBBytes || got.PendingMessageCount != want.PendingMessageCount ||
		got.DiskFreeBytes != want.DiskFreeBytes || got.DiskTotalBytes != want.DiskTotalBytes ||
		got.FederationEnabled != want.FederationEnabled || got.FederationBlocklistCount != want.FederationBlocklistCount {
		t.Errorf("round-tripped snapshot = %+v, want %+v", got, want)
	}
}

// StatsHistory is the series a chart plots, so both ends of its range
// matter: rows before "since" are excluded, and the ones that qualify come
// back oldest first regardless of insertion order.
func TestStatsHistoryFiltersSinceAndOrdersOldestFirst(t *testing.T) {
	db := newTestDB(t)
	base := time.Now().UTC().Truncate(time.Second)
	tooOld := base.Add(-10 * 24 * time.Hour)
	older := base.Add(-2 * 24 * time.Hour)
	newer := base.Add(-1 * 24 * time.Hour)

	for _, capturedAt := range []time.Time{newer, tooOld, older} {
		if err := InsertStatsSnapshot(db, testStatsSnapshot(capturedAt)); err != nil {
			t.Fatalf("InsertStatsSnapshot(%v) error = %v", capturedAt, err)
		}
	}

	history, err := StatsHistory(db, base.Add(-3*24*time.Hour))
	if err != nil {
		t.Fatalf("StatsHistory() error = %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("len(history) = %d, want 2 (tooOld excluded)", len(history))
	}
	if !history[0].CapturedAt.Equal(older) || !history[1].CapturedAt.Equal(newer) {
		t.Errorf("history order = [%v, %v], want [%v, %v]", history[0].CapturedAt, history[1].CapturedAt, older, newer)
	}
}

func TestPruneStatsSnapshotsRemovesOnlyOlderRows(t *testing.T) {
	db := newTestDB(t)
	base := time.Now().UTC().Truncate(time.Second)
	old := base.Add(-400 * 24 * time.Hour)
	recent := base.Add(-1 * time.Hour)

	if err := InsertStatsSnapshot(db, testStatsSnapshot(old)); err != nil {
		t.Fatalf("InsertStatsSnapshot(old) error = %v", err)
	}
	if err := InsertStatsSnapshot(db, testStatsSnapshot(recent)); err != nil {
		t.Fatalf("InsertStatsSnapshot(recent) error = %v", err)
	}

	n, err := PruneStatsSnapshots(db, base.Add(-100*24*time.Hour))
	if err != nil {
		t.Fatalf("PruneStatsSnapshots() error = %v", err)
	}
	if n != 1 {
		t.Errorf("pruned = %d, want 1", n)
	}

	history, err := StatsHistory(db, base.Add(-500*24*time.Hour))
	if err != nil {
		t.Fatalf("StatsHistory() error = %v", err)
	}
	if len(history) != 1 || !history[0].CapturedAt.Equal(recent) {
		t.Errorf("surviving history = %+v, want just the recent snapshot", history)
	}
}
