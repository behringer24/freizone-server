package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// migrateUpTo applies migrations in filename order and stops after version
// stopAfter, so a test can stand a database up in the shape a real server had
// before a given migration and then apply that one migration to it.
func migrateUpTo(t *testing.T, db *sql.DB, stopAfter int) {
	t.Helper()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		filename   TEXT NOT NULL,
		applied_at TEXT NOT NULL
	)`); err != nil {
		t.Fatalf("creating schema_migrations: %v", err)
	}
	names, err := migrationFilenames()
	if err != nil {
		t.Fatalf("migrationFilenames() error = %v", err)
	}
	for _, name := range names {
		version, err := versionFromFilename(name)
		if err != nil {
			t.Fatalf("versionFromFilename(%s) error = %v", name, err)
		}
		if version > stopAfter {
			return
		}
		if err := applyMigration(db, name, version); err != nil {
			t.Fatalf("applyMigration(%s) error = %v", name, err)
		}
	}
}

// The interesting half of 0013 is the upgrade, not the fresh install: it
// rebuilds a populated table while foreign keys are on, and the recipient
// column it carries across is the only record of who may fetch what. A
// mis-ordered rebuild would cascade those rows away with the old table --
// silently, since an empty blob_recipients looks exactly like a server that
// never had an attachment.
func TestMigration0013CarriesExistingBlobsToTheirRecipients(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	migrateUpTo(t, db, 12)

	mustCreateAccount(t, db, "acct1")
	for _, id := range []string{"device1", "device2"} {
		if err := CreateDevice(db, testDevice("acct1", id)); err != nil {
			t.Fatalf("CreateDevice(%s) error = %v", id, err)
		}
	}
	now := time.Now().UTC()
	expires := now.Add(14 * 24 * time.Hour)
	// The pre-0013 shape, written the way the old CreateBlob did.
	for _, row := range []struct {
		blobID   string
		deviceID string
		size     int64
	}{
		{"legacy1", "device1", 111},
		{"legacy2", "device2", 222},
	} {
		if _, err := db.Exec(
			`INSERT INTO blobs (blob_id, recipient_device_id, size_bytes, created_at, expires_at)
			 VALUES (?, ?, ?, ?, ?)`,
			row.blobID, row.deviceID, row.size, formatTime(now), formatTime(expires),
		); err != nil {
			t.Fatalf("inserting legacy blob %s: %v", row.blobID, err)
		}
	}

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	for _, tc := range []struct {
		blobID   string
		deviceID string
		size     int64
	}{
		{"legacy1", "device1", 111},
		{"legacy2", "device2", 222},
	} {
		got, err := GetBlobForDevice(db, tc.blobID, tc.deviceID)
		if err != nil {
			t.Fatalf("GetBlobForDevice(%s, %s) error = %v -- the migration lost its recipient", tc.blobID, tc.deviceID, err)
		}
		if got.SizeBytes != tc.size {
			t.Errorf("%s size = %d, want %d", tc.blobID, got.SizeBytes, tc.size)
		}
		if got.ExpiresAt.IsZero() {
			t.Errorf("%s lost its retention window", tc.blobID)
		}
	}

	// Nothing became unreferenced on the way across, which is what a
	// cascade-during-drop would have produced.
	unreferenced, err := ListUnreferencedBlobs(db, 10)
	if err != nil {
		t.Fatalf("ListUnreferencedBlobs() error = %v", err)
	}
	if len(unreferenced) != 0 {
		t.Errorf("migration left %d unreferenced blobs, want 0", len(unreferenced))
	}

	// The migrated rows behave like natively created ones: quota is charged
	// per recipient, and the cascade still reaches them.
	count, total, err := BlobUsage(db, "device1")
	if err != nil {
		t.Fatalf("BlobUsage() error = %v", err)
	}
	if count != 1 || total != 111 {
		t.Errorf("device1 usage = (%d, %d), want (1, 111)", count, total)
	}
	if _, err := db.Exec(`DELETE FROM devices WHERE device_id = ?`, "device1"); err != nil {
		t.Fatalf("deleting device: %v", err)
	}
	if _, err := GetBlobForDevice(db, "legacy1", "device1"); err == nil {
		t.Error("a migrated claim survived the removal of its device")
	}
}

// TestMigration0015UpgradesPopulatedSetupTokens exercises 0015's rebuild on the
// real upgrade path (audit L3): a database that already has a *claimed* setup
// token row -- the bootstrap admin's -- must carry that row across the table
// rebuild intact, and afterwards deleting the claimant must succeed with the
// reference cleared to NULL (the whole point of the migration). A fresh-install
// test can't catch a rebuild that drops or mangles existing data.
func TestMigration0015UpgradesPopulatedSetupTokens(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	// Stand the DB up in its pre-0015 shape and populate a claimed token.
	migrateUpTo(t, db, 14)
	token, created, err := InitSetupToken(db, time.Now())
	if err != nil || !created {
		t.Fatalf("InitSetupToken() = %q, created=%v, err=%v", token, created, err)
	}
	mustCreateAccount(t, db, "admin")
	if err := ClaimSetupToken(db, token, "admin", time.Now()); err != nil {
		t.Fatalf("ClaimSetupToken() error = %v", err)
	}

	// Apply 0015 (the rebuild) on top of the populated table.
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	// The claimed row survived the rebuild with its data intact.
	claimed, err := SetupTokenClaimed(db)
	if err != nil {
		t.Fatalf("SetupTokenClaimed() error = %v", err)
	}
	if !claimed {
		t.Fatal("setup token lost its claimed state across the rebuild")
	}
	var claimant sql.NullString
	if err := db.QueryRow(`SELECT used_by_account_id FROM setup_tokens WHERE id = 1`).Scan(&claimant); err != nil {
		t.Fatalf("querying setup_tokens after migrate: %v", err)
	}
	if !claimant.Valid || claimant.String != "admin" {
		t.Errorf("used_by_account_id = %v after rebuild, want \"admin\"", claimant)
	}

	// And the new ON DELETE SET NULL behaviour holds on the upgraded DB.
	if err := DeleteAccount(db, "admin"); err != nil {
		t.Fatalf("DeleteAccount() on upgraded DB error = %v (0015's FK clause did not take)", err)
	}
	if err := db.QueryRow(`SELECT used_by_account_id FROM setup_tokens WHERE id = 1`).Scan(&claimant); err != nil {
		t.Fatalf("re-querying setup_tokens: %v", err)
	}
	if claimant.Valid {
		t.Errorf("used_by_account_id = %q after claimant delete, want NULL", claimant.String)
	}
}
