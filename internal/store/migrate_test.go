package store

import (
	"path/filepath"
	"testing"
)

func TestMigrateCreatesExpectedTables(t *testing.T) {
	db := newTestDB(t)

	wantTables := []string{
		"schema_migrations", "accounts", "devices", "used_nonces",
		"setup_tokens", "invite_codes", "signed_prekeys", "one_time_prekeys", "messages",
	}
	for _, name := range wantTables {
		var found string
		err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name = ?`, name).Scan(&found)
		if err != nil {
			t.Errorf("table %q not found: %v", name, err)
		}
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	if err := Migrate(db); err != nil {
		t.Fatalf("first Migrate() error = %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate() error = %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("counting schema_migrations rows: %v", err)
	}
	const wantMigrations = 3
	if count != wantMigrations {
		t.Errorf("schema_migrations has %d rows after two Migrate() calls, want %d", count, wantMigrations)
	}
}

func TestMigrateRecordsVersionAndFilename(t *testing.T) {
	db := newTestDB(t)

	var version int
	var filename string
	if err := db.QueryRow(`SELECT version, filename FROM schema_migrations WHERE version = 1`).Scan(&version, &filename); err != nil {
		t.Fatalf("querying schema_migrations: %v", err)
	}
	if filename != "0001_init_schema.sql" {
		t.Errorf("filename = %q, want 0001_init_schema.sql", filename)
	}
}
