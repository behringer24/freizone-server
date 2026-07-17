package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// newTestDB opens a fresh, fully-migrated temp-file SQLite database for use
// in a single test.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	return db
}
