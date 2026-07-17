package api

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
)

func newTestAPI(t *testing.T, policy config.RegistrationPolicy) (*API, *sql.DB) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatalf("store.Migrate() error = %v", err)
	}

	cfg := &config.Config{RegistrationPolicy: policy, MessageRetentionDays: 14}
	authMW := auth.NewMiddleware(db, nil)
	a := New(db, cfg, authMW, nil)
	a.Now = func() time.Time { return time.Now() }
	return a, db
}
