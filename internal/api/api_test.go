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
	if err := store.InitRegistrationPolicy(db, string(policy)); err != nil {
		t.Fatalf("InitRegistrationPolicy() error = %v", err)
	}
	if err := store.InitVAPIDKeys(db); err != nil {
		t.Fatalf("InitVAPIDKeys() error = %v", err)
	}
	vapidPublicKey, vapidPrivateKey, err := store.GetVAPIDKeys(db)
	if err != nil {
		t.Fatalf("GetVAPIDKeys() error = %v", err)
	}
	if err := store.InitRelayIdentity(db); err != nil {
		t.Fatalf("InitRelayIdentity() error = %v", err)
	}
	relayPub, relayPriv, err := store.GetRelayIdentity(db)
	if err != nil {
		t.Fatalf("GetRelayIdentity() error = %v", err)
	}

	cfg := &config.Config{RegistrationPolicy: policy, MessageRetentionDays: 14}
	authMW := auth.NewMiddleware(db, nil)
	a := New(db, cfg, authMW, nil)
	a.Now = func() time.Time { return time.Now() }
	a.VAPIDPublicKey = vapidPublicKey
	a.VAPIDPrivateKey = vapidPrivateKey
	a.RelayPubKey = relayPub
	a.RelayPrivKey = relayPriv
	return a, db
}
