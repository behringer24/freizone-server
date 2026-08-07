package api

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/blobstore"
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

	cfg := &config.Config{
		RegistrationPolicy:         policy,
		MessageRetentionDays:       14,
		InviteExpiryDays:           14,
		FederationEnabled:          true,
		MaxQueuedMessagesPerDevice: 1000,
		MaxBatchMessages:           100,
		BlobsEnabled:               true,
		MaxBlobBytes:               8 * 1024 * 1024,
		MaxBlobBytesPerDevice:      128 * 1024 * 1024,
		MaxBlobsPerDevice:          200,
		MaxBlobRecipients:          100,
		BlobRetentionDays:          14,
		LandingPageEnabled:         true,
	}
	authMW := auth.NewMiddleware(db, nil)
	// Matches cmd/server: the blob upload authenticates against the client's
	// stated body digest rather than by buffering the body.
	authMW.StreamedBodyPaths = []string{"POST /v1/blobs"}
	a := New(db, cfg, authMW, nil)
	a.Now = func() time.Time { return time.Now() }
	a.VAPIDPublicKey = vapidPublicKey
	a.VAPIDPrivateKey = vapidPrivateKey
	a.RelayPubKey = relayPub
	a.RelayPrivKey = relayPriv

	blobs, err := blobstore.New(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatalf("blobstore.New() error = %v", err)
	}
	a.Blobs = blobs

	return a, db
}
