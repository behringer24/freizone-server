package auth

import (
	"crypto/ed25519"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/store"
)

func newTestDB(t *testing.T) *sql.DB {
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
	return db
}

func setupAccountAndDevice(t *testing.T, db store.DBTX, deviceStatus string) (accountID, deviceID string, priv ed25519.PrivateKey) {
	t.Helper()

	rootPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	devicePub, devicePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	accountID = "acct-" + deviceStatus
	if err := store.CreateAccount(db, store.Account{
		ID:            accountID,
		RootPubKey:    rootPub,
		VersionMarker: 0,
		Status:        store.AccountStatusActive,
		IsAdmin:       false,
		CreatedAt:     time.Now(),
	}); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	deviceID = "device-" + deviceStatus
	dev := store.Device{
		DeviceID:      deviceID,
		AccountID:     accountID,
		DevicePubKey:  devicePub,
		CertIssuedAt:  time.Now(),
		CertSignature: []byte{1, 2, 3},
		Status:        deviceStatus,
		CreatedAt:     time.Now(),
	}
	if err := store.CreateDevice(db, dev); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	return accountID, deviceID, devicePriv
}

func newSignedRequest(method, path string, body []byte, deviceID string, priv ed25519.PrivateKey, ts time.Time, nonce string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	sig := Sign(method, path, req.URL.RawQuery, body, deviceID, ts, nonce, priv)
	req.Header.Set(HeaderKeyID, deviceID)
	req.Header.Set(HeaderTimestamp, FormatTimestamp(ts))
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, sig)
	return req
}

func TestRequireAcceptsValidRequest(t *testing.T) {
	db := newTestDB(t)
	accountID, deviceID, priv := setupAccountAndDevice(t, db, store.DeviceStatusActive)

	mw := NewMiddleware(db, nil)
	var gotIdentity Identity
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity, _ = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := newSignedRequest(http.MethodPost, "/v1/devices", []byte(`{}`), deviceID, priv, time.Now(), "nonce-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	if gotIdentity.AccountID != accountID || gotIdentity.DeviceID != deviceID {
		t.Errorf("identity = %+v, want account=%s device=%s", gotIdentity, accountID, deviceID)
	}
}

func TestRequireRejectsMissingHeaders(t *testing.T) {
	db := newTestDB(t)
	mw := NewMiddleware(db, nil)
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodPost, "/v1/devices", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireRejectsUnknownDevice(t *testing.T) {
	db := newTestDB(t)
	_, priv := mustKeyPair(t)
	mw := NewMiddleware(db, nil)
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := newSignedRequest(http.MethodPost, "/v1/devices", []byte(`{}`), "no-such-device", priv, time.Now(), "nonce-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireRejectsRevokedDevice(t *testing.T) {
	db := newTestDB(t)
	_, deviceID, priv := setupAccountAndDevice(t, db, store.DeviceStatusRevoked)
	mw := NewMiddleware(db, nil)
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := newSignedRequest(http.MethodPost, "/v1/devices", []byte(`{}`), deviceID, priv, time.Now(), "nonce-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireRejectsTamperedBody(t *testing.T) {
	db := newTestDB(t)
	_, deviceID, priv := setupAccountAndDevice(t, db, store.DeviceStatusActive)
	mw := NewMiddleware(db, nil)
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	ts := time.Now()
	nonce := "nonce-1"
	signedBody := []byte(`{"a":1}`)
	sig := Sign(http.MethodPost, "/v1/devices", "", signedBody, deviceID, ts, nonce, priv)

	req := httptest.NewRequest(http.MethodPost, "/v1/devices", strings.NewReader(`{"a":2}`)) // different body than what was signed
	req.Header.Set(HeaderKeyID, deviceID)
	req.Header.Set(HeaderTimestamp, FormatTimestamp(ts))
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, sig)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireRejectsExpiredTimestamp(t *testing.T) {
	db := newTestDB(t)
	_, deviceID, priv := setupAccountAndDevice(t, db, store.DeviceStatusActive)
	mw := NewMiddleware(db, nil)
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	old := time.Now().Add(-10 * time.Minute)
	req := newSignedRequest(http.MethodPost, "/v1/devices", []byte(`{}`), deviceID, priv, old, "nonce-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireRejectsReplayedNonce(t *testing.T) {
	db := newTestDB(t)
	_, deviceID, priv := setupAccountAndDevice(t, db, store.DeviceStatusActive)
	mw := NewMiddleware(db, nil)
	calls := 0
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	ts := time.Now()
	req1 := newSignedRequest(http.MethodPost, "/v1/devices", []byte(`{}`), deviceID, priv, ts, "same-nonce")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rec1.Code)
	}

	req2 := newSignedRequest(http.MethodPost, "/v1/devices", []byte(`{}`), deviceID, priv, ts, "same-nonce")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("replayed request status = %d, want 401", rec2.Code)
	}

	if calls != 1 {
		t.Errorf("handler called %d times, want 1", calls)
	}
}
