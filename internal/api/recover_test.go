package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// recoverDevice is a fresh device keypair minted during recovery (the seed
// carries the root key only, so recovery always makes a new device).
type recoverDevice struct {
	deviceID   string
	devicePub  ed25519.PublicKey
	devicePriv ed25519.PrivateKey
}

func newRecoverDevice(t *testing.T) recoverDevice {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	id, err := devicecert.NewDeviceID()
	if err != nil {
		t.Fatalf("NewDeviceID() error = %v", err)
	}
	return recoverDevice{deviceID: id, devicePub: pub, devicePriv: priv}
}

// recoverBody marshals a recover request body carrying d's device cert signed
// by k's root key.
func recoverBody(t *testing.T, k identityKeys, d recoverDevice) []byte {
	t.Helper()
	issuedAt := time.Now().Truncate(time.Second)
	cert, err := devicecert.SignDeviceCertificate(k.accountID, d.deviceID, d.devicePub, issuedAt, k.rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceCertificate() error = %v", err)
	}
	body, err := json.Marshal(recoverAccountRequest{
		DeviceID:            d.deviceID,
		DevicePubKey:        b64(d.devicePub),
		DeviceCertIssuedAt:  issuedAt.UTC().Format(time.RFC3339),
		DeviceCertSignature: b64(cert.Signature),
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return body
}

// doRootSignedRequest issues a request authenticated by a root-key signature
// (Signature-Key-Id = base64(rootPub)) with the given timestamp and nonce --
// the recovery counterpart of doSignedRequest's device-key signing.
func doRootSignedRequest(t *testing.T, handler http.Handler, path string, body []byte, keyID string, signWith ed25519.PrivateKey, ts time.Time, nonce string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	sig := httpsig.Sign(http.MethodPost, req.URL.Path, req.URL.RawQuery, body, keyID, ts, nonce, signWith)
	req.Header.Set(httpsig.HeaderKeyID, keyID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// recover issues a well-formed, root-signed recovery request for k using d.
func recoverAccount(t *testing.T, a *API, k identityKeys, d recoverDevice) *httptest.ResponseRecorder {
	t.Helper()
	path := "/v1/accounts/" + k.accountID + "/recover"
	ts := time.Now()
	return doRootSignedRequest(t, a.Router(), path, recoverBody(t, k, d), b64(k.rootPub), k.rootPriv, ts, uniqueTestNonce("root", path, ts))
}

func TestHandleRecoverAccount(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	oldDeviceID := k.deviceID

	d := newRecoverDevice(t)
	rec := recoverAccount(t, a, k, d)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}

	var resp accountResponse
	decodeJSON(t, rec, &resp)
	if resp.ID != k.accountID {
		t.Errorf("account id = %q, want %q (recovery must preserve the id)", resp.ID, k.accountID)
	}

	devices, err := store.ListDevicesByAccount(db, k.accountID)
	if err != nil {
		t.Fatalf("ListDevicesByAccount() error = %v", err)
	}
	var newActive, oldRevoked bool
	for _, dev := range devices {
		switch dev.DeviceID {
		case d.deviceID:
			newActive = dev.Status == store.DeviceStatusActive
		case oldDeviceID:
			oldRevoked = dev.Status == store.DeviceStatusRevoked
		}
	}
	if !newActive {
		t.Error("recovered device should be active")
	}
	if !oldRevoked {
		t.Error("previous device should be revoked")
	}

	// The recovered device can now authenticate normal (device-signed) requests.
	authRec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/messages", nil, d.deviceID, d.devicePriv)
	if authRec.Code != http.StatusOK {
		t.Errorf("recovered device auth GET /v1/messages = %d, want 200, body = %s", authRec.Code, authRec.Body.String())
	}
}

func TestHandleRecoverAccountRejectsBlockedAccount(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	if err := store.SetAccountStatus(db, k.accountID, store.AccountStatusDisabled); err != nil {
		t.Fatalf("SetAccountStatus() error = %v", err)
	}

	d := newRecoverDevice(t)
	// A fully valid, root-signed recovery request must still be refused for a
	// disabled account -- recovery must not resurrect it (SRV-06). 403, and only
	// after authentication (no pre-auth status oracle).
	if rec := recoverAccount(t, a, k, d); rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRecoverAccountRejectsBadDeviceCert(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	d := newRecoverDevice(t)

	// A device cert whose signature was made by a DIFFERENT root key must be
	// rejected (400 invalid_certificate), even though the request itself is
	// correctly signed by the real root key.
	other := newIdentityKeys(t)
	issuedAt := time.Now().Truncate(time.Second)
	badCert, err := devicecert.SignDeviceCertificate(k.accountID, d.deviceID, d.devicePub, issuedAt, other.rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceCertificate() error = %v", err)
	}
	body, err := json.Marshal(recoverAccountRequest{
		DeviceID:            d.deviceID,
		DevicePubKey:        b64(d.devicePub),
		DeviceCertIssuedAt:  issuedAt.UTC().Format(time.RFC3339),
		DeviceCertSignature: b64(badCert.Signature),
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	path := "/v1/accounts/" + k.accountID + "/recover"
	ts := time.Now()
	rec := doRootSignedRequest(t, a.Router(), path, body, b64(k.rootPub), k.rootPriv, ts, uniqueTestNonce("badcert", path, ts))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRecoverAccountRejectsKeyIDMismatch(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	d := newRecoverDevice(t)

	// Signed correctly with the real root key, but Signature-Key-Id claims a
	// different key -- the key-id guard (headers.KeyID must equal the account's
	// base64 root pubkey) must reject it.
	path := "/v1/accounts/" + k.accountID + "/recover"
	ts := time.Now()
	wrongKeyID := b64(newIdentityKeys(t).rootPub)
	rec := doRootSignedRequest(t, a.Router(), path, recoverBody(t, k, d), wrongKeyID, k.rootPriv, ts, uniqueTestNonce("keyid", path, ts))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRecoverAccountRevokesAllPreviousDevices(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	// Seed a second active device directly, so the account has two.
	second := newRecoverDevice(t)
	issuedAt := time.Now().Truncate(time.Second)
	cert, err := devicecert.SignDeviceCertificate(k.accountID, second.deviceID, second.devicePub, issuedAt, k.rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceCertificate() error = %v", err)
	}
	if err := store.CreateDevice(db, store.Device{
		DeviceID: second.deviceID, AccountID: k.accountID, DevicePubKey: second.devicePub,
		CertIssuedAt: issuedAt, CertSignature: cert.Signature, Status: store.DeviceStatusActive, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	d := newRecoverDevice(t)
	if rec := recoverAccount(t, a, k, d); rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}

	devices, err := store.ListDevicesByAccount(db, k.accountID)
	if err != nil {
		t.Fatalf("ListDevicesByAccount() error = %v", err)
	}
	for _, dev := range devices {
		if dev.DeviceID == d.deviceID {
			if dev.Status != store.DeviceStatusActive {
				t.Errorf("recovered device status = %q, want active", dev.Status)
			}
			continue
		}
		if dev.Status != store.DeviceStatusRevoked {
			t.Errorf("previous device %s status = %q, want revoked", dev.DeviceID, dev.Status)
		}
	}
}

func TestHandleRecoverAccountRejectsWrongRootKey(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	attacker := newIdentityKeys(t) // a different root key
	d := newRecoverDevice(t)
	// Claim the real account's root key id, but sign with the attacker's key.
	path := "/v1/accounts/" + k.accountID + "/recover"
	ts := time.Now()
	rec := doRootSignedRequest(t, a.Router(), path, recoverBody(t, k, d), b64(k.rootPub), attacker.rootPriv, ts, uniqueTestNonce("attacker", path, ts))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRecoverAccountUnknownAccount(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := newIdentityKeys(t) // never registered
	d := newRecoverDevice(t)
	if rec := recoverAccount(t, a, k, d); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRecoverAccountRejectsReplay(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	d := newRecoverDevice(t)

	path := "/v1/accounts/" + k.accountID + "/recover"
	body := recoverBody(t, k, d)
	ts := time.Now()
	nonce := uniqueTestNonce("replay", path, ts)

	rec1 := doRootSignedRequest(t, a.Router(), path, body, b64(k.rootPub), k.rootPriv, ts, nonce)
	if rec1.Code != http.StatusCreated {
		t.Fatalf("first status = %d, want 201, body = %s", rec1.Code, rec1.Body.String())
	}
	// Exact replay (same timestamp + nonce + signature) must be refused.
	rec2 := doRootSignedRequest(t, a.Router(), path, body, b64(k.rootPub), k.rootPriv, ts, nonce)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("replay status = %d, want 401, body = %s", rec2.Code, rec2.Body.String())
	}
}

func TestHandleRecoverAccountRejectsStaleTimestamp(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	d := newRecoverDevice(t)

	path := "/v1/accounts/" + k.accountID + "/recover"
	stale := time.Now().Add(-10 * time.Minute) // beyond MaxClockSkew (5m)
	rec := doRootSignedRequest(t, a.Router(), path, recoverBody(t, k, d), b64(k.rootPub), k.rootPriv, stale, uniqueTestNonce("stale", path, stale))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (stale timestamp), body = %s", rec.Code, rec.Body.String())
	}
}
