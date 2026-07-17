package api

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/devicecert"
)

// registerAccount registers an account via the API and returns its keys.
func registerAccount(t *testing.T, a *API) identityKeys {
	t.Helper()
	k := newIdentityKeys(t)
	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/accounts", registerBodyT(t, k, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
	return k
}

func TestHandleAddDevice(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	newDevicePub, newDevicePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	newDeviceID, err := devicecert.NewDeviceID()
	if err != nil {
		t.Fatalf("NewDeviceID() error = %v", err)
	}
	issuedAt := time.Now().Truncate(time.Second)

	cert, err := devicecert.SignDeviceCertificate(k.accountID, newDeviceID, newDevicePub, issuedAt, k.rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceCertificate() error = %v", err)
	}

	reqBody, _ := json.Marshal(addDeviceRequest{
		AccountID:    k.accountID,
		DeviceID:     newDeviceID,
		DevicePubKey: b64(newDevicePub),
		IssuedAt:     issuedAt.UTC().Format(time.RFC3339),
		Signature:    b64(cert.Signature),
	})

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/devices", reqBody, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}

	devices, err := store.ListDevicesByAccount(db, k.accountID)
	if err != nil {
		t.Fatalf("ListDevicesByAccount() error = %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("len(devices) = %d, want 2", len(devices))
	}

	_ = newDevicePriv // only the signature (via cert) is needed server-side
}

func TestHandleAddDeviceRejectsAccountMismatch(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k1 := registerAccount(t, a)
	k2 := registerAccount(t, a)

	newDevicePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	newDeviceID, err := devicecert.NewDeviceID()
	if err != nil {
		t.Fatalf("NewDeviceID() error = %v", err)
	}
	issuedAt := time.Now().Truncate(time.Second)

	// Cert signed by k2's root key, but the request claims to add it to
	// k1's account and is signed by k1's device -- must be rejected.
	cert, err := devicecert.SignDeviceCertificate(k1.accountID, newDeviceID, newDevicePub, issuedAt, k2.rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceCertificate() error = %v", err)
	}

	reqBody, _ := json.Marshal(addDeviceRequest{
		AccountID:    k2.accountID,
		DeviceID:     newDeviceID,
		DevicePubKey: b64(newDevicePub),
		IssuedAt:     issuedAt.UTC().Format(time.RFC3339),
		Signature:    b64(cert.Signature),
	})

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/devices", reqBody, k1.deviceID, k1.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRevokeDevice(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	revokedAt := time.Now().Truncate(time.Second)
	rev, err := devicecert.SignDeviceRevocation(k.accountID, k.deviceID, revokedAt, k.rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceRevocation() error = %v", err)
	}

	reqBody, _ := json.Marshal(revokeDeviceRequest{
		AccountID: k.accountID,
		DeviceID:  k.deviceID,
		RevokedAt: revokedAt.UTC().Format(time.RFC3339),
		Signature: b64(rev.Signature),
	})

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+k.deviceID+"/revoke", reqBody, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	dev, err := store.GetDevice(db, k.deviceID)
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if dev.Status != store.DeviceStatusRevoked {
		t.Errorf("device status = %q, want %q", dev.Status, store.DeviceStatusRevoked)
	}
}

func TestHandleRevokeDeviceMismatchedPathAndBody(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	revokedAt := time.Now().Truncate(time.Second)
	rev, err := devicecert.SignDeviceRevocation(k.accountID, k.deviceID, revokedAt, k.rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceRevocation() error = %v", err)
	}

	reqBody, _ := json.Marshal(revokeDeviceRequest{
		AccountID: k.accountID,
		DeviceID:  k.deviceID,
		RevokedAt: revokedAt.UTC().Format(time.RFC3339),
		Signature: b64(rev.Signature),
	})

	// Path says a different device id than the body.
	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/devices/some-other-device/revoke", reqBody, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}
