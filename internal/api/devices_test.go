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

func pushSubscriptionRequestBody(endpoint string) []byte {
	p256dh, auth := "test-p256dh-value", "test-auth-value"
	body, _ := json.Marshal(setPushEndpointRequest{Endpoint: &endpoint, P256dh: &p256dh, Auth: &auth})
	return body
}

func TestHandleSetPushEndpoint(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	endpoint := "https://push.example.org/wake/abc123"
	rec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+k.deviceID+"/push-endpoint", pushSubscriptionRequestBody(endpoint), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	dev, err := store.GetDevice(db, k.deviceID)
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if dev.Push == nil || dev.Push.Endpoint != endpoint {
		t.Errorf("Push = %v, want endpoint %q", dev.Push, endpoint)
	}

	// Clearing with an empty request.
	clearBody, _ := json.Marshal(setPushEndpointRequest{})
	rec = doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+k.deviceID+"/push-endpoint", clearBody, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	dev, err = store.GetDevice(db, k.deviceID)
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if dev.Push != nil {
		t.Errorf("Push = %v, want nil after clearing", dev.Push)
	}
}

func TestHandleSetPushEndpointRejectsOtherDevice(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k1 := registerAccount(t, a)
	k2 := registerAccount(t, a)

	// k1 signs a request targeting k2's device id in the path.
	rec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+k2.deviceID+"/push-endpoint", pushSubscriptionRequestBody("https://push.example.org/wake/abc123"), k1.deviceID, k1.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSetPushEndpointRejectsNonHTTPS(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	for _, endpoint := range []string{"http://push.example.org/wake", "not-a-url", "ftp://push.example.org/wake"} {
		rec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+k.deviceID+"/push-endpoint", pushSubscriptionRequestBody(endpoint), k.deviceID, k.devicePriv)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("endpoint %q: status = %d, want 400, body = %s", endpoint, rec.Code, rec.Body.String())
		}
	}
}

func TestHandleSetPushEndpointRejectsPartialFields(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	endpoint := "https://push.example.org/wake/abc123"
	reqBody, _ := json.Marshal(setPushEndpointRequest{Endpoint: &endpoint}) // p256dh/auth missing

	rec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+k.deviceID+"/push-endpoint", reqBody, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func pushTargetRequestBody(platform, token string) []byte {
	body, _ := json.Marshal(setPushTargetRequest{Platform: &platform, Token: &token})
	return body
}

func TestHandleSetPushTarget(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+k.deviceID+"/push-target", pushTargetRequestBody("fcm", "fcm-registration-token"), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	dev, err := store.GetDevice(db, k.deviceID)
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if dev.PushTarget == nil || dev.PushTarget.Platform != "fcm" || dev.PushTarget.Token != "fcm-registration-token" {
		t.Errorf("PushTarget = %v, want platform=fcm token=fcm-registration-token", dev.PushTarget)
	}

	// Clearing with an empty request.
	clearBody, _ := json.Marshal(setPushTargetRequest{})
	rec = doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+k.deviceID+"/push-target", clearBody, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	dev, err = store.GetDevice(db, k.deviceID)
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if dev.PushTarget != nil {
		t.Errorf("PushTarget = %v, want nil after clearing", dev.PushTarget)
	}
}

func TestHandleSetPushTargetRejectsOtherDevice(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k1 := registerAccount(t, a)
	k2 := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+k2.deviceID+"/push-target", pushTargetRequestBody("fcm", "tok"), k1.deviceID, k1.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSetPushTargetRejectsUnknownPlatform(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+k.deviceID+"/push-target", pushTargetRequestBody("carrier-pigeon", "tok"), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSetPushTargetRejectsPartialFields(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	platform := "fcm"
	reqBody, _ := json.Marshal(setPushTargetRequest{Platform: &platform}) // token missing

	rec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+k.deviceID+"/push-target", reqBody, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSetPushTargetClearsExistingPushSubscription(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	endpoint := "https://push.example.org/wake/abc123"
	rec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+k.deviceID+"/push-endpoint", pushSubscriptionRequestBody(endpoint), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("push-endpoint status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	rec = doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+k.deviceID+"/push-target", pushTargetRequestBody("fcm", "fcm-registration-token"), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("push-target status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	dev, err := store.GetDevice(db, k.deviceID)
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if dev.Push != nil {
		t.Errorf("Push = %v, want nil after registering a push target", dev.Push)
	}
	if dev.PushTarget == nil {
		t.Error("PushTarget = nil, want set")
	}
}
