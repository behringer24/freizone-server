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
	"github.com/behringer24/freizone-server/internal/devicecert"
	"github.com/behringer24/freizone-server/internal/store"
)

// TestEndToEndIdentityFlow exercises the full identity/bootstrap surface
// over a real HTTP round trip (httptest.Server, not just in-process
// ServeHTTP): bootstrap the first admin, register a regular account, add a
// second device to it, revoke the original device, and confirm the public
// directory reflects the final state.
func TestEndToEndIdentityFlow(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	ts := httptest.NewServer(a.Router())
	defer ts.Close()
	client := ts.Client()

	// 1. Bootstrap the first admin account.
	setupToken, _, err := store.InitSetupToken(db, time.Now())
	if err != nil {
		t.Fatalf("InitSetupToken() error = %v", err)
	}

	admin := newIdentityKeys(t)
	resp, err := client.Post(ts.URL+"/v1/bootstrap/claim", "application/json", bytes.NewReader(bootstrapBody(setupToken, admin, admin.certSignature(t))))
	if err != nil {
		t.Fatalf("POST /v1/bootstrap/claim error = %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("bootstrap status = %d, want 201", resp.StatusCode)
	}
	resp.Body.Close()

	adminAccount, err := store.GetAccount(db, admin.accountID)
	if err != nil {
		t.Fatalf("GetAccount(admin) error = %v", err)
	}
	if !adminAccount.IsAdmin {
		t.Fatal("bootstrapped account is not admin")
	}

	// 2. Register a regular (non-admin) account under the open policy.
	user := newIdentityKeys(t)
	resp2, err := client.Post(ts.URL+"/v1/accounts", "application/json", bytes.NewReader(registerBodyT(t, user, nil)))
	if err != nil {
		t.Fatalf("POST /v1/accounts error = %v", err)
	}
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d, want 201", resp2.StatusCode)
	}
	resp2.Body.Close()

	// 3. Add a second device to the user's account, signed by their first
	// (original) device, and certified by their root key.
	newDevicePub, newDevicePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	newDeviceID, err := devicecert.NewDeviceID()
	if err != nil {
		t.Fatalf("NewDeviceID() error = %v", err)
	}
	newDeviceIssuedAt := time.Now().Truncate(time.Second)
	newDeviceCert, err := devicecert.SignDeviceCertificate(user.accountID, newDeviceID, newDevicePub, newDeviceIssuedAt, user.rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceCertificate() error = %v", err)
	}

	addBody, err := json.Marshal(addDeviceRequest{
		AccountID:    user.accountID,
		DeviceID:     newDeviceID,
		DevicePubKey: b64(newDevicePub),
		IssuedAt:     newDeviceIssuedAt.UTC().Format(time.RFC3339),
		Signature:    b64(newDeviceCert.Signature),
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	addReq := newSignedHTTPRequest(t, http.MethodPost, ts.URL+"/v1/devices", addBody, user.deviceID, user.devicePriv)
	resp3, err := client.Do(addReq)
	if err != nil {
		t.Fatalf("POST /v1/devices error = %v", err)
	}
	if resp3.StatusCode != http.StatusCreated {
		t.Fatalf("add device status = %d, want 201", resp3.StatusCode)
	}
	resp3.Body.Close()

	// 4. Revoke the user's original device, signed by the newly-added
	// device (which is now also active on the account).
	revokedAt := time.Now().Truncate(time.Second)
	rev, err := devicecert.SignDeviceRevocation(user.accountID, user.deviceID, revokedAt, user.rootPriv)
	if err != nil {
		t.Fatalf("SignDeviceRevocation() error = %v", err)
	}

	revBody, err := json.Marshal(revokeDeviceRequest{
		AccountID: user.accountID,
		DeviceID:  user.deviceID,
		RevokedAt: revokedAt.UTC().Format(time.RFC3339),
		Signature: b64(rev.Signature),
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	revokeReq := newSignedHTTPRequest(t, http.MethodPost, ts.URL+"/v1/devices/"+user.deviceID+"/revoke", revBody, newDeviceID, newDevicePriv)
	resp4, err := client.Do(revokeReq)
	if err != nil {
		t.Fatalf("POST /v1/devices/{id}/revoke error = %v", err)
	}
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", resp4.StatusCode)
	}
	resp4.Body.Close()

	// 5. The public directory reflects the final state: two devices, the
	// original revoked and the new one active.
	resp5, err := client.Get(ts.URL + "/v1/accounts/" + user.accountID)
	if err != nil {
		t.Fatalf("GET /v1/accounts/{id} error = %v", err)
	}
	defer resp5.Body.Close()
	if resp5.StatusCode != http.StatusOK {
		t.Fatalf("get account status = %d, want 200", resp5.StatusCode)
	}

	var directory accountResponse
	if err := json.NewDecoder(resp5.Body).Decode(&directory); err != nil {
		t.Fatalf("decoding account response: %v", err)
	}
	if directory.ID != user.accountID {
		t.Fatalf("account id = %q, want %q", directory.ID, user.accountID)
	}
	if len(directory.Devices) != 2 {
		t.Fatalf("len(devices) = %d, want 2", len(directory.Devices))
	}

	byID := map[string]deviceResponse{}
	for _, d := range directory.Devices {
		byID[d.DeviceID] = d
	}

	original, ok := byID[user.deviceID]
	if !ok {
		t.Fatalf("original device %q missing from directory", user.deviceID)
	}
	if original.Status != store.DeviceStatusRevoked {
		t.Errorf("original device status = %q, want %q", original.Status, store.DeviceStatusRevoked)
	}
	if original.RevokedAt == nil {
		t.Error("original device revoked_at is nil, want set")
	}

	added, ok := byID[newDeviceID]
	if !ok {
		t.Fatalf("added device %q missing from directory", newDeviceID)
	}
	if added.Status != store.DeviceStatusActive {
		t.Errorf("added device status = %q, want %q", added.Status, store.DeviceStatusActive)
	}
}
