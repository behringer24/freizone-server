package api

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/pkg/devicecert"
)

// uploadedPrekeys holds the private halves of everything uploaded, so a
// test can act as the "responder" (Bob) after an initiator claims a
// bundle.
type uploadedPrekeys struct {
	dhPriv    *ecdh.PrivateKey
	spkPriv   *ecdh.PrivateKey
	spkKeyID  uint32
	otpkPrivs map[uint32]*ecdh.PrivateKey
}

// uploadPrekeysT generates a fresh DH identity key, signed prekey, and
// otpkCount one-time prekeys for k, uploads them via the real handler, and
// returns the private keys.
func uploadPrekeysT(t *testing.T, handler http.Handler, k identityKeys, otpkCount int) uploadedPrekeys {
	t.Helper()
	curve := ecdh.X25519()

	dhPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	spkPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	now := time.Now().Truncate(time.Second)

	dhCert, err := devicecert.SignDHIdentityCertificate(k.accountID, k.deviceID, dhPriv.PublicKey().Bytes(), now, k.devicePriv)
	if err != nil {
		t.Fatalf("SignDHIdentityCertificate() error = %v", err)
	}

	const spkKeyID = uint32(1)
	spkCert, err := devicecert.SignSignedPrekeyCertificate(k.accountID, k.deviceID, spkKeyID, dhPriv.PublicKey().Bytes(), spkPriv.PublicKey().Bytes(), now, k.devicePriv)
	if err != nil {
		t.Fatalf("SignSignedPrekeyCertificate() error = %v", err)
	}

	otpkPrivs := make(map[uint32]*ecdh.PrivateKey, otpkCount)
	otpkDTOs := make([]oneTimePrekeyDTO, 0, otpkCount)
	for i := 0; i < otpkCount; i++ {
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}
		keyID := uint32(100 + i)
		otpkPrivs[keyID] = priv
		otpkDTOs = append(otpkDTOs, oneTimePrekeyDTO{KeyID: keyID, PubKey: b64(priv.PublicKey().Bytes())})
	}

	req := uploadPrekeysRequest{
		DHIdentityCert: &dhIdentityCertDTO{
			DHPubKey:  b64(dhCert.DHPubKey),
			IssuedAt:  dhCert.IssuedAt.UTC().Format(time.RFC3339),
			Signature: b64(dhCert.Signature),
		},
		SignedPrekey: signedPrekeyDTO{
			KeyID:            spkCert.KeyID,
			DHIdentityPubKey: b64(spkCert.DHIdentityPubKey),
			PubKey:           b64(spkCert.PrekeyPubKey),
			IssuedAt:         spkCert.IssuedAt.UTC().Format(time.RFC3339),
			Signature:        b64(spkCert.Signature),
		},
		OneTimePrekeys: otpkDTOs,
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	rec := doSignedRequest(t, handler, http.MethodPost, "/v1/devices/"+k.deviceID+"/prekeys", body, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload prekeys status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	return uploadedPrekeys{dhPriv: dhPriv, spkPriv: spkPriv, spkKeyID: spkKeyID, otpkPrivs: otpkPrivs}
}

func TestHandleUploadPrekeys(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	uploadPrekeysT(t, a.Router(), k, 3)
}

func TestHandleUploadPrekeysRejectsOtherDevice(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k1 := registerAccount(t, a)
	k2 := registerAccount(t, a)

	body := []byte(`{"signed_prekey":{"key_id":1,"dh_identity_pubkey":"","pubkey":"","issued_at":"","signature":""}}`)
	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+k2.deviceID+"/prekeys", body, k1.deviceID, k1.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleUploadPrekeysRequiresIdentityCertOnFirstUpload(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	req := uploadPrekeysRequest{
		SignedPrekey: signedPrekeyDTO{KeyID: 1, DHIdentityPubKey: b64(make([]byte, 32)), PubKey: b64(make([]byte, 32)), IssuedAt: time.Now().UTC().Format(time.RFC3339), Signature: b64(make([]byte, 64))},
	}
	body, _ := json.Marshal(req)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+k.deviceID+"/prekeys", body, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleClaimPrekeyBundleWithOneTimePrekey(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	uploaded := uploadPrekeysT(t, a.Router(), k, 2)

	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+k.deviceID+"/prekey-bundle", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var resp prekeyBundleResponse
	decodeJSON(t, rec, &resp)
	if resp.DeviceID != k.deviceID {
		t.Errorf("device_id = %q, want %q", resp.DeviceID, k.deviceID)
	}
	if resp.DHIdentityPubKey != b64(uploaded.dhPriv.PublicKey().Bytes()) {
		t.Errorf("dh_identity_pubkey mismatch")
	}
	if resp.SignedPrekey.KeyID != uploaded.spkKeyID {
		t.Errorf("signed_prekey.key_id = %d, want %d", resp.SignedPrekey.KeyID, uploaded.spkKeyID)
	}
	if resp.OneTimePrekey == nil {
		t.Fatal("expected a one-time prekey to be claimed")
	}
	if _, ok := uploaded.otpkPrivs[resp.OneTimePrekey.KeyID]; !ok {
		t.Errorf("claimed key_id %d not among uploaded keys", resp.OneTimePrekey.KeyID)
	}
}

func TestHandleClaimPrekeyBundleExhaustsPool(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	uploadPrekeysT(t, a.Router(), k, 1)

	rec1 := doRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+k.deviceID+"/prekey-bundle", nil)
	var resp1 prekeyBundleResponse
	decodeJSON(t, rec1, &resp1)
	if resp1.OneTimePrekey == nil {
		t.Fatal("expected first claim to return a one-time prekey")
	}

	rec2 := doRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+k.deviceID+"/prekey-bundle", nil)
	var resp2 prekeyBundleResponse
	decodeJSON(t, rec2, &resp2)
	if resp2.OneTimePrekey != nil {
		t.Errorf("expected second claim to find an empty pool, got %+v", resp2.OneTimePrekey)
	}
}

func TestHandleClaimPrekeyBundleNotFoundBeforeUpload(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+k.deviceID+"/prekey-bundle", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleGetPrekeyStatus(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	uploadPrekeysT(t, a.Router(), k, 5)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/devices/"+k.deviceID+"/prekey-status", nil, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp prekeyStatusResponse
	decodeJSON(t, rec, &resp)
	if resp.OneTimePrekeysRemaining != 5 {
		t.Errorf("one_time_prekeys_remaining = %d, want 5", resp.OneTimePrekeysRemaining)
	}

	// Claiming one (as an initiator would) should be reflected on the
	// next status check.
	doRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+k.deviceID+"/prekey-bundle", nil)

	rec2 := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/devices/"+k.deviceID+"/prekey-status", nil, k.deviceID, k.devicePriv)
	decodeJSON(t, rec2, &resp)
	if resp.OneTimePrekeysRemaining != 4 {
		t.Errorf("one_time_prekeys_remaining = %d, want 4 after one claim", resp.OneTimePrekeysRemaining)
	}
}

func TestHandleGetPrekeyStatusRejectsOtherDevice(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k1 := registerAccount(t, a)
	k2 := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/devices/"+k2.deviceID+"/prekey-status", nil, k1.deviceID, k1.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleGetPrekeyStatusRequiresAuthentication(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	rec := doRequest(t, a.Router(), http.MethodGet, "/v1/devices/"+k.deviceID+"/prekey-status", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleClaimPrekeyBundleWakesDeviceWhenPoolRunsLow(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	hitCh := make(chan struct{}, 8)
	fakeDistributor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCh <- struct{}{}
	}))
	defer fakeDistributor.Close()
	a.PushClient = fakeDistributor.Client()

	p256dh, authSecret := generateTestPushSubscriptionKeys(t)
	setEndpointBody, _ := json.Marshal(setPushEndpointRequest{Endpoint: &fakeDistributor.URL, P256dh: &p256dh, Auth: &authSecret})
	setRec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+k.deviceID+"/push-endpoint", setEndpointBody, k.deviceID, k.devicePriv)
	if setRec.Code != http.StatusOK {
		t.Fatalf("set push endpoint status = %d, want 200, body = %s", setRec.Code, setRec.Body.String())
	}

	// lowOneTimePrekeyThreshold is 3; upload exactly enough keys that the
	// pool is still above threshold after two claims, and crosses below
	// it on the third -- claims 1 and 2 must NOT wake the device, claim 3
	// must.
	uploadPrekeysT(t, a.Router(), k, lowOneTimePrekeyThreshold+2)

	for i := 0; i < 2; i++ {
		doRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+k.deviceID+"/prekey-bundle", nil)
	}
	select {
	case <-hitCh:
		t.Fatal("push wake fired before the pool crossed the low threshold")
	case <-time.After(300 * time.Millisecond):
	}

	doRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+k.deviceID+"/prekey-bundle", nil)
	select {
	case <-hitCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for low-pool push wake")
	}
}

func TestHandleClaimPrekeyBundleSkipsWakeWhenSubscribed(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	hitCh := make(chan struct{}, 8)
	fakeDistributor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCh <- struct{}{}
	}))
	defer fakeDistributor.Close()
	a.PushClient = fakeDistributor.Client()

	p256dh, authSecret := generateTestPushSubscriptionKeys(t)
	setEndpointBody, _ := json.Marshal(setPushEndpointRequest{Endpoint: &fakeDistributor.URL, P256dh: &p256dh, Auth: &authSecret})
	setRec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+k.deviceID+"/push-endpoint", setEndpointBody, k.deviceID, k.devicePriv)
	if setRec.Code != http.StatusOK {
		t.Fatalf("set push endpoint status = %d, want 200, body = %s", setRec.Code, setRec.Body.String())
	}
	uploadPrekeysT(t, a.Router(), k, 1)

	ts := httptest.NewServer(a.Router())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	streamReq := newSignedHTTPRequest(t, http.MethodGet, ts.URL+"/v1/messages/stream", nil, k.deviceID, k.devicePriv)
	streamReq = streamReq.WithContext(ctx)
	resp, err := ts.Client().Do(streamReq)
	if err != nil {
		t.Fatalf("opening stream: %v", err)
	}
	defer resp.Body.Close()

	// Claiming the device's only prekey drives the pool to 0 (below
	// threshold), but it has a live SSE stream open -- no wake should
	// fire, since it'll re-check its own pool on its next reconnect.
	doRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+k.deviceID+"/prekey-bundle", nil)
	select {
	case <-hitCh:
		t.Fatal("push wake fired despite a live SSE subscriber")
	case <-time.After(300 * time.Millisecond):
	}
}
