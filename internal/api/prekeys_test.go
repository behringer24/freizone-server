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

// errorCodeT decodes rec's error body and returns its machine-readable code.
// The claim endpoint's 404 variants carry distinct codes on purpose (a stale
// cached device id must be tellable from a switched-off federation, see
// docs/PROTOCOL.md §4's stale-device rule), so tests pin the code, not just
// the status.
func errorCodeT(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp errorResponse
	decodeJSON(t, rec, &resp)
	return resp.Error.Code
}

// claimBundleT claims targetDeviceID's prekey bundle the way a real initiator
// does since SRV-04: signed as claimant, which is what earns a one-time prekey.
// Anonymous claims still work but get no key, so tests about the pool must go
// through here.
func claimBundleT(t *testing.T, handler http.Handler, targetDeviceID string, claimant identityKeys) *httptest.ResponseRecorder {
	t.Helper()
	return doSignedRequest(t, handler, http.MethodPost,
		"/v1/devices/"+targetDeviceID+"/prekey-bundle", nil,
		claimant.deviceID, claimant.devicePriv)
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

// replaceOneTimePrekeysT re-asserts uploaded's existing dh identity and
// signed prekey (required on every upload) alongside a fresh one-time-prekey
// batch, with replace_one_time_prekeys set -- what
// pkg/client.PurgeAndReplaceOneTimePrekeys actually sends.
func replaceOneTimePrekeysT(t *testing.T, handler http.Handler, k identityKeys, uploaded uploadedPrekeys, otpkCount int) uploadedPrekeys {
	t.Helper()
	curve := ecdh.X25519()
	now := time.Now().Truncate(time.Second)

	dhCert, err := devicecert.SignDHIdentityCertificate(k.accountID, k.deviceID, uploaded.dhPriv.PublicKey().Bytes(), now, k.devicePriv)
	if err != nil {
		t.Fatalf("SignDHIdentityCertificate() error = %v", err)
	}
	spkCert, err := devicecert.SignSignedPrekeyCertificate(k.accountID, k.deviceID, uploaded.spkKeyID, uploaded.dhPriv.PublicKey().Bytes(), uploaded.spkPriv.PublicKey().Bytes(), now, k.devicePriv)
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
		// Deliberately disjoint from uploadPrekeysT's 100+ range, so a test
		// can tell "a fresh key" from "an old one that should have been
		// discarded" by id alone.
		keyID := uint32(900 + i)
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
		OneTimePrekeys:        otpkDTOs,
		ReplaceOneTimePrekeys: true,
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	rec := doSignedRequest(t, handler, http.MethodPost, "/v1/devices/"+k.deviceID+"/prekeys", body, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload prekeys status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	return uploadedPrekeys{dhPriv: uploaded.dhPriv, spkPriv: uploaded.spkPriv, spkKeyID: uploaded.spkKeyID, otpkPrivs: otpkPrivs}
}

// A client whose published pool has drifted from its own store (SRV-23: the
// Dart/core minting overlap) needs a real way out -- topping up only ever
// adds more on top of the poisoned entries, and the server always hands out
// the oldest unclaimed key first, so the poison would still be claimed
// before any addition. replace_one_time_prekeys is that way out: it must
// actually discard what was there, not just append alongside it.
func TestReplaceOneTimePrekeysDiscardsTheOldPoolNotJustAddsToIt(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	initiator := registerAccount(t, a)

	original := uploadPrekeysT(t, a.Router(), k, 2) // ids 100, 101
	replaced := replaceOneTimePrekeysT(t, a.Router(), k, original, 2) // ids 900, 901

	for i := 0; i < 2; i++ {
		rec := claimBundleT(t, a.Router(), k.deviceID, initiator)
		if rec.Code != http.StatusOK {
			t.Fatalf("claim %d: status = %d, body = %s", i, rec.Code, rec.Body.String())
		}
		var resp prekeyBundleResponse
		decodeJSON(t, rec, &resp)
		if resp.OneTimePrekey == nil {
			t.Fatalf("claim %d: expected a one-time prekey", i)
		}
		if _, ok := original.otpkPrivs[resp.OneTimePrekey.KeyID]; ok {
			t.Errorf("claim %d: got a discarded pre-replace key (id %d) -- replace did not actually discard the old pool", i, resp.OneTimePrekey.KeyID)
		}
		if _, ok := replaced.otpkPrivs[resp.OneTimePrekey.KeyID]; !ok {
			t.Errorf("claim %d: key id %d is neither the old nor the new pool", i, resp.OneTimePrekey.KeyID)
		}
	}

	// The pool held exactly the replacement batch -- a third claim finds it
	// exhausted, not still holding an old entry the replace should have
	// discarded.
	rec := claimBundleT(t, a.Router(), k.deviceID, initiator)
	var resp prekeyBundleResponse
	decodeJSON(t, rec, &resp)
	if resp.OneTimePrekey != nil {
		t.Errorf("claim 3: got a one-time prekey (id %d), want the pool exhausted", resp.OneTimePrekey.KeyID)
	}
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
	initiator := registerAccount(t, a)
	uploaded := uploadPrekeysT(t, a.Router(), k, 2)

	rec := claimBundleT(t, a.Router(), k.deviceID, initiator)
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
	initiator := registerAccount(t, a)
	uploadPrekeysT(t, a.Router(), k, 1)

	rec1 := claimBundleT(t, a.Router(), k.deviceID, initiator)
	var resp1 prekeyBundleResponse
	decodeJSON(t, rec1, &resp1)
	if resp1.OneTimePrekey == nil {
		t.Fatal("expected first claim to return a one-time prekey")
	}

	rec2 := claimBundleT(t, a.Router(), k.deviceID, initiator)
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
	if code := errorCodeT(t, rec); code != "no_prekey_bundle" {
		t.Errorf("error code = %q, want no_prekey_bundle", code)
	}
}

// A device id the server has never seen answers with a code distinct from
// "exists but has no bundle": an initiator holding a cached device id needs
// to know the id itself is dead (re-resolve the peer's device list via
// GET /v1/accounts/{id}) rather than merely not yet provisioned.
func TestHandleClaimPrekeyBundleUnknownDevice(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)

	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/devices/no-such-device/prekey-bundle", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
	if code := errorCodeT(t, rec); code != "unknown_device" {
		t.Errorf("error code = %q, want unknown_device", code)
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
	claimBundleT(t, a.Router(), k.deviceID, registerAccount(t, a))

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

	initiator := registerAccount(t, a)
	for i := 0; i < 2; i++ {
		claimBundleT(t, a.Router(), k.deviceID, initiator)
	}
	select {
	case <-hitCh:
		t.Fatal("push wake fired before the pool crossed the low threshold")
	case <-time.After(300 * time.Millisecond):
	}

	claimBundleT(t, a.Router(), k.deviceID, initiator)
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
	claimBundleT(t, a.Router(), k.deviceID, registerAccount(t, a))
	select {
	case <-hitCh:
		t.Fatal("push wake fired despite a live SSE subscriber")
	case <-time.After(300 * time.Millisecond):
	}
}
