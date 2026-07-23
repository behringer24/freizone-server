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
	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// federationRequestBody builds a federationMessageRequest body for
// sender (a foreign identity, never registered on the target API), with
// its own freshly-signed device certificate embedded, as a real sender
// would build one at send time.
func federationRequestBody(t *testing.T, sender identityKeys, messageID, recipientDeviceID, payload string) []byte {
	t.Helper()
	body, err := json.Marshal(federationMessageRequest{
		SenderAccountID:  sender.accountID,
		SenderRootPubKey: b64(sender.rootPub),
		SenderDeviceCert: federationDeviceCertDTO{
			DeviceID:     sender.deviceID,
			DevicePubKey: b64(sender.devicePub),
			IssuedAt:     sender.issuedAt.UTC().Format(time.RFC3339),
			Signature:    b64(sender.certSignature(t)),
		},
		RecipientDeviceID: recipientDeviceID,
		MessageID:         messageID,
		Payload:           json.RawMessage(payload),
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return body
}

// doFederatedSignedRequest signs with signer's own device pubkey (base64)
// as Signature-Key-Id -- the self-describing-key convention federation
// uses in place of a locally-registered device id.
func doFederatedSignedRequest(t *testing.T, handler http.Handler, path string, body []byte, signer identityKeys) *httptest.ResponseRecorder {
	t.Helper()
	return doKeyIDSignedRequest(t, handler, path, body, b64(signer.devicePub), signer.devicePriv)
}

func doKeyIDSignedRequest(t *testing.T, handler http.Handler, path string, body []byte, keyID string, priv ed25519.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ts := time.Now()
	nonce := uniqueTestNonce(keyID, path, ts)
	sig := httpsig.Sign(http.MethodPost, req.URL.Path, req.URL.RawQuery, body, keyID, ts, nonce, priv)

	req.Header.Set(httpsig.HeaderKeyID, keyID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestHandleReceiveFederatedMessageAccepted(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	bob := registerAccount(t, a)
	alice := newIdentityKeys(t) // foreign sender, never registered on a

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/messages",
		federationRequestBody(t, alice, "fed-msg1", bob.deviceID, `{"ciphertext":"abc"}`), alice)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body = %s", rec.Code, rec.Body.String())
	}

	listRec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/messages", nil, bob.deviceID, bob.devicePriv)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200, body = %s", listRec.Code, listRec.Body.String())
	}
	var msgs []messageResponse
	decodeJSON(t, listRec, &msgs)
	if len(msgs) != 1 || msgs[0].SenderAccountID != alice.accountID {
		t.Errorf("messages = %+v, want one message from %s", msgs, alice.accountID)
	}
}

func TestHandleReceiveFederatedMessageBadCertificate(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	bob := registerAccount(t, a)
	alice := newIdentityKeys(t)
	mallory := newIdentityKeys(t) // wrong signer

	body, err := json.Marshal(federationMessageRequest{
		SenderAccountID:  alice.accountID,
		SenderRootPubKey: b64(alice.rootPub),
		SenderDeviceCert: federationDeviceCertDTO{
			DeviceID:     alice.deviceID,
			DevicePubKey: b64(alice.devicePub),
			IssuedAt:     alice.issuedAt.UTC().Format(time.RFC3339),
			Signature:    b64(mallory.certSignature(t)), // signed by the wrong root key
		},
		RecipientDeviceID: bob.deviceID,
		MessageID:         "fed-bad-cert",
		Payload:           json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/messages", body, alice)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleReceiveFederatedMessageAccountIDMismatch(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	bob := registerAccount(t, a)
	alice := newIdentityKeys(t)
	eve := newIdentityKeys(t)

	var req federationMessageRequest
	if err := json.Unmarshal(federationRequestBody(t, alice, "fed-id-mismatch", bob.deviceID, `{}`), &req); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	req.SenderAccountID = eve.accountID // claim eve's id, present alice's key/cert
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/messages", body, alice)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleReceiveFederatedMessageKeyIDMismatch(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	bob := registerAccount(t, a)
	alice := newIdentityKeys(t)
	mallory := newIdentityKeys(t)

	body := federationRequestBody(t, alice, "fed-keyid-mismatch", bob.deviceID, `{}`)
	// Sign with a DIFFERENT key than the one named in sender_device_cert.
	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/messages", body, mallory)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleReceiveFederatedMessageBlockedSender(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	bob := registerAccount(t, a)
	alice := newIdentityKeys(t)

	if err := store.BlockFederationSender(db, alice.accountID, "admin-account", nil, time.Now()); err != nil {
		t.Fatalf("BlockFederationSender() error = %v", err)
	}

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/messages",
		federationRequestBody(t, alice, "fed-blocked", bob.deviceID, `{}`), alice)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleReceiveFederatedMessageUnknownRecipient(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := newIdentityKeys(t)

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/messages",
		federationRequestBody(t, alice, "fed-unknown-recipient", "no-such-device", `{}`), alice)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleReceiveFederatedMessageInactiveRecipientDevice(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	bob := registerAccount(t, a)
	alice := newIdentityKeys(t)

	if err := store.RevokeDevice(db, bob.deviceID, time.Now()); err != nil {
		t.Fatalf("RevokeDevice() error = %v", err)
	}

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/messages",
		federationRequestBody(t, alice, "fed-revoked-recipient", bob.deviceID, `{}`), alice)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleReceiveFederatedMessageDisabledRecipientAccount(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	bob := registerAccount(t, a)
	alice := newIdentityKeys(t)

	if err := store.SetAccountStatus(db, bob.accountID, store.AccountStatusDisabled); err != nil {
		t.Fatalf("SetAccountStatus() error = %v", err)
	}

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/messages",
		federationRequestBody(t, alice, "fed-disabled-account", bob.deviceID, `{}`), alice)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleReceiveFederatedMessageReplayedMessageID(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	bob := registerAccount(t, a)
	alice := newIdentityKeys(t)

	body := federationRequestBody(t, alice, "fed-dup", bob.deviceID, `{}`)
	rec1 := doFederatedSignedRequest(t, a.Router(), "/v1/federation/messages", body, alice)
	if rec1.Code != http.StatusAccepted {
		t.Fatalf("first send status = %d, want 202, body = %s", rec1.Code, rec1.Body.String())
	}
	rec2 := doFederatedSignedRequest(t, a.Router(), "/v1/federation/messages", body, alice)
	if rec2.Code != http.StatusConflict {
		t.Errorf("second send status = %d, want 409, body = %s", rec2.Code, rec2.Body.String())
	}
}

func TestHandleReceiveFederatedMessageReplayedNonce(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	bob := registerAccount(t, a)
	alice := newIdentityKeys(t)

	keyID := b64(alice.devicePub)
	const path = "/v1/federation/messages"
	ts := time.Now()
	const nonce = "fixed-nonce"

	send := func(body []byte) *httptest.ResponseRecorder {
		sig := httpsig.Sign(http.MethodPost, path, "", body, keyID, ts, nonce, alice.devicePriv)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(httpsig.HeaderKeyID, keyID)
		req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
		req.Header.Set(httpsig.HeaderNonce, nonce)
		req.Header.Set(httpsig.HeaderSignature, sig)
		rec := httptest.NewRecorder()
		a.Router().ServeHTTP(rec, req)
		return rec
	}

	rec1 := send(federationRequestBody(t, alice, "fed-replay-nonce-1", bob.deviceID, `{}`))
	if rec1.Code != http.StatusAccepted {
		t.Fatalf("first send status = %d, want 202, body = %s", rec1.Code, rec1.Body.String())
	}

	// Distinct message_id, same (key, nonce) pair -- proves the nonce
	// replay guard fires independent of the message_id uniqueness check.
	rec2 := send(federationRequestBody(t, alice, "fed-replay-nonce-2", bob.deviceID, `{}`))
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("replayed-nonce status = %d, want 401, body = %s", rec2.Code, rec2.Body.String())
	}
}

func TestHandleReceiveFederatedMessageRejectsWhenRecipientQueueIsFull(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	a.Config.MaxQueuedMessagesPerDevice = 2
	bob := registerAccount(t, a)
	alice := newIdentityKeys(t)

	for i, id := range []string{"fed-q1", "fed-q2"} {
		rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/messages",
			federationRequestBody(t, alice, id, bob.deviceID, `{}`), alice)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("send #%d status = %d, want 202, body = %s", i+1, rec.Code, rec.Body.String())
		}
	}

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/messages",
		federationRequestBody(t, alice, "fed-q3", bob.deviceID, `{}`), alice)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("third send status = %d, want 429, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleReceiveFederatedMessageRejectsOversizedBody(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	bob := registerAccount(t, a)
	alice := newIdentityKeys(t)

	body := federationRequestBody(t, alice, "fed-too-large", bob.deviceID, `{"ciphertext":"abc"}`)
	keyID := b64(alice.devicePub)
	const path = "/v1/federation/messages"
	ts := time.Now()
	nonce := "fed-nonce-too-large"
	sig := httpsig.Sign(http.MethodPost, path, "", body, keyID, ts, nonce, alice.devicePriv)

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(httpsig.HeaderKeyID, keyID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	rec := httptest.NewRecorder()
	req.Body = http.MaxBytesReader(rec, req.Body, int64(len(body)-1))
	a.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleReceiveFederatedMessageDisabledByConfig(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	a.Config.FederationEnabled = false
	bob := registerAccount(t, a)
	alice := newIdentityKeys(t)

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/messages",
		federationRequestBody(t, alice, "fed-disabled-server", bob.deviceID, `{}`), alice)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestFederationBlocklistAdminEndpoints(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	admin := registerAccount(t, a)
	if err := store.SetAccountRole(a.DB, admin.accountID, store.RoleAdmin); err != nil {
		t.Fatalf("SetAccountRole() error = %v", err)
	}
	target := newIdentityKeys(t).accountID

	reason := "spamming"
	blockBody, err := json.Marshal(blockFederationSenderRequest{AccountID: target, Reason: &reason})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	blockRec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/federation-blocklist", blockBody, admin.deviceID, admin.devicePriv)
	if blockRec.Code != http.StatusOK {
		t.Fatalf("block status = %d, want 200, body = %s", blockRec.Code, blockRec.Body.String())
	}

	listRec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/federation-blocklist", nil, admin.deviceID, admin.devicePriv)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200, body = %s", listRec.Code, listRec.Body.String())
	}
	var entries []federationBlockEntryResponse
	decodeJSON(t, listRec, &entries)
	if len(entries) != 1 || entries[0].AccountID != target {
		t.Errorf("blocklist = %+v, want one entry for %s", entries, target)
	}

	unblockRec := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/admin/federation-blocklist/"+target, nil, admin.deviceID, admin.devicePriv)
	if unblockRec.Code != http.StatusOK {
		t.Fatalf("unblock status = %d, want 200, body = %s", unblockRec.Code, unblockRec.Body.String())
	}

	unblockAgainRec := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/admin/federation-blocklist/"+target, nil, admin.deviceID, admin.devicePriv)
	if unblockAgainRec.Code != http.StatusNotFound {
		t.Errorf("second unblock status = %d, want 404, body = %s", unblockAgainRec.Code, unblockAgainRec.Body.String())
	}
}
