package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
)

func batchBody(t *testing.T, items ...batchMessageItem) []byte {
	t.Helper()
	body, err := json.Marshal(sendMessageBatchRequest{Messages: items})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return body
}

func item(messageID, recipientDeviceID string) batchMessageItem {
	return batchMessageItem{
		MessageID:         messageID,
		RecipientDeviceID: recipientDeviceID,
		Payload:           json.RawMessage(`{"ciphertext":"abc"}`),
	}
}

// statuses reads the per-item outcomes out of a batch response, keyed by
// message id -- what a client actually acts on.
func statuses(t *testing.T, rec interface{ Result() *http.Response }) map[string]string {
	t.Helper()
	resp := rec.Result()
	defer resp.Body.Close()

	var parsed batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decoding batch response: %v", err)
	}
	out := map[string]string{}
	for _, r := range parsed.Results {
		out[r.MessageID] = r.Status
	}
	return out
}

func TestSendMessageBatchDeliversToEveryRecipient(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)
	carol := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages/batch",
		batchBody(t, item("g1-bob", bob.deviceID), item("g1-carol", carol.deviceID)),
		alice.deviceID, alice.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	got := statuses(t, rec)
	if got["g1-bob"] != "queued" || got["g1-carol"] != "queued" {
		t.Fatalf("statuses = %v, want both queued", got)
	}

	// Both copies must actually be in their own recipient's queue -- a batch
	// is a transport shortcut, not a different kind of delivery.
	for _, recipient := range []struct {
		name string
		acct identityKeys
	}{{"bob", bob}, {"carol", carol}} {
		listRec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/messages", nil, recipient.acct.deviceID, recipient.acct.devicePriv)
		var msgs []messageResponse
		decodeJSON(t, listRec, &msgs)
		if len(msgs) != 1 || msgs[0].SenderAccountID != alice.accountID {
			t.Errorf("%s: messages = %+v, want one from %s", recipient.name, msgs, alice.accountID)
		}
	}
}

func TestSendMessageBatchReportsFailuresPerItem(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)
	blocked := registerAccount(t, a)

	if err := store.SetAccountStatus(db, blocked.accountID, store.AccountStatusDisabled); err != nil {
		t.Fatalf("disabling account: %v", err)
	}

	// A duplicate, an unknown device, a disabled recipient and a malformed
	// item, all alongside one perfectly good message. The good one must still
	// arrive: in a group, one member's problem is not the others' problem.
	first := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages/batch",
		batchBody(t, item("dup", bob.deviceID)), alice.deviceID, alice.devicePriv)
	if first.Code != http.StatusOK {
		t.Fatalf("setup send status = %d", first.Code)
	}

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages/batch",
		batchBody(t,
			item("good", bob.deviceID),
			item("dup", bob.deviceID),
			item("gone", "ffffffffffffffff"),
			item("disabled", blocked.deviceID),
			batchMessageItem{MessageID: "empty", RecipientDeviceID: bob.deviceID},
		),
		alice.deviceID, alice.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	want := map[string]string{
		"good":     "queued",
		"dup":      "duplicate",
		"gone":     "unknown_recipient",
		"disabled": "unknown_recipient",
		"empty":    "invalid",
	}
	got := statuses(t, rec)
	for id, wantStatus := range want {
		if got[id] != wantStatus {
			t.Errorf("%s: status = %q, want %q", id, got[id], wantStatus)
		}
	}
}

func TestSendMessageBatchRejectsEmptyAndOversizedBatches(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages/batch",
		batchBody(t), alice.deviceID, alice.devicePriv)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty batch status = %d, want 400", rec.Code)
	}

	items := make([]batchMessageItem, a.Config.MaxBatchMessages+1)
	for i := range items {
		items[i] = item(fmt.Sprintf("m%d", i), bob.deviceID)
	}
	rec = doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages/batch",
		batchBody(t, items...), alice.deviceID, alice.devicePriv)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized batch status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestSendMessageBatchRequiresAuthentication(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	bob := registerAccount(t, a)

	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/messages/batch", batchBody(t, item("m1", bob.deviceID)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// federationBatchBody builds a cross-server batch: the sender's identity
// block once at the top, the messages under it.
func federationBatchBody(t *testing.T, sender identityKeys, items ...batchMessageItem) []byte {
	t.Helper()
	body, err := json.Marshal(federationMessageBatchRequest{
		SenderAccountID:  sender.accountID,
		SenderRootPubKey: b64(sender.rootPub),
		SenderDeviceCert: federationDeviceCertDTO{
			DeviceID:     sender.deviceID,
			DevicePubKey: b64(sender.devicePub),
			IssuedAt:     sender.issuedAt.UTC().Format(time.RFC3339),
			Signature:    b64(sender.certSignature(t)),
		},
		Messages: items,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return body
}

func TestFederatedMessageBatchVerifiesTheChainOnceForEveryone(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	bob := registerAccount(t, a)
	carol := registerAccount(t, a)
	alice := newIdentityKeys(t) // a group member on another server

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/federation/messages/batch",
		federationBatchBody(t, alice, item("fed-bob", bob.deviceID), item("fed-carol", carol.deviceID)), alice)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	got := statuses(t, rec)
	if got["fed-bob"] != "queued" || got["fed-carol"] != "queued" {
		t.Fatalf("statuses = %v, want both queued", got)
	}

	listRec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/messages", nil, carol.deviceID, carol.devicePriv)
	var msgs []messageResponse
	decodeJSON(t, listRec, &msgs)
	if len(msgs) != 1 || msgs[0].SenderAccountID != alice.accountID {
		t.Fatalf("messages = %+v, want one from the foreign sender", msgs)
	}
}

func TestFederatedMessageBatchRejectsABadChainBeforeQueueingAnything(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	bob := registerAccount(t, a)
	alice := newIdentityKeys(t)
	impostor := newIdentityKeys(t)

	// Alice's identity block, signed by somebody else's key: the one
	// verification failure must cost the whole batch, not one item of it.
	body := federationBatchBody(t, alice, item("fed-bob", bob.deviceID))
	rec := doKeyIDSignedRequest(t, a.Router(), "/v1/federation/messages/batch", body,
		b64(impostor.devicePub), impostor.devicePriv)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}

	listRec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/messages", nil, bob.deviceID, bob.devicePriv)
	var msgs []messageResponse
	decodeJSON(t, listRec, &msgs)
	if len(msgs) != 0 {
		t.Fatalf("messages = %+v, want none queued", msgs)
	}
}

func TestServerStatusAdvertisesBatchCapability(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)

	rec := doRequest(t, a.Router(), http.MethodGet, "/v1/server-status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var status serverStatusResponse
	decodeJSON(t, rec, &status)
	if !status.BatchMessages {
		t.Error("batch_messages must be advertised, or peers keep falling back to one post per message")
	}
	if status.MaxBatchMessages != a.Config.MaxBatchMessages {
		t.Errorf("max_batch_messages = %d, want %d", status.MaxBatchMessages, a.Config.MaxBatchMessages)
	}
}
