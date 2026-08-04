package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
)

// recipientQuery builds the repeated recipient_device_id parameter a group
// fan-out sends (SRV-18).
func recipientQuery(deviceIDs ...string) string {
	params := make([]string, 0, len(deviceIDs))
	for _, id := range deviceIDs {
		params = append(params, "recipient_device_id="+id)
	}
	return "/v1/blobs?" + strings.Join(params, "&")
}

func decodeUploadResponse(t *testing.T, body []byte) blobUploadResponse {
	t.Helper()
	var resp blobUploadResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decoding upload response: %v", err)
	}
	return resp
}

func statusFor(t *testing.T, resp blobUploadResponse, deviceID string) string {
	t.Helper()
	for _, r := range resp.Recipients {
		if r.RecipientDeviceID == deviceID {
			return r.Status
		}
	}
	t.Fatalf("no outcome reported for %s in %+v", deviceID, resp.Recipients)
	return ""
}

// The whole point of SRV-18: one upload, one stored object, every named
// member able to fetch it.
func TestBlobUploadServesSeveralRecipientsFromOneUpload(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	sender := registerAccount(t, a)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)
	payload := bytes.Repeat([]byte("encrypted group picture"), 50)

	rec := doBlobUpload(t, a.Router(), recipientQuery(alice.deviceID, bob.deviceID),
		payload, hexDigest(payload), sender.deviceID, sender.devicePriv)
	// Several recipients means nothing was created at one location, so 200
	// rather than 201 -- the outcomes are per recipient.
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	resp := decodeUploadResponse(t, rec.Body.Bytes())
	if resp.BlobID == "" {
		t.Fatal("no blob id returned")
	}
	for _, k := range []identityKeys{alice, bob} {
		if got := statusFor(t, resp, k.deviceID); got != "stored" {
			t.Errorf("%s status = %q, want stored", k.deviceID, got)
		}
	}

	for _, k := range []identityKeys{alice, bob} {
		got := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/blobs/"+resp.BlobID, nil, k.deviceID, k.devicePriv)
		if got.Code != http.StatusOK {
			t.Fatalf("download for %s = %d, want 200, body = %s", k.deviceID, got.Code, got.Body.String())
		}
		if !bytes.Equal(got.Body.Bytes(), payload) {
			t.Errorf("%s downloaded %d bytes, want the %d uploaded", k.deviceID, got.Body.Len(), len(payload))
		}
	}

	// A member who was not named is as unable to fetch it as any stranger.
	outsider := registerAccount(t, a)
	denied := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/blobs/"+resp.BlobID, nil, outsider.deviceID, outsider.devicePriv)
	if denied.Code != http.StatusNotFound {
		t.Errorf("unnamed device download = %d, want 404", denied.Code)
	}
}

// One member at their quota, or one that does not exist, must not cost the
// others their copy -- the same rule batch delivery already follows.
func TestBlobUploadReportsFailuresPerRecipient(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	sender := registerAccount(t, a)
	alice := registerAccount(t, a)
	full := registerAccount(t, a)
	payload := []byte("encrypted group picture")

	// Fill one recipient's quota, leave the other's empty.
	a.Config.MaxBlobsPerDevice = 1
	first := doBlobUpload(t, a.Router(), recipientQuery(full.deviceID),
		[]byte("first"), hexDigest([]byte("first")), sender.deviceID, sender.devicePriv)
	if first.Code != http.StatusCreated {
		t.Fatalf("priming upload status = %d, want 201, body = %s", first.Code, first.Body.String())
	}

	rec := doBlobUpload(t, a.Router(), recipientQuery(alice.deviceID, full.deviceID, "device-that-does-not-exist"),
		payload, hexDigest(payload), sender.deviceID, sender.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	resp := decodeUploadResponse(t, rec.Body.Bytes())

	if got := statusFor(t, resp, alice.deviceID); got != "stored" {
		t.Errorf("alice status = %q, want stored", got)
	}
	if got := statusFor(t, resp, full.deviceID); got != "quota_exceeded" {
		t.Errorf("full recipient status = %q, want quota_exceeded", got)
	}
	if got := statusFor(t, resp, "device-that-does-not-exist"); got != "unknown_recipient" {
		t.Errorf("unknown recipient status = %q, want unknown_recipient", got)
	}

	// The one that succeeded really did.
	got := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/blobs/"+resp.BlobID, nil, alice.deviceID, alice.devicePriv)
	if got.Code != http.StatusOK {
		t.Errorf("alice download = %d, want 200", got.Code)
	}
}

// Nothing stored means nothing created: no blob id, and no bytes on disk.
func TestBlobUploadStoresNothingWhenEveryRecipientFails(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	sender := registerAccount(t, a)
	payload := []byte("encrypted group picture")

	rec := doBlobUpload(t, a.Router(), recipientQuery("nobody-1", "nobody-2"),
		payload, hexDigest(payload), sender.deviceID, sender.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	resp := decodeUploadResponse(t, rec.Body.Bytes())
	if resp.BlobID != "" {
		t.Errorf("blob id = %q, want it omitted when nothing was stored", resp.BlobID)
	}
	if len(resp.Recipients) != 2 {
		t.Fatalf("got %d outcomes, want 2", len(resp.Recipients))
	}
	for _, r := range resp.Recipients {
		if r.Status != "unknown_recipient" {
			t.Errorf("%s status = %q, want unknown_recipient", r.RecipientDeviceID, r.Status)
		}
	}
}

// The pre-SRV-18 contract, unchanged: one recipient still answers 201 on
// success and the old status codes on failure, so no client has to be
// updated to keep working.
func TestBlobUploadKeepsTheSingleRecipientContract(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	sender := registerAccount(t, a)
	alice := registerAccount(t, a)
	payload := []byte("encrypted picture")

	rec := doBlobUpload(t, a.Router(), recipientQuery(alice.deviceID),
		payload, hexDigest(payload), sender.deviceID, sender.devicePriv)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
	resp := decodeUploadResponse(t, rec.Body.Bytes())
	if resp.BlobID == "" || resp.Size != int64(len(payload)) || resp.ExpiresAt == "" {
		t.Errorf("response = %+v, want the three fields an older client reads", resp)
	}
	// The new field rides along; an older parser ignores it.
	if got := statusFor(t, resp, alice.deviceID); got != "stored" {
		t.Errorf("status = %q, want stored", got)
	}

	// And a failing single recipient is still an error response, not a
	// 200 with an outcome an older client would never look at.
	failed := doBlobUpload(t, a.Router(), recipientQuery("nobody"),
		payload, hexDigest(payload), sender.deviceID, sender.devicePriv)
	if failed.Code != http.StatusNotFound {
		t.Errorf("unknown single recipient status = %d, want 404, body = %s", failed.Code, failed.Body.String())
	}
}

// A member with barely any quota left must not shrink the upload out from
// under the others: bounding the stream by the smallest headroom would give
// everyone a 413 for one member's housekeeping. The picture is stored for
// whoever it fits, and the one it does not fit is told so.
func TestBlobUploadIsNotShrunkByTheFullestRecipient(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	sender := registerAccount(t, a)
	roomy := registerAccount(t, a)
	nearlyFull := registerAccount(t, a)

	// Leave nearlyFull with 10 bytes of headroom, roomy with plenty.
	a.Config.MaxBlobBytesPerDevice = 1000
	filler := bytes.Repeat([]byte("x"), 990)
	prime := doBlobUpload(t, a.Router(), recipientQuery(nearlyFull.deviceID),
		filler, hexDigest(filler), sender.deviceID, sender.devicePriv)
	if prime.Code != http.StatusCreated {
		t.Fatalf("priming upload status = %d, want 201, body = %s", prime.Code, prime.Body.String())
	}

	payload := bytes.Repeat([]byte("y"), 500)
	rec := doBlobUpload(t, a.Router(), recipientQuery(roomy.deviceID, nearlyFull.deviceID),
		payload, hexDigest(payload), sender.deviceID, sender.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	resp := decodeUploadResponse(t, rec.Body.Bytes())
	if got := statusFor(t, resp, roomy.deviceID); got != "stored" {
		t.Errorf("roomy status = %q, want stored -- a full co-recipient cost it its copy", got)
	}
	if got := statusFor(t, resp, nearlyFull.deviceID); got != "quota_exceeded" {
		t.Errorf("nearly-full status = %q, want quota_exceeded", got)
	}

	got := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/blobs/"+resp.BlobID, nil, roomy.deviceID, roomy.devicePriv)
	if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), payload) {
		t.Errorf("roomy download = %d with %d bytes, want 200 with %d", got.Code, got.Body.Len(), len(payload))
	}
	denied := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/blobs/"+resp.BlobID, nil, nearlyFull.deviceID, nearlyFull.devicePriv)
	if denied.Code != http.StatusNotFound {
		t.Errorf("the recipient it did not fit can still download it: %d", denied.Code)
	}
}

// The mirror image: when it fits nobody, the stream cap catches it mid-body
// and nothing is written at all -- the cheap answer, rather than storing the
// bytes and discovering afterwards that no one may keep them.
func TestBlobUploadRefusesASizeThatFitsNoRecipient(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	sender := registerAccount(t, a)
	first := registerAccount(t, a)
	second := registerAccount(t, a)

	a.Config.MaxBlobBytesPerDevice = 1000
	filler := bytes.Repeat([]byte("x"), 990)
	for _, k := range []identityKeys{first, second} {
		prime := doBlobUpload(t, a.Router(), recipientQuery(k.deviceID),
			filler, hexDigest(filler), sender.deviceID, sender.devicePriv)
		if prime.Code != http.StatusCreated {
			t.Fatalf("priming upload for %s = %d, body = %s", k.deviceID, prime.Code, prime.Body.String())
		}
	}

	payload := bytes.Repeat([]byte("y"), 500)
	rec := doBlobUpload(t, a.Router(), recipientQuery(first.deviceID, second.deviceID),
		payload, hexDigest(payload), sender.deviceID, sender.devicePriv)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("upload status = %d, want 413, body = %s", rec.Code, rec.Body.String())
	}
}

func TestBlobUploadRejectsTooManyRecipients(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	sender := registerAccount(t, a)
	a.Config.MaxBlobRecipients = 2
	payload := []byte("encrypted picture")

	rec := doBlobUpload(t, a.Router(), recipientQuery("a", "b", "c"),
		payload, hexDigest(payload), sender.deviceID, sender.devicePriv)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "too_many_recipients") {
		t.Errorf("body = %s, want a too_many_recipients error", rec.Body.String())
	}
}

// Naming a device twice must charge its quota once -- otherwise a sender
// could exhaust a recipient's allowance with a single upload.
func TestBlobUploadCollapsesDuplicateRecipients(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	sender := registerAccount(t, a)
	alice := registerAccount(t, a)
	payload := []byte("encrypted picture")

	rec := doBlobUpload(t, a.Router(), recipientQuery(alice.deviceID, alice.deviceID),
		payload, hexDigest(payload), sender.deviceID, sender.devicePriv)
	// One distinct recipient, so this is the single-recipient form.
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
	resp := decodeUploadResponse(t, rec.Body.Bytes())
	if len(resp.Recipients) != 1 {
		t.Errorf("got %d outcomes, want 1", len(resp.Recipients))
	}

	count, total, err := store.BlobUsage(db, alice.deviceID)
	if err != nil {
		t.Fatalf("BlobUsage() error = %v", err)
	}
	if count != 1 || total != int64(len(payload)) {
		t.Errorf("usage = (%d, %d), want (1, %d)", count, total, len(payload))
	}
}

// One member deleting their copy must not take the picture away from the
// others; the bytes go with the last claim.
func TestBlobDeleteByOneRecipientLeavesItForTheRest(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	sender := registerAccount(t, a)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)
	payload := []byte("encrypted group picture")

	rec := doBlobUpload(t, a.Router(), recipientQuery(alice.deviceID, bob.deviceID),
		payload, hexDigest(payload), sender.deviceID, sender.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	blobID := decodeUploadResponse(t, rec.Body.Bytes()).BlobID

	del := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/blobs/"+blobID, nil, alice.deviceID, alice.devicePriv)
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204, body = %s", del.Code, del.Body.String())
	}

	gone := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/blobs/"+blobID, nil, alice.deviceID, alice.devicePriv)
	if gone.Code != http.StatusNotFound {
		t.Errorf("deleting device can still download: %d", gone.Code)
	}
	still := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/blobs/"+blobID, nil, bob.deviceID, bob.devicePriv)
	if still.Code != http.StatusOK {
		t.Fatalf("the other recipient lost the blob: %d, body = %s", still.Code, still.Body.String())
	}
	if !bytes.Equal(still.Body.Bytes(), payload) {
		t.Error("the remaining recipient got different bytes back")
	}

	// Now the last claim: the file itself must go.
	last := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/blobs/"+blobID, nil, bob.deviceID, bob.devicePriv)
	if last.Code != http.StatusNoContent {
		t.Fatalf("final delete status = %d, want 204", last.Code)
	}
	if _, err := a.Blobs.Open(blobID); err == nil {
		t.Error("the file survived its last recipient")
	}
}

func TestServerStatusAdvertisesMaxBlobRecipients(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)

	rec := doRequest(t, a.Router(), http.MethodGet, "/v1/server-status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp serverStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding server status: %v", err)
	}
	// Absence means 1 to a client, so a server that supports several must
	// say so explicitly or its senders will fall back to one upload each.
	if resp.MaxBlobRecipients != a.Config.MaxBlobRecipients {
		t.Errorf("max_blob_recipients = %d, want %d", resp.MaxBlobRecipients, a.Config.MaxBlobRecipients)
	}
}
