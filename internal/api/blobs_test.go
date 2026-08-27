package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/httpsig"
)

func hexDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// doBlobUpload signs an upload the way a real client does: over the stated
// body digest rather than the body itself, so the body never has to be
// buffered to authenticate it.
func doBlobUpload(t *testing.T, handler http.Handler, path string, body []byte, digest string, signerDeviceID string, signerPriv ed25519.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(httpsig.HeaderBodyDigest, "sha256="+digest)

	ts := time.Now()
	nonce := uniqueTestNonce(signerDeviceID, path, ts)
	canonical := httpsig.CanonicalStringWithBodyDigest(
		http.MethodPost, req.URL.Path, req.URL.RawQuery, httpsig.FormatTimestamp(ts), nonce, signerDeviceID, digest)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(signerPriv, []byte(canonical)))

	req.Header.Set(httpsig.HeaderKeyID, signerDeviceID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func uploadBlobOK(t *testing.T, a *API, k identityKeys, body []byte) string {
	t.Helper()
	rec := doBlobUpload(t, a.Router(), "/v1/blobs?recipient_device_id="+k.deviceID, body, hexDigest(body), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
	var resp blobUploadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding upload response: %v", err)
	}
	return resp.BlobID
}

func TestBlobUploadDownloadRoundTrip(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	payload := bytes.Repeat([]byte("encrypted image bytes"), 100)

	blobID := uploadBlobOK(t, a, k, payload)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/blobs/"+blobID, nil, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("download status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), payload) {
		t.Errorf("downloaded %d bytes, want the %d uploaded", rec.Body.Len(), len(payload))
	}
}

// TestBlobUploadRejectedWhenServerStorageFull is the regression guard for the
// missing server-wide disk cap (audit M2). With an aggregate ceiling set, an
// upload that fits is stored, and one that would push the total over the cap is
// refused with 507 -- exercising both the cheap pre-flight and the
// authoritative in-transaction check (here the second upload passes the
// pre-flight but is refused inside the write transaction).
func TestBlobUploadRejectedWhenServerStorageFull(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	payload := bytes.Repeat([]byte("x"), 4096)
	// Room for one 4096-byte blob but not two: the first fits, the second
	// clears the pre-flight (4096 < 6000) yet is refused in the transaction
	// (4096 + 4096 > 6000).
	a.Config.MaxBlobBytesTotal = 6000

	uploadBlobOK(t, a, k, payload)

	rec := doBlobUpload(t, a.Router(), "/v1/blobs?recipient_device_id="+k.deviceID, payload, hexDigest(payload), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("over-cap upload status = %d, want 507, body = %s", rec.Code, rec.Body.String())
	}

	// Once full, a further upload is refused cheaply by the pre-flight too.
	rec = doBlobUpload(t, a.Router(), "/v1/blobs?recipient_device_id="+k.deviceID, payload, hexDigest(payload), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusInsufficientStorage {
		t.Errorf("second over-cap upload status = %d, want 507, body = %s", rec.Code, rec.Body.String())
	}
}

func TestBlobUploadRejectsBodyThatDoesNotMatchSignedDigest(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	// Signed over one digest, sending different bytes: the signature is
	// valid, so only the streaming hash check catches this. Without it, a
	// client could sign one thing and store another.
	claimed := []byte("what was signed")
	actual := []byte("what was actually sent")
	rec := doBlobUpload(t, a.Router(), "/v1/blobs?recipient_device_id="+k.deviceID, actual, hexDigest(claimed), k.deviceID, k.devicePriv)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestBlobUploadRejectsUnsignedRequest(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	body := []byte("bytes")

	req := httptest.NewRequest(http.MethodPost, "/v1/blobs?recipient_device_id="+k.deviceID, bytes.NewReader(body))
	req.Header.Set(httpsig.HeaderBodyDigest, "sha256="+hexDigest(body))
	rec := httptest.NewRecorder()
	a.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestBlobUploadRequiresDigestHeader(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	body := []byte("bytes")

	// Without the digest the middleware cannot authenticate without
	// buffering, which is exactly what this route must never do -- so the
	// header is mandatory rather than optional.
	req := httptest.NewRequest(http.MethodPost, "/v1/blobs?recipient_device_id="+k.deviceID, bytes.NewReader(body))
	ts := time.Now()
	nonce := uniqueTestNonce(k.deviceID, "/v1/blobs", ts)
	sig := httpsig.Sign(http.MethodPost, "/v1/blobs", "recipient_device_id="+k.deviceID, body, k.deviceID, ts, nonce, k.devicePriv)
	req.Header.Set(httpsig.HeaderKeyID, k.deviceID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	rec := httptest.NewRecorder()
	a.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when the digest header is absent", rec.Code)
	}
}

func TestBlobDownloadDeniedForAnotherDevice(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	owner := registerAccount(t, a)
	stranger := registerAccount(t, a)

	blobID := uploadBlobOK(t, a, owner, []byte("private image"))

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/blobs/"+blobID, nil, stranger.deviceID, stranger.devicePriv)
	// 404 rather than 403: "not yours" must be indistinguishable from
	// "doesn't exist", so this can't be used to probe for blob ids.
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for another device's blob", rec.Code)
	}
}

func TestBlobDownloadUnknownIDIsNotFound(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/blobs/"+strings.Repeat("ab", 32), nil, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestBlobDeleteRemovesItAndFreesQuota(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	blobID := uploadBlobOK(t, a, k, []byte("image"))

	rec := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/blobs/"+blobID, nil, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}

	count, total, err := store.BlobUsage(db, k.deviceID)
	if err != nil {
		t.Fatalf("BlobUsage() error = %v", err)
	}
	if count != 0 || total != 0 {
		t.Errorf("usage after delete = (%d, %d), want (0, 0)", count, total)
	}
	// The file must be gone too, not just the row.
	if _, err := a.Blobs.Open(blobID); err == nil {
		t.Error("blob file still present after delete")
	}
	rec = doSignedRequest(t, a.Router(), http.MethodGet, "/v1/blobs/"+blobID, nil, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusNotFound {
		t.Errorf("download after delete = %d, want 404", rec.Code)
	}
}

func TestBlobDeleteDeniedForAnotherDevice(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	owner := registerAccount(t, a)
	stranger := registerAccount(t, a)
	blobID := uploadBlobOK(t, a, owner, []byte("image"))

	rec := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/blobs/"+blobID, nil, stranger.deviceID, stranger.devicePriv)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	// And the owner's blob must be untouched.
	rec = doSignedRequest(t, a.Router(), http.MethodGet, "/v1/blobs/"+blobID, nil, owner.deviceID, owner.devicePriv)
	if rec.Code != http.StatusOK {
		t.Errorf("owner's download after a stranger's delete = %d, want 200", rec.Code)
	}
}

func TestBlobUploadRejectsOversize(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	a.Config.MaxBlobBytes = 100
	k := registerAccount(t, a)
	body := bytes.Repeat([]byte("x"), 500)

	rec := doBlobUpload(t, a.Router(), "/v1/blobs?recipient_device_id="+k.deviceID, body, hexDigest(body), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413, body = %s", rec.Code, rec.Body.String())
	}
}

func TestBlobUploadRejectsWhenQuotaFull(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	a.Config.MaxBlobsPerDevice = 1
	k := registerAccount(t, a)

	uploadBlobOK(t, a, k, []byte("first"))

	body := []byte("second")
	rec := doBlobUpload(t, a.Router(), "/v1/blobs?recipient_device_id="+k.deviceID, body, hexDigest(body), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429, body = %s", rec.Code, rec.Body.String())
	}
}

func TestBlobUploadRejectsUnknownRecipientDevice(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	body := []byte("image")

	rec := doBlobUpload(t, a.Router(), "/v1/blobs?recipient_device_id=no-such-device", body, hexDigest(body), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestBlobUploadRejectedWhenDisabled(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	a.Config.BlobsEnabled = false
	k := registerAccount(t, a)
	body := []byte("image")

	rec := doBlobUpload(t, a.Router(), "/v1/blobs?recipient_device_id="+k.deviceID, body, hexDigest(body), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when blobs are disabled, body = %s", rec.Code, rec.Body.String())
	}
}

func TestBlobDownloadSupportsRangeRequests(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	payload := []byte("0123456789abcdefghij")
	blobID := uploadBlobOK(t, a, k, payload)

	// Range support is what lets a client resume an interrupted download --
	// it comes from http.ServeContent, so this guards the choice to use it.
	path := "/v1/blobs/" + blobID
	req := httptest.NewRequest(http.MethodGet, path, nil)
	ts := time.Now()
	nonce := uniqueTestNonce(k.deviceID, path, ts)
	sig := httpsig.Sign(http.MethodGet, path, "", []byte{}, k.deviceID, ts, nonce, k.devicePriv)
	req.Header.Set(httpsig.HeaderKeyID, k.deviceID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)
	req.Header.Set("Range", "bytes=5-9")

	rec := httptest.NewRecorder()
	a.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", rec.Code)
	}
	got, _ := io.ReadAll(rec.Body)
	if string(got) != "56789" {
		t.Errorf("range body = %q, want %q", got, "56789")
	}
}

func TestDigestHeaderCannotBypassBodyBindingOnNormalRoutes(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	// The streamed-body shortcut is scoped to POST /v1/blobs. If it leaked to
	// other routes, a caller could sign one body and send another -- so this
	// signs over a digest, sends different bytes, to a normal route, and
	// requires that it be rejected.
	signedBody := []byte(`{"recipient_device_id":"x","message_id":"y","payload":{}}`)
	sentBody := []byte(`{"recipient_device_id":"other","message_id":"z","payload":{"evil":true}}`)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(sentBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(httpsig.HeaderBodyDigest, "sha256="+hexDigest(signedBody))

	ts := time.Now()
	nonce := uniqueTestNonce(k.deviceID, "/v1/messages", ts)
	canonical := httpsig.CanonicalStringWithBodyDigest(
		http.MethodPost, "/v1/messages", "", httpsig.FormatTimestamp(ts), nonce, k.deviceID, hexDigest(signedBody))
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(k.devicePriv, []byte(canonical)))
	req.Header.Set(httpsig.HeaderKeyID, k.deviceID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	rec := httptest.NewRecorder()
	a.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 -- a claimed digest must not authenticate a normal route", rec.Code)
	}
}
