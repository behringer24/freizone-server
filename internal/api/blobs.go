// Encrypted blob transport (SRV-07): the out-of-band channel for message
// attachments too large to ride inside a message payload. See
// docs/PROTOCOL.md's blob section for the wire format and rationale.
//
// A blob is stored on the RECIPIENT's server -- the same direction messages
// already travel, so a recipient only ever fetches from its own server and
// never has to contact a stranger's. The bytes are ciphertext the server
// cannot read; the key travels inside the end-to-end-encrypted message that
// carries the blob id.
package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/blobstore"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// Headers carrying the federated sender's identity. On the message endpoint
// these are JSON fields, but a blob's body is raw ciphertext, so they move
// into headers instead.
const (
	headerSenderAccountID   = "Freizone-Sender-Account-Id"
	headerSenderRootPubKey  = "Freizone-Sender-Root-Pub-Key"
	headerSenderDeviceID    = "Freizone-Sender-Device-Id"
	headerSenderDevicePub   = "Freizone-Sender-Device-Pub-Key"
	headerSenderCertIssued  = "Freizone-Sender-Cert-Issued-At"
	headerSenderCertSigning = "Freizone-Sender-Cert-Signature"
)

// handleUploadBlob accepts an encrypted attachment for a recipient device on
// THIS server, from a locally registered sender (device-signed, so
// internal/auth.Middleware has already authenticated the caller).
func (a *API) handleUploadBlob(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.IdentityFromContext(r.Context()); !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	// The signature the middleware verified already covers the body digest
	// the client stated, so nothing further is needed to tie this upload to
	// its sender.
	a.storeUploadedBlob(w, r)
}

// handleUploadFederatedBlob is the same upload from a sender on ANY server.
// Public (not behind a.Auth.Require) because a foreign sender has no local
// device row to look up -- it proves its identity chain inline, exactly like
// the federated message endpoint.
func (a *API) handleUploadFederatedBlob(w http.ResponseWriter, r *http.Request) {
	enabled, err := store.GetFederationEnabled(a.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if !enabled {
		writeError(w, http.StatusNotFound, "not_found", "federation is disabled on this server")
		return
	}

	digest, ok := parseBlobDigest(w, r)
	if !ok {
		return
	}
	// Authenticated from headers alone, before a single byte of the body is
	// read: an unauthenticated or forged upload must cost no disk at all.
	if _, ok := a.verifyFederatedSender(w, r, federatedSenderClaim{
		AccountID:  r.Header.Get(headerSenderAccountID),
		RootPubKey: r.Header.Get(headerSenderRootPubKey),
		DeviceCert: federationDeviceCertDTO{
			DeviceID:     r.Header.Get(headerSenderDeviceID),
			DevicePubKey: r.Header.Get(headerSenderDevicePub),
			IssuedAt:     r.Header.Get(headerSenderCertIssued),
			Signature:    r.Header.Get(headerSenderCertSigning),
		},
		BodyDigest: digest,
	}); !ok {
		return
	}

	a.storeUploadedBlob(w, r)
}

// storeUploadedBlob is the shared body of both upload routes: check the
// recipient, check quota, stream the ciphertext to disk while verifying it
// against the signed digest, then record it.
func (a *API) storeUploadedBlob(w http.ResponseWriter, r *http.Request) {
	if !a.Config.BlobsEnabled {
		writeError(w, http.StatusNotFound, "not_found", "blob storage is disabled on this server")
		return
	}

	digest, ok := parseBlobDigest(w, r)
	if !ok {
		return
	}

	recipientDeviceID := r.URL.Query().Get("recipient_device_id")
	if recipientDeviceID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "recipient_device_id is required")
		return
	}
	device, err := store.GetDevice(a.DB, recipientDeviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown recipient device")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if device.Status != store.DeviceStatusActive {
		writeError(w, http.StatusNotFound, "not_found", "recipient device is not active")
		return
	}

	// Quota before storing: the federated route accepts uploads from senders
	// who never registered here, so without this a stranger could fill the
	// disk. Checked against the recipient, since that is who the storage is
	// held for -- the same shape as the message queue's per-device cap.
	count, totalBytes, err := store.BlobUsage(a.DB, recipientDeviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if count >= a.Config.MaxBlobsPerDevice || totalBytes >= a.Config.MaxBlobBytesPerDevice {
		writeError(w, http.StatusTooManyRequests, "blob_quota_exceeded", "recipient device's blob storage is full")
		return
	}

	blobID, err := blobstore.NewBlobID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	// Bound by whatever quota headroom is actually left, not just the
	// per-blob cap, so a single upload can't overshoot the device's total.
	remaining := a.Config.MaxBlobBytesPerDevice - totalBytes
	maxThisBlob := a.Config.MaxBlobBytes
	if remaining < maxThisBlob {
		maxThisBlob = remaining
	}

	written, _, err := a.Blobs.Put(blobID, r.Body, digest, maxThisBlob)
	if err != nil {
		// Put already removed its temp file on every failure path.
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) || strings.Contains(err.Error(), "exceeds") {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "blob exceeds the size limit")
			return
		}
		if strings.Contains(err.Error(), "digest mismatch") {
			writeError(w, http.StatusBadRequest, "digest_mismatch", "body does not match the signed Blob-Digest")
			return
		}
		if a.Logger != nil {
			a.Logger.Warn("blob: storing upload failed", "error", err)
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	now := a.Now()
	expiresAt := now.AddDate(0, 0, a.Config.BlobRetentionDays)
	if err := store.CreateBlob(a.DB, store.Blob{
		BlobID:            blobID,
		RecipientDeviceID: recipientDeviceID,
		SizeBytes:         written,
		CreatedAt:         now,
		ExpiresAt:         expiresAt,
	}); err != nil {
		// The file is already on disk; without a row it is unreachable, so
		// drop it rather than leave it for the orphan sweep.
		_ = a.Blobs.Remove(blobID)
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	writeJSON(w, http.StatusCreated, blobUploadResponse{
		BlobID:    blobID,
		Size:      written,
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	})
}

// handleDownloadBlob serves a blob to its recipient device. Because blobs
// live on the recipient's own server, the fetcher is always a local,
// device-signed caller -- no capability tokens for strangers needed.
func (a *API) handleDownloadBlob(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	blobID := r.PathValue("blob_id")

	// Ownership and existence are answered with the same 404, so a caller
	// cannot use this endpoint to discover which blob ids exist.
	blob, err := store.GetBlobForDevice(a.DB, blobID, identity.DeviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown blob")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	f, err := a.Blobs.Open(blobID)
	if err != nil {
		if errors.Is(err, blobstore.ErrNotFound) {
			// Row without a file: the crash window between writing the file
			// and inserting the row, or a half-finished delete.
			writeError(w, http.StatusNotFound, "not_found", "unknown blob")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	// ServeContent handles range requests, conditional GETs and the
	// Content-Length header, so a client can resume an interrupted download.
	http.ServeContent(w, r, "", blob.CreatedAt, f)
}

// handleDeleteBlob lets a recipient drop a blob it has downloaded, freeing
// its quota before the retention window expires.
func (a *API) handleDeleteBlob(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	blobID := r.PathValue("blob_id")

	if err := store.DeleteBlobForDevice(a.DB, blobID, identity.DeviceID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown blob")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	// Row first, then file: a failure here leaves an orphan file the sweep
	// collects, which is recoverable -- the reverse would leave a row
	// pointing at nothing.
	if err := a.Blobs.Remove(blobID); err != nil && a.Logger != nil {
		a.Logger.Warn("blob: removing file failed", "error", err, "blob_id", blobID)
	}

	w.WriteHeader(http.StatusNoContent)
}

// parseBlobDigest reads and validates the Blob-Digest header, the hex
// SHA-256 the client signed in place of the body itself.
func parseBlobDigest(w http.ResponseWriter, r *http.Request) (string, bool) {
	raw := r.Header.Get(httpsig.HeaderBodyDigest)
	if raw == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", httpsig.HeaderBodyDigest+" is required")
		return "", false
	}
	// Accept both "sha256=<hex>" and a bare hex digest.
	digest := strings.TrimPrefix(strings.TrimSpace(raw), "sha256=")
	if len(digest) != 64 || !isHex(digest) {
		writeError(w, http.StatusBadRequest, "invalid_request", httpsig.HeaderBodyDigest+" must be a hex sha256 digest")
		return "", false
	}
	return strings.ToLower(digest), true
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
