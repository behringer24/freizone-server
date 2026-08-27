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
	"fmt"
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
		writeError(w, http.StatusNotFound, "federation_disabled", "federation is disabled on this server")
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

// blobRecipientOutcome is one named recipient's result. A value rather than
// a response, for the same reason enqueueOutcome is: an upload reports one
// per recipient, and only the single-recipient form turns it into a status
// code (see asError), which keeps the pre-SRV-18 contract intact.
type blobRecipientOutcome string

const (
	blobStored           blobRecipientOutcome = "stored"
	blobUnknownRecipient blobRecipientOutcome = "unknown_recipient"
	blobQuotaExceeded    blobRecipientOutcome = "quota_exceeded"
	blobInternalError    blobRecipientOutcome = "internal_error"
)

func (o blobRecipientOutcome) asError() (status int, code, message string) {
	switch o {
	case blobUnknownRecipient:
		return http.StatusNotFound, "unknown_recipient", "unknown or inactive recipient device"
	case blobQuotaExceeded:
		return http.StatusTooManyRequests, "blob_quota_exceeded", "recipient device's blob storage is full"
	default:
		return http.StatusInternalServerError, "internal", "internal server error"
	}
}

// storeUploadedBlob is the shared body of both upload routes: check every
// named recipient, stream the ciphertext to disk once while verifying it
// against the signed digest, then record it for the recipients that passed.
//
// One upload may name several recipients (SRV-18), which is what lets a group
// picture cost one upload per recipient *server* rather than one per member.
// Failures are per recipient and never fail the upload -- one member at their
// quota must not cost the others their copy.
func (a *API) storeUploadedBlob(w http.ResponseWriter, r *http.Request) {
	if !a.Config.BlobsEnabled {
		writeError(w, http.StatusNotFound, "not_found", "blob storage is disabled on this server")
		return
	}

	digest, ok := parseBlobDigest(w, r)
	if !ok {
		return
	}

	recipients, ok := a.parseBlobRecipients(w, r)
	if !ok {
		return
	}
	// A single recipient keeps the exact status codes and shape it had
	// before this endpoint learned about several, so no client has to change
	// to keep working.
	single := len(recipients) == 1

	// Every recipient is checked before a byte of the body is read: the
	// federated route accepts uploads from senders who never registered
	// here, so an unauthorized or unwanted upload must cost no disk at all.
	outcomes := make([]blobRecipientOutcome, len(recipients))
	accepted := make([]acceptedBlobRecipient, 0, len(recipients))
	// The stream is bounded by the LARGEST headroom among them, not the
	// smallest: a member with a nearly full quota must not shrink the upload
	// out from under the others -- they would all get a 413 for one member's
	// housekeeping. Whoever the stored size then does not fit is dropped
	// afterwards, which is a per-recipient failure like any other.
	var maxHeadroom int64
	for i, deviceID := range recipients {
		outcome, headroom := a.checkBlobRecipient(deviceID)
		outcomes[i] = outcome
		if outcome != blobStored {
			continue
		}
		accepted = append(accepted, acceptedBlobRecipient{index: i, deviceID: deviceID, headroom: headroom})
		if headroom > maxHeadroom {
			maxHeadroom = headroom
		}
	}

	if len(accepted) == 0 {
		a.writeBlobUploadFailure(w, single, recipients, outcomes)
		return
	}

	blobID, err := blobstore.NewBlobID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	maxThisBlob := a.Config.MaxBlobBytes
	if maxHeadroom < maxThisBlob {
		maxThisBlob = maxHeadroom
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

	// Decide the final recipient set inside the write transaction, re-checking
	// each device's quota against the now-known stored size. The pre-flight
	// check above raced the (possibly slow) upload stream: several concurrent
	// uploads to the same device could each have seen room and all committed,
	// blowing past the per-device quota. The single-writer transaction
	// serializes this check-and-insert, so the quota holds. (Security audit H3.)
	candidates := make([]string, len(accepted))
	for i, rcpt := range accepted {
		candidates[i] = rcpt.deviceID
	}
	storedIDs, quotaExceeded, err := a.recordBlobWithQuota(store.Blob{
		BlobID:    blobID,
		SizeBytes: written,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}, candidates)
	if err != nil {
		// The file is already on disk; without rows it is unreachable, so
		// drop it rather than leave it for the orphan sweep.
		_ = a.Blobs.Remove(blobID)
		if a.Logger != nil {
			a.Logger.Warn("blob: recording upload failed", "error", err, "blob_id", blobID)
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	// Reflect the transaction's authoritative decision in the per-recipient
	// outcomes: whoever no longer fit is a per-recipient quota failure, exactly
	// as the stale-headroom filter used to report but now race-free.
	overQuota := make(map[string]struct{}, len(quotaExceeded))
	for _, id := range quotaExceeded {
		overQuota[id] = struct{}{}
	}
	for _, rcpt := range accepted {
		if _, over := overQuota[rcpt.deviceID]; over {
			outcomes[rcpt.index] = blobQuotaExceeded
		}
	}

	// Nothing fit after the re-check: the file has no recipient rows and is
	// unreachable, so drop it and report the per-recipient failures (a single
	// recipient still surfaces its 429, as before).
	if len(storedIDs) == 0 {
		_ = a.Blobs.Remove(blobID)
		a.writeBlobUploadFailure(w, single, recipients, outcomes)
		return
	}

	status := http.StatusOK
	if single {
		status = http.StatusCreated
	}
	writeJSON(w, status, blobUploadResponse{
		BlobID:     blobID,
		Size:       written,
		ExpiresAt:  expiresAt.UTC().Format(time.RFC3339),
		Recipients: blobRecipientResults(recipients, outcomes),
	})
}

// acceptedBlobRecipient is a recipient that passed the pre-flight checks,
// carrying what is needed to reconsider it once the stored size is known:
// where it sits in the reported outcomes, and how much of its quota is left.
type acceptedBlobRecipient struct {
	index    int
	deviceID string
	headroom int64
}

// writeBlobUploadFailure answers an upload that stored nothing. A single
// recipient keeps the status codes it had before SRV-18; several get the
// per-recipient outcomes, since "all of them failed" is still not a
// request-level error the sender can act on without knowing why.
func (a *API) writeBlobUploadFailure(w http.ResponseWriter, single bool, recipients []string, outcomes []blobRecipientOutcome) {
	if single {
		status, code, message := outcomes[0].asError()
		writeError(w, status, code, message)
		return
	}
	writeJSON(w, http.StatusOK, blobUploadResponse{Recipients: blobRecipientResults(recipients, outcomes)})
}

// parseBlobRecipients reads the upload's recipient list. Deliberately the
// *repeated* recipient_device_id parameter rather than a new comma-separated
// one: a one-recipient upload is then byte-identical to what clients sent
// before SRV-18, and §3's signature already covers the raw query string, so
// the recipient set is signed without touching the signature scheme.
func (a *API) parseBlobRecipients(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	values := r.URL.Query()["recipient_device_id"]

	seen := make(map[string]struct{}, len(values))
	ids := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "recipient_device_id is required")
			return nil, false
		}
		// Naming a device twice charges its quota once -- and could not
		// become two rows anyway, the primary key would reject the second.
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		ids = append(ids, v)
	}
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "recipient_device_id is required")
		return nil, false
	}
	if len(ids) > a.Config.MaxBlobRecipients {
		writeError(w, http.StatusBadRequest, "too_many_recipients",
			fmt.Sprintf("an upload may name at most %d recipients", a.Config.MaxBlobRecipients))
		return nil, false
	}
	return ids, true
}

// checkBlobRecipient answers whether one named device may receive this
// upload, and how much of its quota is left if so.
func (a *API) checkBlobRecipient(deviceID string) (blobRecipientOutcome, int64) {
	device, err := store.GetDevice(a.DB, deviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return blobUnknownRecipient, 0
		}
		return blobInternalError, 0
	}
	// Unknown and inactive answer alike, as they do on download: the sender
	// has no business learning which devices exist here.
	if device.Status != store.DeviceStatusActive {
		return blobUnknownRecipient, 0
	}

	// Checked against the recipient, since that is who the storage is held
	// for -- the same shape as the message queue's per-device cap.
	count, totalBytes, err := store.BlobUsage(a.DB, deviceID)
	if err != nil {
		return blobInternalError, 0
	}
	if count >= a.Config.MaxBlobsPerDevice || totalBytes >= a.Config.MaxBlobBytesPerDevice {
		return blobQuotaExceeded, 0
	}
	return blobStored, a.Config.MaxBlobBytesPerDevice - totalBytes
}

// recordBlobWithQuota writes the blob and the recipient rows that still fit
// their per-device quota, in one transaction. The quota re-check happens inside
// the transaction (see store.CreateBlobWithQuota) to close the TOCTOU window
// between the pre-flight check and commit. Returns the device ids actually
// stored and those refused for quota.
func (a *API) recordBlobWithQuota(blob store.Blob, candidates []string) (stored, quotaExceeded []string, err error) {
	tx, err := a.DB.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	stored, quotaExceeded, err = store.CreateBlobWithQuota(tx, blob, candidates, a.Config.MaxBlobsPerDevice, a.Config.MaxBlobBytesPerDevice)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return stored, quotaExceeded, nil
}

// blobRecipientResults pairs each named recipient with its outcome, in the
// order they were named.
func blobRecipientResults(recipients []string, outcomes []blobRecipientOutcome) []blobRecipientResult {
	results := make([]blobRecipientResult, 0, len(recipients))
	for i, deviceID := range recipients {
		results = append(results, blobRecipientResult{
			RecipientDeviceID: deviceID,
			Status:            string(outcomes[i]),
		})
	}
	return results
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
//
// With several recipients (SRV-18) this drops only the caller's own claim;
// the file goes when the last claim does, so one group member deleting their
// copy cannot take the picture away from the rest.
func (a *API) handleDeleteBlob(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	blobID := r.PathValue("blob_id")

	unreferenced, err := a.deleteBlobClaim(blobID, identity.DeviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown blob")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	// Rows first, then file: a failure here leaves an orphan file the sweep
	// collects, which is recoverable -- the reverse would leave a row
	// pointing at nothing.
	if unreferenced {
		if err := a.Blobs.Remove(blobID); err != nil && a.Logger != nil {
			a.Logger.Warn("blob: removing file failed", "error", err, "blob_id", blobID)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// deleteBlobClaim removes one recipient's claim, and the blob itself if that
// was the last one, in a single transaction -- reporting whether the file is
// now unreferenced.
func (a *API) deleteBlobClaim(blobID, deviceID string) (bool, error) {
	tx, err := a.DB.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	unreferenced, err := store.DeleteBlobForDevice(tx, blobID, deviceID)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return unreferenced, nil
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
