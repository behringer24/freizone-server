// Federation: accepting a message from a sender on a DIFFERENT server.
// See docs/PROTOCOL.md's federation section for the full wire format and
// design rationale.
package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// handleReceiveFederatedMessage accepts an encrypted message envelope from
// a sender on ANY server, not just this one. Unlike handleSendMessage
// (which trusts a Signature-Key-Id that internal/auth.Middleware already
// resolved to a locally registered device), this handler has no local row
// to look the sender up in -- it verifies the sender's whole
// self-certifying identity chain inline, from material carried in the
// request itself: account_id == hash(root_pubkey) (pkg/address), the
// device certificate's signature under that root key (pkg/devicecert --
// the same check handleAddDevice does once, at registration time, for a
// local device), and the request signature itself against that certified
// device key. Registered as a public route (see router.go) precisely
// because it performs its own, different authentication rather than
// internal/auth.Middleware's local-device-lookup.
func (a *API) handleReceiveFederatedMessage(w http.ResponseWriter, r *http.Request) {
	// DB-authoritative (admin-settable at runtime via PUT /v1/admin/federation);
	// a.Config.FederationEnabled is only the first-boot seed (see store.InitFederationEnabled).
	enabled, err := store.GetFederationEnabled(a.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if !enabled {
		writeError(w, http.StatusNotFound, "not_found", "federation is disabled on this server")
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req federationMessageRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if req.SenderAccountID == "" || req.SenderRootPubKey == "" || req.SenderDeviceCert.DeviceID == "" ||
		req.RecipientDeviceID == "" || req.MessageID == "" || len(req.Payload) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"sender_account_id, sender_root_pub_key, sender_device_cert, recipient_device_id, message_id, and payload are required")
		return
	}

	senderRootPub, err := decodeBase64Key(req.SenderRootPubKey, ed25519.PublicKeySize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid sender_root_pub_key: "+err.Error())
		return
	}
	if valid, err := address.Verify(req.SenderAccountID, senderRootPub); err != nil || !valid {
		writeError(w, http.StatusBadRequest, "invalid_request", "sender_account_id does not match sender_root_pub_key")
		return
	}

	senderDevicePub, err := decodeBase64Key(req.SenderDeviceCert.DevicePubKey, ed25519.PublicKeySize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid sender_device_cert.device_pub_key: "+err.Error())
		return
	}
	certIssuedAt, err := time.Parse(time.RFC3339, req.SenderDeviceCert.IssuedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid sender_device_cert.issued_at")
		return
	}
	certSig, err := decodeBase64Key(req.SenderDeviceCert.Signature, ed25519.SignatureSize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid sender_device_cert.signature")
		return
	}
	cert := &devicecert.DeviceCertificate{
		AccountID:    req.SenderAccountID,
		DeviceID:     req.SenderDeviceCert.DeviceID,
		DevicePubKey: senderDevicePub,
		IssuedAt:     certIssuedAt,
		Signature:    certSig,
	}
	if err := cert.Verify(senderRootPub); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_certificate", "sender device certificate signature is invalid")
		return
	}

	blocked, err := store.IsFederationBlocked(a.DB, req.SenderAccountID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if blocked {
		writeError(w, http.StatusForbidden, "forbidden", "sender is blocked on this server")
		return
	}

	headers, err := httpsig.ParseRequestHeaders(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return
	}
	// Binds the two independently-supplied facts together: the signature
	// proves possession of the key named in Signature-Key-Id, and the
	// certificate proves that same key is certified under the claimed
	// account -- so Signature-Key-Id must literally be that key, the same
	// self-describing-key convention freizone-gateway already uses.
	if headers.KeyID != base64.StdEncoding.EncodeToString(senderDevicePub) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return
	}
	ts, err := httpsig.ParseTimestamp(headers.Timestamp)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return
	}
	now := a.Now()
	if !httpsig.WithinSkew(ts, now, auth.MaxClockSkew) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return
	}
	canonical := httpsig.CanonicalStringFromRequest(r, headers, body)
	if err := httpsig.Verify(canonical, headers.Signature, senderDevicePub); err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return
	}
	// expires_at = ts + MaxClockSkew, same reasoning as internal/auth's own
	// nonce bookkeeping: once real time has moved this far past ts, a
	// replay of this exact timestamp is already rejected by the skew check
	// above, making the record safe to purge.
	nonceOK, err := store.RecordNonce(a.DB, headers.KeyID, headers.Nonce, ts, ts.Add(auth.MaxClockSkew))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if !nonceOK {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return
	}

	recipientDevice, err := store.GetDevice(a.DB, req.RecipientDeviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown recipient device")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if recipientDevice.Status != store.DeviceStatusActive {
		writeError(w, http.StatusNotFound, "not_found", "recipient device is not active")
		return
	}
	if req.RecipientAccountID != "" && req.RecipientAccountID != recipientDevice.AccountID {
		writeError(w, http.StatusBadRequest, "invalid_request", "recipient_account_id does not match recipient_device_id")
		return
	}
	// Stricter than handleSendMessage's same-server path, which checks
	// only the recipient device's status, not the account's -- worth
	// fixing there too eventually, but not carried forward into new code.
	recipientAccount, err := store.GetAccount(a.DB, recipientDevice.AccountID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if recipientAccount.Status != store.AccountStatusActive {
		writeError(w, http.StatusNotFound, "not_found", "recipient account is not active")
		return
	}
	if !a.checkQueueNotFull(w, req.RecipientDeviceID) {
		return
	}

	msg := store.Message{
		MessageID:          req.MessageID,
		SenderAccountID:    req.SenderAccountID,
		SenderDeviceID:     req.SenderDeviceCert.DeviceID,
		RecipientAccountID: recipientDevice.AccountID,
		RecipientDeviceID:  req.RecipientDeviceID,
		Payload:            string(req.Payload),
		SentAt:             now,
		ExpiresAt:          now.AddDate(0, 0, a.Config.MessageRetentionDays),
	}
	if err := store.CreateMessage(a.DB, msg); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "message_exists", "message_id already used")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	a.queueAndNotify(msg, recipientDevice)

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}
