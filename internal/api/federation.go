// Federation: accepting a message from a sender on a DIFFERENT server.
// See docs/PROTOCOL.md's federation section for the full wire format and
// design rationale.
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/behringer24/freizone-server/internal/store"
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

	sender, ok := a.verifyFederatedSender(w, r, federatedSenderClaim{
		AccountID:   req.SenderAccountID,
		RootPubKey:  req.SenderRootPubKey,
		DeviceCert:  req.SenderDeviceCert,
		BodyDigest:  "", // JSON body: digest is computed from the bytes below
		RequestBody: body,
	})
	if !ok {
		return
	}
	now := a.Now()

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
		SenderAccountID:    sender.AccountID,
		SenderDeviceID:     sender.DeviceID,
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
