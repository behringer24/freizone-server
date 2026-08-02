// Federation: accepting a message from a sender on a DIFFERENT server.
// See docs/PROTOCOL.md's federation section for the full wire format and
// design rationale.
package api

import (
	"encoding/json"
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

	outcome := a.enqueueMessage(enqueueRequest{
		MessageID:          req.MessageID,
		SenderAccountID:    sender.AccountID,
		SenderDeviceID:     sender.DeviceID,
		RecipientAccountID: req.RecipientAccountID,
		RecipientDeviceID:  req.RecipientDeviceID,
		Payload:            req.Payload,
	})
	if outcome != enqueueQueued {
		status, code, message := outcome.asError()
		writeError(w, status, code, message)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

// handleReceiveFederatedMessageBatch is the federated twin of
// handleSendMessageBatch: a group send from a member on another server, whose
// copies for every recipient on *this* server arrive together.
//
// The saving here is larger than the round trip. A federated sender proves its
// identity with an inline certificate chain, and batching verifies that chain
// once for the whole batch rather than once per recipient -- which is the
// expensive part of accepting a stranger's message.
func (a *API) handleReceiveFederatedMessageBatch(w http.ResponseWriter, r *http.Request) {
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

	var req federationMessageBatchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if req.SenderAccountID == "" || req.SenderRootPubKey == "" || req.SenderDeviceCert.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"sender_account_id, sender_root_pub_key, and sender_device_cert are required")
		return
	}
	if !a.checkBatchSize(w, len(req.Messages)) {
		return
	}

	sender, ok := a.verifyFederatedSender(w, r, federatedSenderClaim{
		AccountID:   req.SenderAccountID,
		RootPubKey:  req.SenderRootPubKey,
		DeviceCert:  req.SenderDeviceCert,
		BodyDigest:  "",
		RequestBody: body,
	})
	if !ok {
		return
	}

	results := make([]batchResultItem, 0, len(req.Messages))
	for _, item := range req.Messages {
		outcome := a.enqueueMessage(enqueueRequest{
			MessageID:          item.MessageID,
			SenderAccountID:    sender.AccountID,
			SenderDeviceID:     sender.DeviceID,
			RecipientAccountID: item.RecipientAccountID,
			RecipientDeviceID:  item.RecipientDeviceID,
			Payload:            item.Payload,
		})
		results = append(results, batchResultItem{MessageID: item.MessageID, Status: string(outcome)})
	}

	writeJSON(w, http.StatusOK, batchResponse{Results: results})
}
