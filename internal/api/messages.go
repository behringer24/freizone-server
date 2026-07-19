package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/store"
)

// sseHeartbeatInterval keeps SSE connections alive through idle proxies.
const sseHeartbeatInterval = 25 * time.Second

// handleSendMessage enqueues an opaque, end-to-end-encrypted message
// envelope for a recipient device. The server never inspects payload.
func (a *API) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	var req sendMessageRequest
	if !a.decodeJSONBody(w, r, &req) {
		return
	}
	if req.MessageID == "" || req.RecipientDeviceID == "" || len(req.Payload) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "message_id, recipient_device_id, and payload are required")
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
	if !a.checkQueueNotFull(w, req.RecipientDeviceID) {
		return
	}

	now := a.Now()
	msg := store.Message{
		MessageID:          req.MessageID,
		SenderAccountID:    identity.AccountID,
		SenderDeviceID:     identity.DeviceID,
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

// queueAndNotify publishes msg to any live SSE subscriber for
// recipientDevice, or -- if none is currently connected -- dispatches a
// push wake via whichever mechanism (Web Push, or FCM/APNs via a
// freizone-gateway) recipientDevice has registered. Shared by
// handleSendMessage and handleReceiveFederatedMessage: once a message is
// queued, delivery to the recipient is identical regardless of which
// server the sender came from.
func (a *API) queueAndNotify(msg store.Message, recipientDevice *store.Device) {
	a.broker.publish(msg.RecipientDeviceID, msg)

	if !a.broker.hasSubscribers(msg.RecipientDeviceID) {
		switch {
		case recipientDevice.Push != nil:
			go notifyPush(a.PushClient, a.Logger, a.VAPIDPublicKey, a.VAPIDPrivateKey, *recipientDevice.Push)
		case recipientDevice.PushTarget != nil && a.Config.PushGatewayURL != "":
			go notifyPushViaGateway(a.PushClient, a.Logger, a.Config.PushGatewayURL, a.RelayPubKey, a.RelayPrivKey, *recipientDevice.PushTarget)
		}
	}
}

// decodeJSONBody decodes r's body into v, writing the response and
// returning false on failure. A body rejected by withMaxBody's cap
// (internal/server/middleware.go) surfaces here as a *http.MaxBytesError
// from the underlying read -- json.Decoder passes it through
// unwrapped -- so it gets a clear 413 instead of the generic 400
// "malformed JSON" a real syntax error gets.
func (a *API) decodeJSONBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("request body exceeds the %d byte limit", maxBytesErr.Limit))
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return false
	}
	return true
}

// readBody reads the whole of r's body, writing the response and
// returning ok=false on failure -- same *http.MaxBytesError handling as
// decodeJSONBody, for a caller (handleReceiveFederatedMessage) that
// needs the raw bytes itself (for httpsig canonicalization) rather than
// decoding directly.
func readBody(w http.ResponseWriter, r *http.Request) (body []byte, ok bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("request body exceeds the %d byte limit", maxBytesErr.Limit))
			return nil, false
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "could not read request body")
		return nil, false
	}
	return body, true
}

// checkQueueNotFull rejects with 429 if recipientDeviceID already has
// Config.MaxQueuedMessagesPerDevice messages queued -- see
// store.CountPendingMessages -- so a sender (same-server or federated)
// can't grow one device's backlog without bound.
func (a *API) checkQueueNotFull(w http.ResponseWriter, recipientDeviceID string) bool {
	count, err := store.CountPendingMessages(a.DB, recipientDeviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return false
	}
	if count >= a.Config.MaxQueuedMessagesPerDevice {
		writeError(w, http.StatusTooManyRequests, "recipient_queue_full", "recipient device's message queue is full")
		return false
	}
	return true
}

// handleListMessages polls for messages queued for the caller's device.
func (a *API) handleListMessages(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	messages, err := store.ListPendingMessages(a.DB, identity.DeviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	resp := make([]messageResponse, 0, len(messages))
	for _, m := range messages {
		resp = append(resp, messageResponseFrom(m))
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleDeleteMessage acknowledges a message, removing it from the queue.
func (a *API) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	messageID := r.PathValue("message_id")
	if err := store.DeleteMessage(a.DB, messageID, identity.DeviceID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown message")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleMessageStream serves an SSE stream: first flushing any currently
// pending messages, then pushing new ones live as they arrive, for as long
// as the client stays connected. This is the "active app" live-update
// path; GET /v1/messages remains available as a plain poll.
func (a *API) handleMessageStream(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "streaming is not supported")
		return
	}

	pending, err := store.ListPendingMessages(a.DB, identity.DeviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	for _, m := range pending {
		if !writeSSEMessage(w, m) {
			return
		}
	}
	flusher.Flush()

	ch, unsubscribe := a.broker.subscribe(identity.DeviceID)
	defer unsubscribe()

	ticker := time.NewTicker(sseHeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			if !writeSSEMessage(w, msg) {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			if _, err := w.Write([]byte(": heartbeat\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeSSEMessage(w http.ResponseWriter, m store.Message) bool {
	data, err := json.Marshal(messageResponseFrom(m))
	if err != nil {
		return false
	}
	if _, err := fmt.Fprintf(w, "event: message\ndata: %s\n\n", data); err != nil {
		return false
	}
	return true
}
