package api

import (
	"bytes"
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

	outcome := a.enqueueMessage(enqueueRequest{
		MessageID:          req.MessageID,
		SenderAccountID:    identity.AccountID,
		SenderDeviceID:     identity.DeviceID,
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

// handleSendMessageBatch enqueues several messages in one request (SRV-01).
//
// Group fan-out is N separately encrypted copies from one author, and without
// this each copy costs its own round trip -- so a batch collapses a group send
// to one request per distinct recipient *server* rather than one per recipient
// device. Nothing about authentication changes: every item is from the one
// signing device, and the signature covers the whole body as always.
func (a *API) handleSendMessageBatch(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	var req sendMessageBatchRequest
	if !a.decodeJSONBody(w, r, &req) {
		return
	}
	if !a.checkBatchSize(w, len(req.Messages)) {
		return
	}

	results := make([]batchResultItem, 0, len(req.Messages))
	for _, item := range req.Messages {
		outcome := a.enqueueMessage(enqueueRequest{
			MessageID:          item.MessageID,
			SenderAccountID:    identity.AccountID,
			SenderDeviceID:     identity.DeviceID,
			RecipientAccountID: item.RecipientAccountID,
			RecipientDeviceID:  item.RecipientDeviceID,
			Payload:            item.Payload,
		})
		results = append(results, batchResultItem{MessageID: item.MessageID, Status: string(outcome)})
	}

	writeJSON(w, http.StatusOK, batchResponse{Results: results})
}

// enqueueRequest is one message to queue, from either the same-server or the
// federated path -- by the time we get here the sender has been authenticated
// and only differs in how.
type enqueueRequest struct {
	MessageID          string
	SenderAccountID    string
	SenderDeviceID     string
	RecipientAccountID string
	RecipientDeviceID  string
	Payload            json.RawMessage
}

// enqueueOutcome is one recipient's result. It is deliberately a value rather
// than an HTTP response: a batch reports one of these per item, and only the
// single-message endpoints turn it into a status code (see asError).
type enqueueOutcome string

const (
	enqueueQueued           enqueueOutcome = "queued"
	enqueueInvalid          enqueueOutcome = "invalid"
	enqueueUnknownRecipient enqueueOutcome = "unknown_recipient"
	enqueueDuplicate        enqueueOutcome = "duplicate"
	enqueueQueueFull        enqueueOutcome = "queue_full"
	enqueueInternalError    enqueueOutcome = "internal_error"
)

// asError maps an outcome onto the single-message endpoints' existing
// response contract, unchanged from before batching existed.
func (o enqueueOutcome) asError() (status int, code, message string) {
	switch o {
	case enqueueInvalid:
		return http.StatusBadRequest, "invalid_request",
			"message_id, recipient_device_id, and payload are required, and recipient_account_id must match recipient_device_id"
	case enqueueUnknownRecipient:
		// Same word the batch endpoints use as the per-item status, so a
		// sender can key one stale-device reaction off both shapes (see
		// docs/PROTOCOL.md §4's stale-device rule).
		return http.StatusNotFound, "unknown_recipient", "unknown or inactive recipient"
	case enqueueDuplicate:
		return http.StatusConflict, "message_exists", "message_id already used"
	case enqueueQueueFull:
		return http.StatusTooManyRequests, "recipient_queue_full", "recipient device's message queue is full"
	default:
		return http.StatusInternalServerError, "internal", "internal server error"
	}
}

// enqueueMessage validates one recipient, queues the message, and fires the
// delivery notification -- the whole per-recipient path, shared by the
// same-server and federated endpoints and by their batch forms.
//
// Every failure is a value, not a write to the response: a batch must be able
// to record one recipient's queue being full and carry on with the rest, since
// in a group that recipient's problem is not the other members' problem.
func (a *API) enqueueMessage(req enqueueRequest) enqueueOutcome {
	// A literal `null` payload passes a length check but is not an envelope,
	// and queueing it would hand the recipient something no client can decode.
	// The server still never looks *inside* a payload -- this only rejects the
	// absence of one dressed up as a value.
	if req.MessageID == "" || req.RecipientDeviceID == "" ||
		len(req.Payload) == 0 || bytes.Equal(bytes.TrimSpace(req.Payload), []byte("null")) {
		return enqueueInvalid
	}

	recipientDevice, err := store.GetDevice(a.DB, req.RecipientDeviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return enqueueUnknownRecipient
		}
		return enqueueInternalError
	}
	if recipientDevice.Status != store.DeviceStatusActive {
		return enqueueUnknownRecipient
	}
	if req.RecipientAccountID != "" && req.RecipientAccountID != recipientDevice.AccountID {
		return enqueueInvalid
	}

	// The recipient's *account* must be active too, not just the device. The
	// federated path always checked this and the same-server path never did;
	// unifying them here settles that difference in favour of the stricter
	// reading -- a blocked account should not keep accumulating queued
	// messages from anywhere.
	recipientAccount, err := store.GetAccount(a.DB, recipientDevice.AccountID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return enqueueUnknownRecipient
		}
		return enqueueInternalError
	}
	if recipientAccount.Status != store.AccountStatusActive {
		return enqueueUnknownRecipient
	}

	count, err := store.CountPendingMessages(a.DB, req.RecipientDeviceID)
	if err != nil {
		return enqueueInternalError
	}
	if count >= a.Config.MaxQueuedMessagesPerDevice {
		return enqueueQueueFull
	}

	now := a.Now()
	msg := store.Message{
		MessageID:          req.MessageID,
		SenderAccountID:    req.SenderAccountID,
		SenderDeviceID:     req.SenderDeviceID,
		RecipientAccountID: recipientDevice.AccountID,
		RecipientDeviceID:  req.RecipientDeviceID,
		Payload:            string(req.Payload),
		SentAt:             now,
		ExpiresAt:          now.AddDate(0, 0, a.Config.MessageRetentionDays),
	}
	if err := store.CreateMessage(a.DB, msg); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return enqueueDuplicate
		}
		return enqueueInternalError
	}

	a.queueAndNotify(msg, recipientDevice)
	return enqueueQueued
}

// checkBatchSize rejects an empty or oversized batch. The cap is a bound on
// how many queue writes one request can trigger; MaxRequestBodyBytes already
// bounds the bytes. It is advertised on GET /v1/server-status so a sender
// splits to fit rather than learning the limit from a rejection.
func (a *API) checkBatchSize(w http.ResponseWriter, count int) bool {
	if count == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "messages must not be empty")
		return false
	}
	if count > a.Config.MaxBatchMessages {
		writeError(w, http.StatusBadRequest, "batch_too_large",
			fmt.Sprintf("a batch may carry at most %d messages", a.Config.MaxBatchMessages))
		return false
	}
	return true
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
		a.wakeDevice(recipientDevice)
	}
}

// wakeDevice dispatches a content-free push wake via whichever mechanism
// (Web Push, or FCM/APNs via a freizone-gateway) device has registered --
// a no-op if it has registered neither. Shared by queueAndNotify (a new
// message arrived) and handleClaimPrekeyBundle (the device's one-time-
// prekey pool just ran low) -- both are just "go sync" nudges,
// indistinguishable on the wire (see docs/PROTOCOL.md's push-wake
// section), so one wake mechanism serves every reason to wake a device.
func (a *API) wakeDevice(device *store.Device) {
	switch {
	case device.Push != nil:
		go a.notifyPush(device.DeviceID, *device.Push)
	case device.PushTarget != nil && a.Config.PushGatewayURL != "":
		go a.notifyPushViaGateway(device.DeviceID, *device.PushTarget)
	case device.PushTarget != nil:
		// The device asked to be woken through a gateway, but this server
		// has none configured (FREIZONE_PUSH_GATEWAY_URL), so the wake is
		// dropped. Warn rather than stay silent: from the outside this is
		// indistinguishable from push being broken -- the device simply
		// never hears about new messages until it reconnects -- and the
		// cause is a deployment gap only the operator can close.
		if a.Logger != nil {
			a.Logger.Warn("push: device has a push target but no push gateway is configured; wake dropped",
				"device_id", device.DeviceID, "platform", device.PushTarget.Platform)
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
