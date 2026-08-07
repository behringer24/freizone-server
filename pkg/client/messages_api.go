package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// IncomingMessage is one envelope as the server hands it over, from the queue
// or from the stream. The payload is opaque here: only the crypto layer can
// open it.
type IncomingMessage struct {
	MessageID       string
	SenderAccountID string
	SenderDeviceID  string
	SentAt          time.Time
	Payload         json.RawMessage
}

type incomingMessageWire struct {
	MessageID       string          `json:"message_id"`
	SenderAccountID string          `json:"sender_account_id"`
	SenderDeviceID  string          `json:"sender_device_id"`
	SentAt          string          `json:"sent_at"`
	Payload         json.RawMessage `json:"payload"`
}

func (w incomingMessageWire) resolve() (IncomingMessage, error) {
	msg := IncomingMessage{
		MessageID:       w.MessageID,
		SenderAccountID: w.SenderAccountID,
		SenderDeviceID:  w.SenderDeviceID,
		Payload:         w.Payload,
	}
	if w.SentAt == "" {
		return msg, nil
	}
	// The server formats RFC3339; parse the wider Nano form, which accepts it
	// and anything more precise a future server might send.
	sentAt, err := time.Parse(time.RFC3339Nano, w.SentAt)
	if err != nil {
		return IncomingMessage{}, fmt.Errorf("client: parsing sent_at %q: %w", w.SentAt, err)
	}
	msg.SentAt = sentAt
	return msg, nil
}

// SendMessage delivers one encrypted envelope to a device on this account's own
// server.
//
// A 409 counts as delivered, not as a failure: the server de-duplicates by
// message id, so the second copy of a retry being refused is the retry working
// exactly as intended. Treating it as an error is how a client ends up either
// sending twice or reporting a delivered message as failed.
func (c *Client) SendMessage(ctx context.Context, recipientAccountID, recipientDeviceID, messageID string, payload json.RawMessage) error {
	err := c.do(ctx, request{
		method: http.MethodPost,
		path:   "/v1/messages",
		auth:   authDevice,
		body: map[string]any{
			"message_id":           messageID,
			"recipient_account_id": recipientAccountID,
			"recipient_device_id":  recipientDeviceID,
			"payload":              payload,
		},
	}, nil)

	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict {
		return nil
	}
	return err
}

// FetchMessages returns everything queued for this device.
//
// The queue is drained by acknowledging each envelope, never by reading it --
// see [Client.AckMessage]. That is what makes delivery at-least-once and why
// the same envelope legitimately arrives twice.
func (c *Client) FetchMessages(ctx context.Context) ([]IncomingMessage, error) {
	// A bare JSON array, not an object with a "messages" key.
	var wire []incomingMessageWire
	if err := c.do(ctx, request{
		method: http.MethodGet,
		path:   "/v1/messages",
		auth:   authDevice,
	}, &wire); err != nil {
		return nil, err
	}

	msgs := make([]IncomingMessage, 0, len(wire))
	for _, w := range wire {
		msg, err := w.resolve()
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
	}
	return msgs, nil
}

// AckMessage deletes one envelope from the server queue, which is the only
// thing that drains it.
//
// Best effort by design: a lost acknowledgement means redelivery, which the
// duplicate check upstream is there to absorb. A 404 is success -- something
// already deleted is deleted.
func (c *Client) AckMessage(ctx context.Context, messageID string) error {
	err := c.do(ctx, request{
		method: http.MethodDelete,
		path:   "/v1/messages/" + messageID,
		auth:   authDevice,
	}, nil)

	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
		return nil
	}
	return err
}
