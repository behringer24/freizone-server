package main

import (
	"encoding/json"
	"time"
)

// The devclient speaks the exact plaintext envelope the Flutter app uses, so
// text messages and receipts interoperate byte-for-byte. Mirrors
// freizone-app/lib/state/message_content.dart (v1 text) and
// receipt_signal.dart (v2 receipt). The server never sees any of this -- it
// is the decrypted payload inside the wire.Envelope ciphertext.

const (
	textEnvelopeVersion = 1
	receiptVersion      = 2

	// receiptTimeLayout matches Dart's DateTime.toIso8601String() for a UTC
	// instant: millisecond precision, trailing "Z". The app parses tolerantly,
	// so exact matching isn't strictly required, but emitting the same shape
	// keeps the wire clean and comparisons unambiguous.
	receiptTimeLayout = "2006-01-02T15:04:05.000Z"
)

// messageContent is the v1 text envelope. Only the fields the devclient
// produces or reads are modelled; unknown fields the app might add are simply
// ignored on decode.
type messageContent struct {
	V            int    `json:"v"`
	ID           string `json:"id"`
	Text         string `json:"text"`
	Attachments  []any  `json:"attachments"`
	ReplyTo      string `json:"reply_to,omitempty"`
	SenderServer string `json:"sender_server,omitempty"`
	SentAt       string `json:"sent_at,omitempty"`
}

// receiptSignal is the v2 receipt envelope. up_to_sent_at is a cumulative
// high-water mark echoing the original message's sent_at back to its sender.
type receiptSignal struct {
	V          int    `json:"v"`
	Kind       string `json:"kind"`
	Status     string `json:"status"` // "delivered" | "read"
	UpToSentAt string `json:"up_to_sent_at"`
}

// encodeText wraps text in a fresh v1 envelope. Returns the plaintext bytes to
// encrypt and the sent_at string stamped into it (the sender's own clock),
// which the caller records for roundtrip timing.
func encodeText(text string) (plaintext []byte, sentAt string, err error) {
	id, err := randomMessageID()
	if err != nil {
		return nil, "", err
	}
	sentAt = time.Now().UTC().Format(receiptTimeLayout)
	b, err := json.Marshal(messageContent{
		V:           textEnvelopeVersion,
		ID:          id,
		Text:        text,
		Attachments: []any{}, // always [] like the app, never null
		SentAt:      sentAt,
	})
	return b, sentAt, err
}

// encodeReceipt builds a v2 receipt for the given status echoing upToSentAt.
func encodeReceipt(status, upToSentAt string) ([]byte, error) {
	return json.Marshal(receiptSignal{
		V:          receiptVersion,
		Kind:       "receipt",
		Status:     status,
		UpToSentAt: upToSentAt,
	})
}

type decodedKind int

const (
	decodedText decodedKind = iota
	decodedReceipt
)

// decodedPlaintext is the result of interpreting a decrypted payload.
type decodedPlaintext struct {
	kind decodedKind

	// text fields (decodedText)
	text   string
	sentAt string // raw sent_at string from the envelope; "" if absent/legacy

	// receipt fields (decodedReceipt)
	status     string
	upToSentAt string

	raw []byte // original bytes, for display
}

// decodePlaintext interprets a decrypted payload as a receipt (v2), a text
// envelope (v1), or -- as a fallback -- legacy raw text (what older devclients
// sent before adopting the app envelope). Trying the receipt shape FIRST is
// the loop-prevention rule the app uses: a receipt must never be answered with
// another receipt.
func decodePlaintext(b []byte) decodedPlaintext {
	var probe struct {
		V    int    `json:"v"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(b, &probe); err == nil && probe.V != 0 {
		switch {
		case probe.V == receiptVersion && probe.Kind == "receipt":
			var r receiptSignal
			if json.Unmarshal(b, &r) == nil && r.Status != "" && r.UpToSentAt != "" {
				return decodedPlaintext{kind: decodedReceipt, status: r.Status, upToSentAt: r.UpToSentAt, raw: b}
			}
		case probe.V == textEnvelopeVersion:
			var mc messageContent
			if json.Unmarshal(b, &mc) == nil {
				return decodedPlaintext{kind: decodedText, text: mc.Text, sentAt: mc.SentAt, raw: b}
			}
		}
	}
	// Legacy / unknown: treat the whole payload as raw text.
	return decodedPlaintext{kind: decodedText, text: string(b), raw: b}
}
