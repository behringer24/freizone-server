// Package wire defines the client-side JSON shape of a chat message
// envelope: what a Freizone client puts in a message's opaque "payload"
// field (see docs/PROTOCOL.md). The server never parses this -- it's a
// contract between clients only, built on top of pkg/ratchet.
package wire

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/behringer24/freizone-server/pkg/ratchet"
)

// Envelope is the full contents of a message's opaque payload. Prekey is
// present only on the first message of a new session.
type Envelope struct {
	Prekey     *PrekeyFields `json:"prekey,omitempty"`
	Header     HeaderDTO     `json:"header"`
	Ciphertext string        `json:"ciphertext"`
}

// PrekeyFields carries the X3DH material a responder needs to derive the
// same shared secret as the initiator, present only on a session's first
// message.
type PrekeyFields struct {
	SenderDHIdentityPub string  `json:"sender_dh_identity_pub"`
	SenderEphemeralPub  string  `json:"sender_ephemeral_pub"`
	SignedPrekeyID      uint32  `json:"signed_prekey_id"`
	OneTimePrekeyID     *uint32 `json:"one_time_prekey_id,omitempty"`

	// Rekey says why this block is here (SRV-17), because a prekey block
	// arriving over a session the receiver already holds is otherwise
	// ambiguous, and the two readings need opposite handling:
	//
	//   true  -- the sender deliberately discarded their session and
	//            re-established (SRV-03). Theirs is the only session they can
	//            read, so the receiver adopts it whatever any tie-break says.
	//   false -- an ordinary establishment. If the receiver already holds a
	//            session, the two established at the same moment (routine in a
	//            group, docs/PROTOCOL.md §5) and the lower-account-id tie-break
	//            decides which one both sides will send on.
	//   absent -- a sender that predates this field. The receiver falls back to
	//            inferring it from the decrypted content, exactly as before: a
	//            `v: 3` re-key envelope means the deliberate case.
	//
	// Deliberately a tri-state rather than a plain bool: `false` and "said
	// nothing" are different facts, and only telling them apart lets the
	// content-sniffing fallback ever be removed. A sender that sets this
	// truthfully is never guessed about.
	//
	// Not covered by any signature -- there is none over the prekey block, here
	// or before this field. A tampered value can make a receiver mis-handle one
	// establishment (adopt a session it would have kept, or the reverse), which
	// is a nuisance the ratchet recovers from, not a break: every message still
	// has to decrypt, and only the sender's own keys can make that happen.
	Rekey *bool `json:"rekey,omitempty"`
}

// HeaderDTO is the base64-friendly wire form of ratchet.Header.
type HeaderDTO struct {
	DHPub string `json:"dh_pub"`
	PN    uint32 `json:"pn"`
	N     uint32 `json:"n"`
}

// HeaderToDTO converts a ratchet.Header to its wire form.
func HeaderToDTO(h ratchet.Header) HeaderDTO {
	return HeaderDTO{DHPub: base64.StdEncoding.EncodeToString(h.DHPub), PN: h.PN, N: h.N}
}

// ToHeader converts a wire header back to a ratchet.Header.
func (d HeaderDTO) ToHeader() (ratchet.Header, error) {
	dhPub, err := base64.StdEncoding.DecodeString(d.DHPub)
	if err != nil {
		return ratchet.Header{}, fmt.Errorf("wire: decoding header dh_pub: %w", err)
	}
	return ratchet.Header{DHPub: dhPub, PN: d.PN, N: d.N}, nil
}

// InitialMessageToPrekeyFields converts a ratchet.InitialMessage to its
// wire form.
func InitialMessageToPrekeyFields(im *ratchet.InitialMessage) PrekeyFields {
	return PrekeyFields{
		SenderDHIdentityPub: base64.StdEncoding.EncodeToString(im.SenderDHIdentityPub),
		SenderEphemeralPub:  base64.StdEncoding.EncodeToString(im.SenderEphemeralPub),
		SignedPrekeyID:      im.SignedPrekeyID,
		OneTimePrekeyID:     im.OneTimePrekeyID,
	}
}

// ToInitialMessage converts wire prekey fields back to a
// ratchet.InitialMessage.
func (p PrekeyFields) ToInitialMessage() (*ratchet.InitialMessage, error) {
	senderDH, err := base64.StdEncoding.DecodeString(p.SenderDHIdentityPub)
	if err != nil {
		return nil, fmt.Errorf("wire: decoding sender_dh_identity_pub: %w", err)
	}
	senderEph, err := base64.StdEncoding.DecodeString(p.SenderEphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("wire: decoding sender_ephemeral_pub: %w", err)
	}
	return &ratchet.InitialMessage{
		SenderDHIdentityPub: senderDH,
		SenderEphemeralPub:  senderEph,
		SignedPrekeyID:      p.SignedPrekeyID,
		OneTimePrekeyID:     p.OneTimePrekeyID,
	}, nil
}

// NewEnvelope builds an Envelope for a header+ciphertext pair, optionally
// with X3DH initial-message fields for a session's first message (pass nil
// for every later message on an already-established session).
//
// Leaves [PrekeyFields.Rekey] absent, which reads as "this sender says
// nothing" -- correct for a caller that does not track the difference. A
// caller that does should use [NewEnvelopeRekey] and always state it, so the
// receiver never has to guess.
func NewEnvelope(initial *ratchet.InitialMessage, header ratchet.Header, ciphertext []byte) Envelope {
	return NewEnvelopeRekey(initial, header, ciphertext, nil)
}

// NewEnvelopeRekey is [NewEnvelope] with an explicit [PrekeyFields.Rekey]:
// point at true for a deliberate re-key (SRV-03), at false for an ordinary
// establishment, or pass nil to say nothing at all. Ignored when initial is
// nil, since there is no prekey block to carry it.
func NewEnvelopeRekey(initial *ratchet.InitialMessage, header ratchet.Header, ciphertext []byte, rekey *bool) Envelope {
	env := Envelope{
		Header:     HeaderToDTO(header),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	if initial != nil {
		fields := InitialMessageToPrekeyFields(initial)
		fields.Rekey = rekey
		env.Prekey = &fields
	}
	return env
}

// DecodeCiphertext decodes the envelope's base64 ciphertext.
func (e Envelope) DecodeCiphertext() ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(e.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("wire: decoding ciphertext: %w", err)
	}
	return ct, nil
}

// MarshalPayload serializes the envelope for use as a message's payload.
func (e Envelope) MarshalPayload() (json.RawMessage, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("wire: marshaling envelope: %w", err)
	}
	return json.RawMessage(data), nil
}

// ParseEnvelope decodes a message's opaque payload into an Envelope.
func ParseEnvelope(payload json.RawMessage) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return Envelope{}, fmt.Errorf("wire: parsing envelope: %w", err)
	}
	return env, nil
}
