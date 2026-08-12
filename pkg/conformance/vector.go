// Package conformance holds shared receive-path test vectors for Freizone
// clients (SRV-23, see docs/design/23-shared-client-core.md).
//
// The protocol is currently implemented twice -- cmd/devclient here, and
// freizone-app's Dart state layer -- on top of the same pkg/ratchet and
// pkg/wire. The cryptography therefore cannot diverge; the *decisions* around
// it can, and they are what a vector pins: what a receiver does with an
// envelope it cannot decrypt, with a redelivered X3DH initial, with a prekey
// block that arrives while a session already exists.
//
// Expectations here are authored from docs/PROTOCOL.md, deliberately NOT
// recorded from either implementation. Recording would enshrine whichever
// behaviour is wrong; authoring means a vector can fail on both sides at once
// and still be right. A failing vector is therefore a claim about the
// implementation, not about the vector.
package conformance

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/behringer24/freizone-server/pkg/ratchet"
)

// Outcome is what processing one envelope produced for the receiver.
type Outcome string

const (
	// OutcomeDecrypted: plaintext was recovered and is new.
	OutcomeDecrypted Outcome = "decrypted"
	// OutcomeDuplicate: this exact envelope was already processed. Nothing is
	// wrong -- delivery is at-least-once -- so it must neither be retried nor
	// counted as evidence of a desync, and the ratchet must not advance again.
	OutcomeDuplicate Outcome = "duplicate"
	// OutcomeUndecryptable: no session could read it. Whether that is evidence
	// of a desync is a separate question, see Expect.CountsAsDesyncEvidence.
	OutcomeUndecryptable Outcome = "undecryptable"
)

// SessionEffect is what processing did to the session the receiver SENDS on --
// specifically whether it was *replaced* by one derived from the peer's prekey
// block, not whether its bytes changed (an ordinary decrypt advances the
// ratchet and changes them every time).
//
// Observable as the session's X3DH role: a receiver holding its own initiator
// session that adopts the peer's ends up with a responder session, and
// decrypting never changes a role. The limit of that: when both the old and the
// new session are responder sessions -- a redelivered initial rebuilt on top of
// an established one -- the role is identical either way and cannot give the
// replacement away. Vectors covering that case assert it functionally instead,
// with a later message that only still decrypts if nothing was reset.
type SessionEffect string

const (
	// SessionEstablished: there was no session and one was created.
	SessionEstablished SessionEffect = "established"
	// SessionAdoptedPeer: an existing session was replaced by one built from
	// the peer's prekey block -- either a deliberate re-key (SRV-17) or the
	// losing half of a simultaneous establishment.
	SessionAdoptedPeer SessionEffect = "adopted_peer"
	// SessionUnchanged: the session the receiver sends on was left alone. The
	// interesting case: a redelivered or stale prekey block must land here, not
	// on SessionAdoptedPeer.
	SessionUnchanged SessionEffect = "unchanged"
)

// Vector is one receive-path case: a receiver's starting state and an ordered
// list of envelopes with the decision expected for each. Steps share state --
// step 2 sees what step 1 did -- which is the only way to express redelivery
// and duplicate handling at all.
type Vector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Reference points at the rule being tested (a PROTOCOL.md section, a
	// roadmap code), so a failure can be argued from the spec.
	Reference string   `json:"reference,omitempty"`
	Receiver  Receiver `json:"receiver"`
	Steps     []Step   `json:"steps"`
}

// Receiver is the state an implementation must be primed with before step 1.
// Deliberately protocol-level rather than shaped after either client's own
// store, so both can map onto it.
type Receiver struct {
	AccountID        string            `json:"account_id"`
	DHIdentityPriv   []byte            `json:"dh_identity_priv"`
	SignedPrekeyPriv []byte            `json:"signed_prekey_priv"`
	OneTimePrekeys   map[uint32][]byte `json:"one_time_prekeys,omitempty"`

	// Sessions and InboundSessions are keyed by peer account id and hold
	// marshalled ratchet.Session blobs. InboundSessions are read-only ones,
	// kept for messages still in flight on a session we lost a tie-break for.
	Sessions        map[string]json.RawMessage `json:"sessions,omitempty"`
	InboundSessions map[string]json.RawMessage `json:"inbound_sessions,omitempty"`

	// ProcessedMessageIDs are ids already handled. An implementation without
	// this concept cannot pass the redelivery vectors, which is the point.
	ProcessedMessageIDs []string `json:"processed_message_ids,omitempty"`
}

// Step is one envelope handed to the receiver, plus what must come of it.
type Step struct {
	Label           string          `json:"label"`
	MessageID       string          `json:"message_id"`
	SenderAccountID string          `json:"sender_account_id"`
	Payload         json.RawMessage `json:"payload"`
	Expect          Expect          `json:"expect"`
}

// Expect is the observable decision surface. Pointer fields are assertions
// only when set, so a vector can pin one effect without claiming anything
// about the others.
type Expect struct {
	Outcome Outcome `json:"outcome"`

	// Text is the decoded v1 message text, asserted when Outcome is
	// OutcomeDecrypted.
	Text string `json:"text,omitempty"`

	// FailureCode is ratchet.FailureCode's classification of the failure. An
	// implementation that wraps the ratchet error and loses the code cannot
	// satisfy this, which is itself worth failing on: the code is what tells a
	// duplicate apart from a real desync.
	FailureCode string `json:"failure_code,omitempty"`

	// CountsAsDesyncEvidence: whether this step should push the receiver
	// toward an automatic re-key (SRV-03). A duplicate must not.
	CountsAsDesyncEvidence *bool `json:"counts_as_desync_evidence,omitempty"`

	// SessionEffect on the session used for sending.
	SessionEffect SessionEffect `json:"session_effect,omitempty"`

	// InboundSessionKept: whether a read-only session was retained for this
	// peer after the step.
	InboundSessionKept *bool `json:"inbound_session_kept,omitempty"`

	// OneTimePrekeysRemaining pins the pool size. A responder attempt that
	// fails must not burn a prekey, or a redelivered initial drains the pool.
	OneTimePrekeysRemaining *int `json:"one_time_prekeys_remaining,omitempty"`
}

// DHIdentityKey returns the receiver's X25519 identity private key.
func (r Receiver) DHIdentityKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(r.DHIdentityPriv)
}

// SignedPrekey returns the receiver's signed prekey private key.
func (r Receiver) SignedPrekey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(r.SignedPrekeyPriv)
}

// OneTimePrekey returns the private key for id, or nil if the pool has no
// such entry -- an initial referencing a prekey we never held, or already
// consumed, is a normal case and not an error.
func (r Receiver) OneTimePrekey(id uint32) (*ecdh.PrivateKey, error) {
	raw, ok := r.OneTimePrekeys[id]
	if !ok {
		return nil, nil
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// Session unmarshals the stored session for peer, or nil if there is none.
func (r Receiver) Session(peer string) (*ratchet.Session, error) {
	return unmarshalSession(r.Sessions[peer])
}

// InboundSession unmarshals the stored read-only session for peer, or nil.
func (r Receiver) InboundSession(peer string) (*ratchet.Session, error) {
	return unmarshalSession(r.InboundSessions[peer])
}

func unmarshalSession(raw json.RawMessage) (*ratchet.Session, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var s ratchet.Session
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("conformance: unmarshalling session: %w", err)
	}
	return &s, nil
}

// Load reads every *.json vector from dir, sorted by filename so a failing
// run is reproducible.
func Load(dir string) ([]Vector, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)

	vectors := make([]Vector, 0, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var v Vector
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields() // a typo in a vector must fail loudly
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("conformance: %s: %w", filepath.Base(p), err)
		}
		if err := v.validate(); err != nil {
			return nil, fmt.Errorf("conformance: %s: %w", filepath.Base(p), err)
		}
		vectors = append(vectors, v)
	}
	if len(vectors) == 0 {
		return nil, fmt.Errorf("conformance: no vectors found in %s", dir)
	}
	return vectors, nil
}

func (v Vector) validate() error {
	if v.Name == "" {
		return fmt.Errorf("vector has no name")
	}
	if len(v.Steps) == 0 {
		return fmt.Errorf("%s: no steps", v.Name)
	}
	if len(v.Receiver.DHIdentityPriv) == 0 || len(v.Receiver.SignedPrekeyPriv) == 0 {
		return fmt.Errorf("%s: receiver is missing X3DH key material", v.Name)
	}
	for i, s := range v.Steps {
		switch s.Expect.Outcome {
		case OutcomeDecrypted, OutcomeDuplicate, OutcomeUndecryptable:
		default:
			return fmt.Errorf("%s: step %d (%s): unknown outcome %q", v.Name, i+1, s.Label, s.Expect.Outcome)
		}
		if len(s.Payload) == 0 {
			return fmt.Errorf("%s: step %d (%s): empty payload", v.Name, i+1, s.Label)
		}
		if s.MessageID == "" {
			return fmt.Errorf("%s: step %d (%s): no message id", v.Name, i+1, s.Label)
		}
	}
	return nil
}
