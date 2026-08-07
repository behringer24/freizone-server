package conformance

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/behringer24/freizone-server/pkg/ratchet"
	"github.com/behringer24/freizone-server/pkg/wire"
)

// Account ids are fixed literals, not derived from the generated keys, because
// the tie-break for a simultaneous establishment (docs/PROTOCOL.md §5) is a
// plain string comparison on account id: the lower one's session wins.
// Deriving them would make regeneration flip which side wins and silently
// invert half the vectors. They are deliberately synthetic and obviously
// ordered -- nothing in the receive path parses an account id, it is only a map
// key and a comparison operand.
const (
	receiverAccount = "fz1mmmm00000000000000000000000000receiver"
	peerLower       = "fz1aaaa000000000000000000000000000000peer"
	peerHigher      = "fz1zzzz000000000000000000000000000000peer"
)

// Plaintext envelope versions, mirroring cmd/devclient/message.go and
// freizone-app's message_content.dart / rekey_signal.dart.
const (
	textVersion  = 1
	rekeyVersion = 3
)

// party is one side's full key material during generation.
type party struct {
	accountID string
	dhPriv    *ecdh.PrivateKey
	spkPriv   *ecdh.PrivateKey
	spkID     uint32
	otpks     map[uint32]*ecdh.PrivateKey
}

func newParty(accountID string, otpkIDs ...uint32) (*party, error) {
	curve := ecdh.X25519()
	dhPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	spkPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	p := &party{
		accountID: accountID,
		dhPriv:    dhPriv,
		spkPriv:   spkPriv,
		spkID:     1,
		otpks:     make(map[uint32]*ecdh.PrivateKey, len(otpkIDs)),
	}
	for _, id := range otpkIDs {
		k, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		p.otpks[id] = k
	}
	return p, nil
}

// bundle is what an initiator would have fetched for this party. Pass otpkID
// nil to model an exhausted one-time-prekey pool.
func (p *party) bundle(otpkID *uint32) ratchet.RemoteBundle {
	b := ratchet.RemoteBundle{
		DHIdentityPubKey: p.dhPriv.PublicKey(),
		SignedPrekeyID:   p.spkID,
		SignedPrekeyPub:  p.spkPriv.PublicKey(),
	}
	if otpkID != nil {
		if k, ok := p.otpks[*otpkID]; ok {
			b.OneTimePrekeyID = otpkID
			b.OneTimePrekeyPub = k.PublicKey()
		}
	}
	return b
}

// receiver renders this party as the vector's starting receiver state.
func (p *party) receiver() Receiver {
	r := Receiver{
		AccountID:        p.accountID,
		DHIdentityPriv:   p.dhPriv.Bytes(),
		SignedPrekeyPriv: p.spkPriv.Bytes(),
	}
	if len(p.otpks) > 0 {
		r.OneTimePrekeys = make(map[uint32][]byte, len(p.otpks))
		for id, k := range p.otpks {
			r.OneTimePrekeys[id] = k.Bytes()
		}
	}
	return r
}

// send encrypts plaintext on s and wraps it in a wire envelope. Pass initial
// for a session's first message, and rekey to qualify that prekey block
// (SRV-17): true for a deliberate re-key, false for an ordinary establishment,
// nil to model a sender predating the field.
func send(s *ratchet.Session, initial *ratchet.InitialMessage, rekey *bool, plaintext []byte) (json.RawMessage, error) {
	header, ciphertext, err := s.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return wire.NewEnvelopeRekey(initial, header, ciphertext, rekey).MarshalPayload()
}

// sendCorrupted is send with one ciphertext byte flipped, so the AEAD tag
// cannot verify -- the symptom a genuinely desynced session produces. Pass
// initial to model a first-contact envelope that arrives damaged.
func sendCorrupted(s *ratchet.Session, initial *ratchet.InitialMessage, plaintext []byte) (json.RawMessage, error) {
	header, ciphertext, err := s.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("conformance: empty ciphertext")
	}
	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	corrupted[0] ^= 0xff
	return wire.NewEnvelopeRekey(initial, header, corrupted, nil).MarshalPayload()
}

func textPlaintext(id, text string) []byte {
	b, _ := json.Marshal(map[string]any{
		"v":           textVersion,
		"id":          id,
		"text":        text,
		"attachments": []any{},
	})
	return b
}

func rekeyPlaintext(reason string) []byte {
	b, _ := json.Marshal(map[string]any{
		"v":      rekeyVersion,
		"kind":   "rekey",
		"reason": reason,
	})
	return b
}

func marshalSession(s *ratchet.Session) (json.RawMessage, error) {
	return json.Marshal(s)
}

func boolPtr(b bool) *bool    { return &b }
func intPtr(i int) *int       { return &i }
func u32Ptr(u uint32) *uint32 { return &u }

// establish runs a full X3DH exchange so the responder ends up holding an
// advanced session: the state a vector needs when it starts mid-conversation
// rather than at first contact. Returns the initiator's session (to keep
// sending on) and the responder's.
func establish(initiator, responder *party, otpkID *uint32, firstText string) (initSess, respSess *ratchet.Session, err error) {
	initSess, initial, err := ratchet.InitiateSession(initiator.dhPriv, responder.bundle(otpkID))
	if err != nil {
		return nil, nil, err
	}
	header, ciphertext, err := initSess.Encrypt(textPlaintext("setup", firstText))
	if err != nil {
		return nil, nil, err
	}
	var otpkPriv *ecdh.PrivateKey
	if initial.OneTimePrekeyID != nil {
		otpkPriv = responder.otpks[*initial.OneTimePrekeyID]
		delete(responder.otpks, *initial.OneTimePrekeyID)
	}
	respSess, err = ratchet.RespondToSession(responder.dhPriv, responder.spkPriv, otpkPriv, initial)
	if err != nil {
		return nil, nil, err
	}
	if _, err := respSess.Decrypt(header, ciphertext); err != nil {
		return nil, nil, fmt.Errorf("conformance: setup exchange did not decrypt: %w", err)
	}
	return initSess, respSess, nil
}

// Generate builds every vector from scratch. Called by the -update path of
// TestVectorsAreGenerated; the committed testdata is what tests actually run
// against, so regeneration is a deliberate act.
func Generate() ([]Vector, error) {
	var out []Vector
	for _, build := range []func() (Vector, error){
		vectorFirstContact,
		vectorRedeliveredInitial,
		vectorFailedResponderKeepsPrekey,
		vectorDuplicateIsNotDesyncEvidence,
		vectorCorruptedIsDesyncEvidence,
		vectorRaceLowerPeerWins,
		vectorRaceHigherPeerLoses,
		vectorDeliberateRekeyBeatsTieBreak,
		vectorLegacyRekeyInferredFromPlaintext,
	} {
		v, err := build()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func vectorFirstContact() (Vector, error) {
	bob, err := newParty(receiverAccount, 1)
	if err != nil {
		return Vector{}, err
	}
	alice, err := newParty(peerHigher)
	if err != nil {
		return Vector{}, err
	}
	aliceSess, initial, err := ratchet.InitiateSession(alice.dhPriv, bob.bundle(u32Ptr(1)))
	if err != nil {
		return Vector{}, err
	}
	payload, err := send(aliceSess, initial, boolPtr(false), textPlaintext("m1", "hello"))
	if err != nil {
		return Vector{}, err
	}
	return Vector{
		Name:        "first-contact-establishes-session",
		Description: "No session and an envelope carrying a prekey block: the receiver runs X3DH as responder, decrypts, and consumes the referenced one-time prekey.",
		Reference:   "PROTOCOL.md §5",
		Receiver:    bob.receiver(),
		Steps: []Step{{
			Label:           "alice's first message",
			MessageID:       "m1",
			SenderAccountID: alice.accountID,
			Payload:         payload,
			Expect: Expect{
				Outcome:                 OutcomeDecrypted,
				Text:                    "hello",
				SessionEffect:           SessionEstablished,
				OneTimePrekeysRemaining: intPtr(0),
				InboundSessionKept:      boolPtr(false),
			},
		}},
	}, nil
}

func vectorRedeliveredInitial() (Vector, error) {
	bob, err := newParty(receiverAccount, 1)
	if err != nil {
		return Vector{}, err
	}
	// peerLower on purpose: a receiver that applies the §5 tie-break without
	// first checking whether it has already handled this message id will treat
	// the redelivery as "their session wins" and overwrite the advanced one.
	alice, err := newParty(peerLower)
	if err != nil {
		return Vector{}, err
	}
	// No one-time prekey, which is what makes the redelivery dangerous rather
	// than merely wasteful: the responder step is fully repeatable, so it
	// rebuilds a session that decrypts this same first message all over again
	// and looks entirely legitimate. Referencing a one-time prekey would mask
	// the bug -- the prekey is gone after the first pass, so the second attempt
	// fails for an unrelated reason and the session survives by accident.
	aliceSess, initial, err := ratchet.InitiateSession(alice.dhPriv, bob.bundle(nil))
	if err != nil {
		return Vector{}, err
	}
	first, err := send(aliceSess, initial, boolPtr(false), textPlaintext("m1", "first"))
	if err != nil {
		return Vector{}, err
	}
	second, err := send(aliceSess, nil, nil, textPlaintext("m2", "second"))
	if err != nil {
		return Vector{}, err
	}
	// Sent after the redelivery, and the real teeth of this vector: a receiver
	// that rebuilt its responder session on the redelivered initial has thrown
	// away the chain state this message continues, so it can no longer read it.
	// A functional assertion rather than an introspective one -- both roles are
	// "responder" here, so nothing about the session's shape gives the reset
	// away.
	third, err := send(aliceSess, nil, nil, textPlaintext("m3", "third"))
	if err != nil {
		return Vector{}, err
	}
	return Vector{
		Name: "redelivered-initial-must-not-reset-session",
		Description: "Delivery is at-least-once, so the very first envelope legitimately arrives twice -- via " +
			"a reconnecting stream, or a push wake racing the live one. It must be recognised by message id " +
			"and dropped: reprocessing re-decrypts a message the user has already seen, and rebuilds the " +
			"responder session on top of the one that has since advanced, discarding its skipped-key state. " +
			"Recognising the id is the only defence, because the rebuilt session decrypts this particular " +
			"envelope perfectly well and looks entirely legitimate.\n\n" +
			"Note what this vector does and does not prove. Step 4 shows the rewound session can still read " +
			"a later message, because X3DH is deterministic and the receiver has sent nothing in between, so " +
			"no DH ratchet step has happened -- the rewind is recoverable here. Turning that into permanent " +
			"breakage requires the receiver to have sent something first, which needs send-side modelling " +
			"this receive-only format cannot express.",
		Reference: "PROTOCOL.md §5",
		Receiver:  bob.receiver(),
		Steps: []Step{
			{
				Label:           "initial arrives",
				MessageID:       "m1",
				SenderAccountID: alice.accountID,
				Payload:         first,
				Expect: Expect{
					Outcome:                 OutcomeDecrypted,
					Text:                    "first",
					SessionEffect:           SessionEstablished,
					OneTimePrekeysRemaining: intPtr(1),
				},
			},
			{
				Label:           "ordinary follow-up advances the session",
				MessageID:       "m2",
				SenderAccountID: alice.accountID,
				Payload:         second,
				Expect: Expect{
					Outcome:                 OutcomeDecrypted,
					Text:                    "second",
					SessionEffect:           SessionUnchanged,
					OneTimePrekeysRemaining: intPtr(1),
				},
			},
			{
				Label:           "the initial is redelivered",
				MessageID:       "m1",
				SenderAccountID: alice.accountID,
				Payload:         first,
				Expect: Expect{
					Outcome:                 OutcomeDuplicate,
					SessionEffect:           SessionUnchanged,
					OneTimePrekeysRemaining: intPtr(1),
					CountsAsDesyncEvidence:  boolPtr(false),
				},
			},
			{
				Label:           "a later message still decrypts",
				MessageID:       "m3",
				SenderAccountID: alice.accountID,
				Payload:         third,
				Expect: Expect{
					Outcome:                 OutcomeDecrypted,
					Text:                    "third",
					SessionEffect:           SessionUnchanged,
					OneTimePrekeysRemaining: intPtr(1),
				},
			},
		},
	}, nil
}

func vectorFailedResponderKeepsPrekey() (Vector, error) {
	bob, err := newParty(receiverAccount, 1)
	if err != nil {
		return Vector{}, err
	}
	alice, err := newParty(peerHigher)
	if err != nil {
		return Vector{}, err
	}
	aliceSess, initial, err := ratchet.InitiateSession(alice.dhPriv, bob.bundle(u32Ptr(1)))
	if err != nil {
		return Vector{}, err
	}
	payload, err := sendCorrupted(aliceSess, initial, textPlaintext("m1", "unreadable"))
	if err != nil {
		return Vector{}, err
	}
	return Vector{
		Name: "failed-responder-attempt-must-not-burn-prekey",
		Description: "An initial referencing a held one-time prekey, whose ciphertext does not verify. The " +
			"prekey may only be marked consumed once a session built from it actually decrypts something: " +
			"consuming it up front means every stale, damaged or redelivered initial drains the pool, and a " +
			"drained pool downgrades every later first contact to the weaker no-one-time-prekey path.",
		Reference: "PROTOCOL.md §5",
		Receiver:  bob.receiver(),
		Steps: []Step{{
			Label:           "damaged first contact",
			MessageID:       "m1",
			SenderAccountID: alice.accountID,
			Payload:         payload,
			Expect: Expect{
				Outcome:                 OutcomeUndecryptable,
				SessionEffect:           SessionUnchanged,
				OneTimePrekeysRemaining: intPtr(1),
			},
		}},
	}, nil
}

func vectorDuplicateIsNotDesyncEvidence() (Vector, error) {
	bob, err := newParty(receiverAccount, 1)
	if err != nil {
		return Vector{}, err
	}
	alice, err := newParty(peerHigher)
	if err != nil {
		return Vector{}, err
	}
	aliceSess, bobSess, err := establish(alice, bob, u32Ptr(1), "setup")
	if err != nil {
		return Vector{}, err
	}
	payload, err := send(aliceSess, nil, nil, textPlaintext("m1", "one"))
	if err != nil {
		return Vector{}, err
	}
	bobBlob, err := marshalSession(bobSess)
	if err != nil {
		return Vector{}, err
	}
	r := bob.receiver()
	r.Sessions = map[string]json.RawMessage{alice.accountID: bobBlob}
	return Vector{
		Name: "duplicate-ordinary-message-is-not-desync-evidence",
		Description: "The same envelope twice on an established session. The second is a duplicate, not a " +
			"fault: nothing is wrong, so it must not be counted toward an automatic re-key and the session " +
			"must stay usable.",
		Reference: "SRV-03",
		Receiver:  r,
		Steps: []Step{
			{
				Label:           "message arrives",
				MessageID:       "m1",
				SenderAccountID: alice.accountID,
				Payload:         payload,
				Expect: Expect{
					Outcome:       OutcomeDecrypted,
					Text:          "one",
					SessionEffect: SessionUnchanged,
				},
			},
			{
				Label:           "same message redelivered",
				MessageID:       "m1",
				SenderAccountID: alice.accountID,
				Payload:         payload,
				Expect: Expect{
					Outcome:                OutcomeDuplicate,
					SessionEffect:          SessionUnchanged,
					CountsAsDesyncEvidence: boolPtr(false),
				},
			},
		},
	}, nil
}

func vectorCorruptedIsDesyncEvidence() (Vector, error) {
	bob, err := newParty(receiverAccount, 1)
	if err != nil {
		return Vector{}, err
	}
	alice, err := newParty(peerHigher)
	if err != nil {
		return Vector{}, err
	}
	aliceSess, bobSess, err := establish(alice, bob, u32Ptr(1), "setup")
	if err != nil {
		return Vector{}, err
	}
	payload, err := sendCorrupted(aliceSess, nil, textPlaintext("m1", "unreadable"))
	if err != nil {
		return Vector{}, err
	}
	bobBlob, err := marshalSession(bobSess)
	if err != nil {
		return Vector{}, err
	}
	r := bob.receiver()
	r.Sessions = map[string]json.RawMessage{alice.accountID: bobBlob}
	return Vector{
		Name: "authentication-failure-is-desync-evidence",
		Description: "An envelope whose AEAD tag does not verify. Cryptographically this cannot happen by " +
			"chance, so it is the desync symptom and must be classified as such -- the counterpart to the " +
			"duplicate case, and the distinction an implementation that discards the ratchet's failure code " +
			"cannot make.",
		Reference: "SRV-03",
		Receiver:  r,
		Steps: []Step{{
			Label:           "corrupted ciphertext",
			MessageID:       "m1",
			SenderAccountID: alice.accountID,
			Payload:         payload,
			Expect: Expect{
				Outcome:                OutcomeUndecryptable,
				FailureCode:            ratchet.FailureAuthentication,
				CountsAsDesyncEvidence: boolPtr(true),
				SessionEffect:          SessionUnchanged,
			},
		}},
	}, nil
}

// raceVector builds a simultaneous establishment: the receiver already holds
// its own initiator session toward the peer, and the peer's own initial
// arrives. wins says whose session both sides should end up sending on.
func raceVector(name, description string, peerAccount string, rekey *bool, plaintext []byte, expect Expect) (Vector, error) {
	bob, err := newParty(receiverAccount, 1)
	if err != nil {
		return Vector{}, err
	}
	alice, err := newParty(peerAccount, 1)
	if err != nil {
		return Vector{}, err
	}
	// Bob reached for Alice at the same moment, so he holds his own initiator
	// session and cannot read hers.
	bobOwnSess, _, err := ratchet.InitiateSession(bob.dhPriv, alice.bundle(u32Ptr(1)))
	if err != nil {
		return Vector{}, err
	}
	aliceSess, initial, err := ratchet.InitiateSession(alice.dhPriv, bob.bundle(u32Ptr(1)))
	if err != nil {
		return Vector{}, err
	}
	payload, err := send(aliceSess, initial, rekey, plaintext)
	if err != nil {
		return Vector{}, err
	}
	bobBlob, err := marshalSession(bobOwnSess)
	if err != nil {
		return Vector{}, err
	}
	r := bob.receiver()
	r.Sessions = map[string]json.RawMessage{alice.accountID: bobBlob}
	return Vector{
		Name:        name,
		Description: description,
		Reference:   "PROTOCOL.md §5",
		Receiver:    r,
		Steps: []Step{{
			Label:           "peer's own initial arrives",
			MessageID:       "m1",
			SenderAccountID: alice.accountID,
			Payload:         payload,
			Expect:          expect,
		}},
	}, nil
}

func vectorRaceLowerPeerWins() (Vector, error) {
	return raceVector(
		"race-lower-peer-account-id-wins",
		"Both sides established at once and the peer's account id sorts lower, so the peer's session wins "+
			"and the receiver adopts it. Positive control for the tie-break itself.",
		peerLower,
		boolPtr(false),
		textPlaintext("m1", "hi"),
		Expect{
			Outcome:       OutcomeDecrypted,
			Text:          "hi",
			SessionEffect: SessionAdoptedPeer,
		},
	)
}

func vectorRaceHigherPeerLoses() (Vector, error) {
	return raceVector(
		"race-higher-peer-account-id-loses-but-stays-readable",
		"The peer's account id sorts higher, so the receiver keeps its own session for sending -- but the "+
			"peer goes on sending from theirs until the receiver's next message lands, so it must be kept "+
			"for reading rather than discarded.",
		peerHigher,
		boolPtr(false),
		textPlaintext("m1", "hi"),
		Expect{
			Outcome:            OutcomeDecrypted,
			Text:               "hi",
			SessionEffect:      SessionUnchanged,
			InboundSessionKept: boolPtr(true),
		},
	)
}

func vectorDeliberateRekeyBeatsTieBreak() (Vector, error) {
	return raceVector(
		"deliberate-rekey-wins-against-tie-break",
		"The prekey block says this is a deliberate re-key (SRV-17), so there is no race and no tie-break "+
			"to apply: the sender discarded their session and theirs is the only one they can read. It wins "+
			"even though their account id sorts higher.",
		peerHigher,
		boolPtr(true),
		rekeyPlaintext("decrypt_failures"),
		Expect{
			Outcome:       OutcomeDecrypted,
			SessionEffect: SessionAdoptedPeer,
		},
	)
}

func vectorLegacyRekeyInferredFromPlaintext() (Vector, error) {
	return raceVector(
		"legacy-rekey-inferred-from-plaintext",
		"A sender predating SRV-17 leaves the prekey block unqualified. The re-key must then be inferred "+
			"from the decrypted content being a re-key signal (v:3), because that sender threw its session "+
			"away and can read nothing else -- applying the tie-break instead strands the conversation.",
		peerHigher,
		nil,
		rekeyPlaintext("decrypt_failures"),
		Expect{
			Outcome:       OutcomeDecrypted,
			SessionEffect: SessionAdoptedPeer,
		},
	)
}
