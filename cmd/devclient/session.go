package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/behringer24/freizone-server/pkg/ratchet"
	"github.com/behringer24/freizone-server/pkg/wire"
)

// Session establishment, shared by every path that sends or receives: the
// interactive one-to-one chat (chat.go), the group fan-out (group_send.go) and
// the group watcher (group_watch.go). It lives in its own file because all
// three meet the same X3DH cases -- a first establishment, a peer who
// deliberately re-keyed, and both sides establishing at the same moment -- and
// a copy per path is how one of them silently ends up handling fewer of them.

// ordinaryEstablishment is what this client puts in every prekey block's
// `rekey` field (SRV-17): it has no "reset secure session" of its own, so an
// initial from here is always a first establishment, never a re-key. Stated
// rather than omitted, because omitting it asks the receiver to guess from the
// decrypted content -- and a client that knows the answer should say it.
var ordinaryEstablishment = false

// newSendEnvelope builds the payload for one outgoing message, declaring the
// establishment as ordinary when it carries a prekey block.
func newSendEnvelope(initial *ratchet.InitialMessage, header ratchet.Header, ciphertext []byte) (json.RawMessage, error) {
	return wire.NewEnvelopeRekey(initial, header, ciphertext, &ordinaryEstablishment).MarshalPayload()
}

// getOrCreateSession returns the existing session with peerAccountID, or
// establishes a new one as X3DH initiator by claiming the peer's prekey
// bundle. Callers must hold the state's lock.
func getOrCreateSession(state *State, peerAccountID, peerServer, peerDeviceID string, peerDevicePubKey ed25519.PublicKey) (*ratchet.Session, *ratchet.InitialMessage, error) {
	if s, ok := state.Sessions[peerAccountID]; ok {
		return s, nil, nil
	}

	bundle, err := claimPrekeyBundle(state, peerServer, peerDeviceID)
	if err != nil {
		return nil, nil, err
	}
	remote, err := bundleToRemoteBundle(bundle, peerAccountID, peerDeviceID, peerDevicePubKey)
	if err != nil {
		return nil, nil, err
	}

	dhPriv, err := ecdh.X25519().NewPrivateKey(state.DHIdentityPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("loading local dh identity key: %w", err)
	}

	session, initial, err := ratchet.InitiateSession(dhPriv, remote)
	if err != nil {
		return nil, nil, fmt.Errorf("initiating x3dh session: %w", err)
	}

	state.Sessions[peerAccountID] = session
	return session, initial, nil
}

func respondToNewSession(state *State, prekeyFields *wire.PrekeyFields) (*ratchet.Session, error) {
	initial, err := prekeyFields.ToInitialMessage()
	if err != nil {
		return nil, err
	}

	curve := ecdh.X25519()
	dhPriv, err := curve.NewPrivateKey(state.DHIdentityPriv)
	if err != nil {
		return nil, fmt.Errorf("loading local dh identity key: %w", err)
	}
	spkPriv, err := curve.NewPrivateKey(state.SignedPrekeyPriv)
	if err != nil {
		return nil, fmt.Errorf("loading local signed prekey: %w", err)
	}

	var otpkPriv *ecdh.PrivateKey
	if initial.OneTimePrekeyID != nil {
		if stored, ok := state.OneTimePrekeys[*initial.OneTimePrekeyID]; ok {
			otpkPriv, err = curve.NewPrivateKey(stored.Priv)
			if err != nil {
				return nil, fmt.Errorf("loading one-time prekey: %w", err)
			}
			delete(state.OneTimePrekeys, *initial.OneTimePrekeyID)
		}
	}

	return ratchet.RespondToSession(dhPriv, spkPriv, otpkPriv, initial)
}

// decryptIncoming decrypts one envelope from msg's sender and interprets the
// plaintext, establishing or adopting a session as the prekey block requires.
// Callers must hold the state's lock (Decrypt mutates session state).
func decryptIncoming(state *State, msg messageResponse) (decodedPlaintext, error) {
	env, err := wire.ParseEnvelope(msg.Payload)
	if err != nil {
		return decodedPlaintext{}, err
	}
	header, err := env.Header.ToHeader()
	if err != nil {
		return decodedPlaintext{}, err
	}
	ciphertext, err := env.DecodeCiphertext()
	if err != nil {
		return decodedPlaintext{}, err
	}

	session, haveSession := state.Sessions[msg.SenderAccountID]

	// A prekey block needs handling even when a session already exists.
	//
	// Simultaneous X3DH initiation is rare between two people chatting and
	// routine in a group: a new member establishes a session with every
	// existing member at once, and those members do the same toward them, so
	// both sides regularly end up holding their own initiator session for the
	// same pair. Neither can read the other's.
	//
	// The tie-break is the one docs/PROTOCOL.md §5 already uses for re-keying,
	// derived from data both sides have: the LOWER account id's session wins.
	// The loser adopts the winner's; the winner reads the message with a
	// throwaway responder session and keeps its own for sending, so the two
	// converge after one message instead of swapping symmetrically forever.
	// Unless the sender says it is a deliberate re-key (SRV-17), in which case
	// there is no race and no tie-break to apply: they discarded their session,
	// so theirs is the only one they can read and it wins outright. A sender that
	// says nothing (an older client) is treated as the racing case, exactly as
	// before the field existed.
	if env.Prekey != nil {
		deliberateRekey := env.Prekey.Rekey != nil && *env.Prekey.Rekey
		theirsWins := deliberateRekey || msg.SenderAccountID < state.AccountID
		fresh, ferr := respondToNewSession(state, env.Prekey)
		if ferr == nil {
			if plaintext, derr := fresh.Decrypt(header, ciphertext); derr == nil {
				switch {
				case !haveSession || theirsWins:
					state.Sessions[msg.SenderAccountID] = fresh
				default:
					// Our session wins, so we keep sending on it -- but they
					// are still sending on theirs until our next message
					// reaches them. Keeping this one for reading is what stops
					// those in-flight messages being stranded.
					state.InboundSessions[msg.SenderAccountID] = fresh
				}
				return decodePlaintext(plaintext), nil
			}
		}
		if !haveSession {
			if ferr != nil {
				return decodedPlaintext{}, ferr
			}
			return decodedPlaintext{}, fmt.Errorf("prekey block from %s did not decrypt", shortID(msg.SenderAccountID))
		}
		// A stale or redelivered prekey block must not disturb a session that
		// still works, so fall through and try the ones we have.
	}

	if haveSession {
		if plaintext, derr := session.Decrypt(header, ciphertext); derr == nil {
			return decodePlaintext(plaintext), nil
		}
	}
	// Last resort: the losing side of a simultaneous establishment, kept
	// exactly for the messages that were already on their way.
	if inbound, ok := state.InboundSessions[msg.SenderAccountID]; ok {
		if plaintext, derr := inbound.Decrypt(header, ciphertext); derr == nil {
			return decodePlaintext(plaintext), nil
		}
	}
	if !haveSession {
		return decodedPlaintext{}, fmt.Errorf("no session with %s and message carries no x3dh fields", shortID(msg.SenderAccountID))
	}
	return decodedPlaintext{}, fmt.Errorf("no session decrypts this message from %s", shortID(msg.SenderAccountID))
}
