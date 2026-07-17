package ratchet

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// x3dhInfo domain-separates the X3DH shared-secret KDF from every other
// HKDF use in this package.
const x3dhInfo = "Freizone-X3DH-v1"

// RemoteBundle is what an initiator fetches from the server (POST
// /v1/devices/{id}/prekey-bundle) before starting a session with a device
// it hasn't talked to yet.
type RemoteBundle struct {
	DHIdentityPubKey *ecdh.PublicKey
	SignedPrekeyID   uint32
	SignedPrekeyPub  *ecdh.PublicKey
	OneTimePrekeyID  *uint32         // nil if the pool was empty
	OneTimePrekeyPub *ecdh.PublicKey // nil if the pool was empty
}

// InitialMessage carries the extra X3DH material an initiator must send
// alongside its first Double-Ratchet-encrypted message, so the responder
// can derive the same shared secret and bootstrap its own session.
type InitialMessage struct {
	SenderDHIdentityPub []byte  `json:"sender_dh_identity_pub"` // 32 bytes
	SenderEphemeralPub  []byte  `json:"sender_ephemeral_pub"`   // 32 bytes
	SignedPrekeyID      uint32  `json:"signed_prekey_id"`
	OneTimePrekeyID     *uint32 `json:"one_time_prekey_id,omitempty"`
}

// InitiateSession runs X3DH as the initiator against a fetched
// RemoteBundle and returns a Double Ratchet session ready to Encrypt, plus
// the InitialMessage the responder needs to complete its side.
func InitiateSession(localDHIdentityPriv *ecdh.PrivateKey, remote RemoteBundle) (*Session, *InitialMessage, error) {
	curve := ecdh.X25519()

	ephemeralPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet: generating ephemeral key: %w", err)
	}

	dh1, err := localDHIdentityPriv.ECDH(remote.SignedPrekeyPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet: x3dh dh1: %w", err)
	}
	dh2, err := ephemeralPriv.ECDH(remote.DHIdentityPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet: x3dh dh2: %w", err)
	}
	dh3, err := ephemeralPriv.ECDH(remote.SignedPrekeyPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet: x3dh dh3: %w", err)
	}

	ikm := x3dhIKM(dh1, dh2, dh3, nil)
	var otpkID *uint32
	if remote.OneTimePrekeyPub != nil {
		dh4, err := ephemeralPriv.ECDH(remote.OneTimePrekeyPub)
		if err != nil {
			return nil, nil, fmt.Errorf("ratchet: x3dh dh4: %w", err)
		}
		ikm = x3dhIKM(dh1, dh2, dh3, dh4)
		otpkID = remote.OneTimePrekeyID
	}

	sk, err := deriveX3DHSecret(ikm)
	if err != nil {
		return nil, nil, err
	}

	ad := sessionAD(localDHIdentityPriv.PublicKey().Bytes(), remote.DHIdentityPubKey.Bytes())

	ratchetPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet: generating initial ratchet key: %w", err)
	}

	session, err := newInitiatorSession(sk, ad, ratchetPriv, remote.SignedPrekeyPub)
	if err != nil {
		return nil, nil, err
	}

	initial := &InitialMessage{
		SenderDHIdentityPub: localDHIdentityPriv.PublicKey().Bytes(),
		SenderEphemeralPub:  ephemeralPriv.PublicKey().Bytes(),
		SignedPrekeyID:      remote.SignedPrekeyID,
		OneTimePrekeyID:     otpkID,
	}
	return session, initial, nil
}

// RespondToSession runs X3DH as the responder, given an initiator's
// InitialMessage and the responder's own long-term DH identity key, the
// signed-prekey keypair the initiator used, and the one-time prekey
// private key the initiator consumed (nil if InitialMessage.OneTimePrekeyID
// was nil).
func RespondToSession(localDHIdentityPriv *ecdh.PrivateKey, signedPrekeyPriv *ecdh.PrivateKey, oneTimePrekeyPriv *ecdh.PrivateKey, initial *InitialMessage) (*Session, error) {
	curve := ecdh.X25519()

	senderIdentityPub, err := curve.NewPublicKey(initial.SenderDHIdentityPub)
	if err != nil {
		return nil, fmt.Errorf("ratchet: invalid sender dh identity public key: %w", err)
	}
	senderEphemeralPub, err := curve.NewPublicKey(initial.SenderEphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ratchet: invalid sender ephemeral public key: %w", err)
	}

	dh1, err := signedPrekeyPriv.ECDH(senderIdentityPub)
	if err != nil {
		return nil, fmt.Errorf("ratchet: x3dh dh1: %w", err)
	}
	dh2, err := localDHIdentityPriv.ECDH(senderEphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ratchet: x3dh dh2: %w", err)
	}
	dh3, err := signedPrekeyPriv.ECDH(senderEphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ratchet: x3dh dh3: %w", err)
	}

	ikm := x3dhIKM(dh1, dh2, dh3, nil)
	if initial.OneTimePrekeyID != nil {
		if oneTimePrekeyPriv == nil {
			return nil, fmt.Errorf("ratchet: initial message references one-time prekey %d but no matching private key was provided", *initial.OneTimePrekeyID)
		}
		dh4, err := oneTimePrekeyPriv.ECDH(senderEphemeralPub)
		if err != nil {
			return nil, fmt.Errorf("ratchet: x3dh dh4: %w", err)
		}
		ikm = x3dhIKM(dh1, dh2, dh3, dh4)
	}

	sk, err := deriveX3DHSecret(ikm)
	if err != nil {
		return nil, err
	}

	ad := sessionAD(initial.SenderDHIdentityPub, localDHIdentityPriv.PublicKey().Bytes())

	return newResponderSession(sk, ad, signedPrekeyPriv), nil
}

// x3dhIKM builds the HKDF input key material: F || DH1 || DH2 || DH3 [||
// DH4], where F is 32 0xFF bytes (the X25519 case from the spec).
func x3dhIKM(dh1, dh2, dh3, dh4 []byte) []byte {
	f := bytes.Repeat([]byte{0xFF}, 32)
	ikm := make([]byte, 0, len(f)+len(dh1)+len(dh2)+len(dh3)+len(dh4))
	ikm = append(ikm, f...)
	ikm = append(ikm, dh1...)
	ikm = append(ikm, dh2...)
	ikm = append(ikm, dh3...)
	ikm = append(ikm, dh4...)
	return ikm
}

// deriveX3DHSecret is X3DH's KDF: HKDF-SHA256 with a zero salt and a fixed
// application info string.
func deriveX3DHSecret(ikm []byte) ([]byte, error) {
	salt := make([]byte, sha256.Size)
	r := hkdf.New(sha256.New, ikm, salt, []byte(x3dhInfo))
	sk := make([]byte, 32)
	if _, err := io.ReadFull(r, sk); err != nil {
		return nil, fmt.Errorf("ratchet: deriving x3dh shared secret: %w", err)
	}
	return sk, nil
}

// sessionAD builds the fixed associated data for a session:
// Encode(initiator's DH identity pubkey) || Encode(responder's), always in
// that role order regardless of who is currently sending.
func sessionAD(initiatorDHPub, responderDHPub []byte) []byte {
	ad := make([]byte, 0, len(initiatorDHPub)+len(responderDHPub))
	ad = append(ad, initiatorDHPub...)
	ad = append(ad, responderDHPub...)
	return ad
}
