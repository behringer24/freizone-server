package ratchet

import (
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
)

// Role records which side of X3DH a session came from. It doesn't affect
// the ratchet mechanics (those are symmetric once bootstrapped) but is
// useful for debugging and is preserved across persistence.
type Role string

const (
	RoleInitiator Role = "initiator"
	RoleResponder Role = "responder"
)

// Session is one Double Ratchet session with a single remote device,
// bootstrapped from an X3DH key agreement. The zero value is not usable;
// construct via InitiateSession or RespondToSession.
type Session struct {
	Role Role
	// AD is fixed for the lifetime of the session: Encode(initiator's DH
	// identity pubkey) || Encode(responder's DH identity pubkey), in that
	// order regardless of which side is currently sending.
	AD []byte

	DHs *ecdh.PrivateKey // this side's current ratchet keypair
	DHr *ecdh.PublicKey  // the other side's current ratchet public key; nil until known

	RK  []byte // 32 bytes
	CKs []byte // sending chain key; nil until established
	CKr []byte // receiving chain key; nil until established

	Ns, Nr, PN uint32

	Skipped map[skippedKey][]byte
}

func newInitiatorSession(sk, ad []byte, ratchetPriv *ecdh.PrivateKey, remoteSignedPrekeyPub *ecdh.PublicKey) (*Session, error) {
	dh, err := ratchetPriv.ECDH(remoteSignedPrekeyPub)
	if err != nil {
		return nil, fmt.Errorf("ratchet: initial dh ratchet: %w", err)
	}
	rk, cks, err := kdfRK(sk, dh)
	if err != nil {
		return nil, err
	}
	return &Session{
		Role: RoleInitiator,
		AD:   ad,
		DHs:  ratchetPriv,
		DHr:  remoteSignedPrekeyPub,
		RK:   rk,
		CKs:  cks,
	}, nil
}

func newResponderSession(sk, ad []byte, signedPrekeyPriv *ecdh.PrivateKey) *Session {
	return &Session{
		Role: RoleResponder,
		AD:   ad,
		DHs:  signedPrekeyPriv,
		RK:   sk,
	}
}

// Encrypt advances the sending chain by one step and encrypts plaintext,
// returning the header that must accompany the ciphertext to the peer.
func (s *Session) Encrypt(plaintext []byte) (Header, []byte, error) {
	if s.CKs == nil {
		return Header{}, nil, errors.New("ratchet: no sending chain established yet")
	}

	ck, mk := kdfCK(s.CKs)
	s.CKs = ck

	header := Header{DHPub: s.DHs.PublicKey().Bytes(), PN: s.PN, N: s.Ns}
	s.Ns++

	ciphertext, err := sealMessage(mk, plaintext, s.AD, header)
	if err != nil {
		return Header{}, nil, err
	}
	return header, ciphertext, nil
}

// Decrypt authenticates and decrypts ciphertext given its header,
// performing a DH ratchet step first if the header carries a new remote
// ratchet public key (this is also how a responder's very first received
// message bootstraps its receiving -- and, in turn, sending -- chain).
func (s *Session) Decrypt(header Header, ciphertext []byte) ([]byte, error) {
	if mk, ok := s.trySkippedMessageKey(header); ok {
		return openMessage(mk, ciphertext, s.AD, header)
	}

	if !headerMatchesDHr(header, s.DHr) {
		if s.DHr != nil {
			if err := s.skipMessageKeys(header.PN); err != nil {
				return nil, err
			}
		}
		if err := s.dhRatchetStep(header.DHPub); err != nil {
			return nil, err
		}
	}

	if err := s.skipMessageKeys(header.N); err != nil {
		return nil, err
	}

	ck, mk := kdfCK(s.CKr)
	s.CKr = ck
	s.Nr++

	return openMessage(mk, ciphertext, s.AD, header)
}

// sessionJSON is Session's on-disk representation: ecdh keys don't marshal
// directly, so this substitutes raw/base64-friendly byte slices.
type sessionJSON struct {
	Role    Role               `json:"role"`
	AD      []byte             `json:"ad"`
	DHsPriv []byte             `json:"dhs_priv"`
	DHrPub  []byte             `json:"dhr_pub,omitempty"`
	RK      []byte             `json:"rk"`
	CKs     []byte             `json:"cks,omitempty"`
	CKr     []byte             `json:"ckr,omitempty"`
	Ns      uint32             `json:"ns"`
	Nr      uint32             `json:"nr"`
	PN      uint32             `json:"pn"`
	Skipped []skippedEntryJSON `json:"skipped,omitempty"`
}

type skippedEntryJSON struct {
	DHPub []byte `json:"dh_pub"`
	N     uint32 `json:"n"`
	MK    []byte `json:"mk"`
}

// MarshalJSON implements json.Marshaler.
func (s *Session) MarshalJSON() ([]byte, error) {
	sj := sessionJSON{
		Role: s.Role,
		AD:   s.AD,
		RK:   s.RK,
		CKs:  s.CKs,
		CKr:  s.CKr,
		Ns:   s.Ns,
		Nr:   s.Nr,
		PN:   s.PN,
	}
	if s.DHs != nil {
		sj.DHsPriv = s.DHs.Bytes()
	}
	if s.DHr != nil {
		sj.DHrPub = s.DHr.Bytes()
	}
	for k, mk := range s.Skipped {
		sj.Skipped = append(sj.Skipped, skippedEntryJSON{DHPub: []byte(k.dhPub), N: k.n, MK: mk})
	}
	return json.Marshal(sj)
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *Session) UnmarshalJSON(data []byte) error {
	var sj sessionJSON
	if err := json.Unmarshal(data, &sj); err != nil {
		return err
	}

	s.Role = sj.Role
	s.AD = sj.AD
	s.RK = sj.RK
	s.CKs = sj.CKs
	s.CKr = sj.CKr
	s.Ns = sj.Ns
	s.Nr = sj.Nr
	s.PN = sj.PN

	if len(sj.DHsPriv) > 0 {
		priv, err := ecdh.X25519().NewPrivateKey(sj.DHsPriv)
		if err != nil {
			return fmt.Errorf("ratchet: decoding persisted ratchet private key: %w", err)
		}
		s.DHs = priv
	}
	if len(sj.DHrPub) > 0 {
		pub, err := ecdh.X25519().NewPublicKey(sj.DHrPub)
		if err != nil {
			return fmt.Errorf("ratchet: decoding persisted remote ratchet public key: %w", err)
		}
		s.DHr = pub
	}

	if len(sj.Skipped) > 0 {
		s.Skipped = make(map[skippedKey][]byte, len(sj.Skipped))
		for _, e := range sj.Skipped {
			s.Skipped[skippedKey{dhPub: string(e.DHPub), n: e.N}] = e.MK
		}
	}
	return nil
}
