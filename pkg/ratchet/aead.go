package ratchet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// messageKeyInfo domain-separates per-message key/nonce derivation from the
// root-key and chain-key KDFs above.
const messageKeyInfo = "Freizone-DR-msg-v1"

// deriveMessageKeyMaterial expands a single-use Double Ratchet message key
// into an AES-256 key and a GCM nonce via one HKDF call. Deriving the nonce
// this way (rather than choosing it at random) is safe specifically because
// mk is never reused across more than one message.
func deriveMessageKeyMaterial(mk []byte) (key, nonce []byte, err error) {
	r := hkdf.New(sha256.New, mk, nil, []byte(messageKeyInfo))
	out := make([]byte, 32+12)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, nil, fmt.Errorf("ratchet: deriving message key material: %w", err)
	}
	return out[:32], out[32:], nil
}

func gcmFor(mk []byte) (cipher.AEAD, []byte, error) {
	key, nonce, err := deriveMessageKeyMaterial(mk)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet: constructing cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet: constructing GCM: %w", err)
	}
	return gcm, nonce, nil
}

// sealMessage encrypts plaintext under a one-time message key, with the
// session's fixed associated data plus the message header bound in as
// AEAD associated data.
func sealMessage(mk, plaintext, sessionAD []byte, header Header) ([]byte, error) {
	gcm, nonce, err := gcmFor(mk)
	if err != nil {
		return nil, err
	}
	ad := append(append([]byte{}, sessionAD...), header.Bytes()...)
	return gcm.Seal(nil, nonce, plaintext, ad), nil
}

// openMessage decrypts and authenticates ciphertext produced by sealMessage.
func openMessage(mk, ciphertext, sessionAD []byte, header Header) ([]byte, error) {
	gcm, nonce, err := gcmFor(mk)
	if err != nil {
		return nil, err
	}
	ad := append(append([]byte{}, sessionAD...), header.Bytes()...)
	plaintext, err := gcm.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("ratchet: message authentication failed: %w", err)
	}
	return plaintext, nil
}
