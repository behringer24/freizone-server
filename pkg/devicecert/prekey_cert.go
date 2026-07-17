package devicecert

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// x25519PubKeySize is the byte length of an X25519 public key. devicecert
// doesn't otherwise depend on crypto/ecdh -- these certificates only carry
// and validate the key's length, never perform Diffie-Hellman themselves.
const x25519PubKeySize = 32

// DHIdentityCertificate binds a device's X25519 Diffie-Hellman identity key
// (used for X3DH/Double Ratchet key agreement) to that device. Unlike
// DeviceCertificate, this is signed by the device's own Ed25519 private
// key, not the account's root key -- a device already certified by the
// root is vouching for its own X3DH key material.
type DHIdentityCertificate struct {
	AccountID string    `json:"account_id"`
	DeviceID  string    `json:"device_id"`
	DHPubKey  []byte    `json:"dh_pub_key"` // X25519, 32 bytes
	IssuedAt  time.Time `json:"issued_at"`
	Signature []byte    `json:"signature"`
}

// SignDHIdentityCertificate builds and signs a new DH identity certificate
// with the device's own Ed25519 private key.
func SignDHIdentityCertificate(accountID, deviceID string, dhPubKey []byte, issuedAt time.Time, devicePriv ed25519.PrivateKey) (*DHIdentityCertificate, error) {
	cert := &DHIdentityCertificate{
		AccountID: accountID,
		DeviceID:  deviceID,
		DHPubKey:  dhPubKey,
		IssuedAt:  issuedAt,
	}
	buf, err := cert.signingBytes()
	if err != nil {
		return nil, err
	}
	cert.Signature = ed25519.Sign(devicePriv, buf)
	return cert, nil
}

// Verify checks the certificate's structure and its signature against the
// device's Ed25519 public key.
func (c *DHIdentityCertificate) Verify(devicePubKey ed25519.PublicKey) error {
	buf, err := c.signingBytes()
	if err != nil {
		return err
	}
	if len(c.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("devicecert: signature must be %d bytes, got %d", ed25519.SignatureSize, len(c.Signature))
	}
	if !ed25519.Verify(devicePubKey, buf, c.Signature) {
		return errors.New("devicecert: dh identity signature verification failed")
	}
	return nil
}

func (c *DHIdentityCertificate) signingBytes() ([]byte, error) {
	deviceIDRaw, err := decodeDeviceID(c.DeviceID)
	if err != nil {
		return nil, err
	}
	if len(c.DHPubKey) != x25519PubKeySize {
		return nil, fmt.Errorf("devicecert: dh identity public key must be %d bytes, got %d", x25519PubKeySize, len(c.DHPubKey))
	}

	var buf bytes.Buffer
	writeLengthPrefixed(&buf, []byte(c.AccountID))
	buf.Write(deviceIDRaw)
	buf.Write(c.DHPubKey)
	writeLengthPrefixed(&buf, []byte(c.IssuedAt.UTC().Format(time.RFC3339)))
	return buf.Bytes(), nil
}

// SignedPrekeyCertificate binds a rotatable X3DH signed prekey to a
// specific DH identity key (DHIdentityPubKey), so the signature can't be
// replayed against a substituted identity key. Signed by the device's own
// Ed25519 private key, same as DHIdentityCertificate.
type SignedPrekeyCertificate struct {
	AccountID        string    `json:"account_id"`
	DeviceID         string    `json:"device_id"`
	KeyID            uint32    `json:"key_id"`
	DHIdentityPubKey []byte    `json:"dh_identity_pub_key"` // X25519, 32 bytes -- must match the device's DHIdentityCertificate
	PrekeyPubKey     []byte    `json:"prekey_pub_key"`      // X25519, 32 bytes
	IssuedAt         time.Time `json:"issued_at"`
	Signature        []byte    `json:"signature"`
}

// SignSignedPrekeyCertificate builds and signs a new signed-prekey
// certificate with the device's own Ed25519 private key.
func SignSignedPrekeyCertificate(accountID, deviceID string, keyID uint32, dhIdentityPubKey, prekeyPubKey []byte, issuedAt time.Time, devicePriv ed25519.PrivateKey) (*SignedPrekeyCertificate, error) {
	cert := &SignedPrekeyCertificate{
		AccountID:        accountID,
		DeviceID:         deviceID,
		KeyID:            keyID,
		DHIdentityPubKey: dhIdentityPubKey,
		PrekeyPubKey:     prekeyPubKey,
		IssuedAt:         issuedAt,
	}
	buf, err := cert.signingBytes()
	if err != nil {
		return nil, err
	}
	cert.Signature = ed25519.Sign(devicePriv, buf)
	return cert, nil
}

// Verify checks the certificate's structure and its signature against the
// device's Ed25519 public key.
func (c *SignedPrekeyCertificate) Verify(devicePubKey ed25519.PublicKey) error {
	buf, err := c.signingBytes()
	if err != nil {
		return err
	}
	if len(c.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("devicecert: signature must be %d bytes, got %d", ed25519.SignatureSize, len(c.Signature))
	}
	if !ed25519.Verify(devicePubKey, buf, c.Signature) {
		return errors.New("devicecert: signed prekey signature verification failed")
	}
	return nil
}

func (c *SignedPrekeyCertificate) signingBytes() ([]byte, error) {
	deviceIDRaw, err := decodeDeviceID(c.DeviceID)
	if err != nil {
		return nil, err
	}
	if len(c.DHIdentityPubKey) != x25519PubKeySize {
		return nil, fmt.Errorf("devicecert: dh identity public key must be %d bytes, got %d", x25519PubKeySize, len(c.DHIdentityPubKey))
	}
	if len(c.PrekeyPubKey) != x25519PubKeySize {
		return nil, fmt.Errorf("devicecert: prekey public key must be %d bytes, got %d", x25519PubKeySize, len(c.PrekeyPubKey))
	}

	var buf bytes.Buffer
	writeLengthPrefixed(&buf, []byte(c.AccountID))
	buf.Write(deviceIDRaw)
	var keyIDBytes [4]byte
	binary.BigEndian.PutUint32(keyIDBytes[:], c.KeyID)
	buf.Write(keyIDBytes[:])
	buf.Write(c.DHIdentityPubKey)
	buf.Write(c.PrekeyPubKey)
	writeLengthPrefixed(&buf, []byte(c.IssuedAt.UTC().Format(time.RFC3339)))
	return buf.Bytes(), nil
}
