// Package devicecert implements Freizone's device certificate and device
// revocation records: statements signed by an account's root Ed25519 key
// that authorize (or revoke) a device's identity key.
//
// The signing byte layout is a cross-repo wire-format contract shared with
// the mobile client -- see docs/PROTOCOL.md.
package devicecert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// deviceIDBytes is the raw byte length of a device ID (before hex encoding).
const deviceIDBytes = 8

// NewDeviceID generates a new random device ID, hex-encoded (16 characters).
func NewDeviceID() (string, error) {
	raw := make([]byte, deviceIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("devicecert: generating device id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// DeviceCertificate authorizes a device's identity key under an account's
// root key.
type DeviceCertificate struct {
	AccountID    string            `json:"account_id"`
	DeviceID     string            `json:"device_id"`
	DevicePubKey ed25519.PublicKey `json:"device_pub_key"`
	IssuedAt     time.Time         `json:"issued_at"`
	Signature    []byte            `json:"signature"`
}

// SignDeviceCertificate builds and signs a new device certificate with the
// given account's root private key.
func SignDeviceCertificate(accountID, deviceID string, devicePubKey ed25519.PublicKey, issuedAt time.Time, rootPriv ed25519.PrivateKey) (*DeviceCertificate, error) {
	cert := &DeviceCertificate{
		AccountID:    accountID,
		DeviceID:     deviceID,
		DevicePubKey: devicePubKey,
		IssuedAt:     issuedAt,
	}
	buf, err := cert.signingBytes()
	if err != nil {
		return nil, err
	}
	cert.Signature = ed25519.Sign(rootPriv, buf)
	return cert, nil
}

// Verify checks the certificate's structure and its signature against the
// given root public key. A nil error means the certificate is valid.
func (c *DeviceCertificate) Verify(rootPubKey ed25519.PublicKey) error {
	buf, err := c.signingBytes()
	if err != nil {
		return err
	}
	if len(c.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("devicecert: signature must be %d bytes, got %d", ed25519.SignatureSize, len(c.Signature))
	}
	if !ed25519.Verify(rootPubKey, buf, c.Signature) {
		return errors.New("devicecert: signature verification failed")
	}
	return nil
}

func (c *DeviceCertificate) signingBytes() ([]byte, error) {
	deviceIDRaw, err := decodeDeviceID(c.DeviceID)
	if err != nil {
		return nil, err
	}
	if len(c.DevicePubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("devicecert: device public key must be %d bytes, got %d", ed25519.PublicKeySize, len(c.DevicePubKey))
	}

	var buf bytes.Buffer
	writeLengthPrefixed(&buf, []byte(c.AccountID))
	buf.Write(deviceIDRaw)
	buf.Write(c.DevicePubKey)
	writeLengthPrefixed(&buf, []byte(c.IssuedAt.UTC().Format(time.RFC3339)))
	return buf.Bytes(), nil
}

// DeviceRevocation revokes a previously certified device, signed by the
// account's root key.
type DeviceRevocation struct {
	AccountID string    `json:"account_id"`
	DeviceID  string    `json:"device_id"`
	RevokedAt time.Time `json:"revoked_at"`
	Signature []byte    `json:"signature"`
}

// SignDeviceRevocation builds and signs a new device revocation with the
// given account's root private key.
func SignDeviceRevocation(accountID, deviceID string, revokedAt time.Time, rootPriv ed25519.PrivateKey) (*DeviceRevocation, error) {
	rev := &DeviceRevocation{
		AccountID: accountID,
		DeviceID:  deviceID,
		RevokedAt: revokedAt,
	}
	buf, err := rev.signingBytes()
	if err != nil {
		return nil, err
	}
	rev.Signature = ed25519.Sign(rootPriv, buf)
	return rev, nil
}

// Verify checks the revocation's structure and its signature against the
// given root public key.
func (r *DeviceRevocation) Verify(rootPubKey ed25519.PublicKey) error {
	buf, err := r.signingBytes()
	if err != nil {
		return err
	}
	if len(r.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("devicecert: signature must be %d bytes, got %d", ed25519.SignatureSize, len(r.Signature))
	}
	if !ed25519.Verify(rootPubKey, buf, r.Signature) {
		return errors.New("devicecert: revocation signature verification failed")
	}
	return nil
}

func (r *DeviceRevocation) signingBytes() ([]byte, error) {
	deviceIDRaw, err := decodeDeviceID(r.DeviceID)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writeLengthPrefixed(&buf, []byte(r.AccountID))
	buf.Write(deviceIDRaw)
	writeLengthPrefixed(&buf, []byte(r.RevokedAt.UTC().Format(time.RFC3339)))
	return buf.Bytes(), nil
}

func decodeDeviceID(id string) ([]byte, error) {
	raw, err := hex.DecodeString(id)
	if err != nil {
		return nil, fmt.Errorf("devicecert: device id must be hex-encoded: %w", err)
	}
	if len(raw) != deviceIDBytes {
		return nil, fmt.Errorf("devicecert: device id must decode to %d bytes, got %d", deviceIDBytes, len(raw))
	}
	return raw, nil
}

func writeLengthPrefixed(buf *bytes.Buffer, data []byte) {
	var lenBytes [2]byte
	binary.BigEndian.PutUint16(lenBytes[:], uint16(len(data)))
	buf.Write(lenBytes[:])
	buf.Write(data)
}
