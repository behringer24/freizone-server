// Package profileclaim implements the self-asserted profile name: a short
// name an account states about itself, signed by one of its device identity
// keys and carried inside the encrypted channel (SRV-32).
//
// The signing byte layout is a cross-repo wire-format contract shared with
// the mobile client -- see docs/PROTOCOL.md §6.
//
// It is its own package, and not part of pkg/client, for the reason pkg/address
// is its own package: verifying a claim needs no store, no HTTP and no session,
// so the server can check the claims a report carries (SRV-33) without
// importing the client core that opens an account directory.
package profileclaim

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// deviceIDBytes is the raw byte length of a device ID (before hex encoding),
// matching pkg/devicecert.
const deviceIDBytes = 8

// MaxNameBytes bounds a name on the wire. Long enough for a full name with a
// role after it ("Andreas Behringer (Kassenwart)"), short enough that it can
// never be a message in disguise -- this field rides on every conversation an
// account has, and nothing renders it with room to grow.
const MaxNameBytes = 64

// Claim is one signed statement of the form "this account calls itself N".
//
// AccountID is deliberately **not** on the wire: the recipient already knows
// who sent the envelope it arrived in, so sending it would pay for the same
// string on every message. It is covered by the signature all the same, which
// is what stops a claim being lifted out of one account's message and replayed
// under another's identity.
type Claim struct {
	Name      string    `json:"name"`
	DeviceID  string    `json:"device_id"`
	IssuedAt  time.Time `json:"issued_at"`
	Signature []byte    `json:"signature"`
}

// Sign builds and signs a claim with a device's identity private key.
//
// The device key, not the root key: the root key never leaves the primary
// device (PROTOCOL §2), and a name people correct from whichever phone is in
// their hand must not require it. The chain root -> device certificate ->
// claim stays verifiable by any recipient from GET /v1/accounts/{id}.
func Sign(accountID, deviceID, name string, issuedAt time.Time, devicePriv ed25519.PrivateKey) (*Claim, error) {
	name = NormalizeName(name)
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	// Truncated to the second: the signing bytes are RFC 3339 without
	// fractions, so anything finer would be signed away and leave the wire
	// value disagreeing with what was actually covered.
	c := &Claim{Name: name, DeviceID: deviceID, IssuedAt: issuedAt.UTC().Truncate(time.Second)}
	buf, err := c.signingBytes(accountID)
	if err != nil {
		return nil, err
	}
	c.Signature = ed25519.Sign(devicePriv, buf)
	return c, nil
}

// Verify checks a claim's structure and its signature.
//
// The caller is responsible for the rest of the chain: that devicePubKey is
// the key of the device the claim names, and that the device is certified by
// the account it is being verified for. This function cannot check either --
// it has no key material beyond what it is handed -- and a caller that skips
// them has verified nothing worth having.
func (c *Claim) Verify(accountID string, devicePubKey ed25519.PublicKey) error {
	// Structure before signature: a name that breaks the rules is refused even
	// when it is correctly signed, or a hostile client could sign its way past
	// every display rule this package exists to enforce.
	if err := ValidateName(c.Name); err != nil {
		return err
	}
	if len(c.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("profileclaim: signature must be %d bytes, got %d", ed25519.SignatureSize, len(c.Signature))
	}
	if len(devicePubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("profileclaim: device public key must be %d bytes, got %d", ed25519.PublicKeySize, len(devicePubKey))
	}
	buf, err := c.signingBytes(accountID)
	if err != nil {
		return err
	}
	if !ed25519.Verify(devicePubKey, buf, c.Signature) {
		return errors.New("profileclaim: signature verification failed")
	}
	return nil
}

// IsWithdrawal reports whether this claim retracts the name rather than
// setting one. An empty name is how somebody clears their profile; without it
// there would be no way back out of having stated one.
func (c *Claim) IsWithdrawal() bool { return c.Name == "" }

// SupersedesTime reports whether this claim is newer than a previously stored
// one, which is the only ordering rule there is: last writer wins, per
// account, by the sender's own clock.
//
// Comparing two claims by one account's clock is safe in a way that comparing
// either against local time is not -- the two sides never have to agree on the
// time, only on which of two statements came second. Equal timestamps do not
// supersede: a replayed claim must not displace the copy already stored.
func (c *Claim) SupersedesTime(stored time.Time) bool {
	return c.IssuedAt.After(stored)
}

// NormalizeName trims the surrounding whitespace a text field collects. It
// deliberately does no Unicode normalization: the signature covers the exact
// bytes, so any normalization would have to happen identically in every
// client before signing or the signature stops verifying.
func NormalizeName(name string) string { return strings.TrimSpace(name) }

// ValidateName enforces what a name may contain. Empty is valid -- it is the
// withdrawal (see IsWithdrawal).
func ValidateName(name string) error {
	if len(name) > MaxNameBytes {
		return fmt.Errorf("profileclaim: name must be at most %d bytes, got %d", MaxNameBytes, len(name))
	}
	if name != strings.TrimSpace(name) {
		return errors.New("profileclaim: name must not start or end with whitespace")
	}
	for _, r := range name {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			// A name is one line. Line breaks would let it impersonate the
			// surrounding UI wherever it is rendered.
			return errors.New("profileclaim: name must not contain line breaks or tabs")
		case unicode.IsControl(r):
			return fmt.Errorf("profileclaim: name must not contain control character %U", r)
		case isBidiControl(r):
			// The spoofing case this rule exists for: an override can make a
			// name render as something other than what it says, which is the
			// whole point of showing the asserted name to a moderator.
			return fmt.Errorf("profileclaim: name must not contain bidirectional control character %U", r)
		}
	}
	return nil
}

// isBidiControl reports the explicit directional formatting characters.
//
// Written as code points on purpose: spelling them literally would put invisible
// characters into a source file, which is the very trick this guards against.
// Zero-width joiners are deliberately absent -- they are how composed emoji
// are written, and they cannot reorder anything.
func isBidiControl(r rune) bool {
	switch {
	case r == 0x200E || r == 0x200F: // LRM, RLM
		return true
	case r >= 0x202A && r <= 0x202E: // LRE, RLE, PDF, LRO, RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI, RLI, FSI, PDI
		return true
	}
	return false
}

// signingBytes is the cross-repo contract (PROTOCOL §6):
//
//	uint16BE(len(account_id)) || account_id
//	|| device_id (8 raw bytes)
//	|| uint16BE(len(name))    || name
//	|| uint16BE(len(issued_at_str)) || issued_at_str
//
// The account id is in there so a claim cannot be replayed under another
// identity; the server half of the address is not, so an SRV-24 move leaves
// every claim in the field intact.
func (c *Claim) signingBytes(accountID string) ([]byte, error) {
	if accountID == "" {
		return nil, errors.New("profileclaim: account id is required")
	}
	deviceIDRaw, err := hex.DecodeString(c.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("profileclaim: device id must be hex-encoded: %w", err)
	}
	if len(deviceIDRaw) != deviceIDBytes {
		return nil, fmt.Errorf("profileclaim: device id must decode to %d bytes, got %d", deviceIDBytes, len(deviceIDRaw))
	}

	var buf bytes.Buffer
	writeLengthPrefixed(&buf, []byte(accountID))
	buf.Write(deviceIDRaw)
	writeLengthPrefixed(&buf, []byte(c.Name))
	writeLengthPrefixed(&buf, []byte(c.IssuedAt.UTC().Format(time.RFC3339)))
	return buf.Bytes(), nil
}

func writeLengthPrefixed(buf *bytes.Buffer, data []byte) {
	var lenBytes [2]byte
	binary.BigEndian.PutUint16(lenBytes[:], uint16(len(data)))
	buf.Write(lenBytes[:])
	buf.Write(data)
}
