// Package attest implements Freizone server attestations: signed statements
// about a server -- its domain, a tier, a display subject and a validity
// window -- issued by the project and verified by a client or server itself
// against a small, compiled-in set of trusted issuer public keys. Nothing is
// ever consulted online to check one.
//
// See docs/design/19-attested-servers.md for the reasoning behind each
// choice recorded here: why the attestation binds the domain rather than
// the server's own identity key, why there is no revocation beyond expiry,
// and why trust anchors ship as a set rather than a single key.
//
// This package is MIT-licensed (see LICENSE in this directory), unlike the
// rest of this AGPL-3.0-or-later repository. A verification rule that only
// one implementation is permitted to use is not a verification rule, and any
// Freizone client -- not only this project's own -- must be able to verify
// an attestation without taking on copyleft to do it.
//
// SPDX-License-Identifier: MIT
package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Version1 is the original attestation format: domain, tier, subject,
// validity window, issuer key. Version2 adds Seats. Decode understands both;
// anything else it rejects outright rather than guessing at an unknown
// layout.
const Version1 = 1

// Version2 adds Seats to Version1's fields. Sign always produces Version2
// now; Version1 stays decodable so tokens issued before this field existed
// keep verifying (Seats reads back as 0, the same "unspecified" value a
// Version2 token would use for the same thing).
const Version2 = 2

// CurrentVersion is the format Sign produces.
const CurrentVersion = Version2

const (
	issuerKeySize = ed25519.PublicKeySize
	signatureSize = ed25519.SignatureSize

	maxDomainLen  = 1<<16 - 1
	maxTierLen    = 1<<8 - 1
	maxSubjectLen = 1<<16 - 1
)

// Tier classifies why a server was attested. Deliberately just a string, not
// a closed enum: new values must be introducible without a released client
// having to know them by name. A build meeting a tier it does not recognise
// should show a neutral "attested" label rather than nothing at all -- the
// standing forward-compatibility rule this project tracks as SRV-10 --
// which is also why this package does not validate Tier against the known
// constants below; that is a rendering decision for the caller, not a
// structural one for this package.
type Tier = string

// Tier values in use today.
const (
	// TierCommunity marks a server verified as non-commercial and operated
	// in agreement with the project -- the maintainer's own servers are the
	// first to carry it.
	TierCommunity = "community"
	// TierCommercial marks a server holding a paid licence.
	TierCommercial = "commercial"
)

// Attestation is a signed statement about one server. The zero value is not
// meaningful on its own -- build one with Sign, or parse one with Decode.
type Attestation struct {
	// Version is the format this attestation was built with -- Version1 or
	// Version2 today, see the constants above.
	Version int
	// Domain is the server this attestation is about, lower-cased. Valid
	// checks it case-insensitively against the domain a client is actually
	// talking to -- see docs/design/19-attested-servers.md on why the
	// attestation binds the domain rather than the server's own identity
	// key.
	Domain string
	// Tier is why this server was attested; see the Tier constants above.
	Tier string
	// Subject is a display name for the operator, e.g. "Example GmbH". Not
	// used for anything but presentation.
	Subject string
	// Seats is an advisory account-count ceiling shown to the operator's own
	// admins, not a technical limit -- nothing in this package or the server
	// enforces it, the same way expiry is warned about rather than enforced
	// (docs/design/19-attested-servers.md). 0 means "unspecified" -- either
	// an unlimited seat count, or a Version1 token that predates this field
	// entirely; the two are indistinguishable on purpose, since neither
	// implies a ceiling to warn about. Present on every tier, not only
	// commercial -- a community server can just as well be attested for an
	// unbounded seat count. Added in Version2.
	Seats uint32
	// IssuedAt and ExpiresAt bound the attestation's validity window.
	// Signing truncates both to whole seconds; sub-second precision is
	// never carried across Encode/Decode.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// IssuerKey is the Ed25519 public key that signed this attestation,
	// carried in the attestation itself so verification is self-describing
	// -- the same "the key ID is the public key, no lookup, no prior
	// handshake" shape this project already uses between a server and a
	// freizone-gateway instance. Verify checks it against a trusted set
	// rather than trusting it outright.
	IssuerKey ed25519.PublicKey
	// Signature is the Ed25519 signature over every field above, in the
	// fixed layout signingBytes defines.
	Signature []byte
}

// GenerateIssuerKey creates a new Ed25519 issuer keypair. A thin wrapper
// over crypto/ed25519 -- there is nothing attest-specific about the
// generation itself, this just gives the issuing tool and this package's
// tests one obvious, documented entry point.
//
// The private half this returns must never be written to a git repository
// or to any machine reachable from the network: see
// docs/design/19-attested-servers.md on why several issuer keys are
// generated together, offline, with only their public halves ever compiled
// into a client or server.
func GenerateIssuerKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Sign builds and signs a new attestation for domain, valid from issuedAt
// until expiresAt, under issuerPriv. The domain is normalized (trimmed,
// lower-cased) before it is stored and signed, so Valid's case-insensitive
// comparison is really comparing two values already in the same form rather
// than doing the work itself. seats is 0 for "unspecified/unlimited" -- see
// the Seats field doc.
func Sign(domain, tier, subject string, seats uint32, issuedAt, expiresAt time.Time, issuerPriv ed25519.PrivateKey) (*Attestation, error) {
	if len(issuerPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("attest: issuer private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(issuerPriv))
	}
	pub, ok := issuerPriv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("attest: issuer private key did not yield an Ed25519 public key")
	}

	a := &Attestation{
		Version:   CurrentVersion,
		Domain:    strings.ToLower(strings.TrimSpace(domain)),
		Tier:      tier,
		Subject:   subject,
		Seats:     seats,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		IssuerKey: pub,
	}
	buf, err := a.signingBytes()
	if err != nil {
		return nil, err
	}
	a.Signature = ed25519.Sign(issuerPriv, buf)
	return a, nil
}

// Verify checks the attestation's signature against trustedIssuers -- the
// set of issuer public keys this build was compiled with (see
// TrustedIssuers). It does not check the domain or the validity window;
// call Valid for that. The split mirrors pkg/devicecert's own separation
// between "is this signature genuine" and the business rules layered on top
// of it: an attestation can be genuinely signed and still be for the wrong
// server, or simply expired.
func (a *Attestation) Verify(trustedIssuers []ed25519.PublicKey) error {
	buf, err := a.signingBytes()
	if err != nil {
		return err
	}
	if len(a.Signature) != signatureSize {
		return fmt.Errorf("attest: signature must be %d bytes, got %d", signatureSize, len(a.Signature))
	}

	trusted := false
	for _, k := range trustedIssuers {
		if bytes.Equal(k, a.IssuerKey) {
			trusted = true
			break
		}
	}
	if !trusted {
		return errors.New("attest: issuer key is not in the trusted set")
	}

	if !ed25519.Verify(a.IssuerKey, buf, a.Signature) {
		return errors.New("attest: signature verification failed")
	}
	return nil
}

// Valid checks the business rules Verify deliberately leaves out: that this
// attestation is for domain (matched case-insensitively) and that now falls
// within its validity window. Call Verify first -- Valid says nothing about
// whether the attestation is genuine, only whether it applies.
func (a *Attestation) Valid(domain string, now time.Time) error {
	if !strings.EqualFold(a.Domain, strings.TrimSpace(domain)) {
		return fmt.Errorf("attest: attestation is for %q, not %q", a.Domain, domain)
	}
	if now.Before(a.IssuedAt) {
		return fmt.Errorf("attest: attestation is not valid until %s", a.IssuedAt.UTC().Format(time.RFC3339))
	}
	if !now.Before(a.ExpiresAt) {
		return fmt.Errorf("attest: attestation expired at %s", a.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// Encode serializes the attestation, signature included, into the single
// opaque token an operator pastes into their server's configuration and the
// server then serves verbatim on GET /v1/server-status. Nothing in it is
// sensitive -- see docs/design/19-attested-servers.md on why the token
// itself is not a secret; its safety comes from the domain binding, not from
// being hidden.
func (a *Attestation) Encode() (string, error) {
	body, err := a.signingBytes()
	if err != nil {
		return "", err
	}
	if len(a.Signature) != signatureSize {
		return "", fmt.Errorf("attest: signature must be %d bytes, got %d", signatureSize, len(a.Signature))
	}
	full := make([]byte, 0, len(body)+signatureSize)
	full = append(full, body...)
	full = append(full, a.Signature...)
	return base64.RawURLEncoding.EncodeToString(full), nil
}

// Decode parses a token produced by Encode. It only checks structure --
// call Verify against a trusted issuer set, then Valid against the domain
// actually being talked to, before relying on anything it returns.
func Decode(token string) (*Attestation, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return nil, fmt.Errorf("attest: invalid token encoding: %w", err)
	}
	r := bytes.NewReader(raw)

	version, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("attest: truncated token (version): %w", err)
	}
	if version != Version1 && version != Version2 {
		return nil, fmt.Errorf("attest: unsupported version %d", version)
	}

	domain, err := readLenPrefixed16(r)
	if err != nil {
		return nil, fmt.Errorf("attest: truncated token (domain): %w", err)
	}
	tier, err := readLenPrefixed8(r)
	if err != nil {
		return nil, fmt.Errorf("attest: truncated token (tier): %w", err)
	}
	subject, err := readLenPrefixed16(r)
	if err != nil {
		return nil, fmt.Errorf("attest: truncated token (subject): %w", err)
	}
	var seats uint32
	if version >= Version2 {
		seats, err = readUint32(r)
		if err != nil {
			return nil, fmt.Errorf("attest: truncated token (seats): %w", err)
		}
	}
	issuedAt, err := readUnixSeconds(r)
	if err != nil {
		return nil, fmt.Errorf("attest: truncated token (issued_at): %w", err)
	}
	expiresAt, err := readUnixSeconds(r)
	if err != nil {
		return nil, fmt.Errorf("attest: truncated token (expires_at): %w", err)
	}
	issuerKey := make([]byte, issuerKeySize)
	if _, err := io.ReadFull(r, issuerKey); err != nil {
		return nil, fmt.Errorf("attest: truncated token (issuer_key): %w", err)
	}
	signature := make([]byte, signatureSize)
	if _, err := io.ReadFull(r, signature); err != nil {
		return nil, fmt.Errorf("attest: truncated token (signature): %w", err)
	}
	if r.Len() != 0 {
		return nil, fmt.Errorf("attest: %d unexpected trailing byte(s) after signature", r.Len())
	}

	return &Attestation{
		Version:   int(version),
		Domain:    string(domain),
		Tier:      string(tier),
		Subject:   string(subject),
		Seats:     seats,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		IssuerKey: ed25519.PublicKey(issuerKey),
		Signature: signature,
	}, nil
}

// signingBytes is the fixed byte layout every signature covers: a
// cross-repo wire-format contract in the same spirit as pkg/devicecert's,
// except this one is public precisely because third-party clients must be
// able to reproduce it (see the package doc comment on the MIT licence).
// Field order and every length prefix are part of the contract for a given
// Version -- changing either needs a new one, which is exactly what
// Version2's Seats field did: everything through Subject is unchanged, then
// Version2 inserts four bytes before IssuedAt that Version1 never had.
func (a *Attestation) signingBytes() ([]byte, error) {
	if a.Version != Version1 && a.Version != Version2 {
		return nil, fmt.Errorf("attest: unsupported version %d", a.Version)
	}
	if len(a.Domain) == 0 || len(a.Domain) > maxDomainLen {
		return nil, fmt.Errorf("attest: domain length out of range: %d", len(a.Domain))
	}
	if len(a.Tier) == 0 || len(a.Tier) > maxTierLen {
		return nil, fmt.Errorf("attest: tier length out of range: %d", len(a.Tier))
	}
	if len(a.Subject) > maxSubjectLen {
		return nil, fmt.Errorf("attest: subject length out of range: %d", len(a.Subject))
	}
	if len(a.IssuerKey) != issuerKeySize {
		return nil, fmt.Errorf("attest: issuer key must be %d bytes, got %d", issuerKeySize, len(a.IssuerKey))
	}

	var buf bytes.Buffer
	buf.WriteByte(byte(a.Version))
	writeLenPrefixed16(&buf, []byte(a.Domain))
	writeLenPrefixed8(&buf, []byte(a.Tier))
	writeLenPrefixed16(&buf, []byte(a.Subject))
	if a.Version >= Version2 {
		writeUint32(&buf, a.Seats)
	}
	writeUnixSeconds(&buf, a.IssuedAt)
	writeUnixSeconds(&buf, a.ExpiresAt)
	buf.Write(a.IssuerKey)
	return buf.Bytes(), nil
}

func writeLenPrefixed16(buf *bytes.Buffer, data []byte) {
	var lenBytes [2]byte
	binary.BigEndian.PutUint16(lenBytes[:], uint16(len(data)))
	buf.Write(lenBytes[:])
	buf.Write(data)
}

func writeLenPrefixed8(buf *bytes.Buffer, data []byte) {
	buf.WriteByte(byte(len(data)))
	buf.Write(data)
}

func writeUint32(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

func readUint32(r *bytes.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func writeUnixSeconds(buf *bytes.Buffer, t time.Time) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(t.UTC().Unix()))
	buf.Write(b[:])
}

func readLenPrefixed16(r *bytes.Reader) ([]byte, error) {
	var lenBytes [2]byte
	if _, err := io.ReadFull(r, lenBytes[:]); err != nil {
		return nil, err
	}
	out := make([]byte, binary.BigEndian.Uint16(lenBytes[:]))
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func readLenPrefixed8(r *bytes.Reader) ([]byte, error) {
	n, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func readUnixSeconds(r *bytes.Reader) (time.Time, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(binary.BigEndian.Uint64(b[:])), 0).UTC(), nil
}
