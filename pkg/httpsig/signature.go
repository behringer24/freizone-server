// Package httpsig implements Freizone's per-request signature
// authentication: every API request is signed by the calling device's
// Ed25519 identity key instead of carrying a session or password. Public
// (not internal) because both the server (verification, via
// internal/auth's Middleware) and any client -- including the mobile
// app's Go core -- need to build the same canonical string and, for
// clients, produce the Signature header itself.
package httpsig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HTTP headers carrying the signature material. Naming and canonicalization
// are a cross-repo wire-format contract -- see docs/PROTOCOL.md.
const (
	HeaderKeyID     = "Signature-Key-Id"
	HeaderTimestamp = "Signature-Timestamp"
	HeaderNonce     = "Signature-Nonce"
	HeaderSignature = "Signature"
)

// CanonicalString builds the exact newline-joined byte sequence that gets
// signed for a request:
//
//	METHOD\npath\nrawQuery\ntimestamp\nnonce\nkeyID\nsha256_hex(body)
func CanonicalString(method, path, rawQuery, timestamp, nonce, keyID string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	return strings.Join([]string{
		method,
		path,
		rawQuery,
		timestamp,
		nonce,
		keyID,
		hex.EncodeToString(bodyHash[:]),
	}, "\n")
}

// RequestSignatureHeaders holds the parsed values of the four signature
// headers from an incoming request.
type RequestSignatureHeaders struct {
	KeyID     string
	Timestamp string
	Nonce     string
	Signature string
}

// ParseRequestHeaders extracts the signature headers from r, returning an
// error if any are missing.
func ParseRequestHeaders(r *http.Request) (RequestSignatureHeaders, error) {
	h := RequestSignatureHeaders{
		KeyID:     r.Header.Get(HeaderKeyID),
		Timestamp: r.Header.Get(HeaderTimestamp),
		Nonce:     r.Header.Get(HeaderNonce),
		Signature: r.Header.Get(HeaderSignature),
	}
	if h.KeyID == "" || h.Timestamp == "" || h.Nonce == "" || h.Signature == "" {
		return RequestSignatureHeaders{}, errors.New("auth: missing signature header")
	}
	return h, nil
}

// CanonicalStringFromRequest builds the canonical string for an incoming
// request given its already-parsed signature headers and its raw body
// bytes (the caller is responsible for having read r.Body and restoring it
// for downstream handlers).
func CanonicalStringFromRequest(r *http.Request, h RequestSignatureHeaders, body []byte) string {
	return CanonicalString(r.Method, r.URL.Path, r.URL.RawQuery, h.Timestamp, h.Nonce, h.KeyID, body)
}

// Sign computes the base64-encoded signature for a request, for use by a
// client (or test code) constructing the Signature header.
func Sign(method, path, rawQuery string, body []byte, keyID string, timestamp time.Time, nonce string, priv ed25519.PrivateKey) string {
	canonical := CanonicalString(method, path, rawQuery, FormatTimestamp(timestamp), nonce, keyID, body)
	sig := ed25519.Sign(priv, []byte(canonical))
	return base64.StdEncoding.EncodeToString(sig)
}

// Verify checks a base64-encoded signature against the canonical string and
// device public key.
func Verify(canonical string, signatureB64 string, pubKey ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("auth: decoding signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("auth: signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	if !ed25519.Verify(pubKey, []byte(canonical), sig) {
		return errors.New("auth: signature verification failed")
	}
	return nil
}

// FormatTimestamp renders a time as the decimal Unix-seconds string used in
// the Signature-Timestamp header.
func FormatTimestamp(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}

// ParseTimestamp parses the Signature-Timestamp header value.
func ParseTimestamp(s string) (time.Time, error) {
	sec, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("auth: invalid timestamp: %w", err)
	}
	return time.Unix(sec, 0).UTC(), nil
}

// WithinSkew reports whether ts is within maxSkew of now, in either
// direction.
func WithinSkew(ts, now time.Time, maxSkew time.Duration) bool {
	diff := now.Sub(ts)
	if diff < 0 {
		diff = -diff
	}
	return diff <= maxSkew
}
