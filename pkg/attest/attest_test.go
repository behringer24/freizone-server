// SPDX-License-Identifier: MIT
package attest

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func mustIssuerKey(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

func mustSign(t *testing.T, priv ed25519.PrivateKey, domain string, issuedAt, expiresAt time.Time) *Attestation {
	t.Helper()
	a, err := Sign(domain, TierCommunity, "Example GmbH", 0, issuedAt, expiresAt, priv)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return a
}

func TestGenerateIssuerKeyProducesUsableKeypair(t *testing.T) {
	pub, priv, err := GenerateIssuerKey()
	if err != nil {
		t.Fatalf("GenerateIssuerKey() error = %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("len(pub) = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("len(priv) = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	a := mustSign(t, priv, "chat.example.org", time.Now(), time.Now().Add(24*time.Hour))
	if err := a.Verify([]ed25519.PublicKey{pub}); err != nil {
		t.Errorf("Verify() with the generated key error = %v, want nil", err)
	}
}

func TestSignNormalizesDomain(t *testing.T) {
	_, priv := mustIssuerKey(t, 1)
	a := mustSign(t, priv, "  Chat.Example.ORG  ", time.Now(), time.Now().Add(time.Hour))
	if a.Domain != "chat.example.org" {
		t.Errorf("Domain = %q, want %q", a.Domain, "chat.example.org")
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv := mustIssuerKey(t, 1)
	now := time.Now()
	a := mustSign(t, priv, "chat.example.org", now, now.Add(24*time.Hour))

	if err := a.Verify([]ed25519.PublicKey{pub}); err != nil {
		t.Errorf("Verify() error = %v, want nil", err)
	}
}

func TestVerifyRejectsUntrustedIssuer(t *testing.T) {
	otherPub, _ := mustIssuerKey(t, 2)
	_, priv := mustIssuerKey(t, 1)
	now := time.Now()
	a := mustSign(t, priv, "chat.example.org", now, now.Add(24*time.Hour))

	if err := a.Verify([]ed25519.PublicKey{otherPub}); err == nil {
		t.Error("expected Verify() to fail when the signing key is not in the trusted set")
	}
}

func TestVerifyAcceptsAnyKeyInTrustedSet(t *testing.T) {
	pub1, priv1 := mustIssuerKey(t, 1)
	pub2, _ := mustIssuerKey(t, 2)
	pub3, _ := mustIssuerKey(t, 3)
	now := time.Now()
	a := mustSign(t, priv1, "chat.example.org", now, now.Add(24*time.Hour))

	if err := a.Verify([]ed25519.PublicKey{pub2, pub3, pub1}); err != nil {
		t.Errorf("Verify() error = %v, want nil when the signer is one of several trusted keys", err)
	}
}

func TestVerifyRejectsTamperedFields(t *testing.T) {
	pub, priv := mustIssuerKey(t, 1)
	now := time.Now()
	a := mustSign(t, priv, "chat.example.org", now, now.Add(24*time.Hour))

	tests := []struct {
		name   string
		mutate func(*Attestation)
	}{
		{"domain", func(a *Attestation) { a.Domain = "evil.example.org" }},
		{"tier", func(a *Attestation) { a.Tier = TierCommercial }},
		{"subject", func(a *Attestation) { a.Subject = "Someone Else GmbH" }},
		{"seats", func(a *Attestation) { a.Seats = a.Seats + 1 }},
		{"issued at", func(a *Attestation) { a.IssuedAt = a.IssuedAt.Add(-time.Hour) }},
		{"expires at", func(a *Attestation) { a.ExpiresAt = a.ExpiresAt.Add(time.Hour) }},
		{"issuer key", func(a *Attestation) { otherPub, _, _ := ed25519.GenerateKey(nil); a.IssuerKey = otherPub }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := *a
			tampered.Signature = append([]byte{}, a.Signature...)
			tt.mutate(&tampered)
			if err := tampered.Verify([]ed25519.PublicKey{pub}); err == nil {
				t.Errorf("expected Verify() to fail after tampering with %s", tt.name)
			}
		})
	}
}

func TestValidChecksDomainCaseInsensitively(t *testing.T) {
	_, priv := mustIssuerKey(t, 1)
	now := time.Now()
	a := mustSign(t, priv, "chat.example.org", now.Add(-time.Minute), now.Add(time.Hour))

	if err := a.Valid("Chat.Example.ORG", now); err != nil {
		t.Errorf("Valid() error = %v, want nil for a case-different match", err)
	}
	if err := a.Valid("other.example.org", now); err == nil {
		t.Error("expected Valid() to fail for a different domain")
	}
}

func TestValidRejectsOutsideWindow(t *testing.T) {
	_, priv := mustIssuerKey(t, 1)
	now := time.Now()

	notYetValid := mustSign(t, priv, "chat.example.org", now.Add(time.Hour), now.Add(2*time.Hour))
	if err := notYetValid.Valid("chat.example.org", now); err == nil {
		t.Error("expected Valid() to fail before issued_at")
	}

	expired := mustSign(t, priv, "chat.example.org", now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err := expired.Valid("chat.example.org", now); err == nil {
		t.Error("expected Valid() to fail after expires_at")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	pub, priv := mustIssuerKey(t, 1)
	now := time.Now()
	a := mustSign(t, priv, "chat.example.org", now, now.Add(30*24*time.Hour))

	token, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if token == "" {
		t.Fatal("Encode() returned an empty token")
	}

	decoded, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if decoded.Domain != a.Domain {
		t.Errorf("Domain = %q, want %q", decoded.Domain, a.Domain)
	}
	if decoded.Tier != a.Tier {
		t.Errorf("Tier = %q, want %q", decoded.Tier, a.Tier)
	}
	if decoded.Subject != a.Subject {
		t.Errorf("Subject = %q, want %q", decoded.Subject, a.Subject)
	}
	if !decoded.IssuedAt.Equal(a.IssuedAt.Truncate(time.Second)) {
		t.Errorf("IssuedAt = %v, want %v", decoded.IssuedAt, a.IssuedAt.Truncate(time.Second))
	}
	if !decoded.ExpiresAt.Equal(a.ExpiresAt.Truncate(time.Second)) {
		t.Errorf("ExpiresAt = %v, want %v", decoded.ExpiresAt, a.ExpiresAt.Truncate(time.Second))
	}

	if err := decoded.Verify([]ed25519.PublicKey{pub}); err != nil {
		t.Errorf("Verify() on the decoded attestation error = %v, want nil", err)
	}
	if err := decoded.Valid("chat.example.org", now); err != nil {
		t.Errorf("Valid() on the decoded attestation error = %v, want nil", err)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"not base64", "not-valid-base64!!!"},
		{"empty", ""},
		{"truncated", "AQ"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Decode(tt.token); err == nil {
				t.Errorf("expected Decode(%q) to fail", tt.token)
			}
		})
	}
}

func TestDecodeRejectsTrailingBytes(t *testing.T) {
	_, priv := mustIssuerKey(t, 1)
	now := time.Now()
	a := mustSign(t, priv, "chat.example.org", now, now.Add(time.Hour))

	token, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decoding test token: %v", err)
	}
	raw = append(raw, 0xff)
	tamperedToken := base64.RawURLEncoding.EncodeToString(raw)

	if _, err := Decode(tamperedToken); err == nil {
		t.Error("expected Decode() to reject a token with trailing bytes")
	}
}

func TestDecodeRejectsUnsupportedVersion(t *testing.T) {
	_, priv := mustIssuerKey(t, 1)
	now := time.Now()
	a := mustSign(t, priv, "chat.example.org", now, now.Add(time.Hour))

	token, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decoding test token: %v", err)
	}
	raw[0] = 99
	tamperedToken := base64.RawURLEncoding.EncodeToString(raw)

	if _, err := Decode(tamperedToken); err == nil {
		t.Error("expected Decode() to reject an unsupported version byte")
	}
}

func TestSignRejectsWrongIssuerKeySize(t *testing.T) {
	if _, err := Sign("chat.example.org", TierCommunity, "Example", 0, time.Now(), time.Now().Add(time.Hour), ed25519.PrivateKey([]byte{1, 2, 3})); err == nil {
		t.Fatal("expected Sign() to reject an undersized issuer private key")
	}
}

func TestSignRejectsEmptyDomain(t *testing.T) {
	_, priv := mustIssuerKey(t, 1)
	if _, err := Sign("", TierCommunity, "Example", 0, time.Now(), time.Now().Add(time.Hour), priv); err == nil {
		t.Fatal("expected Sign() to reject an empty domain")
	}
}

func TestSignRejectsEmptyTier(t *testing.T) {
	_, priv := mustIssuerKey(t, 1)
	if _, err := Sign("chat.example.org", "", "Example", 0, time.Now(), time.Now().Add(time.Hour), priv); err == nil {
		t.Fatal("expected Sign() to reject an empty tier")
	}
}

func TestSignProducesCurrentVersion(t *testing.T) {
	_, priv := mustIssuerKey(t, 1)
	now := time.Now()
	a := mustSign(t, priv, "chat.example.org", now, now.Add(time.Hour))
	if a.Version != CurrentVersion {
		t.Errorf("Version = %d, want CurrentVersion (%d)", a.Version, CurrentVersion)
	}
}

func TestEncodeDecodeRoundTripWithSeats(t *testing.T) {
	pub, priv := mustIssuerKey(t, 1)
	now := time.Now()
	a, err := Sign("chat.example.org", TierCommercial, "Example GmbH", 500, now, now.Add(30*24*time.Hour), priv)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	token, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if decoded.Seats != 500 {
		t.Errorf("Seats = %d, want 500", decoded.Seats)
	}
	if decoded.Version != Version2 {
		t.Errorf("Version = %d, want %d", decoded.Version, Version2)
	}
	if err := decoded.Verify([]ed25519.PublicKey{pub}); err != nil {
		t.Errorf("Verify() on the decoded attestation error = %v, want nil", err)
	}
}

func TestDecodeVersion1TokenReadsSeatsAsZero(t *testing.T) {
	// A hand-built Version1 token -- no Seats bytes at all -- must still
	// decode and verify, with Seats reading back as 0 ("unspecified"), not
	// as an error. Built directly rather than via Sign, which always
	// produces CurrentVersion now: this is standing in for a token issued
	// before Version2 existed.
	pub, priv := mustIssuerKey(t, 1)
	now := time.Now().Truncate(time.Second)
	v1 := &Attestation{
		Version:   Version1,
		Domain:    "chat.example.org",
		Tier:      TierCommunity,
		Subject:   "Example GmbH",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		IssuerKey: pub,
	}
	buf, err := v1.signingBytes()
	if err != nil {
		t.Fatalf("signingBytes() error = %v", err)
	}
	v1.Signature = ed25519.Sign(priv, buf)

	token, err := v1.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.Version != Version1 {
		t.Errorf("Version = %d, want %d", decoded.Version, Version1)
	}
	if decoded.Seats != 0 {
		t.Errorf("Seats = %d, want 0 for a Version1 token", decoded.Seats)
	}
	if err := decoded.Verify([]ed25519.PublicKey{pub}); err != nil {
		t.Errorf("Verify() on a decoded Version1 token error = %v, want nil", err)
	}
}

