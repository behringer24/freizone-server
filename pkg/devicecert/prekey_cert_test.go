package devicecert

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func mustDeviceKey(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

func mustX25519PubKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return key.PublicKey().Bytes()
}

// TestPrekeyVerifyRejectsWrongLengthKeyWithoutPanic guards the defense-in-depth
// length check (audit L2) on both prekey certificate verifiers: a non-32-byte
// verifier key must be a returned error, not an ed25519.Verify panic.
func TestPrekeyVerifyRejectsWrongLengthKeyWithoutPanic(t *testing.T) {
	_, devicePriv := mustDeviceKey(t, 1)
	deviceID, _ := NewDeviceID()
	dhPub := mustX25519PubKey(t)

	dhCert, err := SignDHIdentityCertificate("account123", deviceID, dhPub, time.Now(), devicePriv)
	if err != nil {
		t.Fatalf("SignDHIdentityCertificate() error = %v", err)
	}
	if err := dhCert.Verify(make(ed25519.PublicKey, 10)); err == nil {
		t.Error("DHIdentityCertificate.Verify() with a 10-byte device key = nil, want an error (not a panic)")
	}

	spCert, err := SignSignedPrekeyCertificate("account123", deviceID, 1, dhPub, mustX25519PubKey(t), time.Now(), devicePriv)
	if err != nil {
		t.Fatalf("SignSignedPrekeyCertificate() error = %v", err)
	}
	if err := spCert.Verify(make(ed25519.PublicKey, 10)); err == nil {
		t.Error("SignedPrekeyCertificate.Verify() with a 10-byte device key = nil, want an error (not a panic)")
	}
}

func TestSignAndVerifyDHIdentityCertificate(t *testing.T) {
	devicePub, devicePriv := mustDeviceKey(t, 1)
	dhPub := mustX25519PubKey(t)
	deviceID, _ := NewDeviceID()

	cert, err := SignDHIdentityCertificate("account123", deviceID, dhPub, time.Now(), devicePriv)
	if err != nil {
		t.Fatalf("SignDHIdentityCertificate() error = %v", err)
	}
	if err := cert.Verify(devicePub); err != nil {
		t.Errorf("Verify() error = %v, want nil", err)
	}
}

func TestVerifyDHIdentityCertificateRejectsWrongDeviceKey(t *testing.T) {
	_, devicePriv := mustDeviceKey(t, 1)
	otherPub, _ := mustDeviceKey(t, 2)
	dhPub := mustX25519PubKey(t)
	deviceID, _ := NewDeviceID()

	cert, err := SignDHIdentityCertificate("account123", deviceID, dhPub, time.Now(), devicePriv)
	if err != nil {
		t.Fatalf("SignDHIdentityCertificate() error = %v", err)
	}
	if err := cert.Verify(otherPub); err == nil {
		t.Error("expected Verify() to fail against the wrong device key")
	}
}

func TestVerifyDHIdentityCertificateRejectsTamperedDHKey(t *testing.T) {
	devicePub, devicePriv := mustDeviceKey(t, 1)
	dhPub := mustX25519PubKey(t)
	deviceID, _ := NewDeviceID()

	cert, err := SignDHIdentityCertificate("account123", deviceID, dhPub, time.Now(), devicePriv)
	if err != nil {
		t.Fatalf("SignDHIdentityCertificate() error = %v", err)
	}

	cert.DHPubKey = mustX25519PubKey(t) // swap in a different (still validly-sized) key
	if err := cert.Verify(devicePub); err == nil {
		t.Error("expected Verify() to fail after swapping the dh public key")
	}
}

// The account id is signing input like any other field, so a *cosmetic*
// re-spelling of the very same id breaks verification just as a substituted one
// does. Worth pinning down rather than leaving implied: it is why a group event
// (pkg/group) may only carry the canonical id -- a member recorded under a
// dash-grouped one is verified against this certificate, fails here, and is
// unreachable while looking perfectly ordinary in the member list.
func TestVerifyDHIdentityCertificateRejectsARespelledAccountID(t *testing.T) {
	devicePub, devicePriv := mustDeviceKey(t, 1)
	dhPub := mustX25519PubKey(t)
	deviceID, _ := NewDeviceID()

	const accountID = "q2xjxe3gtqutyftankjcv"
	cert, err := SignDHIdentityCertificate(accountID, deviceID, dhPub, time.Now(), devicePriv)
	if err != nil {
		t.Fatalf("SignDHIdentityCertificate() error = %v", err)
	}

	cert.AccountID = "q2xjx-e3gtq-utyft-ankjc-v" // the same id, dash-grouped
	if err := cert.Verify(devicePub); err == nil {
		t.Error("expected Verify() to fail for a dash-grouped spelling of the signed account id")
	}
}

func TestDHIdentityCertificateRejectsWrongKeySize(t *testing.T) {
	_, devicePriv := mustDeviceKey(t, 1)
	deviceID, _ := NewDeviceID()

	if _, err := SignDHIdentityCertificate("account123", deviceID, []byte{1, 2, 3}, time.Now(), devicePriv); err == nil {
		t.Fatal("expected SignDHIdentityCertificate to reject an undersized dh public key")
	}
}

func TestSignAndVerifySignedPrekeyCertificate(t *testing.T) {
	devicePub, devicePriv := mustDeviceKey(t, 3)
	dhIdentityPub := mustX25519PubKey(t)
	prekeyPub := mustX25519PubKey(t)
	deviceID, _ := NewDeviceID()

	cert, err := SignSignedPrekeyCertificate("account123", deviceID, 1, dhIdentityPub, prekeyPub, time.Now(), devicePriv)
	if err != nil {
		t.Fatalf("SignSignedPrekeyCertificate() error = %v", err)
	}
	if err := cert.Verify(devicePub); err != nil {
		t.Errorf("Verify() error = %v, want nil", err)
	}
}

func TestVerifySignedPrekeyCertificateRejectsIdentityKeySubstitution(t *testing.T) {
	// This is exactly the attack the certificate is meant to prevent: a
	// signature over (dh_identity_pubkey, prekey_pubkey) must not verify
	// once the identity key is swapped for a different one, even though
	// the prekey itself is untouched.
	devicePub, devicePriv := mustDeviceKey(t, 3)
	dhIdentityPub := mustX25519PubKey(t)
	prekeyPub := mustX25519PubKey(t)
	deviceID, _ := NewDeviceID()

	cert, err := SignSignedPrekeyCertificate("account123", deviceID, 1, dhIdentityPub, prekeyPub, time.Now(), devicePriv)
	if err != nil {
		t.Fatalf("SignSignedPrekeyCertificate() error = %v", err)
	}

	cert.DHIdentityPubKey = mustX25519PubKey(t) // substitute a different identity key
	if err := cert.Verify(devicePub); err == nil {
		t.Error("expected Verify() to fail after substituting the dh identity key")
	}
}

func TestVerifySignedPrekeyCertificateRejectsTamperedFields(t *testing.T) {
	devicePub, devicePriv := mustDeviceKey(t, 3)
	dhIdentityPub := mustX25519PubKey(t)
	prekeyPub := mustX25519PubKey(t)
	deviceID, _ := NewDeviceID()

	cert, err := SignSignedPrekeyCertificate("account123", deviceID, 1, dhIdentityPub, prekeyPub, time.Now(), devicePriv)
	if err != nil {
		t.Fatalf("SignSignedPrekeyCertificate() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*SignedPrekeyCertificate)
	}{
		{"key id", func(c *SignedPrekeyCertificate) { c.KeyID = 99 }},
		{"prekey pubkey", func(c *SignedPrekeyCertificate) { c.PrekeyPubKey = mustX25519PubKey(t) }},
		{"account id", func(c *SignedPrekeyCertificate) { c.AccountID = "someone-else" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := *cert
			tampered.Signature = append([]byte{}, cert.Signature...)
			tt.mutate(&tampered)
			if err := tampered.Verify(devicePub); err == nil {
				t.Errorf("expected Verify() to fail after tampering with %s", tt.name)
			}
		})
	}
}

func TestSignedPrekeyCertificateRejectsWrongKeySizes(t *testing.T) {
	_, devicePriv := mustDeviceKey(t, 3)
	prekeyPub := mustX25519PubKey(t)
	dhIdentityPub := mustX25519PubKey(t)
	deviceID, _ := NewDeviceID()

	if _, err := SignSignedPrekeyCertificate("account123", deviceID, 1, []byte{1, 2, 3}, prekeyPub, time.Now(), devicePriv); err == nil {
		t.Error("expected rejection of undersized dh identity pubkey")
	}
	if _, err := SignSignedPrekeyCertificate("account123", deviceID, 1, dhIdentityPub, []byte{1, 2, 3}, time.Now(), devicePriv); err == nil {
		t.Error("expected rejection of undersized prekey pubkey")
	}
}
