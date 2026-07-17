package ratchet

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

type parties struct {
	aliceDHPriv *ecdh.PrivateKey
	bobDHPriv   *ecdh.PrivateKey
	bobSPKPriv  *ecdh.PrivateKey
	bobOTPKPriv *ecdh.PrivateKey
	otpkID      uint32
	bundle      RemoteBundle
}

func setupParties(t *testing.T, includeOneTimePrekey bool) parties {
	t.Helper()
	curve := ecdh.X25519()

	gen := func() *ecdh.PrivateKey {
		k, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}
		return k
	}

	p := parties{
		aliceDHPriv: gen(),
		bobDHPriv:   gen(),
		bobSPKPriv:  gen(),
		otpkID:      1,
	}
	p.bundle = RemoteBundle{
		DHIdentityPubKey: p.bobDHPriv.PublicKey(),
		SignedPrekeyID:   1,
		SignedPrekeyPub:  p.bobSPKPriv.PublicKey(),
	}
	if includeOneTimePrekey {
		p.bobOTPKPriv = gen()
		p.bundle.OneTimePrekeyID = &p.otpkID
		p.bundle.OneTimePrekeyPub = p.bobOTPKPriv.PublicKey()
	}
	return p
}

func mustInitiateAndRespond(t *testing.T, p parties) (alice, bob *Session) {
	t.Helper()

	alice, initial, err := InitiateSession(p.aliceDHPriv, p.bundle)
	if err != nil {
		t.Fatalf("InitiateSession() error = %v", err)
	}

	bob, err = RespondToSession(p.bobDHPriv, p.bobSPKPriv, p.bobOTPKPriv, initial)
	if err != nil {
		t.Fatalf("RespondToSession() error = %v", err)
	}
	return alice, bob
}

func TestX3DHAgreementWithOneTimePrekey(t *testing.T) {
	p := setupParties(t, true)
	alice, bob := mustInitiateAndRespond(t, p)

	header, ciphertext, err := alice.Encrypt([]byte("hello bob"))
	if err != nil {
		t.Fatalf("alice.Encrypt() error = %v", err)
	}
	plaintext, err := bob.Decrypt(header, ciphertext)
	if err != nil {
		t.Fatalf("bob.Decrypt() error = %v", err)
	}
	if string(plaintext) != "hello bob" {
		t.Errorf("plaintext = %q, want %q", plaintext, "hello bob")
	}
}

func TestX3DHAgreementWithoutOneTimePrekey(t *testing.T) {
	p := setupParties(t, false)
	alice, bob := mustInitiateAndRespond(t, p)

	header, ciphertext, err := alice.Encrypt([]byte("hello bob, no otpk"))
	if err != nil {
		t.Fatalf("alice.Encrypt() error = %v", err)
	}
	plaintext, err := bob.Decrypt(header, ciphertext)
	if err != nil {
		t.Fatalf("bob.Decrypt() error = %v", err)
	}
	if string(plaintext) != "hello bob, no otpk" {
		t.Errorf("plaintext = %q, want %q", plaintext, "hello bob, no otpk")
	}
}

func TestRespondToSessionRequiresOneTimePrekeyPrivWhenReferenced(t *testing.T) {
	p := setupParties(t, true)
	_, initial, err := InitiateSession(p.aliceDHPriv, p.bundle)
	if err != nil {
		t.Fatalf("InitiateSession() error = %v", err)
	}

	if _, err := RespondToSession(p.bobDHPriv, p.bobSPKPriv, nil, initial); err == nil {
		t.Error("expected RespondToSession() to fail when the referenced one-time prekey private key is missing")
	}
}

func TestSessionADIsFixedRegardlessOfSender(t *testing.T) {
	p := setupParties(t, true)
	alice, bob := mustInitiateAndRespond(t, p)

	if string(alice.AD) != string(bob.AD) {
		t.Fatalf("alice.AD and bob.AD differ:\nalice=%x\nbob=%x", alice.AD, bob.AD)
	}

	// Round-trip in both directions to make sure AD agreement isn't a
	// coincidence of who happens to send first.
	h1, c1, err := alice.Encrypt([]byte("from alice"))
	if err != nil {
		t.Fatalf("alice.Encrypt() error = %v", err)
	}
	if _, err := bob.Decrypt(h1, c1); err != nil {
		t.Fatalf("bob.Decrypt() error = %v", err)
	}

	h2, c2, err := bob.Encrypt([]byte("from bob"))
	if err != nil {
		t.Fatalf("bob.Encrypt() error = %v", err)
	}
	if _, err := alice.Decrypt(h2, c2); err != nil {
		t.Fatalf("alice.Decrypt() error = %v", err)
	}
}
