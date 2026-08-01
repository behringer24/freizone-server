package ratchet

import (
	"errors"
	"fmt"
	"testing"
)

// The whole point of the Failure* codes is that a consumer can act on the
// distinction, so each test drives a real session into the failure rather than
// constructing the error by hand -- otherwise the mapping could drift away
// from what Decrypt actually returns and the tests would never notice.

func TestFailureCodeAuthenticationOnTamperedCiphertext(t *testing.T) {
	p := setupParties(t, true)
	alice, bob := mustInitiateAndRespond(t, p)

	h, c, err := alice.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("alice.Encrypt() error = %v", err)
	}
	tampered := append([]byte{}, c...)
	tampered[0] ^= 0xFF

	_, err = bob.Decrypt(h, tampered)
	if got := FailureCode(err); got != FailureAuthentication {
		t.Errorf("FailureCode(%v) = %q, want %q", err, got, FailureAuthentication)
	}
	if !SuggestsDesync(err) {
		t.Error("SuggestsDesync() = false for an authentication failure, want true")
	}
}

func TestFailureCodeDuplicateIsNotADesync(t *testing.T) {
	p := setupParties(t, true)
	alice, bob := mustInitiateAndRespond(t, p)

	h, c, err := alice.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("alice.Encrypt() error = %v", err)
	}
	if _, err := bob.Decrypt(h, c); err != nil {
		t.Fatalf("bob.Decrypt() error = %v", err)
	}

	_, err = bob.Decrypt(h, c) // at-least-once delivery: the same envelope again
	if got := FailureCode(err); got != FailureDuplicateMessage {
		t.Errorf("FailureCode(%v) = %q, want %q", err, got, FailureDuplicateMessage)
	}
	if SuggestsDesync(err) {
		t.Error("SuggestsDesync() = true for a redelivery, want false -- recovering from one would throw away a perfectly healthy session")
	}
}

func TestFailureCodeTooManySkipped(t *testing.T) {
	p := setupParties(t, true)
	alice, bob := mustInitiateAndRespond(t, p)

	h, c, err := alice.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("alice.Encrypt() error = %v", err)
	}
	h.N += maxSkippedMessageKeys + 1 // claim an absurd gap in Alice's chain

	_, err = bob.Decrypt(h, c)
	if got := FailureCode(err); got != FailureTooManySkipped {
		t.Errorf("FailureCode(%v) = %q, want %q", err, got, FailureTooManySkipped)
	}
	if !SuggestsDesync(err) {
		t.Error("SuggestsDesync() = false for an unbridgeable chain gap, want true")
	}
}

// A fresh initiator has a sending chain but no receiving one until the
// responder's first message arrives. A message claiming to already be several
// steps into that not-yet-existing chain is what a peer whose session state has
// been rolled back looks like from here -- the shape the cross-isolate
// last-writer-wins bug used to produce. Hand-built, because a healthy pair
// never emits it: the responder cannot even encrypt this early.
func TestFailureCodeNoReceivingChain(t *testing.T) {
	p := setupParties(t, true)
	alice, _, err := InitiateSession(p.aliceDHPriv, p.bundle)
	if err != nil {
		t.Fatalf("InitiateSession() error = %v", err)
	}

	// The responder's initial ratchet key IS its signed prekey (see §5), so
	// this header matches what Alice already holds as DHr -- no DH step is
	// taken, and the missing receiving chain is what stops it.
	header := Header{DHPub: p.bobSPKPriv.PublicKey().Bytes(), N: 3}

	_, err = alice.Decrypt(header, []byte("irrelevant"))
	if got := FailureCode(err); got != FailureNoReceivingChain {
		t.Errorf("FailureCode(%v) = %q, want %q", err, got, FailureNoReceivingChain)
	}
	if !SuggestsDesync(err) {
		t.Error("SuggestsDesync() = false for a message on a nonexistent receiving chain, want true")
	}
}

func TestFailureCodeLeavesUnknownErrorsUndiagnosed(t *testing.T) {
	if got := FailureCode(nil); got != "" {
		t.Errorf("FailureCode(nil) = %q, want empty", got)
	}
	other := fmt.Errorf("decoding persisted ratchet private key: %w", errors.New("bad key"))
	if got := FailureCode(other); got != "" {
		t.Errorf("FailureCode(%v) = %q, want empty", other, got)
	}
	if SuggestsDesync(other) {
		t.Error("SuggestsDesync() = true for an unclassified error, want false -- an undiagnosed failure is no reason to discard a session")
	}
}
