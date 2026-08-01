package ratchet

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

// The full recovery loop from §5, at the crypto layer: a genuinely desynced
// pair, the failure a client detects it by, and the re-key that heals it. The
// app's own automatic path (freizone-app's session_recovery.dart) is the policy
// on top -- when to give up and who re-keys first -- but if this loop didn't
// work underneath, no policy could save it.
//
// Desync is staged the way it actually happened in the field: one side ends up
// holding a session from a *different* X3DH exchange than the other, which is
// what a redelivered `prekey` block or a rolled-back profile save produced.

type peer struct {
	dhPriv  *ecdh.PrivateKey // long-term DH identity
	spkPriv *ecdh.PrivateKey // signed prekey, doubles as the initial ratchet key
}

func (p peer) bundle() RemoteBundle {
	return RemoteBundle{
		DHIdentityPubKey: p.dhPriv.PublicKey(),
		SignedPrekeyID:   1,
		SignedPrekeyPub:  p.spkPriv.PublicKey(),
	}
}

func newPeer(t *testing.T) peer {
	t.Helper()
	curve := ecdh.X25519()
	dh, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	spk, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return peer{dhPriv: dh, spkPriv: spk}
}

// send encrypts through from and decrypts through to, failing the test if
// either end refuses.
func send(t *testing.T, from, to *Session, text string) {
	t.Helper()
	h, c, err := from.Encrypt([]byte(text))
	if err != nil {
		t.Fatalf("Encrypt(%q) error = %v", text, err)
	}
	got, err := to.Decrypt(h, c)
	if err != nil {
		t.Fatalf("Decrypt(%q) error = %v", text, err)
	}
	if string(got) != text {
		t.Fatalf("plaintext = %q, want %q", got, text)
	}
}

func TestRekeyRecoversADesyncedPair(t *testing.T) {
	alice, bob := newPeer(t), newPeer(t)

	// A healthy conversation, in both directions.
	aliceSession, initial, err := InitiateSession(alice.dhPriv, bob.bundle())
	if err != nil {
		t.Fatalf("InitiateSession() error = %v", err)
	}
	bobSession, err := RespondToSession(bob.dhPriv, bob.spkPriv, nil, initial)
	if err != nil {
		t.Fatalf("RespondToSession() error = %v", err)
	}
	send(t, aliceSession, bobSession, "hello bob")
	send(t, bobSession, aliceSession, "hello alice")

	// Desync: Bob's session is replaced by one from an unrelated X3DH exchange,
	// while Alice keeps the original. Nothing about this is detectable up front
	// -- both sides believe they hold a working session.
	_, strayInitial, err := InitiateSession(alice.dhPriv, bob.bundle())
	if err != nil {
		t.Fatalf("InitiateSession() error = %v", err)
	}
	strandedBob, err := RespondToSession(bob.dhPriv, bob.spkPriv, nil, strayInitial)
	if err != nil {
		t.Fatalf("RespondToSession() error = %v", err)
	}

	// What detection actually sees, and why repetition is what makes it
	// conclusive: the same envelope fails identically every time.
	h, c, err := aliceSession.Encrypt([]byte("this one is lost"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		_, err := strandedBob.Decrypt(h, c)
		if got := FailureCode(err); got != FailureAuthentication {
			t.Fatalf("attempt %d: FailureCode(%v) = %q, want %q", attempt, err, got, FailureAuthentication)
		}
	}

	// Recovery: Bob discards the stranded session and initiates a fresh X3DH
	// against Alice's bundle -- the invisible re-key envelope (§6) is what
	// carries this on the wire. Alice accepts the `prekey` block over her
	// existing session because it decrypts the message that came with it.
	bobRekeyed, rekeyInitial, err := InitiateSession(bob.dhPriv, alice.bundle())
	if err != nil {
		t.Fatalf("InitiateSession() error = %v", err)
	}
	rekeyHeader, rekeyCiphertext, err := bobRekeyed.Encrypt([]byte("rekey"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	aliceRekeyed, err := RespondToSession(alice.dhPriv, alice.spkPriv, nil, rekeyInitial)
	if err != nil {
		t.Fatalf("RespondToSession() error = %v", err)
	}
	if _, err := aliceRekeyed.Decrypt(rekeyHeader, rekeyCiphertext); err != nil {
		t.Fatalf("the re-key must decrypt its own accompanying message, or a receiver has no way to tell it from a stale one: %v", err)
	}

	// Healed, both ways -- the direction that was broken first.
	send(t, bobRekeyed, aliceRekeyed, "can you read me now")
	send(t, aliceRekeyed, bobRekeyed, "yes")
}

// The guard that makes accepting a re-key safe at all: a `prekey` block that
// doesn't decrypt its own message must leave the receiver's existing session
// usable, so a stale or replayed one cannot break a healthy conversation.
func TestAStaleRekeyProposalCannotBreakAHealthySession(t *testing.T) {
	alice, bob := newPeer(t), newPeer(t)

	aliceSession, initial, err := InitiateSession(alice.dhPriv, bob.bundle())
	if err != nil {
		t.Fatalf("InitiateSession() error = %v", err)
	}
	bobSession, err := RespondToSession(bob.dhPriv, bob.spkPriv, nil, initial)
	if err != nil {
		t.Fatalf("RespondToSession() error = %v", err)
	}
	send(t, aliceSession, bobSession, "hello bob")

	// A `prekey` block Bob never sent this message under: Alice builds the
	// responder session it implies and tries it against a message that actually
	// belongs to the live session.
	_, stray, err := InitiateSession(bob.dhPriv, alice.bundle())
	if err != nil {
		t.Fatalf("InitiateSession() error = %v", err)
	}
	h, c, err := bobSession.Encrypt([]byte("an ordinary reply"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	speculative, err := RespondToSession(alice.dhPriv, alice.spkPriv, nil, stray)
	if err != nil {
		t.Fatalf("RespondToSession() error = %v", err)
	}
	if _, err := speculative.Decrypt(h, c); err == nil {
		t.Fatal("a session built from an unrelated prekey block must not decrypt this message")
	}

	// Alice falls back to the live session, and that very message still reads.
	got, err := aliceSession.Decrypt(h, c)
	if err != nil {
		t.Fatalf("the live session must still decrypt after a rejected re-key proposal: %v", err)
	}
	if string(got) != "an ordinary reply" {
		t.Errorf("plaintext = %q, want %q", got, "an ordinary reply")
	}
	// And keeps working afterwards, in both directions.
	send(t, aliceSession, bobSession, "still here")
	send(t, bobSession, aliceSession, "so am i")
}
