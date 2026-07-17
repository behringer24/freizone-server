package ratchet

import (
	"encoding/json"
	"testing"
)

func TestRatchetManyMessagesBothDirectionsInOrder(t *testing.T) {
	p := setupParties(t, true)
	alice, bob := mustInitiateAndRespond(t, p)

	// Alice sends a burst; Bob decrypts in order.
	for i := 0; i < 5; i++ {
		msg := []byte("alice message " + string(rune('0'+i)))
		h, c, err := alice.Encrypt(msg)
		if err != nil {
			t.Fatalf("alice.Encrypt() error = %v", err)
		}
		got, err := bob.Decrypt(h, c)
		if err != nil {
			t.Fatalf("bob.Decrypt() error = %v", err)
		}
		if string(got) != string(msg) {
			t.Fatalf("got %q, want %q", got, msg)
		}
	}

	// Bob replies with a burst; Alice decrypts in order. This exercises the
	// DH ratchet transition (Bob's first send after only ever receiving).
	for i := 0; i < 5; i++ {
		msg := []byte("bob message " + string(rune('0'+i)))
		h, c, err := bob.Encrypt(msg)
		if err != nil {
			t.Fatalf("bob.Encrypt() error = %v", err)
		}
		got, err := alice.Decrypt(h, c)
		if err != nil {
			t.Fatalf("alice.Decrypt() error = %v", err)
		}
		if string(got) != string(msg) {
			t.Fatalf("got %q, want %q", got, msg)
		}
	}

	// And back again, to exercise a second DH ratchet transition on Alice's side.
	for i := 0; i < 3; i++ {
		msg := []byte("alice again " + string(rune('0'+i)))
		h, c, err := alice.Encrypt(msg)
		if err != nil {
			t.Fatalf("alice.Encrypt() error = %v", err)
		}
		got, err := bob.Decrypt(h, c)
		if err != nil {
			t.Fatalf("bob.Decrypt() error = %v", err)
		}
		if string(got) != string(msg) {
			t.Fatalf("got %q, want %q", got, msg)
		}
	}
}

func TestRatchetOutOfOrderDelivery(t *testing.T) {
	p := setupParties(t, true)
	alice, bob := mustInitiateAndRespond(t, p)

	type sent struct {
		header Header
		cipher []byte
		plain  string
	}

	var messages []sent
	for i := 0; i < 4; i++ {
		plain := "msg-" + string(rune('a'+i))
		h, c, err := alice.Encrypt([]byte(plain))
		if err != nil {
			t.Fatalf("alice.Encrypt() error = %v", err)
		}
		messages = append(messages, sent{header: h, cipher: c, plain: plain})
	}

	// Deliver to Bob out of order: 2, 0, 3, 1.
	order := []int{2, 0, 3, 1}
	for _, idx := range order {
		m := messages[idx]
		got, err := bob.Decrypt(m.header, m.cipher)
		if err != nil {
			t.Fatalf("bob.Decrypt(message %d) error = %v", idx, err)
		}
		if string(got) != m.plain {
			t.Errorf("message %d: got %q, want %q", idx, got, m.plain)
		}
	}
}

func TestRatchetOutOfOrderAcrossDHRatchetTransition(t *testing.T) {
	p := setupParties(t, true)
	alice, bob := mustInitiateAndRespond(t, p)

	// Alice sends two messages in her first sending chain.
	h1, c1, err := alice.Encrypt([]byte("first"))
	if err != nil {
		t.Fatalf("alice.Encrypt() error = %v", err)
	}
	h2, c2, err := alice.Encrypt([]byte("second"))
	if err != nil {
		t.Fatalf("alice.Encrypt() error = %v", err)
	}

	// Bob only receives the second message first -- this forces him to skip
	// message 0 in what will become an old receiving chain once he later
	// also ratchets forward himself.
	got2, err := bob.Decrypt(h2, c2)
	if err != nil {
		t.Fatalf("bob.Decrypt(second) error = %v", err)
	}
	if string(got2) != "second" {
		t.Fatalf("got %q, want %q", got2, "second")
	}

	// Bob replies (DH ratchet forward on his side).
	hReply, cReply, err := bob.Encrypt([]byte("reply"))
	if err != nil {
		t.Fatalf("bob.Encrypt() error = %v", err)
	}
	gotReply, err := alice.Decrypt(hReply, cReply)
	if err != nil {
		t.Fatalf("alice.Decrypt(reply) error = %v", err)
	}
	if string(gotReply) != "reply" {
		t.Fatalf("got %q, want %q", gotReply, "reply")
	}

	// Now the late first message from Alice's old sending chain finally
	// arrives at Bob.
	got1, err := bob.Decrypt(h1, c1)
	if err != nil {
		t.Fatalf("bob.Decrypt(first, delayed) error = %v", err)
	}
	if string(got1) != "first" {
		t.Fatalf("got %q, want %q", got1, "first")
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	p := setupParties(t, true)
	alice, bob := mustInitiateAndRespond(t, p)

	h, c, err := alice.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("alice.Encrypt() error = %v", err)
	}
	tampered := append([]byte{}, c...)
	tampered[0] ^= 0xFF

	if _, err := bob.Decrypt(h, tampered); err == nil {
		t.Error("expected Decrypt() to reject tampered ciphertext")
	}
}

func TestDecryptRejectsTamperedHeader(t *testing.T) {
	p := setupParties(t, true)
	alice, bob := mustInitiateAndRespond(t, p)

	h, c, err := alice.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("alice.Encrypt() error = %v", err)
	}
	h.N++ // claim a different message number than was actually used to seal it

	if _, err := bob.Decrypt(h, c); err == nil {
		t.Error("expected Decrypt() to reject a tampered header (bound into AEAD associated data)")
	}
}

func TestSessionJSONRoundTrip(t *testing.T) {
	p := setupParties(t, true)
	alice, bob := mustInitiateAndRespond(t, p)

	// Exchange a couple of messages before persisting, to exercise
	// non-zero-state serialization (chain keys, message counters).
	h, c, err := alice.Encrypt([]byte("before reload"))
	if err != nil {
		t.Fatalf("alice.Encrypt() error = %v", err)
	}
	if _, err := bob.Decrypt(h, c); err != nil {
		t.Fatalf("bob.Decrypt() error = %v", err)
	}

	data, err := json.Marshal(alice)
	if err != nil {
		t.Fatalf("json.Marshal(alice) error = %v", err)
	}
	var reloaded Session
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	h2, c2, err := reloaded.Encrypt([]byte("after reload"))
	if err != nil {
		t.Fatalf("reloaded.Encrypt() error = %v", err)
	}
	got, err := bob.Decrypt(h2, c2)
	if err != nil {
		t.Fatalf("bob.Decrypt(post-reload) error = %v", err)
	}
	if string(got) != "after reload" {
		t.Errorf("got %q, want %q", got, "after reload")
	}
}

func TestSessionJSONRoundTripPreservesSkippedKeys(t *testing.T) {
	p := setupParties(t, true)
	alice, bob := mustInitiateAndRespond(t, p)

	h1, c1, err := alice.Encrypt([]byte("skip me"))
	if err != nil {
		t.Fatalf("alice.Encrypt() error = %v", err)
	}
	h2, c2, err := alice.Encrypt([]byte("deliver me first"))
	if err != nil {
		t.Fatalf("alice.Encrypt() error = %v", err)
	}

	// Bob receives message 2 first, buffering a skipped key for message 1.
	if _, err := bob.Decrypt(h2, c2); err != nil {
		t.Fatalf("bob.Decrypt(second) error = %v", err)
	}
	if len(bob.Skipped) == 0 {
		t.Fatal("expected bob to have buffered at least one skipped message key")
	}

	data, err := json.Marshal(bob)
	if err != nil {
		t.Fatalf("json.Marshal(bob) error = %v", err)
	}
	var reloaded Session
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	got, err := reloaded.Decrypt(h1, c1)
	if err != nil {
		t.Fatalf("reloaded.Decrypt(first, from skipped key) error = %v", err)
	}
	if string(got) != "skip me" {
		t.Errorf("got %q, want %q", got, "skip me")
	}
}

func TestEncryptFailsWithoutSendingChain(t *testing.T) {
	p := setupParties(t, true)
	_, bob := mustInitiateAndRespond(t, p)

	// Bob has not received anything yet, so he has no sending chain.
	if _, _, err := bob.Encrypt([]byte("too early")); err == nil {
		t.Error("expected Encrypt() to fail before any receiving chain has been established")
	}
}
