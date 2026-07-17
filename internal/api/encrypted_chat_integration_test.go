package api

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/ratchet"
	"github.com/behringer24/freizone-server/internal/wire"
)

func mustBase64Decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode %q: %v", s, err)
	}
	return b
}

// TestEndToEndEncryptedChat exercises the full path a real client would
// take: register two accounts, upload prekeys, claim a bundle, run X3DH,
// and exchange Double-Ratchet-encrypted messages through the real
// send/list/delete API -- proving internal/ratchet, internal/wire, and the
// prekey/message endpoints all fit together correctly, end to end.
func TestEndToEndEncryptedChat(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	handler := a.Router()
	curve := ecdh.X25519()

	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	aliceKeys := uploadPrekeysT(t, handler, alice, 0)
	bobKeys := uploadPrekeysT(t, handler, bob, 1)

	// Alice claims Bob's prekey bundle, exactly as a real initiator would.
	claimRec := doRequest(t, handler, http.MethodPost, "/v1/devices/"+bob.deviceID+"/prekey-bundle", nil)
	if claimRec.Code != http.StatusOK {
		t.Fatalf("claim status = %d, want 200, body = %s", claimRec.Code, claimRec.Body.String())
	}
	var bundle prekeyBundleResponse
	decodeJSON(t, claimRec, &bundle)

	bobDHIdentityPub, err := curve.NewPublicKey(mustBase64Decode(t, bundle.DHIdentityPubKey))
	if err != nil {
		t.Fatalf("parsing dh identity pubkey: %v", err)
	}
	bobSPKPub, err := curve.NewPublicKey(mustBase64Decode(t, bundle.SignedPrekey.PubKey))
	if err != nil {
		t.Fatalf("parsing signed prekey pubkey: %v", err)
	}

	remote := ratchet.RemoteBundle{
		DHIdentityPubKey: bobDHIdentityPub,
		SignedPrekeyID:   bundle.SignedPrekey.KeyID,
		SignedPrekeyPub:  bobSPKPub,
	}
	if bundle.OneTimePrekey != nil {
		otpkPub, err := curve.NewPublicKey(mustBase64Decode(t, bundle.OneTimePrekey.PubKey))
		if err != nil {
			t.Fatalf("parsing one-time prekey pubkey: %v", err)
		}
		keyID := bundle.OneTimePrekey.KeyID
		remote.OneTimePrekeyID = &keyID
		remote.OneTimePrekeyPub = otpkPub
	}

	// Alice initiates X3DH + Double Ratchet and sends her first message.
	aliceSession, initial, err := ratchet.InitiateSession(aliceKeys.dhPriv, remote)
	if err != nil {
		t.Fatalf("InitiateSession() error = %v", err)
	}

	plaintext1 := []byte("hello bob, this is alice")
	header1, ciphertext1, err := aliceSession.Encrypt(plaintext1)
	if err != nil {
		t.Fatalf("aliceSession.Encrypt() error = %v", err)
	}

	payload1, err := wire.NewEnvelope(initial, header1, ciphertext1).MarshalPayload()
	if err != nil {
		t.Fatalf("MarshalPayload() error = %v", err)
	}

	sendBody1, err := json.Marshal(sendMessageRequest{MessageID: "chat1", RecipientDeviceID: bob.deviceID, Payload: payload1})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	sendRec1 := doSignedRequest(t, handler, http.MethodPost, "/v1/messages", sendBody1, alice.deviceID, alice.devicePriv)
	if sendRec1.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202, body = %s", sendRec1.Code, sendRec1.Body.String())
	}

	// Bob polls, reconstructs the session via X3DH, and decrypts.
	listRec1 := doSignedRequest(t, handler, http.MethodGet, "/v1/messages", nil, bob.deviceID, bob.devicePriv)
	var bobInbox []messageResponse
	decodeJSON(t, listRec1, &bobInbox)
	if len(bobInbox) != 1 {
		t.Fatalf("len(bobInbox) = %d, want 1", len(bobInbox))
	}

	env1, err := wire.ParseEnvelope(bobInbox[0].Payload)
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	if env1.Prekey == nil {
		t.Fatal("expected the first message to carry x3dh prekey fields")
	}
	initialMsg, err := env1.Prekey.ToInitialMessage()
	if err != nil {
		t.Fatalf("ToInitialMessage() error = %v", err)
	}
	header1Decoded, err := env1.Header.ToHeader()
	if err != nil {
		t.Fatalf("ToHeader() error = %v", err)
	}
	ciphertext1Decoded, err := env1.DecodeCiphertext()
	if err != nil {
		t.Fatalf("DecodeCiphertext() error = %v", err)
	}

	var otpkPriv *ecdh.PrivateKey
	if initialMsg.OneTimePrekeyID != nil {
		otpkPriv = bobKeys.otpkPrivs[*initialMsg.OneTimePrekeyID]
	}
	bobSession, err := ratchet.RespondToSession(bobKeys.dhPriv, bobKeys.spkPriv, otpkPriv, initialMsg)
	if err != nil {
		t.Fatalf("RespondToSession() error = %v", err)
	}

	decrypted1, err := bobSession.Decrypt(header1Decoded, ciphertext1Decoded)
	if err != nil {
		t.Fatalf("bobSession.Decrypt() error = %v", err)
	}
	if string(decrypted1) != string(plaintext1) {
		t.Errorf("decrypted1 = %q, want %q", decrypted1, plaintext1)
	}

	ackRec := doSignedRequest(t, handler, http.MethodDelete, "/v1/messages/chat1", nil, bob.deviceID, bob.devicePriv)
	if ackRec.Code != http.StatusOK {
		t.Fatalf("ack status = %d, want 200, body = %s", ackRec.Code, ackRec.Body.String())
	}

	// Bob replies on the now-established session (no more X3DH fields needed).
	plaintext2 := []byte("hi alice, bob here")
	header2, ciphertext2, err := bobSession.Encrypt(plaintext2)
	if err != nil {
		t.Fatalf("bobSession.Encrypt() error = %v", err)
	}
	payload2, err := wire.NewEnvelope(nil, header2, ciphertext2).MarshalPayload()
	if err != nil {
		t.Fatalf("MarshalPayload() error = %v", err)
	}
	sendBody2, err := json.Marshal(sendMessageRequest{MessageID: "chat2", RecipientDeviceID: alice.deviceID, Payload: payload2})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	sendRec2 := doSignedRequest(t, handler, http.MethodPost, "/v1/messages", sendBody2, bob.deviceID, bob.devicePriv)
	if sendRec2.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202, body = %s", sendRec2.Code, sendRec2.Body.String())
	}

	listRec2 := doSignedRequest(t, handler, http.MethodGet, "/v1/messages", nil, alice.deviceID, alice.devicePriv)
	var aliceInbox []messageResponse
	decodeJSON(t, listRec2, &aliceInbox)
	if len(aliceInbox) != 1 {
		t.Fatalf("len(aliceInbox) = %d, want 1", len(aliceInbox))
	}

	env2, err := wire.ParseEnvelope(aliceInbox[0].Payload)
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	if env2.Prekey != nil {
		t.Error("expected the reply to carry no x3dh prekey fields")
	}
	header2Decoded, err := env2.Header.ToHeader()
	if err != nil {
		t.Fatalf("ToHeader() error = %v", err)
	}
	ciphertext2Decoded, err := env2.DecodeCiphertext()
	if err != nil {
		t.Fatalf("DecodeCiphertext() error = %v", err)
	}

	decrypted2, err := aliceSession.Decrypt(header2Decoded, ciphertext2Decoded)
	if err != nil {
		t.Fatalf("aliceSession.Decrypt() error = %v", err)
	}
	if string(decrypted2) != string(plaintext2) {
		t.Errorf("decrypted2 = %q, want %q", decrypted2, plaintext2)
	}
}
