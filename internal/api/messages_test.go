package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// generateTestPushSubscriptionKeys returns a syntactically and
// cryptographically valid p256dh/auth pair -- webpush-go performs real
// ECDH against p256dh when sending, so these can't be placeholder
// strings the way most other test fixtures in this file are.
func generateTestPushSubscriptionKeys(t *testing.T) (p256dh, auth string) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating p256 key: %v", err)
	}
	authBytes := make([]byte, 16)
	if _, err := rand.Read(authBytes); err != nil {
		t.Fatalf("generating auth secret: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), base64.RawURLEncoding.EncodeToString(authBytes)
}

func sendMessageBody(t *testing.T, messageID, recipientDeviceID string, payload string) []byte {
	t.Helper()
	body, err := json.Marshal(sendMessageRequest{
		MessageID:         messageID,
		RecipientDeviceID: recipientDeviceID,
		Payload:           json.RawMessage(payload),
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return body
}

func TestHandleSendListAndDeleteMessage(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	sendRec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", sendMessageBody(t, "msg1", bob.deviceID, `{"ciphertext":"abc"}`), alice.deviceID, alice.devicePriv)
	if sendRec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202, body = %s", sendRec.Code, sendRec.Body.String())
	}

	listRec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/messages", nil, bob.deviceID, bob.devicePriv)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200, body = %s", listRec.Code, listRec.Body.String())
	}
	var messages []messageResponse
	decodeJSON(t, listRec, &messages)
	if len(messages) != 1 || messages[0].MessageID != "msg1" {
		t.Fatalf("messages = %+v, want one message msg1", messages)
	}
	if messages[0].SenderAccountID != alice.accountID {
		t.Errorf("sender_account_id = %q, want %q", messages[0].SenderAccountID, alice.accountID)
	}

	deleteRec := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/messages/msg1", nil, bob.deviceID, bob.devicePriv)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200, body = %s", deleteRec.Code, deleteRec.Body.String())
	}

	listRec2 := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/messages", nil, bob.deviceID, bob.devicePriv)
	var messages2 []messageResponse
	decodeJSON(t, listRec2, &messages2)
	if len(messages2) != 0 {
		t.Errorf("messages after delete = %+v, want none", messages2)
	}
}

func TestHandleSendMessageRejectsWhenRecipientQueueIsFull(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	a.Config.MaxQueuedMessagesPerDevice = 2
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	for i, id := range []string{"msg1", "msg2"} {
		rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", sendMessageBody(t, id, bob.deviceID, `{}`), alice.deviceID, alice.devicePriv)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("send #%d status = %d, want 202, body = %s", i+1, rec.Code, rec.Body.String())
		}
	}

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", sendMessageBody(t, "msg3", bob.deviceID, `{}`), alice.deviceID, alice.devicePriv)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("third send status = %d, want 429, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSendMessageRejectsOversizedBody(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	body := sendMessageBody(t, "msg-too-large", bob.deviceID, `{"ciphertext":"abc"}`)
	const path = "/v1/messages"
	ts := time.Now()
	nonce := "nonce-too-large"
	sig := httpsig.Sign(http.MethodPost, path, "", body, alice.deviceID, ts, nonce, alice.devicePriv)

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(httpsig.HeaderKeyID, alice.deviceID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	rec := httptest.NewRecorder()
	// Simulates internal/server's withMaxBody middleware, which isn't
	// part of a.Router() itself -- one byte under the real body size, so
	// the read is guaranteed to be cut short.
	req.Body = http.MaxBytesReader(rec, req.Body, int64(len(body)-1))
	a.Router().ServeHTTP(rec, req)

	// This route is wrapped in a.Auth.Require (internal/auth/
	// middleware.go), which reads the body itself first, to verify the
	// request signature, before this handler ever runs -- so the
	// MaxBytesError is hit there, and internal/auth's blanket "same 401
	// for every failure mode" policy applies, not this handler's own
	// (413) handling of the same error. The oversized body is still
	// rejected either way -- decodeJSONBody's 413 path is exercised by
	// handleReceiveFederatedMessage instead, which has no such
	// preceding middleware (see federation_test.go).
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (rejected by auth middleware's own body read), body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSendMessageUnknownRecipient(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", sendMessageBody(t, "msg1", "no-such-device", `{}`), alice.deviceID, alice.devicePriv)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSendMessageDuplicateID(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	body := sendMessageBody(t, "dup", bob.deviceID, `{}`)
	rec1 := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", body, alice.deviceID, alice.devicePriv)
	if rec1.Code != http.StatusAccepted {
		t.Fatalf("first send status = %d, want 202", rec1.Code)
	}
	rec2 := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", body, alice.deviceID, alice.devicePriv)
	if rec2.Code != http.StatusConflict {
		t.Errorf("second send status = %d, want 409, body = %s", rec2.Code, rec2.Body.String())
	}
}

func TestHandleDeleteMessageWrongOwner(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)
	eve := registerAccount(t, a)

	sendRec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", sendMessageBody(t, "msg1", bob.deviceID, `{}`), alice.deviceID, alice.devicePriv)
	if sendRec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202", sendRec.Code)
	}

	rec := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/messages/msg1", nil, eve.deviceID, eve.devicePriv)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleMessageStreamLivePush(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	ts := httptest.NewServer(a.Router())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	streamReq := newSignedHTTPRequest(t, http.MethodGet, ts.URL+"/v1/messages/stream", nil, bob.deviceID, bob.devicePriv)
	streamReq = streamReq.WithContext(ctx)

	resp, err := ts.Client().Do(streamReq)
	if err != nil {
		t.Fatalf("opening stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}

	// Send a message only after the stream is open, to exercise the live
	// push path (not the initial-flush-of-pending path).
	go func() {
		time.Sleep(50 * time.Millisecond)
		sendReq := newSignedHTTPRequest(t, http.MethodPost, ts.URL+"/v1/messages", sendMessageBody(t, "live1", bob.deviceID, `{"ciphertext":"live"}`), alice.deviceID, alice.devicePriv)
		sendResp, err := ts.Client().Do(sendReq)
		if err != nil {
			t.Errorf("sending live message: %v", err)
			return
		}
		sendResp.Body.Close()
	}()

	type result struct {
		line string
		err  error
	}
	lineCh := make(chan result, 1)
	go func() {
		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				lineCh <- result{err: err}
				return
			}
			if strings.HasPrefix(line, "data: ") {
				lineCh <- result{line: line}
				return
			}
		}
	}()

	select {
	case r := <-lineCh:
		if r.err != nil {
			t.Fatalf("reading SSE stream: %v", r.err)
		}
		var got messageResponse
		if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(r.line), "data: ")), &got); err != nil {
			t.Fatalf("decoding SSE data line %q: %v", r.line, err)
		}
		if got.MessageID != "live1" {
			t.Errorf("MessageID = %q, want live1", got.MessageID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for live SSE push")
	}
}

func TestHandleMessageStreamFlushesPending(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	// Queue a message before the stream is ever opened.
	sendRec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", sendMessageBody(t, "pending1", bob.deviceID, `{"ciphertext":"pending"}`), alice.deviceID, alice.devicePriv)
	if sendRec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202", sendRec.Code)
	}

	ts := httptest.NewServer(a.Router())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	streamReq := newSignedHTTPRequest(t, http.MethodGet, ts.URL+"/v1/messages/stream", nil, bob.deviceID, bob.devicePriv)
	streamReq = streamReq.WithContext(ctx)

	resp, err := ts.Client().Do(streamReq)
	if err != nil {
		t.Fatalf("opening stream: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	lineCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				errCh <- err
				return
			}
			if strings.HasPrefix(line, "data: ") {
				lineCh <- line
				return
			}
		}
	}()

	select {
	case line := <-lineCh:
		var got messageResponse
		if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(line), "data: ")), &got); err != nil {
			t.Fatalf("decoding SSE data line %q: %v", line, err)
		}
		if got.MessageID != "pending1" {
			t.Errorf("MessageID = %q, want pending1", got.MessageID)
		}
	case err := <-errCh:
		t.Fatalf("reading SSE stream: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for flushed pending message")
	}
}

func TestHandleSendMessageTriggersPushWhenNoSubscriber(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	hitCh := make(chan struct{}, 1)
	fakeDistributor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCh <- struct{}{}
	}))
	defer fakeDistributor.Close()
	a.PushClient = fakeDistributor.Client()

	p256dh, authSecret := generateTestPushSubscriptionKeys(t)
	setEndpointBody, _ := json.Marshal(setPushEndpointRequest{Endpoint: &fakeDistributor.URL, P256dh: &p256dh, Auth: &authSecret})
	setRec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+bob.deviceID+"/push-endpoint", setEndpointBody, bob.deviceID, bob.devicePriv)
	if setRec.Code != http.StatusOK {
		t.Fatalf("set push endpoint status = %d, want 200, body = %s", setRec.Code, setRec.Body.String())
	}

	// Bob has no live SSE stream open, so sending him a message should
	// trigger a wake POST to his registered (fake) push endpoint.
	sendRec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", sendMessageBody(t, "msg1", bob.deviceID, `{}`), alice.deviceID, alice.devicePriv)
	if sendRec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202, body = %s", sendRec.Code, sendRec.Body.String())
	}

	select {
	case <-hitCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for push wake request")
	}
}

func TestHandleSendMessageSkipsPushWhenSubscribed(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	hitCh := make(chan struct{}, 1)
	fakeDistributor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCh <- struct{}{}
	}))
	defer fakeDistributor.Close()
	a.PushClient = fakeDistributor.Client()

	p256dh, authSecret := generateTestPushSubscriptionKeys(t)
	setEndpointBody, _ := json.Marshal(setPushEndpointRequest{Endpoint: &fakeDistributor.URL, P256dh: &p256dh, Auth: &authSecret})
	setRec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+bob.deviceID+"/push-endpoint", setEndpointBody, bob.deviceID, bob.devicePriv)
	if setRec.Code != http.StatusOK {
		t.Fatalf("set push endpoint status = %d, want 200, body = %s", setRec.Code, setRec.Body.String())
	}

	ts := httptest.NewServer(a.Router())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	streamReq := newSignedHTTPRequest(t, http.MethodGet, ts.URL+"/v1/messages/stream", nil, bob.deviceID, bob.devicePriv)
	streamReq = streamReq.WithContext(ctx)
	resp, err := ts.Client().Do(streamReq)
	if err != nil {
		t.Fatalf("opening stream: %v", err)
	}
	defer resp.Body.Close()

	// Bob's SSE stream is live, so the push wake should be skipped
	// entirely -- he'll get the message over the stream instead.
	sendRec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", sendMessageBody(t, "msg1", bob.deviceID, `{}`), alice.deviceID, alice.devicePriv)
	if sendRec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202, body = %s", sendRec.Code, sendRec.Body.String())
	}

	select {
	case <-hitCh:
		t.Fatal("push wake request was sent despite a live SSE subscriber")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestHandleSendMessageTriggersGatewayPushWhenNoSubscriber(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	type gotRequest struct {
		platform, token string
		verified        bool
	}
	reqCh := make(chan gotRequest, 1)
	fakeGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyID := r.Header.Get(httpsig.HeaderKeyID)
		ts := r.Header.Get(httpsig.HeaderTimestamp)
		nonce := r.Header.Get(httpsig.HeaderNonce)
		sig := r.Header.Get(httpsig.HeaderSignature)

		body, _ := io.ReadAll(r.Body)
		canonical := httpsig.CanonicalString(r.Method, r.URL.Path, r.URL.RawQuery, ts, nonce, keyID, body)
		pubKey, err := base64.StdEncoding.DecodeString(keyID)
		verified := err == nil && httpsig.Verify(canonical, sig, pubKey) == nil

		var payload struct{ Platform, Token string }
		json.Unmarshal(body, &payload)

		reqCh <- gotRequest{platform: payload.Platform, token: payload.Token, verified: verified}
		w.WriteHeader(http.StatusOK)
	}))
	defer fakeGateway.Close()
	a.PushClient = fakeGateway.Client()
	a.Config.PushGatewayURL = fakeGateway.URL

	setTargetBody, _ := json.Marshal(setPushTargetRequest{Platform: strPtr("fcm"), Token: strPtr("fcm-registration-token")})
	setRec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+bob.deviceID+"/push-target", setTargetBody, bob.deviceID, bob.devicePriv)
	if setRec.Code != http.StatusOK {
		t.Fatalf("set push target status = %d, want 200, body = %s", setRec.Code, setRec.Body.String())
	}

	sendRec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", sendMessageBody(t, "msg1", bob.deviceID, `{}`), alice.deviceID, alice.devicePriv)
	if sendRec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202, body = %s", sendRec.Code, sendRec.Body.String())
	}

	select {
	case got := <-reqCh:
		if got.platform != "fcm" || got.token != "fcm-registration-token" {
			t.Errorf("gateway request = %+v, want platform=fcm token=fcm-registration-token", got)
		}
		if !got.verified {
			t.Error("gateway request signature did not verify against its own embedded Signature-Key-Id")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for gateway push request")
	}
}

func TestHandleSendMessageSkipsGatewayPushWhenGatewayURLUnset(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	hitCh := make(chan struct{}, 1)
	fakeGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCh <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer fakeGateway.Close()
	a.PushClient = fakeGateway.Client()
	// a.Config.PushGatewayURL intentionally left empty.

	setTargetBody, _ := json.Marshal(setPushTargetRequest{Platform: strPtr("fcm"), Token: strPtr("fcm-registration-token")})
	setRec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+bob.deviceID+"/push-target", setTargetBody, bob.deviceID, bob.devicePriv)
	if setRec.Code != http.StatusOK {
		t.Fatalf("set push target status = %d, want 200, body = %s", setRec.Code, setRec.Body.String())
	}

	sendRec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", sendMessageBody(t, "msg1", bob.deviceID, `{}`), alice.deviceID, alice.devicePriv)
	if sendRec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202, body = %s", sendRec.Code, sendRec.Body.String())
	}

	select {
	case <-hitCh:
		t.Fatal("gateway push request was sent despite no PushGatewayURL being configured")
	case <-time.After(300 * time.Millisecond):
	}
}

func strPtr(s string) *string { return &s }
