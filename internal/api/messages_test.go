package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
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
	// The single-message form names the same condition the batch form reports
	// as a per-item status, under the same word (stale-device rule, §4).
	if code := errorCodeT(t, rec); code != "unknown_recipient" {
		t.Errorf("error code = %q, want unknown_recipient", code)
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

// SRV-28: a device may hold only so many streams at once, and being refused
// has to say so rather than hand back a stream that ends immediately -- the
// subscription is therefore taken before the SSE headers are written.
func TestHandleMessageStreamCapsConcurrentStreamsPerDevice(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	a.Config.MaxStreamsPerDevice = 2
	bob := registerAccount(t, a)
	carol := registerAccount(t, a)

	ts := httptest.NewServer(a.Router())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	open := func(who identityKeys) *http.Response {
		t.Helper()
		req := newSignedHTTPRequest(t, http.MethodGet, ts.URL+"/v1/messages/stream", nil, who.deviceID, who.devicePriv)
		resp, err := ts.Client().Do(req.WithContext(ctx))
		if err != nil {
			t.Fatalf("opening stream: %v", err)
		}
		return resp
	}

	first := open(bob)
	defer first.Body.Close()
	second := open(bob)
	defer second.Body.Close()
	if first.StatusCode != http.StatusOK || second.StatusCode != http.StatusOK {
		t.Fatalf("the first two streams are within the cap, got %d and %d", first.StatusCode, second.StatusCode)
	}

	third := open(bob)
	defer third.Body.Close()
	if third.StatusCode != http.StatusTooManyRequests {
		t.Errorf("third stream status = %d, want 429", third.StatusCode)
	}
	// A refusal is a JSON error, not an empty event stream: a client that has
	// lost track of its own connections has to be able to tell which happened.
	if ct := third.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("a refused stream should answer as a JSON error, got Content-Type %q", ct)
	}

	// One device's runaway must not cost anybody else their stream.
	other := open(carol)
	defer other.Body.Close()
	if other.StatusCode != http.StatusOK {
		t.Errorf("another device has its own allowance, got %d", other.StatusCode)
	}
}

// The regression that a server-wide WriteTimeout would have caused (SRV-28):
// a healthy but quiet stream must survive past the point such a timeout would
// have cut it. Measured against a real connection rather than reasoned about,
// because the failure is invisible from the handler's side -- its writes go on
// reporting success while the client has already seen the connection end.
//
// Deliberately not driven by wall-clock heartbeats, which would make this a
// slow test: the pending flush proves the stream is up, and a message sent
// well after any per-write deadline would have elapsed proves it is still
// carrying traffic.
func TestAQuietStreamIsNotCutByAWriteDeadline(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	ts := httptest.NewServer(a.Router())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	streamReq := newSignedHTTPRequest(t, http.MethodGet, ts.URL+"/v1/messages/stream", nil, bob.deviceID, bob.devicePriv)
	resp, err := ts.Client().Do(streamReq.WithContext(ctx))
	if err != nil {
		t.Fatalf("opening stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}

	lines := make(chan string, 4)
	go func() {
		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				close(lines)
				return
			}
			if strings.HasPrefix(line, "data: ") {
				lines <- line
			}
		}
	}()

	// Sit idle, writing nothing, then send. A per-response deadline set once
	// would have expired across this gap; a per-write one is refreshed by the
	// write itself and is unaffected.
	time.Sleep(300 * time.Millisecond)

	sendReq := newSignedHTTPRequest(t, http.MethodPost, ts.URL+"/v1/messages", sendMessageBody(t, "afterquiet", bob.deviceID, `{"ciphertext":"still here"}`), alice.deviceID, alice.devicePriv)
	sendResp, err := ts.Client().Do(sendReq)
	if err != nil {
		t.Fatalf("sending after the quiet period: %v", err)
	}
	sendResp.Body.Close()

	select {
	case line, ok := <-lines:
		if !ok {
			t.Fatal("the stream was closed during the quiet period instead of carrying the message")
		}
		var got messageResponse
		if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(line), "data: ")), &got); err != nil {
			t.Fatalf("decoding SSE data line %q: %v", line, err)
		}
		if got.MessageID != "afterquiet" {
			t.Errorf("MessageID = %q, want afterquiet", got.MessageID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out: a quiet stream stopped delivering")
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
	a.GatewayClient = fakeGateway.Client()
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
	a.GatewayClient = fakeGateway.Client()
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

// waitForPushTarget polls bob's device until its push target matches want
// (nil for "cleared"), since the wake -- and therefore any cleanup it
// triggers -- runs in its own goroutine after the send has already
// responded.
func waitForPushTarget(t *testing.T, db *sql.DB, deviceID string, wantCleared bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		device, err := store.GetDevice(db, deviceID)
		if err != nil {
			t.Fatalf("GetDevice() error = %v", err)
		}
		if (device.PushTarget == nil) == wantCleared {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	state := "cleared"
	if !wantCleared {
		state = "kept"
	}
	t.Fatalf("push target was not %s within the timeout", state)
}

func TestGatewayGoneDropsDeadPushTarget(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	// 410 Gone is the gateway's "this token is permanently dead" signal
	// (app uninstalled / data cleared), so the registration must be
	// dropped rather than retried on every future message.
	fakeGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer fakeGateway.Close()
	a.GatewayClient = fakeGateway.Client()
	a.Config.PushGatewayURL = fakeGateway.URL

	setTargetBody, _ := json.Marshal(setPushTargetRequest{Platform: strPtr("fcm"), Token: strPtr("dead-token")})
	if rec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+bob.deviceID+"/push-target", setTargetBody, bob.deviceID, bob.devicePriv); rec.Code != http.StatusOK {
		t.Fatalf("set push target status = %d, want 200", rec.Code)
	}

	if rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", sendMessageBody(t, "msg1", bob.deviceID, `{}`), alice.deviceID, alice.devicePriv); rec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202", rec.Code)
	}

	waitForPushTarget(t, db, bob.deviceID, true)

	// The device itself must survive: it's still a valid device that can
	// receive over SSE/poll and re-register a fresh token later.
	device, err := store.GetDevice(db, bob.deviceID)
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if device.Status != store.DeviceStatusActive {
		t.Errorf("device status = %q, want it to stay active", device.Status)
	}
}

func TestGatewayTransientFailureKeepsPushTarget(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	// 502 means this attempt failed upstream, not that the token is dead --
	// dropping the registration here would silently disable push for a
	// perfectly good device on any transient FCM hiccup.
	hitCh := make(chan struct{}, 1)
	fakeGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		select {
		case hitCh <- struct{}{}:
		default:
		}
	}))
	defer fakeGateway.Close()
	a.GatewayClient = fakeGateway.Client()
	a.Config.PushGatewayURL = fakeGateway.URL

	setTargetBody, _ := json.Marshal(setPushTargetRequest{Platform: strPtr("fcm"), Token: strPtr("live-token")})
	if rec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+bob.deviceID+"/push-target", setTargetBody, bob.deviceID, bob.devicePriv); rec.Code != http.StatusOK {
		t.Fatalf("set push target status = %d, want 200", rec.Code)
	}

	if rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", sendMessageBody(t, "msg1", bob.deviceID, `{}`), alice.deviceID, alice.devicePriv); rec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202", rec.Code)
	}

	select {
	case <-hitCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for gateway push request")
	}

	device, err := store.GetDevice(db, bob.deviceID)
	if err != nil {
		t.Fatalf("GetDevice() error = %v", err)
	}
	if device.PushTarget == nil {
		t.Error("push target was dropped on a transient 502; only a 410 may drop it")
	}
}

func TestWebPushGoneDropsDeadSubscription(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	// A push service answering 410 (or 404) means the subscription is
	// permanently gone, per the Web Push protocol -- stop sending to it.
	// TLS because handleSetPushEndpoint only accepts https:// endpoints.
	fakeDistributor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer fakeDistributor.Close()
	a.PushClient = fakeDistributor.Client()

	p256dh, authSecret := generateTestPushSubscriptionKeys(t)
	setEndpointBody, _ := json.Marshal(setPushEndpointRequest{Endpoint: &fakeDistributor.URL, P256dh: &p256dh, Auth: &authSecret})
	if rec := doSignedRequest(t, a.Router(), http.MethodPut, "/v1/devices/"+bob.deviceID+"/push-endpoint", setEndpointBody, bob.deviceID, bob.devicePriv); rec.Code != http.StatusOK {
		t.Fatalf("set push endpoint status = %d, want 200", rec.Code)
	}

	if rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages", sendMessageBody(t, "msg1", bob.deviceID, `{}`), alice.deviceID, alice.devicePriv); rec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202", rec.Code)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		device, err := store.GetDevice(db, bob.deviceID)
		if err != nil {
			t.Fatalf("GetDevice() error = %v", err)
		}
		if device.Push == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("dead web push subscription was not cleared within the timeout")
}

func strPtr(s string) *string { return &s }
