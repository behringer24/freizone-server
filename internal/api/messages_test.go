package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
)

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
