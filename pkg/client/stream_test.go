package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// fastPolicy keeps the reconnect logic under test while making the test fast
// and deterministic. The shape of the policy is what matters here, not the real
// durations.
var fastPolicy = StreamPolicy{
	ConnectTimeout:    time.Second,
	InitialRetryDelay: time.Millisecond,
	MaxRetryDelay:     5 * time.Millisecond,
	QuickRetryDelay:   time.Millisecond,
}

// writeSSE writes one `event: message` / `data: ...` frame in the server's own
// format and flushes, so the client sees it immediately rather than when some
// buffer happens to fill.
func writeSSE(t *testing.T, w http.ResponseWriter, msg map[string]any) {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshalling frame: %v", err)
	}
	fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
	w.(http.Flusher).Flush()
}

func awaitEvent(t *testing.T, events <-chan StreamEvent, want StreamEventKind) StreamEvent {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatalf("stream closed while waiting for %v", want)
			}
			if ev.Kind == want {
				return ev
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %v", want)
		}
	}
}

// --- message endpoints ------------------------------------------------------

// The server de-duplicates by message id, so a retry's second copy being
// refused is the retry working. Reading 409 as failure is how a client ends up
// either sending twice or reporting a delivered message as failed.
func TestSendMessageTreatsConflictAsDelivered(t *testing.T) {
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":{"code":"duplicate_message","message":"already queued"}}`))
	})

	if err := c.SendMessage(context.Background(), "fz1peer", "device-2", "m1", json.RawMessage(`{"v":5}`)); err != nil {
		t.Errorf("a 409 should count as delivered, got %v", err)
	}
}

func TestSendMessageSurfacesRealFailures(t *testing.T) {
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"code":"unknown_recipient","message":"no such device"}}`))
	})

	err := c.SendMessage(context.Background(), "fz1peer", "device-2", "m1", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("a 404 must not be swallowed the way a 409 is")
	}
	if !IsStaleDevice(err) {
		t.Errorf("want a stale-device classification, got %v", err)
	}
}

// Something already deleted is deleted. The acknowledgement is best effort by
// design -- a lost one means redelivery, which the duplicate check absorbs.
func TestAckMessageTreatsNotFoundAsSuccess(t *testing.T) {
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"code":"not_found","message":"gone"}}`))
	})

	if err := c.AckMessage(context.Background(), "m1"); err != nil {
		t.Errorf("acknowledging an already-deleted message should succeed, got %v", err)
	}
}

// GET /v1/messages answers with a bare JSON array. Probing for an object alone
// would report a perfectly good server as the wrong address the moment anything
// drained the queue.
func TestFetchMessagesDecodesABareArray(t *testing.T) {
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
			{"message_id":"m1","sender_account_id":"fz1a","sender_device_id":"d1",
			 "sent_at":"2026-08-07T09:00:00Z","payload":{"v":3}},
			{"message_id":"m2","sender_account_id":"fz1b","sender_device_id":"d2",
			 "sent_at":"2026-08-07T09:01:00Z","payload":{"v":1}}
		]`))
	})

	msgs, err := c.FetchMessages(context.Background())
	if err != nil {
		t.Fatalf("FetchMessages: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("want 2 messages, got %d", len(msgs))
	}
	if msgs[0].MessageID != "m1" || msgs[0].SenderAccountID != "fz1a" {
		t.Errorf("first message: %+v", msgs[0])
	}
	if !msgs[0].SentAt.Equal(time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("sent_at: got %v", msgs[0].SentAt)
	}
	if string(msgs[1].Payload) != `{"v":1}` {
		t.Errorf("payload should stay opaque and intact, got %s", msgs[1].Payload)
	}
}

func TestFetchMessagesOnAnEmptyQueue(t *testing.T) {
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	})
	msgs, err := c.FetchMessages(context.Background())
	if err != nil {
		t.Fatalf("FetchMessages: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("want an empty slice, got %v", msgs)
	}
}

// --- the stream -------------------------------------------------------------

func TestStreamDeliversMessagesAndIgnoresTheRest(t *testing.T) {
	pub, priv := newDeviceKey(t)
	var verifyErr error
	var signed atomic.Bool

	c := newServedClient(t, pub, priv, func(w http.ResponseWriter, r *http.Request) {
		headers, err := httpsig.ParseRequestHeaders(r)
		if err == nil {
			verifyErr = httpsig.Verify(httpsig.CanonicalStringFromRequest(r, headers, nil), headers.Signature, pub)
			signed.Store(true)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()

		// A heartbeat comment and a blank line carry nothing; a malformed frame
		// must cost itself and never the connection.
		fmt.Fprint(w, ": heartbeat\n\n")
		fmt.Fprint(w, "event: message\ndata: {not json\n\n")
		w.(http.Flusher).Flush()

		writeSSE(t, w, map[string]any{
			"message_id": "m1", "sender_account_id": "fz1a",
			"sender_device_id": "d1", "sent_at": "2026-08-07T09:00:00Z",
			"payload": map[string]any{"v": 3},
		})
		<-r.Context().Done()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := c.Stream(ctx, fastPolicy)

	awaitEvent(t, events, StreamConnected)
	ev := awaitEvent(t, events, StreamMessage)
	if ev.Message.MessageID != "m1" {
		t.Errorf("message: %+v", ev.Message)
	}
	if !signed.Load() {
		t.Error("the stream request carried no signature headers")
	}
	if verifyErr != nil {
		t.Errorf("stream signature did not verify with the server's own code: %v", verifyErr)
	}
}

// A stream that came up and then ended is not an error: a resume from
// background looks exactly like this. It reconnects quickly and resets the
// backoff, so a healthy link recovers in well under a second.
func TestStreamReconnectsQuicklyAfterADrop(t *testing.T) {
	var connects atomic.Int32
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		connects.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		// End the response straight away, which is what a blip looks like.
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := c.Stream(ctx, fastPolicy)

	awaitEvent(t, events, StreamConnected)
	awaitEvent(t, events, StreamDisconnected)
	// Reconnecting at all is the point; a second Connected proves the loop
	// carried on rather than giving up after one drop.
	awaitEvent(t, events, StreamConnected)

	if got := connects.Load(); got < 2 {
		t.Errorf("want at least 2 connects, got %d", got)
	}
}

// An attempt that never comes up is reported and retried with backoff, so an
// offline home server is probed ever less aggressively rather than hammered.
func TestStreamRetriesWhenItNeverComesUp(t *testing.T) {
	var attempts atomic.Int32
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":{"code":"unavailable","message":"down"}}`))
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := c.Stream(ctx, fastPolicy)

	ev := awaitEvent(t, events, StreamFailed)
	if ev.Err == nil {
		t.Error("a failed attempt should say why")
	}
	var apiErr *APIError
	if !errors.As(ev.Err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("want the server's status carried through, got %v", ev.Err)
	}
	awaitEvent(t, events, StreamFailed)

	if got := attempts.Load(); got < 2 {
		t.Errorf("want at least 2 attempts, got %d", got)
	}
}

// Cancelling the context is the only way to stop the loop, and it must close
// the channel so a caller ranging over it finishes rather than blocking.
func TestStreamStopsAndClosesOnCancel(t *testing.T) {
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})

	ctx, cancel := context.WithCancel(context.Background())
	events := c.Stream(ctx, fastPolicy)
	awaitEvent(t, events, StreamConnected)

	cancel()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-events:
			if !ok {
				return // closed, as it must be
			}
		case <-deadline:
			t.Fatal("channel was not closed after the context was cancelled")
		}
	}
}

// A consumer that stops reading must not be able to stall the connection --
// which to the server would look like a client that is still there.
func TestStreamDoesNotBlockOnAnUnreadChannel(t *testing.T) {
	const frames = 200
	done := make(chan struct{})
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for i := 0; i < frames; i++ {
			writeSSE(t, w, map[string]any{
				"message_id": fmt.Sprintf("m%d", i), "sender_account_id": "fz1a",
				"sender_device_id": "d1", "payload": map[string]any{"v": 1},
			})
		}
		close(done)
		<-r.Context().Done()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Deliberately never read the channel while the server floods it.
	c.Stream(ctx, fastPolicy)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("writing far more events than the buffer holds stalled the stream")
	}
}

func TestStreamWithoutAnIdentityReportsIt(t *testing.T) {
	c := openTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ev := awaitEvent(t, c.Stream(ctx, fastPolicy), StreamFailed)
	if !errors.Is(ev.Err, ErrNoIdentity) {
		t.Errorf("want ErrNoIdentity, got %v", ev.Err)
	}
}

// A timed-out connect must name the deadline it exceeded AND the layer that
// stalled. Both matter: "context canceled" alone is the same text a deliberate
// stop produces, and knowing only that it timed out does not say whether the
// name resolved, the port answered, or TLS failed.
func TestConnectTimeoutProbesTheLayers(t *testing.T) {
	block := make(chan struct{})
	c := servedClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/server-status" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{}`))
			return
		}
		<-block // the stream endpoint never answers
	})
	t.Cleanup(func() { close(block) })

	policy := fastPolicy
	policy.ConnectTimeout = 200 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	msg := awaitEvent(t, c.Stream(ctx, policy), StreamFailed).Err.Error()
	for _, want := range []string{"did not open within", "200ms", "resolves to", "connects", "answered 200"} {
		if !strings.Contains(msg, want) {
			t.Errorf("probe should report %q, got: %s", want, msg)
		}
	}
}
