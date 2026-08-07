package client

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// StreamEventKind is what happened on the message stream.
type StreamEventKind int

const (
	// StreamConnected fires once per successful (re)connect, not just the
	// first. A caller uses it to redo whatever only holds while connected --
	// re-checking the one-time-prekey pool, for instance, which otherwise only
	// ever happens at launch.
	StreamConnected StreamEventKind = iota

	// StreamMessage carries one envelope.
	StreamMessage

	// StreamDisconnected reports a stream that had come up and then ended. Not
	// an error on its own: a resume from background or a brief blip looks
	// exactly like this, and the reconnect is already under way.
	StreamDisconnected

	// StreamFailed reports a connect attempt that never came up. Err says why.
	// Also not fatal -- the next attempt is already scheduled, with backoff.
	StreamFailed
)

// StreamEvent is one thing that happened, delivered on the channel [Client.Stream]
// returns.
//
// Deliberately one channel of a tagged union rather than several channels. A
// caller in Go can switch on Kind, and freizone-app's FFI wrapper -- which can
// only offer a blocking "give me the next event" call across the boundary --
// needs exactly this shape. Several channels would have to be multiplexed back
// into one there anyway, and the multiplexing would live on the wrong side.
type StreamEvent struct {
	Kind    StreamEventKind
	Message IncomingMessage
	Err     error
}

// StreamPolicy tunes reconnection. The zero value means the defaults, which are
// the ones freizone-app arrived at against real servers -- see the field
// comments for why each is what it is.
type StreamPolicy struct {
	// ConnectTimeout bounds a single connect attempt, so a host that is routed
	// but dead surfaces as unreachable in seconds instead of after the
	// OS-level TCP timeout. Default 10s.
	ConnectTimeout time.Duration

	// InitialRetryDelay and MaxRetryDelay bound the exponential backoff used
	// when an attempt never comes up, so an offline home server is probed ever
	// less aggressively rather than hammered -- yet still recovers within
	// MaxRetryDelay once it returns. Defaults 3s and 30s.
	InitialRetryDelay time.Duration
	MaxRetryDelay     time.Duration

	// QuickRetryDelay is used instead when the stream *had* come up and then
	// dropped, with the backoff reset. A healthy link then recovers in well
	// under a second rather than after a full retry delay -- which is the
	// difference between a resume from background feeling instant and feeling
	// broken. Default 500ms.
	QuickRetryDelay time.Duration
}

func (p StreamPolicy) withDefaults() StreamPolicy {
	if p.ConnectTimeout <= 0 {
		p.ConnectTimeout = 10 * time.Second
	}
	if p.InitialRetryDelay <= 0 {
		p.InitialRetryDelay = 3 * time.Second
	}
	if p.MaxRetryDelay <= 0 {
		p.MaxRetryDelay = 30 * time.Second
	}
	if p.QuickRetryDelay <= 0 {
		p.QuickRetryDelay = 500 * time.Millisecond
	}
	return p
}

// Stream opens the message stream and keeps it open, reconnecting on its own
// until ctx is cancelled. The returned channel is closed once the loop has
// stopped, so a caller can range over it.
//
// Events are dropped rather than blocking the stream if the caller stops
// reading: a consumer that has gone away must not be able to stall the
// connection, and a stalled connection would look to the server like a client
// that is still there.
func (c *Client) Stream(ctx context.Context, policy StreamPolicy) <-chan StreamEvent {
	policy = policy.withDefaults()
	events := make(chan StreamEvent, 32)

	go func() {
		defer close(events)

		delay := policy.InitialRetryDelay
		for ctx.Err() == nil {
			established, err := c.streamOnce(ctx, policy, events)
			if ctx.Err() != nil {
				return
			}

			switch {
			case established:
				// Came up and then ended. Reconnect almost immediately and
				// reset the backoff -- the link is evidently fine.
				send(ctx, events, StreamEvent{Kind: StreamDisconnected, Err: err})
				delay = policy.InitialRetryDelay
				if !sleep(ctx, policy.QuickRetryDelay) {
					return
				}
			default:
				send(ctx, events, StreamEvent{Kind: StreamFailed, Err: err})
				// Jitter by ±20% so several sessions against one server do not
				// reconnect in lockstep and arrive as a thundering herd.
				jittered := time.Duration(float64(delay) * (0.8 + rand.Float64()*0.4))
				if !sleep(ctx, jittered) {
					return
				}
				delay = min(delay*2, policy.MaxRetryDelay)
			}
		}
	}()

	return events
}

// streamOnce runs one connect-and-read attempt. It reports whether the stream
// ever came up, which is what decides between a quick reconnect and a backed-off
// one.
func (c *Client) streamOnce(ctx context.Context, policy StreamPolicy, events chan<- StreamEvent) (established bool, err error) {
	id, err := c.Identity()
	if err != nil {
		return false, err
	}

	// One cancellable context per attempt, cancelled on every exit path. This
	// is what stops a timed-out connect from leaving its socket behind: against
	// a dead-but-routed host, every backoff retry would otherwise pile up
	// another dial that only clears on the OS-level TCP timeout minutes later.
	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	req, err := c.streamRequest(attemptCtx, id)
	if err != nil {
		return false, err
	}

	// The deadline covers reaching the stream, not reading from it: a healthy
	// stream is idle for as long as nobody writes to this account, with only a
	// heartbeat comment every 25 seconds or so.
	connectTimer := time.AfterFunc(policy.ConnectTimeout, cancel)

	resp, err := httpClient.Do(req)
	if err != nil {
		connectTimer.Stop()
		return false, fmt.Errorf("client: opening message stream: %w", err)
	}
	defer resp.Body.Close()
	connectTimer.Stop()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return false, &APIError{
			StatusCode: resp.StatusCode,
			Message:    strings.TrimSpace(string(body)),
		}
	}

	send(ctx, events, StreamEvent{Kind: StreamConnected})

	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// Reaching here having already announced the connection is the
			// ordinary end of a stream, not a fault.
			return true, err
		}
		data, ok := strings.CutPrefix(strings.TrimRight(line, "\r\n"), "data: ")
		if !ok {
			// An `event: message` line, a `: heartbeat` comment, or the blank
			// line between frames. Nothing here needs any of them.
			continue
		}

		var wire incomingMessageWire
		if err := json.Unmarshal([]byte(data), &wire); err != nil {
			// A malformed frame costs itself, never the connection.
			continue
		}
		msg, err := wire.resolve()
		if err != nil {
			continue
		}
		send(ctx, events, StreamEvent{Kind: StreamMessage, Message: msg})
	}
}

func (c *Client) streamRequest(ctx context.Context, id Identity) (*http.Request, error) {
	const path = "/v1/messages/stream"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id.Server+path, nil)
	if err != nil {
		return nil, fmt.Errorf("client: building stream request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	nonce, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("client: generating stream nonce: %w", err)
	}
	ts := time.Now()
	sig := httpsig.Sign(http.MethodGet, path, "", nil, id.DeviceID, ts, nonce, ed25519.PrivateKey(id.DevicePriv))

	req.Header.Set(httpsig.HeaderKeyID, id.DeviceID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)
	return req, nil
}

// send delivers an event unless the buffer is full or the caller is gone.
// Dropping is the right failure: a consumer that stopped reading must not be
// able to stall the connection.
func send(ctx context.Context, events chan<- StreamEvent, ev StreamEvent) {
	select {
	case events <- ev:
	case <-ctx.Done():
	default:
	}
}

// sleep waits for d, reporting false if ctx ended first.
func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
