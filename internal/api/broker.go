package api

import (
	"errors"
	"sync"

	"github.com/behringer24/freizone-server/internal/store"
)

// messageBroker fans out newly-queued messages to any SSE stream currently
// connected for the recipient device, on top of the durable queue in the
// database. It is process-local by design -- there's no multi-instance or
// federation delivery in this milestone.
type messageBroker struct {
	mu   sync.Mutex
	subs map[string][]chan store.Message
}

func newMessageBroker() *messageBroker {
	return &messageBroker{subs: make(map[string][]chan store.Message)}
}

// errTooManyStreams is what subscribe refuses with once deviceID already
// holds its limit. The caller answers it with 429 rather than dropping the
// connection silently: a client that has lost track of its own streams needs
// to be told, and a stream refused without a reason reads as the server being
// broken.
var errTooManyStreams = errors.New("too many concurrent streams for this device")

// subscribe registers a new subscriber for deviceID, refusing once that
// device already holds maxPerDevice of them (SRV-28). Call the returned
// unsubscribe function exactly once, when the caller stops listening.
//
// The cap is checked and the slot taken under one lock: two reconnects
// arriving together would otherwise both see room and both take it.
func (b *messageBroker) subscribe(deviceID string, maxPerDevice int) (ch <-chan store.Message, unsubscribe func(), err error) {
	c := make(chan store.Message, 16)

	b.mu.Lock()
	if len(b.subs[deviceID]) >= maxPerDevice {
		b.mu.Unlock()
		return nil, nil, errTooManyStreams
	}
	b.subs[deviceID] = append(b.subs[deviceID], c)
	b.mu.Unlock()

	unsubscribe = func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		subs := b.subs[deviceID]
		for i, existing := range subs {
			if existing == c {
				b.subs[deviceID] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		if len(b.subs[deviceID]) == 0 {
			delete(b.subs, deviceID)
		}
		close(c)
	}
	return c, unsubscribe, nil
}

// hasResponsiveSubscriber reports whether deviceID has an SSE stream that is
// not just connected but currently *keeping up* -- at least one subscriber
// with room left in its buffer.
//
// Room, rather than mere presence, because presence is not what the callers
// actually want to know. They ask in order to skip a push wake, and the only
// justification for skipping one is that the device is being told some other
// way. A subscriber whose buffer is full is by definition not draining what
// it already has, so it is no evidence of anything (SRV-27). Being wrong in
// this direction costs a redundant wake, which the device answers with a sync
// that finds nothing new; being wrong the other way costs the delivery.
func (b *messageBroker) hasResponsiveSubscriber(deviceID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.subs[deviceID] {
		if len(c) < cap(c) {
			return true
		}
	}
	return false
}

// publish notifies every subscriber currently connected for deviceID and
// reports whether at least one of them actually took the message.
//
// Subscribers with a full buffer are skipped rather than blocked on -- one
// stalled reader must not hold up the handler that is queuing for everybody
// else -- and the durable queue is what makes that safe: the message is
// already committed, so a skipped subscriber loses the *notification*, never
// the message.
//
// Returning whether it landed is what closes SRV-27. The caller's next
// decision is whether to send a push wake instead, and asking a second
// question ("does this device have subscribers?") to answer it was the bug:
// a full buffer made publish drop the message while the device still counted
// as connected, so the one case that most needed a fallback nudge was exactly
// the case that suppressed it. One question, answered by the code that knows.
func (b *messageBroker) publish(deviceID string, msg store.Message) (delivered bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.subs[deviceID] {
		select {
		case c <- msg:
			delivered = true
		default:
		}
	}
	return delivered
}
