package api

import (
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

// subscribe registers a new subscriber for deviceID. Call the returned
// unsubscribe function exactly once, when the caller stops listening.
func (b *messageBroker) subscribe(deviceID string) (ch <-chan store.Message, unsubscribe func()) {
	c := make(chan store.Message, 16)

	b.mu.Lock()
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
	return c, unsubscribe
}

// hasSubscribers reports whether deviceID currently has a live SSE stream
// connected -- used to decide whether a push wake is needed at all (an
// actively-connected device already gets the message via publish).
func (b *messageBroker) hasSubscribers(deviceID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs[deviceID]) > 0
}

// publish notifies every subscriber currently connected for deviceID.
// Subscribers with a full buffer are skipped rather than blocked on --
// they'll still see the message via the durable queue on their next poll
// or reconnect.
func (b *messageBroker) publish(deviceID string, msg store.Message) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.subs[deviceID] {
		select {
		case c <- msg:
		default:
		}
	}
}
