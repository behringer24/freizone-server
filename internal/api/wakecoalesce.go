package api

import (
	"sync"
	"time"
)

// wakeCoalescer collapses repeated wakes for one device into at most one
// per window.
//
// A wake carries no content, no sender and not even a reason -- wakeDevice
// serves both "a message arrived" and "your prekey pool ran low", and the
// two are indistinguishable on the wire (see docs/PROTOCOL.md). So for a
// given device, N wakes in quick succession say exactly what one says: go
// sync. The device wakes, fetches everything pending, and sleeps again;
// whether the trigger was one message or twenty changes nothing about what
// it does. A lively group otherwise costs one push per message per member.
//
// The shape is a trailing-edge debounce with an immediate leading send:
//
//	wake() with no wake in the current window -> send now, open a window
//	wake() inside an open window              -> arm one trailing send at
//	                                             the window's end
//
// so an idle device is never delayed -- only follow-up wakes to a device
// that has just been woken anyway are merged. The bound is at most one
// wake per device per window, instead of one per message.
//
// The leading send is what makes this safe. Suppressing wakes inside the
// window without the trailing one would lose notifications outright: the
// device syncs, finds only what had arrived by then, sleeps, and a message
// arriving a second later gets no wake at all -- it sits in the durable
// queue until the device reconnects of its own accord. That is the same
// failure SRV-27 already produced once by asking a second, weaker question
// before deciding to skip a wake (see queueAndNotify). The invariant to
// preserve is that every wake() either sends now or guarantees a later
// send; there is no third branch.
type wakeCoalescer struct {
	window time.Duration
	send   func(deviceID string)

	// now and afterFunc are injectable so tests can drive the clock
	// instead of sleeping through real windows.
	now       func() time.Time
	afterFunc func(d time.Duration, f func())

	mu      sync.Mutex
	devices map[string]*wakeWindow
}

// wakeWindow is one device's state: when it may next be sent to, and
// whether a trailing send is already armed for the current window. pending
// is what keeps a burst from arming one timer per message.
type wakeWindow struct {
	nextAllowed time.Time
	pending     bool
}

// newWakeCoalescer returns a coalescer that calls send for each wake it
// decides to emit. A window of 0 or less disables coalescing: wake then
// calls send directly and no state is kept at all.
func newWakeCoalescer(window time.Duration, send func(deviceID string)) *wakeCoalescer {
	return &wakeCoalescer{
		window:    window,
		send:      send,
		now:       time.Now,
		afterFunc: func(d time.Duration, f func()) { time.AfterFunc(d, f) },
		devices:   map[string]*wakeWindow{},
	}
}

// wake requests a wake for deviceID, sending immediately or merging it into
// the window's trailing send.
func (c *wakeCoalescer) wake(deviceID string) {
	if c.window <= 0 {
		c.send(deviceID)
		return
	}

	c.mu.Lock()
	now := c.now()
	w, ok := c.devices[deviceID]
	if !ok {
		w = &wakeWindow{}
		c.devices[deviceID] = w
	}

	if !now.Before(w.nextAllowed) {
		w.nextAllowed = now.Add(c.window)
		c.mu.Unlock()
		c.send(deviceID) // leading edge, outside the lock
		return
	}

	if w.pending {
		c.mu.Unlock() // a trailing send is already coming; this wake rides along
		return
	}
	w.pending = true
	delay := w.nextAllowed.Sub(now)
	c.mu.Unlock()

	c.afterFunc(delay, func() { c.fire(deviceID) })
}

// fire emits a window's trailing wake and opens the next window.
func (c *wakeCoalescer) fire(deviceID string) {
	c.mu.Lock()
	w, ok := c.devices[deviceID]
	if !ok || !w.pending {
		c.mu.Unlock()
		return
	}
	w.pending = false
	w.nextAllowed = c.now().Add(c.window)
	c.mu.Unlock()

	c.send(deviceID)
}

// flush emits every armed trailing wake immediately. Called during
// shutdown, once the listener has stopped, so a restart does not swallow
// the notification for messages that arrived in the last window. The wake
// is best-effort either way, but losing one here is avoidable and would
// look exactly like push being broken for whoever was mid-conversation.
func (c *wakeCoalescer) flush() {
	c.mu.Lock()
	var due []string
	for deviceID, w := range c.devices {
		if w.pending {
			w.pending = false
			due = append(due, deviceID)
		}
	}
	c.mu.Unlock()

	for _, deviceID := range due {
		c.send(deviceID)
	}
}

// evictIdle drops state for devices whose window has closed with nothing
// armed, so the map tracks currently-active devices rather than every
// device ever woken. Bounded by active devices either way -- unlike the
// gateway's nonce cache, this does not grow with request rate -- but an
// unbounded map is still one nobody has to think about again.
func (c *wakeCoalescer) evictIdle() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for deviceID, w := range c.devices {
		if !w.pending && now.After(w.nextAllowed) {
			delete(c.devices, deviceID)
		}
	}
}
