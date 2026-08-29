package api

import (
	"sync"
	"testing"
	"time"
)

// fakeClock drives a wakeCoalescer without sleeping. Timers are recorded
// rather than run, and advance() fires the ones that have come due, so the
// tests below assert on exact wake counts instead of racing a real window.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []fakeTimer
}

type fakeTimer struct {
	due time.Time
	f   func()
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) after(d time.Duration, f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timers = append(c.timers, fakeTimer{due: c.now.Add(d), f: f})
}

// advance moves the clock and runs every timer that has come due, outside
// the lock so a callback may arm another one.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	var due []func()
	var remaining []fakeTimer
	for _, t := range c.timers {
		if !t.due.After(now) {
			due = append(due, t.f)
		} else {
			remaining = append(remaining, t)
		}
	}
	c.timers = remaining
	c.mu.Unlock()

	for _, f := range due {
		f()
	}
}

// recorder counts wakes per device.
type recorder struct {
	mu     sync.Mutex
	counts map[string]int
}

func newRecorder() *recorder { return &recorder{counts: map[string]int{}} }

func (r *recorder) send(deviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts[deviceID]++
}

func (r *recorder) count(deviceID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[deviceID]
}

func newTestCoalescer(window time.Duration) (*wakeCoalescer, *fakeClock, *recorder) {
	clock := newFakeClock()
	rec := newRecorder()
	c := newWakeCoalescer(window, rec.send)
	c.now = clock.Now
	c.afterFunc = clock.after
	return c, clock, rec
}

// TestWakeCoalescerSendsFirstWakeImmediately is the property that decides
// whether coalescing is acceptable at all: an idle device is never made to
// wait for the window.
func TestWakeCoalescerSendsFirstWakeImmediately(t *testing.T) {
	c, _, rec := newTestCoalescer(3 * time.Second)

	c.wake("dev-1")

	if got := rec.count("dev-1"); got != 1 {
		t.Errorf("wakes after the first request = %d, want 1 sent without advancing the clock", got)
	}
}

func TestWakeCoalescerMergesABurstIntoOneTrailingWake(t *testing.T) {
	c, clock, rec := newTestCoalescer(3 * time.Second)

	c.wake("dev-1") // leading edge, sent now
	clock.advance(800 * time.Millisecond)
	c.wake("dev-1") // arms the trailing send
	clock.advance(700 * time.Millisecond)
	c.wake("dev-1") // rides along
	clock.advance(500 * time.Millisecond)
	c.wake("dev-1") // rides along

	if got := rec.count("dev-1"); got != 1 {
		t.Fatalf("wakes before the window closed = %d, want 1 (only the leading edge)", got)
	}

	clock.advance(1 * time.Second) // now at t=3.0, the window's end

	if got := rec.count("dev-1"); got != 2 {
		t.Errorf("wakes after the window closed = %d, want 2 -- four requests should collapse to a leading and one trailing wake", got)
	}
}

// TestWakeCoalescerNeverDropsAWake is the invariant that makes the trailing
// edge necessary: every request either sends now or guarantees a later
// send. A message arriving just inside a window must still get a wake, or
// it sits in the queue until the device reconnects on its own (SRV-27).
func TestWakeCoalescerNeverDropsAWake(t *testing.T) {
	c, clock, rec := newTestCoalescer(3 * time.Second)

	c.wake("dev-1")
	clock.advance(2999 * time.Millisecond)
	c.wake("dev-1") // one millisecond before the window closes

	clock.advance(10 * time.Second)

	if got := rec.count("dev-1"); got < 2 {
		t.Errorf("wakes = %d, want at least 2 -- a request inside the window must still produce a wake", got)
	}
}

func TestWakeCoalescerReopensAfterAQuietPeriod(t *testing.T) {
	c, clock, rec := newTestCoalescer(3 * time.Second)

	c.wake("dev-1")
	clock.advance(30 * time.Second) // long silence, window has closed
	c.wake("dev-1")

	if got := rec.count("dev-1"); got != 2 {
		t.Errorf("wakes = %d, want 2 -- after the window closes the next wake is immediate again", got)
	}
}

func TestWakeCoalescerKeepsDevicesIndependent(t *testing.T) {
	c, clock, rec := newTestCoalescer(3 * time.Second)

	c.wake("dev-1")
	c.wake("dev-2")
	c.wake("dev-1") // merged for dev-1 only

	if got := rec.count("dev-2"); got != 1 {
		t.Errorf("dev-2 wakes = %d, want 1 -- one device's burst must not delay another's", got)
	}

	clock.advance(3 * time.Second)

	if got := rec.count("dev-1"); got != 2 {
		t.Errorf("dev-1 wakes = %d, want 2", got)
	}
	if got := rec.count("dev-2"); got != 1 {
		t.Errorf("dev-2 wakes = %d, want 1 -- dev-2 never had a second request", got)
	}
}

func TestWakeCoalescerBoundsWakesPerWindow(t *testing.T) {
	c, clock, rec := newTestCoalescer(3 * time.Second)

	// A steady stream far denser than the window: 100 requests over 9s.
	for i := 0; i < 100; i++ {
		c.wake("dev-1")
		clock.advance(90 * time.Millisecond)
	}
	clock.advance(3 * time.Second)

	// 9s of traffic plus the trailing window is four windows, so at most
	// four wakes -- against 100 without coalescing.
	if got := rec.count("dev-1"); got > 4 {
		t.Errorf("wakes = %d, want at most 4 -- the bound is one per window, not one per message", got)
	}
	if got := rec.count("dev-1"); got == 100 {
		t.Error("no coalescing happened at all")
	}
}

// TestWakeCoalescerDisabledPassesEveryWakeThrough pins the escape hatch:
// FREIZONE_PUSH_COALESCE_WINDOW=0 restores one push per message exactly.
func TestWakeCoalescerDisabledPassesEveryWakeThrough(t *testing.T) {
	c, _, rec := newTestCoalescer(0)

	for i := 0; i < 5; i++ {
		c.wake("dev-1")
	}

	if got := rec.count("dev-1"); got != 5 {
		t.Errorf("wakes with coalescing disabled = %d, want 5 (one per request)", got)
	}
}

func TestWakeCoalescerFlushEmitsPendingWakes(t *testing.T) {
	c, clock, rec := newTestCoalescer(3 * time.Second)

	c.wake("dev-1")
	clock.advance(500 * time.Millisecond)
	c.wake("dev-1") // pending, would fire at t=3.0

	c.flush() // shutdown before the window closes

	if got := rec.count("dev-1"); got != 2 {
		t.Errorf("wakes after flush = %d, want 2 -- a pending wake must not be lost on shutdown", got)
	}

	// And the flushed wake must not fire a second time when its timer runs.
	clock.advance(10 * time.Second)
	if got := rec.count("dev-1"); got != 2 {
		t.Errorf("wakes after the timer also ran = %d, want 2 -- flush and timer must not both send", got)
	}
}

func TestWakeCoalescerEvictsIdleDevices(t *testing.T) {
	c, clock, _ := newTestCoalescer(3 * time.Second)

	c.wake("dev-1")
	c.wake("dev-2")
	clock.advance(500 * time.Millisecond)
	c.wake("dev-2") // dev-2 has a pending trailing wake, dev-1 does not

	c.evictIdle() // dev-1's window is still open, so nothing goes yet

	c.mu.Lock()
	afterEarly := len(c.devices)
	c.mu.Unlock()
	if afterEarly != 2 {
		t.Errorf("tracked devices = %d, want 2 -- an open window must not be evicted", afterEarly)
	}

	// Firing dev-2's trailing wake is itself a wake, so it opens a fresh
	// window for that device -- it is not evictable yet, and evicting it
	// would be wrong.
	clock.advance(10 * time.Second)
	c.evictIdle()

	c.mu.Lock()
	afterTrailing := len(c.devices)
	_, dev2Kept := c.devices["dev-2"]
	c.mu.Unlock()
	if afterTrailing != 1 || !dev2Kept {
		t.Errorf("tracked devices = %d (dev-2 kept: %v), want only dev-2 -- its trailing wake just opened a new window",
			afterTrailing, dev2Kept)
	}

	clock.advance(10 * time.Second) // now dev-2's new window has closed too
	c.evictIdle()

	c.mu.Lock()
	afterLate := len(c.devices)
	c.mu.Unlock()
	if afterLate != 0 {
		t.Errorf("tracked devices = %d, want 0 -- closed windows with nothing pending are dropped", afterLate)
	}
}
