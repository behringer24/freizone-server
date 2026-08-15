package api

import (
	"errors"
	"testing"

	"github.com/behringer24/freizone-server/internal/store"
)

// The bug SRV-27 describes, at the level it actually lives: publish has to
// say whether the message landed, because "is anything subscribed?" is a
// weaker question that answers yes in the one case that matters.
func TestPublishReportsWhetherTheMessageLanded(t *testing.T) {
	b := newMessageBroker()

	if b.publish("device-1", store.Message{MessageID: "m0"}) {
		t.Error("nothing is subscribed, so nothing can have taken the message")
	}

	ch, unsubscribe, _ := b.subscribe("device-1", 4)
	defer unsubscribe()

	if !b.publish("device-1", store.Message{MessageID: "m1"}) {
		t.Fatal("a subscriber with an empty buffer must take the message")
	}

	// Fill the rest of the buffer, then overflow it. The 17th message is the
	// one the old code dropped while still reporting the device as connected.
	for i := 0; i < cap(ch)-1; i++ {
		if !b.publish("device-1", store.Message{MessageID: "filler"}) {
			t.Fatalf("filling: message %d should still fit", i)
		}
	}
	if b.publish("device-1", store.Message{MessageID: "overflow"}) {
		t.Error("a full buffer cannot have taken the message, so publish must say so")
	}
}

// The predicate the prekey path still asks (prekeys.go): a subscriber that is
// not draining is not evidence that the device is being reached, so it must
// not suppress a wake.
func TestAFullSubscriberIsNotResponsive(t *testing.T) {
	b := newMessageBroker()

	if b.hasResponsiveSubscriber("device-1") {
		t.Error("nothing is subscribed")
	}

	ch, unsubscribe, _ := b.subscribe("device-1", 4)
	defer unsubscribe()

	if !b.hasResponsiveSubscriber("device-1") {
		t.Fatal("a fresh subscriber has room and is responsive")
	}

	for i := 0; i < cap(ch); i++ {
		b.publish("device-1", store.Message{MessageID: "filler"})
	}
	if b.hasResponsiveSubscriber("device-1") {
		t.Error("a subscriber whose buffer is full is not keeping up, so it is not responsive")
	}

	// Draining restores it: the stall was the state, not the subscriber.
	<-ch
	if !b.hasResponsiveSubscriber("device-1") {
		t.Error("room in the buffer again means the stream is keeping up after all")
	}
}

// One device with two streams: only one keeps up. The message reaches that
// one, so no wake is owed -- a per-subscriber check must not be a per-device
// verdict.
func TestOneKeepingUpSubscriberIsEnough(t *testing.T) {
	b := newMessageBroker()

	stalled, unsubscribeStalled, _ := b.subscribe("device-1", 4)
	defer unsubscribeStalled()
	for i := 0; i < cap(stalled); i++ {
		b.publish("device-1", store.Message{MessageID: "filler"})
	}

	fresh, unsubscribeFresh, _ := b.subscribe("device-1", 4)
	defer unsubscribeFresh()

	if !b.publish("device-1", store.Message{MessageID: "m1"}) {
		t.Error("the second stream had room, so the message did land")
	}
	if !b.hasResponsiveSubscriber("device-1") {
		t.Error("one stream keeping up is enough to call the device reachable")
	}
	if got := <-fresh; got.MessageID != "m1" {
		t.Errorf("the keeping-up stream should hold m1, got %q", got.MessageID)
	}
}

// SRV-28: the subscriber map only ever grew, so a client with a reconnect bug
// accumulated streams until the process ran out of file descriptors. The cap
// is per device, and a released slot has to be reusable -- a limit that only
// ever counts up would turn a day of ordinary reconnects into a refusal.
func TestSubscribeRefusesPastTheCapAndReleasesSlots(t *testing.T) {
	b := newMessageBroker()

	var release []func()
	for i := 0; i < 2; i++ {
		_, unsubscribe, err := b.subscribe("device-1", 2)
		if err != nil {
			t.Fatalf("stream %d is within the cap: %v", i, err)
		}
		release = append(release, unsubscribe)
	}

	if _, _, err := b.subscribe("device-1", 2); !errors.Is(err, errTooManyStreams) {
		t.Errorf("the third stream must be refused, got %v", err)
	}

	// Another device is unaffected: the cap is per device precisely so one
	// client's runaway cannot become everybody else's outage.
	if _, unsubscribe, err := b.subscribe("device-2", 2); err != nil {
		t.Errorf("a different device has its own allowance: %v", err)
	} else {
		unsubscribe()
	}

	release[0]()
	if _, unsubscribe, err := b.subscribe("device-1", 2); err != nil {
		t.Errorf("a released slot must be reusable, got %v", err)
	} else {
		unsubscribe()
	}
	release[1]()
}
