package client

import (
	"strings"
	"testing"
)

// The queue a fresh connection finds: everything that arrived while nothing
// was listening. Draining it has to read each envelope and take it off the
// server, or the next connection finds the same pile.
func TestDrainReadsTheQueueAndClearsIt(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID

	for _, text := range []string{"first", "second"} {
		if _, err := alice.SendText(t.Context(), bobID, text, SendOptions{}); err != nil {
			t.Fatalf("SendText %q: %v", text, err)
		}
	}
	if srv.queueLen("bob") != 2 {
		t.Fatalf("expected two envelopes queued, got %d", srv.queueLen("bob"))
	}

	report, err := bob.Drain(t.Context(), ReceiveOptions{})
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(report.Failures) != 0 {
		t.Fatalf("nothing should have failed: %v", report.Failures)
	}
	if len(report.Results) != 2 {
		t.Fatalf("want two results, got %d", len(report.Results))
	}
	if report.Results[0].Content.Text != "first" || report.Results[1].Content.Text != "second" {
		t.Errorf("results are not in arrival order: %q then %q",
			report.Results[0].Content.Text, report.Results[1].Content.Text)
	}
	if srv.queueLen("bob") != 0 {
		t.Errorf("a drained queue must be acknowledged away, %d left", srv.queueLen("bob"))
	}

	// The transcript is the durable half, and the point of draining at all.
	msgs, err := bob.Messages(identityOf(t, alice).AccountID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 2 {
		t.Errorf("want two messages in the transcript, got %d", len(msgs))
	}
}

// The overlap this design has to survive: a drain runs while the live stream
// is up, so one envelope can arrive down both paths. Nothing anywhere
// coordinates the two -- what makes it safe is that the second copy is
// recognised by the id the first one was already marked with.
//
// The consequences that would be visible if it were not: a second transcript
// line, and a second confirmation moving a watermark the sender has already
// watched move.
//
// Worth saying what this does and does not pin, since it passes either way:
// it holds the *outcome*, not the mechanism. The duplicate check in
// HandleAndAck is a second line -- the first is that the receive path returns
// nothing to confirm with once it has recognised the id. Removing either one
// alone leaves this green, which is exactly why both are written down.
func TestAnEnvelopeSeenTwiceIsHandledOnce(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	aliceID := identityOf(t, alice).AccountID
	bobID := identityOf(t, bob).AccountID

	if _, err := alice.SendText(t.Context(), bobID, "only once", SendOptions{}); err != nil {
		t.Fatalf("SendText: %v", err)
	}

	// Take a copy of the envelope before draining, which is what the stream
	// would be holding at the same moment.
	queued, err := bob.FetchMessages(t.Context())
	if err != nil {
		t.Fatalf("FetchMessages: %v", err)
	}
	if len(queued) != 1 {
		t.Fatalf("want one envelope, got %d", len(queued))
	}

	report, err := bob.Drain(t.Context(), ReceiveOptions{})
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(report.Results) != 1 || report.Results[0].Duplicate {
		t.Fatalf("the first pass must read it as new: %+v", report.Results)
	}
	confirmationsAfterFirst := srv.queueLen("alice")

	// Now the stream's copy of the same envelope.
	again, err := bob.HandleAndAck(t.Context(), queued[0], ReceiveOptions{})
	if err != nil {
		t.Fatalf("handling the second copy: %v", err)
	}
	if !again.Duplicate {
		t.Error("the second copy has to be recognised as a duplicate")
	}

	msgs, err := bob.Messages(aliceID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 1 {
		t.Errorf("one envelope must leave one transcript line, got %d", len(msgs))
	}
	if got := srv.queueLen("alice"); got != confirmationsAfterFirst {
		t.Errorf("a duplicate must not be confirmed again: alice had %d, now %d",
			confirmationsAfterFirst, got)
	}
}

// An envelope that fails to decrypt is not acknowledged while a later attempt
// could still resolve it -- but once the client has given up, it must be taken
// off the queue. A deterministic failure that is never acknowledged blocks
// everything behind it for as long as the queue holds it.
func TestAPoisonEnvelopeIsOnlyAcknowledgedOnceGivenUpOn(t *testing.T) {
	srv := newFakeServer(t)
	bob := srv.account(t, "bob")

	poison := IncomingMessage{
		MessageID:       "poison-1",
		SenderAccountID: "qstranger000000000000",
		SenderDeviceID:  "deadbeef",
		Payload:         []byte(`{"v":1,"header":{"dh":"AAAA","n":0,"pn":0},"ciphertext":"AAAA"}`),
	}
	// On the queue for real, so that "acknowledged" means something: an
	// envelope that was never there would read as acknowledged from the start.
	srv.queueRaw("bob", poison)

	// MaxDecryptAttempts is the bound; everything before it stays on the queue
	// because the next attempt might work.
	for attempt := 1; attempt < MaxDecryptAttempts; attempt++ {
		_, err := bob.HandleAndAck(t.Context(), poison, ReceiveOptions{})
		if err == nil {
			t.Fatalf("attempt %d: this envelope cannot be readable", attempt)
		}
		if srv.acked("poison-1") {
			t.Fatalf("attempt %d acknowledged an envelope a retry might still resolve", attempt)
		}
	}

	if _, err := bob.HandleAndAck(t.Context(), poison, ReceiveOptions{}); err == nil {
		t.Fatal("the last attempt still fails; it just stops trying")
	}
	if !srv.acked("poison-1") {
		t.Error("once given up on, the envelope has to leave the queue or it blocks the ones behind it")
	}
}

// Drain reports a failure rather than returning one: a queue is a batch, and
// one unreadable envelope must not hide the readable ones behind it.
func TestOneBadEnvelopeDoesNotStopTheRest(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID

	srv.queueRaw("bob", IncomingMessage{
		MessageID:       "poison-2",
		SenderAccountID: "qstranger000000000000",
		SenderDeviceID:  "deadbeef",
		Payload:         []byte(`{"v":1,"header":{"dh":"AAAA","n":0,"pn":0},"ciphertext":"AAAA"}`),
	})
	if _, err := alice.SendText(t.Context(), bobID, "behind the bad one", SendOptions{}); err != nil {
		t.Fatalf("SendText: %v", err)
	}

	report, err := bob.Drain(t.Context(), ReceiveOptions{})
	if err != nil {
		t.Fatalf("Drain must not fail for one bad envelope: %v", err)
	}
	if len(report.Failures) != 1 || report.Failures[0].MessageID != "poison-2" {
		t.Fatalf("want the bad envelope reported: %+v", report.Failures)
	}
	if report.Failures[0].Acknowledged {
		t.Error("a first failure is still worth retrying, so it stays on the queue")
	}
	if len(report.Results) != 1 || report.Results[0].Content.Text != "behind the bad one" {
		t.Fatalf("the good envelope behind it must still be read: %+v", report.Results)
	}
}

// Upkeep is best-effort by nature: one part failing must not stop the others,
// and must not fail the call. An unreachable server is the ordinary way to see
// all four fail at once.
func TestMaintainReportsProblemsRatherThanFailing(t *testing.T) {
	srv := newFakeServer(t)
	bob := srv.account(t, "bob")

	// Point the account at a server that is not there. Nothing is reachable,
	// so every part has something to report.
	id := identityOf(t, bob)
	id.Server = "http://127.0.0.1:1"
	if err := bob.SetIdentity(id); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}

	report := bob.Maintain(t.Context())
	if len(report.Problems) == 0 {
		t.Fatal("an unreachable server has to be reported, not swallowed")
	}
	if report.PrekeysToppedUp {
		t.Error("nothing was topped up against a server that is not there")
	}
	// The text is what an operator reads in a log, so it has to say which part
	// failed rather than only that something did.
	var named bool
	for _, p := range report.Problems {
		if strings.Contains(p.Error(), "prekeys") {
			named = true
		}
	}
	if !named {
		t.Errorf("a problem should name the part that failed: %v", report.Problems)
	}
}

func TestMaintainOnAHealthyServerReportsNothingWrong(t *testing.T) {
	srv := newFakeServer(t)
	bob := srv.account(t, "bob")

	report := bob.Maintain(t.Context())
	if len(report.Problems) != 0 {
		t.Errorf("nothing should have failed: %v", report.Problems)
	}
	if !report.PrekeysToppedUp {
		t.Error("the prekey pool should have been topped up")
	}
}
