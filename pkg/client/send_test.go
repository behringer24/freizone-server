package client

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

// The send path, exercised against the receive path rather than against
// asserted request bodies. Every round trip here is a real envelope through a
// real queue, opened by the code that has to open it in the field -- which is
// the only way a test can fail when the two halves disagree.

// The whole loop: reach out to a stranger, say something, have them read it.
func TestMessageTravelsFromOneClientToTheOther(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID

	convo, err := alice.StartConversation(t.Context(), bobID, "")
	if err != nil {
		t.Fatalf("StartConversation: %v", err)
	}
	if dev, _ := alice.peerDevice(bobID); dev == nil || dev.DeviceID != srv.deviceIDs["bob"] {
		t.Errorf("resolved device: want %q, got %+v", srv.deviceIDs["bob"], dev)
	}
	if convo.PendingApproval {
		t.Error("a conversation the user opened is not a request awaiting their own approval")
	}

	sent, err := alice.SendText(t.Context(), bobID, "hello bob", SendOptions{})
	if err != nil {
		t.Fatalf("SendText: %v", err)
	}
	if !sent.EstablishedSession {
		t.Error("the first message to a new peer has to establish the session")
	}
	if sent.WithoutOneTimePrekey {
		t.Error("bob published a pool, so this should have claimed one")
	}
	if sent.Message.SendState != SendSent {
		t.Errorf("send state: want %q, got %q", SendSent, sent.Message.SendState)
	}

	got := deliverTo(t, bob)
	if len(got) != 1 {
		t.Fatalf("bob received %d envelopes, want 1", len(got))
	}
	if got[0].Content.Text != "hello bob" {
		t.Errorf("bob read %q", got[0].Content.Text)
	}
	if got[0].Content.ID != sent.Message.ID {
		t.Error("the message id has to survive the round trip, or a reply cannot refer to it")
	}
	// Sent with every message so a peer who has lost local state can still
	// find the way back.
	if got[0].Content.SenderServer != srv.url {
		t.Errorf("sender server: want %q, got %q", srv.url, got[0].Content.SenderServer)
	}
	// Alice reached out, so from bob's side this is a stranger's first message.
	bobsView, err := bob.Conversation(identityOf(t, alice).AccountID)
	if err != nil || bobsView == nil {
		t.Fatalf("bob's conversation: %v, %v", bobsView, err)
	}
	if !bobsView.PendingApproval {
		t.Error("bob did not ask for this conversation, so it is a request")
	}

	// And back, which is the half that only works if bob's responder session
	// is the one alice's initiator session expects.
	if _, err := bob.SendText(t.Context(), identityOf(t, alice).AccountID, "hello alice", SendOptions{}); err != nil {
		t.Fatalf("bob's reply: %v", err)
	}
	back := deliverTo(t, alice)
	if len(back) != 1 || back[0].Content.Text != "hello alice" {
		t.Fatalf("alice read %+v", back)
	}
}

// The rule the whole file is shaped around: a send that does not arrive must
// not move the ratchet.
func TestAFailedSendDoesNotAdvanceTheRatchet(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}

	// One that works, so there is an established session to damage.
	if _, err := alice.SendText(t.Context(), bobID, "first", SendOptions{}); err != nil {
		t.Fatalf("SendText: %v", err)
	}
	deliverTo(t, bob)

	before := sessionSnapshot(t, alice, bobID)

	srv.set(func(s *fakeServer) { s.sendStatus = http.StatusInternalServerError })
	failed, err := alice.SendText(t.Context(), bobID, "never arrives", SendOptions{})
	if err == nil {
		t.Fatal("the send must report the failure")
	}
	if failed.Message.SendState == SendSent {
		t.Error("a failed send must not be recorded as sent")
	}

	if after := sessionSnapshot(t, alice, bobID); after != before {
		t.Fatal("the ratchet advanced for a message that never left -- the peer would see a gap they cannot bridge")
	}

	// The retry is what proves it: it re-encrypts under the message number the
	// failed attempt gave back, so bob's ratchet accepts it in sequence.
	srv.set(func(s *fakeServer) { s.sendStatus = 0 })
	if _, err := alice.RetryMessage(t.Context(), bobID, failed.Message.ID); err != nil {
		t.Fatalf("RetryMessage: %v", err)
	}
	got := deliverTo(t, bob)
	if len(got) != 1 || got[0].Content.Text != "never arrives" {
		t.Fatalf("bob read %+v after the retry", got)
	}

	msgs, err := alice.Messages(bobID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if last := msgs[len(msgs)-1]; last.SendState != SendSent {
		t.Errorf("after a successful retry the line must read as sent, got %q", last.SendState)
	}
}

// The nastier half of the same rule: the POST failed but the server had
// already stored the message. The retry must not show up twice.
func TestARetryOfAMessageThatArrivedIsRejectedAsADuplicate(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}
	if _, err := alice.SendText(t.Context(), bobID, "first", SendOptions{}); err != nil {
		t.Fatalf("SendText: %v", err)
	}
	deliverTo(t, bob)

	// The session as it stands before the send, which is what a failure would
	// put back.
	before, err := alice.Session(bobID, Sending)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}

	// Delivered, then reported as failed -- a response lost on the way back,
	// which from the sender's side is indistinguishable from a send that never
	// landed. Restoring the session by hand is exactly what deliver's rollback
	// does; the point of the test is what happens *after* it.
	sent, err := alice.SendText(t.Context(), bobID, "arrives once", SendOptions{})
	if err != nil {
		t.Fatalf("SendText: %v", err)
	}
	if err := alice.SetSession(bobID, Sending, before); err != nil {
		t.Fatalf("rolling the session back: %v", err)
	}
	if err := alice.SetMessageSendState(bobID, sent.Message.ID, SendFailed); err != nil {
		t.Fatalf("SetMessageSendState: %v", err)
	}

	if _, err := alice.RetryMessage(t.Context(), bobID, sent.Message.ID); err != nil {
		t.Fatalf("RetryMessage: %v", err)
	}

	got := deliverTo(t, bob)
	var shown int
	for _, res := range got {
		if res.StoredMessageID != "" {
			shown++
		}
	}
	if shown != 1 {
		t.Fatalf("bob stored %d copies of one message; the ratchet must reject the second", shown)
	}
	msgs, err := bob.Messages(identityOf(t, alice).AccountID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	var arrives int
	for _, m := range msgs {
		if m.Text == "arrives once" {
			arrives++
		}
	}
	if arrives != 1 {
		t.Errorf("bob's transcript shows the message %d times", arrives)
	}
}

// A re-key closes the loop the receive path could only report: recovery is the
// one decision that has to send something to take effect.
func TestResetSessionReEstablishesAndThePeerAdoptsIt(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	aliceID := identityOf(t, alice).AccountID
	bobID := identityOf(t, bob).AccountID

	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}
	if _, err := alice.SendText(t.Context(), bobID, "before", SendOptions{}); err != nil {
		t.Fatalf("SendText: %v", err)
	}
	deliverTo(t, bob)

	if err := alice.ResetSession(t.Context(), bobID, RekeyUserRequested); err != nil {
		t.Fatalf("ResetSession: %v", err)
	}

	// Alice's own side shows what happened.
	msgs, err := alice.Messages(bobID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	last := msgs[len(msgs)-1]
	if last.Kind != MessageSystemInfo || last.Text != SessionResetMarker {
		t.Errorf("alice's marker: want %q, got %q / %q", SessionResetMarker, last.Kind, last.Text)
	}

	// Bob adopts it, and the signal itself stays invisible.
	got := deliverTo(t, bob)
	if len(got) != 1 {
		t.Fatalf("bob received %d envelopes, want the re-key signal", len(got))
	}
	if !got[0].AdoptedPeerSession {
		t.Fatal("a deliberate re-key must be adopted whatever the tie-break would say")
	}
	if got[0].StoredMessageID != "" || got[0].ShouldNotify {
		t.Error("a re-key signal is never stored and never notifies")
	}
	bobsView, err := bob.Messages(aliceID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if l := bobsView[len(bobsView)-1]; l.Text != SessionResetMarker {
		t.Errorf("bob's marker: want %q, got %q", SessionResetMarker, l.Text)
	}

	// And the conversation still works on the new session, in both directions.
	if _, err := alice.SendText(t.Context(), bobID, "after", SendOptions{}); err != nil {
		t.Fatalf("SendText after reset: %v", err)
	}
	after := deliverTo(t, bob)
	if len(after) != 1 || after[0].Content.Text != "after" {
		t.Fatalf("bob read %+v after the re-key", after)
	}
	if _, err := bob.SendText(t.Context(), aliceID, "and back", SendOptions{}); err != nil {
		t.Fatalf("bob's reply: %v", err)
	}
	back := deliverTo(t, alice)
	if len(back) != 1 || back[0].Content.Text != "and back" {
		t.Fatalf("alice read %+v", back)
	}
}

// Topping up must not rotate the signed prekey. Rotating it on every top-up
// would replace the key peers are mid-establishment against, several times a
// day, for nothing.
func TestTopUpReAssertsTheSignedPrekeyRatherThanRotatingIt(t *testing.T) {
	srv := newFakeServer(t)
	c := srv.account(t, "d1")

	published := srv.publishedSignedPrekey("d1")
	if err := c.TopUpOneTimePrekeys(t.Context()); err != nil {
		t.Fatalf("TopUpOneTimePrekeys: %v", err)
	}

	after := srv.publishedSignedPrekey("d1")
	if after.KeyID != published.KeyID || after.PubKey != published.PubKey {
		t.Errorf("the signed prekey was rotated by a top-up: %d/%s became %d/%s",
			published.KeyID, published.PubKey[:8], after.KeyID, after.PubKey[:8])
	}
	// Re-signed, though: the endpoint replaces whatever is on file, so leaving
	// it out is not an option.
	if after.Signature == "" {
		t.Error("the re-assertion still has to carry a valid certificate")
	}
	// And a rotation, when actually asked for, does change it.
	if err := c.RotatePrekeys(t.Context()); err != nil {
		t.Fatalf("RotatePrekeys: %v", err)
	}
	if rotated := srv.publishedSignedPrekey("d1"); rotated.KeyID == published.KeyID {
		t.Error("RotatePrekeys must mint a new signed prekey")
	}
}

// A pool that is merely a little down is left alone; one that has run low is
// brought back to a full batch.
func TestTopUpOnlyRefillsBelowTheWaterMark(t *testing.T) {
	srv := newFakeServer(t)
	c := srv.account(t, "d1")
	if got := srv.remainingPrekeys("d1"); got != OneTimePrekeyBatch {
		t.Fatalf("after registration the pool holds %d, want %d", got, OneTimePrekeyBatch)
	}

	drain := func(to int) {
		srv.set(func(s *fakeServer) {
			s.device("d1").oneTimePrekeys = s.device("d1").oneTimePrekeys[:to]
		})
	}

	drain(OneTimePrekeyLowWaterMark)
	if err := c.TopUpOneTimePrekeys(t.Context()); err != nil {
		t.Fatalf("TopUpOneTimePrekeys: %v", err)
	}
	if got := srv.remainingPrekeys("d1"); got != OneTimePrekeyLowWaterMark {
		t.Errorf("a pool at the water mark must be left alone, got %d", got)
	}

	drain(1)
	if err := c.TopUpOneTimePrekeys(t.Context()); err != nil {
		t.Fatalf("TopUpOneTimePrekeys: %v", err)
	}
	if got := srv.remainingPrekeys("d1"); got != OneTimePrekeyBatch {
		t.Errorf("a low pool must come back to a full batch, got %d", got)
	}
}

// A session established without a one-time prekey still works -- and says so,
// because the alternative is that it degrades silently forever.
func TestAWithheldOneTimePrekeyIsReportedNotRefused(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}
	srv.set(func(s *fakeServer) { s.unauthenticatedClaim = true })

	sent, err := alice.SendText(t.Context(), bobID, "still works", SendOptions{})
	if err != nil {
		t.Fatalf("SendText: %v", err)
	}
	if !sent.WithoutOneTimePrekey {
		t.Error("a session started without a one-time prekey has to be reported as such")
	}
	got := deliverTo(t, bob)
	if len(got) != 1 || got[0].Content.Text != "still works" {
		t.Fatalf("a weaker session must still deliver, got %+v", got)
	}
}

// The stale-device rule at sending time: nothing propagates a device being
// replaced, so the send that trips over the dead id is the one that heals it.
func TestASendToAReplacedDeviceForgetsTheCachedOne(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}
	if _, err := alice.SendText(t.Context(), bobID, "first", SendOptions{}); err != nil {
		t.Fatalf("SendText: %v", err)
	}
	deliverTo(t, bob)

	srv.set(func(s *fakeServer) { s.sendStatus = http.StatusNotFound })
	if _, err := alice.SendText(t.Context(), bobID, "to a dead device", SendOptions{}); err == nil {
		t.Fatal("the send must fail")
	}

	dev, err := alice.peerDevice(bobID)
	if err != nil {
		t.Fatalf("peerDevice: %v", err)
	}
	if dev != nil {
		t.Error("a device the server no longer knows must not stay cached, or every retry fails against the same dead id")
	}
	// The session goes with it. Keeping one bound to a device that no longer
	// exists means the next send encrypts to a stranger's ratchet.
	session, err := alice.Session(bobID, Sending)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if session != nil {
		t.Error("the session bound to the forgotten device must go with it")
	}

	// Healed: the next send re-resolves and re-establishes.
	srv.set(func(s *fakeServer) { s.sendStatus = 0 })
	sent, err := alice.SendText(t.Context(), bobID, "to the new one", SendOptions{})
	if err != nil {
		t.Fatalf("SendText after healing: %v", err)
	}
	if !sent.EstablishedSession {
		t.Error("re-resolving means establishing a session again")
	}
}

// Federation off is a dead end in both directions, so it is refused before the
// message is ever encrypted.
func TestSendingToAnotherServerIsRefusedWhenFederationIsOff(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID

	// A peer recorded as living on another server, which is what makes the
	// send federated regardless of where the test server actually is.
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}
	convo, _ := alice.Conversation(bobID)
	convo.PeerServer = srv.url
	if err := alice.PutConversation(*convo); err != nil {
		t.Fatalf("PutConversation: %v", err)
	}

	srv.set(func(s *fakeServer) { s.federationEnabled = false })
	_, err := alice.SendText(t.Context(), bobID, "over the border", SendOptions{})
	if !errors.Is(err, ErrFederationDisabled) {
		t.Fatalf("want ErrFederationDisabled, got %v", err)
	}
	// Refused before encrypting, so nothing was spent on it.
	if session, _ := alice.Session(bobID, Sending); session != nil {
		t.Error("a refused send must not have established a session")
	}

	srv.set(func(s *fakeServer) { s.federationEnabled = true })
	if _, err := alice.SendText(t.Context(), bobID, "over the border", SendOptions{}); err != nil {
		t.Fatalf("SendText with federation on: %v", err)
	}
	if got := deliverTo(t, bob); len(got) != 1 {
		t.Fatalf("bob received %d envelopes over the federated route", len(got))
	}
}

// A receipt that would not move the watermark is not worth a message.
func TestAReceiptIsNotSentTwiceForTheSameWatermark(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}
	if _, err := alice.SendText(t.Context(), bobID, "establish", SendOptions{}); err != nil {
		t.Fatalf("SendText: %v", err)
	}
	deliverTo(t, bob)

	upTo := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	if err := alice.SendReceipt(t.Context(), bobID, ReceiptRead, upTo); err != nil {
		t.Fatalf("SendReceipt: %v", err)
	}
	if got := srv.queueLen("bob"); got != 1 {
		t.Fatalf("the first receipt should be sent, queue holds %d", got)
	}

	// The same watermark again, and an older one: both say nothing new.
	if err := alice.SendReceipt(t.Context(), bobID, ReceiptRead, upTo); err != nil {
		t.Fatalf("SendReceipt again: %v", err)
	}
	if err := alice.SendReceipt(t.Context(), bobID, ReceiptRead, upTo.Add(-time.Minute)); err != nil {
		t.Fatalf("SendReceipt older: %v", err)
	}
	if got := srv.queueLen("bob"); got != 1 {
		t.Errorf("a receipt saying nothing new was sent anyway, queue holds %d", got)
	}

	// A newer one is real news.
	if err := alice.SendReceipt(t.Context(), bobID, ReceiptRead, upTo.Add(time.Minute)); err != nil {
		t.Fatalf("SendReceipt newer: %v", err)
	}
	if got := srv.queueLen("bob"); got != 2 {
		t.Errorf("a newer watermark must be sent, queue holds %d", got)
	}

	// And it lands as a watermark on bob's side rather than as a message.
	got := deliverTo(t, bob)
	for _, res := range got {
		if res.StoredMessageID != "" {
			t.Error("a receipt must not appear in the transcript")
		}
	}
}

// Recovery is the decision the receive path could only report. It fires only
// for peers worth sending to.
func TestRecoveryReKeysOnlyEligiblePeers(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}
	if _, err := alice.SendText(t.Context(), bobID, "establish", SendOptions{}); err != nil {
		t.Fatalf("SendText: %v", err)
	}
	deliverTo(t, bob)

	// Evidence that the session is broken, old enough to clear the grace
	// period whichever way the ids compare.
	long := time.Now().UTC().Add(-2 * AutoRekeyResponderGrace)
	if _, err := alice.RecordDesyncEvidence(bobID, long); err != nil {
		t.Fatalf("RecordDesyncEvidence: %v", err)
	}

	// Blocked first: no amount of evidence justifies messaging somebody the
	// user has blocked.
	if err := alice.BlockPeer(bobID, ""); err != nil {
		t.Fatalf("BlockPeer: %v", err)
	}
	blockedConvo, _ := alice.Conversation(bobID)
	blockedConvo.Blocked = true
	if err := alice.PutConversation(*blockedConvo); err != nil {
		t.Fatalf("PutConversation: %v", err)
	}
	recovered, err := alice.RecoverDesyncedSessions(t.Context())
	if err != nil {
		t.Fatalf("RecoverDesyncedSessions: %v", err)
	}
	if len(recovered) != 0 {
		t.Errorf("a blocked peer must not be re-keyed, got %v", recovered)
	}

	if err := alice.UnblockPeer(bobID); err != nil {
		t.Fatalf("UnblockPeer: %v", err)
	}
	unblocked, _ := alice.Conversation(bobID)
	unblocked.Blocked = false
	if err := alice.PutConversation(*unblocked); err != nil {
		t.Fatalf("PutConversation: %v", err)
	}

	recovered, err = alice.RecoverDesyncedSessions(t.Context())
	if err != nil {
		t.Fatalf("RecoverDesyncedSessions: %v", err)
	}
	if len(recovered) != 1 || recovered[0] != bobID {
		t.Fatalf("want bob re-keyed, got %v", recovered)
	}
	got := deliverTo(t, bob)
	if len(got) != 1 || !got[0].AdoptedPeerSession {
		t.Fatalf("bob must adopt the recovery re-key, got %+v", got)
	}

	// The attempt is spaced out: running again straight away must do nothing,
	// or every reconnect burns one of bob's one-time prekeys.
	if _, err := alice.RecordDesyncEvidence(bobID, time.Now().UTC()); err != nil {
		t.Fatalf("RecordDesyncEvidence: %v", err)
	}
	again, err := alice.RecoverDesyncedSessions(t.Context())
	if err != nil {
		t.Fatalf("RecoverDesyncedSessions: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("a second re-key straight after the first must be spaced out, got %v", again)
	}
}

// A server that hands back an account whose id does not derive from the root
// key it came with is answering for somebody else.
func TestResolveRefusesAnAccountThatDoesNotMatchItsRootKey(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID

	srv.set(func(s *fakeServer) {
		// Same id, somebody else's root key.
		s.accounts[bobID].rootPub = identityOf(t, alice).RootPub
	})

	_, err := alice.ResolvePeer(t.Context(), bobID, "")
	if err == nil {
		t.Fatal("an account that does not match its root key must be refused")
	}
}

// The certificates in a prekey bundle are what stop the server choosing the
// keys a session is built on.
func TestClaimRefusesABundleWithABrokenCertificate(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID
	if _, err := alice.StartConversation(t.Context(), bobID, ""); err != nil {
		t.Fatalf("StartConversation: %v", err)
	}

	srv.set(func(s *fakeServer) {
		spk := s.device("bob").signedPrekey
		// A valid-looking key with a signature that covers a different one.
		spk.PubKey = s.device("bob").dhIdentityPub
		s.device("bob").signedPrekey = spk
	})

	if _, err := alice.SendText(t.Context(), bobID, "to a substituted key", SendOptions{}); err == nil {
		t.Fatal("a bundle whose certificate does not verify must be refused")
	}
	if session, _ := alice.Session(bobID, Sending); session != nil {
		t.Error("nothing may be established from a bundle that failed verification")
	}
}

func identityOf(t *testing.T, c *Client) Identity {
	t.Helper()
	id, err := c.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	return id
}

// sessionSnapshot is a comparable fingerprint of the sending session, so a
// test can say "unchanged" without reaching into the ratchet's internals.
func sessionSnapshot(t *testing.T, c *Client, peer string) string {
	t.Helper()
	s, err := c.Session(peer, Sending)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if s == nil {
		return ""
	}
	raw, err := s.MarshalJSON()
	if err != nil {
		t.Fatalf("marshalling session: %v", err)
	}
	return string(raw)
}
