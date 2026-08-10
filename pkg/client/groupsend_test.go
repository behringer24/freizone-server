package client

import (
	"bytes"
	"net/http"
	"testing"
)

// Groups, end to end: three real clients through the stub server, every
// envelope encrypted once per member into that member's own ratchet.
//
// This is where the two halves of stage 5 meet. A test that drove only the
// send side would prove that the right bytes were posted and nothing about
// whether anyone can fold them.

// groupOf runs a client's receive loop and reconciles, which is what a caller
// does with a GroupOutcome: the receive half reports what it found, the send
// half acts on it.
func syncGroups(t *testing.T, c *Client) []ReceiveResult {
	t.Helper()
	results := deliverTo(t, c)
	for _, res := range results {
		if res.Group == nil {
			continue
		}
		if err := c.ReconcileGroup(t.Context(), *res.Group, res.PeerAccountID); err != nil {
			t.Fatalf("ReconcileGroup: %v", err)
		}
	}
	return results
}

// The whole loop: found a group, invite two people, have them accept, and say
// something everybody can read.
func TestAGroupMessageReachesEveryMember(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	carol := srv.account(t, "carol")
	bobID := identityOf(t, bob).AccountID
	carolID := identityOf(t, carol).AccountID

	groupID, err := alice.CreateGroup(t.Context(), "Wandergruppe")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := alice.InviteToGroup(t.Context(), groupID, bobID, ""); err != nil {
		t.Fatalf("InviteToGroup bob: %v", err)
	}
	if err := alice.InviteToGroup(t.Context(), groupID, carolID, ""); err != nil {
		t.Fatalf("InviteToGroup carol: %v", err)
	}

	// Bob hears about it, and being asked into a group is worth interrupting
	// somebody for.
	got := syncGroups(t, bob)
	var invited bool
	for _, res := range got {
		if res.Group != nil && res.Group.Invited {
			invited = true
			if !res.ShouldNotify {
				t.Error("an invitation is the one group event that notifies")
			}
		}
	}
	if !invited {
		t.Fatalf("bob was not told he was invited: %+v", got)
	}
	syncGroups(t, carol)

	membership, err := bob.GroupMembership(groupID)
	if err != nil || membership == nil {
		t.Fatalf("bob's view of the group: %v, %v", membership, err)
	}
	if membership.Name != "Wandergruppe" {
		t.Errorf("group name: want %q, got %q", "Wandergruppe", membership.Name)
	}

	// Nothing is sent into a group before somebody accepts.
	if _, err := bob.SendGroupText(t.Context(), groupID, "am I in?", SendOptions{}); err == nil {
		t.Error("an invitee who has not accepted must not be able to send")
	}

	if err := bob.AcceptGroupInvitation(t.Context(), groupID); err != nil {
		t.Fatalf("AcceptGroupInvitation: %v", err)
	}
	if err := carol.AcceptGroupInvitation(t.Context(), groupID); err != nil {
		t.Fatalf("carol accepting: %v", err)
	}
	syncGroups(t, alice)
	syncGroups(t, bob)
	syncGroups(t, carol)

	sent, err := alice.SendGroupText(t.Context(), groupID, "wer kommt mit?", SendOptions{})
	if err != nil {
		t.Fatalf("SendGroupText: %v", err)
	}
	if len(sent.Message.Deliveries) != 2 {
		t.Fatalf("want a delivery record per member, got %+v", sent.Message.Deliveries)
	}
	for _, d := range sent.Message.Deliveries {
		if d.State != SendSent {
			t.Errorf("delivery to %s: %s", d.AccountID, d.State)
		}
	}

	for name, member := range map[string]*Client{"bob": bob, "carol": carol} {
		results := syncGroups(t, member)
		var read string
		for _, res := range results {
			if res.StoredMessageID != "" {
				read = res.Content.Text
			}
		}
		if read != "wer kommt mit?" {
			t.Errorf("%s read %q", name, read)
		}
		msgs, err := member.Messages(groupID)
		if err != nil {
			t.Fatalf("%s's transcript: %v", name, err)
		}
		var found bool
		for _, m := range msgs {
			if m.Text == "wer kommt mit?" {
				found = true
				if m.SenderAccountID != identityOf(t, alice).AccountID {
					t.Errorf("%s: the line must name its author, got %q", name, m.SenderAccountID)
				}
			}
		}
		if !found {
			t.Errorf("%s's group transcript has no message", name)
		}
	}
}

// A member who was unreachable is owed the facts, and gets them on the next
// attempt rather than never.
func TestAnUnreachableMemberIsOwedTheFactsAndPaidLater(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID

	groupID, err := alice.CreateGroup(t.Context(), "Ausflug")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	// Bob's server refuses everything while he is invited.
	srv.set(func(s *fakeServer) { s.sendStatus = http.StatusServiceUnavailable })
	if err := alice.InviteToGroup(t.Context(), groupID, bobID, ""); err != nil {
		t.Fatalf("InviteToGroup: %v", err)
	}
	if srv.queueLen("bob") != 0 {
		t.Fatal("nothing should have reached bob")
	}
	peers, err := alice.groupPeersFor(groupID)
	if err != nil {
		t.Fatalf("groupPeersFor: %v", err)
	}
	if !peers.Owed[bobID] {
		t.Fatal("a member who could not be reached must be owed the facts, or the invitation is simply lost")
	}

	srv.set(func(s *fakeServer) { s.sendStatus = 0 })
	paid, err := alice.PayGroupSnapshotDebts(t.Context())
	if err != nil {
		t.Fatalf("PayGroupSnapshotDebts: %v", err)
	}
	if paid != 1 {
		t.Fatalf("want one debt settled, got %d", paid)
	}

	got := syncGroups(t, bob)
	var invited bool
	for _, res := range got {
		if res.Group != nil && res.Group.Invited {
			invited = true
		}
	}
	if !invited {
		t.Fatalf("bob never got the invitation: %+v", got)
	}

	// Settled, so it is not paid again on every reconnect.
	peers, err = alice.groupPeersFor(groupID)
	if err != nil {
		t.Fatalf("groupPeersFor: %v", err)
	}
	if peers.Owed[bobID] {
		t.Error("a settled debt must be cleared")
	}
}

// A member who holds no facts at all cannot be told so by any hash -- their
// own only travels on messages they cannot send. Asking outright is the only
// way out, and it is answered.
func TestAMemberWithNoFactsAsksAndIsAnswered(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID
	aliceID := identityOf(t, alice).AccountID

	groupID, err := alice.CreateGroup(t.Context(), "Ausflug")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := alice.InviteToGroup(t.Context(), groupID, bobID, ""); err != nil {
		t.Fatalf("InviteToGroup: %v", err)
	}
	syncGroups(t, bob)
	if err := bob.AcceptGroupInvitation(t.Context(), groupID); err != nil {
		t.Fatalf("AcceptGroupInvitation: %v", err)
	}
	syncGroups(t, alice)

	// Bob loses everything he knew about the group -- a reinstall, a wipe.
	if err := bob.forgetGroupForTest(groupID); err != nil {
		t.Fatalf("forgetting the group: %v", err)
	}
	if st, _ := bob.GroupState(groupID); st != nil {
		t.Fatal("the group should be gone")
	}

	// Alice writes. Bob can decrypt it -- the session is one-to-one -- but has
	// no idea what group it belongs to.
	if _, err := alice.SendGroupText(t.Context(), groupID, "immer noch dabei?", SendOptions{}); err != nil {
		t.Fatalf("SendGroupText: %v", err)
	}
	got := syncGroups(t, bob)
	if len(got) != 1 || got[0].Group == nil || got[0].Group.GroupID != groupID {
		t.Fatalf("bob received %+v", got)
	}

	// The reconcile turned into a request. Alice answers it.
	if srv.queueLen("alice") == 0 {
		t.Fatal("bob must ask for the facts he cannot otherwise get")
	}
	syncGroups(t, alice)
	syncGroups(t, bob)

	membership, err := bob.GroupMembership(groupID)
	if err != nil || membership == nil {
		t.Fatalf("bob's facts did not come back: %v, %v", membership, err)
	}
	if memberOf(membership, aliceID) == nil || memberOf(membership, bobID) == nil {
		t.Errorf("membership after recovery: %+v", membership.Members)
	}
}

// Asking is rate limited: a group whose every member writes must not produce a
// request per message.
func TestAskingForFactsIsRateLimited(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID

	groupID, err := alice.CreateGroup(t.Context(), "Ausflug")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := alice.InviteToGroup(t.Context(), groupID, bobID, ""); err != nil {
		t.Fatalf("InviteToGroup: %v", err)
	}
	syncGroups(t, bob)
	if err := bob.AcceptGroupInvitation(t.Context(), groupID); err != nil {
		t.Fatalf("accepting: %v", err)
	}
	syncGroups(t, alice)
	if err := bob.forgetGroupForTest(groupID); err != nil {
		t.Fatalf("forgetting: %v", err)
	}

	aliceID := identityOf(t, alice).AccountID
	before := srv.queueLen("alice")
	for i := 0; i < 3; i++ {
		if err := bob.AskForGroupFacts(t.Context(), groupID, aliceID, ""); err != nil {
			t.Fatalf("AskForGroupFacts: %v", err)
		}
	}
	if got := srv.queueLen("alice") - before; got != 1 {
		t.Errorf("three asks in a row produced %d requests, want 1", got)
	}
}

// Two members who stay divergent must not trade snapshots forever.
func TestTheSameForeignHashIsAnsweredOnlyOnce(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID

	groupID, err := alice.CreateGroup(t.Context(), "Ausflug")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := alice.InviteToGroup(t.Context(), groupID, bobID, ""); err != nil {
		t.Fatalf("InviteToGroup: %v", err)
	}
	srv.set(func(s *fakeServer) { s.queues = map[string][]queuedEnvelope{} })

	outcome := GroupOutcome{GroupID: groupID, PeerStateHash: "a-hash-we-do-not-share"}
	for i := 0; i < 3; i++ {
		if err := alice.ReconcileGroup(t.Context(), outcome, bobID); err != nil {
			t.Fatalf("ReconcileGroup: %v", err)
		}
	}
	if got := srv.queueLen("bob"); got != 1 {
		t.Errorf("the same foreign hash was answered %d times, want 1", got)
	}

	// It survives a restart, which the in-memory version this replaces does
	// not: a reconnect would otherwise re-open the loop.
	reopened, err := Open(alice.Path())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.ReconcileGroup(t.Context(), outcome, bobID); err != nil {
		t.Fatalf("ReconcileGroup after reopen: %v", err)
	}
	if got := srv.queueLen("bob"); got != 1 {
		t.Errorf("the loop re-opened after a restart: %d snapshots", got)
	}

	// A different hash is different news, and an outright request is always
	// answered.
	if err := alice.ReconcileGroup(t.Context(), GroupOutcome{GroupID: groupID, PeerStateHash: "another"}, bobID); err != nil {
		t.Fatalf("ReconcileGroup: %v", err)
	}
	if err := alice.ReconcileGroup(t.Context(), GroupOutcome{GroupID: groupID, WantsSnapshot: true}, bobID); err != nil {
		t.Fatalf("ReconcileGroup: %v", err)
	}
	if got := srv.queueLen("bob"); got != 3 {
		t.Errorf("want 3 snapshots in total, got %d", got)
	}
}

// A group receipt goes to the author alone and is filed against that member.
func TestAGroupReceiptIsFiledPerMember(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID

	groupID := groupWith(t, srv, alice, bob)
	sent, err := alice.SendGroupText(t.Context(), groupID, "gelesen?", SendOptions{})
	if err != nil {
		t.Fatalf("SendGroupText: %v", err)
	}
	got := syncGroups(t, bob)
	if len(got) == 0 || got[0].Group == nil || got[0].Group.DeliveredUpTo == nil {
		t.Fatalf("bob has nothing to confirm: %+v", got)
	}
	// The anchor is the sender's own clock, and it is a *group* field: sent
	// through the one-to-one one it would confirm alice's unrelated direct
	// messages.
	if got[0].DeliveredUpTo != nil {
		t.Error("a group anchor must not travel through the one-to-one field, or it would confirm unrelated direct messages")
	}
	_ = sent

	upTo := *got[0].Group.DeliveredUpTo
	if err := bob.SendGroupReceipt(t.Context(), groupID, identityOf(t, alice).AccountID, ReceiptRead, upTo); err != nil {
		t.Fatalf("SendGroupReceipt: %v", err)
	}
	syncGroups(t, alice)

	chat, err := alice.GroupChat(groupID)
	if err != nil || chat == nil {
		t.Fatalf("GroupChat: %v, %v", chat, err)
	}
	receipt, ok := chat.MemberReceipts[bobID]
	if !ok || receipt.ReadUpTo == nil {
		t.Fatalf("bob's receipt was not filed: %+v", chat.MemberReceipts)
	}
	if !receipt.ReadUpTo.Equal(upTo.UTC()) {
		t.Errorf("watermark: want %s, got %s", upTo, receipt.ReadUpTo)
	}
	// It must not have become a visible line.
	msgs, err := alice.Messages(groupID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	for _, m := range msgs {
		if m.Kind == MessageNormal && !m.Mine {
			t.Error("a receipt appeared in the transcript")
		}
	}
}

// A picture is uploaded once for the whole group, granted to every member's
// device rather than copied per member.
func TestAGroupPictureIsUploadedOnce(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	carol := srv.account(t, "carol")

	groupID := groupWith(t, srv, alice, bob, carol)
	original := imageBytes()
	sent, err := alice.SendGroupText(t.Context(), groupID, "vom Gipfel", SendOptions{
		Media: &OutgoingMedia{Bytes: original, MimeType: "image/jpeg", Thumb: []byte("tiny")},
	})
	if err != nil {
		t.Fatalf("SendGroupText: %v", err)
	}
	if got := srv.blobCount(); got != 1 {
		t.Fatalf("one picture, %d blobs", got)
	}
	blobID := sent.Message.Attachments[0].BlobID
	if got := srv.blobRecipientsFor(blobID); len(got) != 2 {
		t.Errorf("the blob must be granted to every member's device, got %d", len(got))
	}

	for _, member := range []*Client{bob, carol} {
		results := syncGroups(t, member)
		var att Attachment
		var messageID string
		for _, res := range results {
			if len(res.Content.Attachments) == 1 {
				att, messageID = res.Content.Attachments[0], res.StoredMessageID
			}
		}
		if messageID == "" {
			t.Fatal("a member did not receive the picture")
		}
		fetched, err := member.EnsureAttachment(t.Context(), groupID, messageID, "", att)
		if err != nil {
			t.Fatalf("EnsureAttachment: %v", err)
		}
		if !bytes.Equal(fetched, original) {
			t.Error("the picture came back different")
		}
	}
}

// Leaving tells the others, and takes effect on their side.
func TestLeavingAGroupReachesTheOthers(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	bobID := identityOf(t, bob).AccountID

	groupID := groupWith(t, srv, alice, bob)
	if err := bob.LeaveGroup(t.Context(), groupID); err != nil {
		t.Fatalf("LeaveGroup: %v", err)
	}
	syncGroups(t, alice)

	membership, err := alice.GroupMembership(groupID)
	if err != nil || membership == nil {
		t.Fatalf("GroupMembership: %v, %v", membership, err)
	}
	if memberOf(membership, bobID) != nil {
		t.Error("bob is still a member on alice's side")
	}
	msgs, err := alice.Messages(groupID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	var narrated bool
	for _, m := range msgs {
		if m.Kind == MessageSystemInfo && m.Text == memberLabel(bobID)+" left the group." {
			narrated = true
		}
	}
	if !narrated {
		t.Errorf("leaving was not narrated: %+v", msgs)
	}

	// And nothing more is sent to them.
	sent, err := alice.SendGroupText(t.Context(), groupID, "allein", SendOptions{})
	if err != nil {
		t.Fatalf("SendGroupText: %v", err)
	}
	if len(sent.Message.Deliveries) != 0 {
		t.Errorf("a message went to %d recipients after everyone left", len(sent.Message.Deliveries))
	}
}

// An action the fold would reject is never broadcast: it would only produce a
// divergent view of the group.
func TestAnActionTheFoldRejectsIsNotSent(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	aliceID := identityOf(t, alice).AccountID

	groupID := groupWith(t, srv, alice, bob)
	srv.set(func(s *fakeServer) { s.queues = map[string][]queuedEnvelope{} })

	// A member trying to remove the founder, whose authority is key possession
	// and cannot be voted away.
	if err := bob.RemoveFromGroup(t.Context(), groupID, aliceID); err == nil {
		t.Fatal("a member must not be able to remove the founder")
	}
	if got := srv.queueLen("alice"); got != 0 {
		t.Errorf("a rejected action was broadcast anyway: %d envelopes", got)
	}
	membership, err := bob.GroupMembership(groupID)
	if err != nil || memberOf(membership, aliceID) == nil {
		t.Error("the rejected action changed the local view")
	}
}

// A group send that reaches one member but not the other is retried into
// exactly the gap: the member who already has it is not sent a duplicate, and
// the one who does not gets it.
func TestRetryGroupMessageAddressesOnlyTheGap(t *testing.T) {
	srv := newFakeServer(t)
	alice := srv.account(t, "alice")
	bob := srv.account(t, "bob")
	carol := srv.account(t, "carol")
	bobID := identityOf(t, bob).AccountID

	groupID := groupWith(t, srv, alice, bob, carol)

	// Bob's copy never arrives; carol's does.
	srv.set(func(s *fakeServer) { s.failAccounts = map[string]bool{bobID: true} })
	sent, err := alice.SendGroupText(t.Context(), groupID, "wo seid ihr?", SendOptions{})
	if err != nil {
		t.Fatalf("SendGroupText: %v", err)
	}
	if sent.Message.SendState != SendSent {
		t.Fatalf("delivered to somebody is sent, got %s", sent.Message.SendState)
	}
	for _, d := range sent.Message.Deliveries {
		want := SendSent
		if d.AccountID == bobID {
			want = SendFailed
		}
		if d.State != want {
			t.Errorf("delivery to %s: want %s, got %s", d.AccountID, want, d.State)
		}
	}
	if srv.queueLen("carol") != 1 {
		t.Fatalf("carol should already have her copy, queue has %d", srv.queueLen("carol"))
	}

	// Bob's server recovers. The retry must reach him without giving carol a
	// second copy of the same message.
	srv.set(func(s *fakeServer) { s.failAccounts = nil })
	retried, err := alice.RetryGroupMessage(t.Context(), groupID, sent.Message.ID)
	if err != nil {
		t.Fatalf("RetryGroupMessage: %v", err)
	}
	if retried.Message.SendState != SendSent {
		t.Errorf("retried message: want sent, got %s", retried.Message.SendState)
	}
	for _, d := range retried.Message.Deliveries {
		if d.State != SendSent {
			t.Errorf("delivery to %s after retry: %s", d.AccountID, d.State)
		}
	}
	if srv.queueLen("carol") != 1 {
		t.Errorf("carol must not receive a duplicate: queue has %d", srv.queueLen("carol"))
	}
	if srv.queueLen("bob") != 1 {
		t.Fatalf("bob should now have exactly one copy, queue has %d", srv.queueLen("bob"))
	}

	// Retrying a message with nothing left pending is a harmless no-op, not an
	// error -- and must not resend to anyone who already has it. Checked before
	// draining either queue below, since a queue length of zero would prove
	// nothing about whether a duplicate was sent.
	again, err := alice.RetryGroupMessage(t.Context(), groupID, sent.Message.ID)
	if err != nil {
		t.Fatalf("retrying a fully-delivered message should be a no-op, got: %v", err)
	}
	if again.Message.SendState != SendSent {
		t.Errorf("no-op retry: want sent, got %s", again.Message.SendState)
	}
	if srv.queueLen("carol") != 1 || srv.queueLen("bob") != 1 {
		t.Errorf("no-op retry must not resend: carol=%d bob=%d", srv.queueLen("carol"), srv.queueLen("bob"))
	}

	got := syncGroups(t, bob)
	var read string
	for _, res := range got {
		if res.StoredMessageID != "" {
			read = res.Content.Text
		}
	}
	if read != "wo seid ihr?" {
		t.Errorf("bob read %q", read)
	}

	if _, err := alice.RetryGroupMessage(t.Context(), groupID, "no-such-message"); err == nil {
		t.Error("retrying an unknown message must be refused")
	}
}

// groupWith founds a group and gets everyone in it, which most tests need
// before they can start.
func groupWith(t *testing.T, srv *fakeServer, founder *Client, members ...*Client) string {
	t.Helper()
	groupID, err := founder.CreateGroup(t.Context(), "Testgruppe")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	for _, m := range members {
		if err := founder.InviteToGroup(t.Context(), groupID, identityOf(t, m).AccountID, ""); err != nil {
			t.Fatalf("InviteToGroup: %v", err)
		}
	}
	for _, m := range members {
		syncGroups(t, m)
		if err := m.AcceptGroupInvitation(t.Context(), groupID); err != nil {
			t.Fatalf("AcceptGroupInvitation: %v", err)
		}
	}
	syncGroups(t, founder)
	for _, m := range members {
		syncGroups(t, m)
	}
	// Drain anything the acceptances produced, so a test counting envelopes
	// starts from zero.
	srv.set(func(s *fakeServer) { s.queues = map[string][]queuedEnvelope{} })
	return groupID
}

// forgetGroupForTest wipes everything this account knows about a group, as a
// reinstall would.
func (c *Client) forgetGroupForTest(groupID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, name := range []string{fileFacts, fileHeld, filePeers, fileChat} {
		path, err := c.store.groupPath(groupID, name)
		if err != nil {
			return err
		}
		if err := removeFile(path); err != nil {
			return err
		}
	}
	return nil
}
