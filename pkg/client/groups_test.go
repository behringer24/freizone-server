package client

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/group"
)

// The receiving half of groups, driven with real signed events rather than
// hand-built maps. A group fact is only a fact because it verifies, so a test
// that fabricates them proves nothing about the code that checks them.

// founder is somebody else's device, holding a group they can invite into.
type founder struct {
	t         *testing.T
	accountID string
	rootPub   ed25519.PublicKey
	rootPriv  ed25519.PrivateKey
	deviceID  string
	devicePub ed25519.PublicKey
	devPriv   ed25519.PrivateKey

	groupID  string
	groupKey ed25519.PrivateKey
	state    *group.State

	// now advances a second per event. Real facts happen at different times,
	// and the fold buckets by timestamp -- so events sharing a second are
	// applied in an order nothing here controls, and two otherwise identical
	// ones are literally the same fact and deduplicate.
	now time.Time
}

func (f *founder) tick() time.Time {
	f.now = f.now.Add(time.Second)
	return f.now
}

func newFounder(t *testing.T) *founder {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating root key: %v", err)
	}
	// A real address, derived from the root key: every event names an account,
	// and the fold validates that it is one.
	name, err := address.DeriveID(rootPub)
	if err != nil {
		t.Fatalf("deriving account id: %v", err)
	}
	devicePub, devPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating device key: %v", err)
	}
	deviceID, err := devicecert.NewDeviceID()
	if err != nil {
		t.Fatalf("generating device id: %v", err)
	}

	f := &founder{
		t: t, accountID: name, rootPub: rootPub, rootPriv: rootPriv,
		deviceID: deviceID, devicePub: devicePub, devPriv: devPriv,
		now: time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC),
	}

	nonce, err := group.NewNonce()
	if err != nil {
		t.Fatalf("group nonce: %v", err)
	}
	// Derived from the founder's own root seed rather than stored, which is
	// what makes a group survive its founder losing the device.
	f.groupKey, err = group.DeriveRootKey(rootPriv.Seed(), nonce)
	if err != nil {
		t.Fatalf("deriving group key: %v", err)
	}
	groupPub := f.groupKey.Public().(ed25519.PublicKey)
	if f.groupID, err = group.DeriveID(groupPub); err != nil {
		t.Fatalf("deriving group id: %v", err)
	}

	genesis := &group.Event{
		Type: group.EventGenesis, GroupID: f.groupID, IssuedAt: f.tick(),
		RootPubKey: groupPub, Nonce: nonce, Subject: name, Server: "https://home.test",
	}
	if err := group.SignRoot(genesis, f.groupKey); err != nil {
		t.Fatalf("signing genesis: %v", err)
	}
	f.state = group.NewState()
	if res := f.state.Apply([]*group.Event{genesis}); len(res.Rejected) > 0 {
		t.Fatalf("own genesis rejected: %s", res.Rejected[0].Reason)
	}
	return f
}

// sign produces a device-signed event and applies it to the founder's own
// state, which is what a real member does before passing it on.
func (f *founder) sign(e *group.Event) *group.Event {
	f.t.Helper()
	e.GroupID = f.groupID
	if e.IssuedAt.IsZero() {
		e.IssuedAt = f.tick()
	}
	cert, err := devicecert.SignDeviceCertificate(f.accountID, f.deviceID, f.devicePub, time.Now().UTC(), f.rootPriv)
	if err != nil {
		f.t.Fatalf("signing device certificate: %v", err)
	}
	signer := &group.Signer{AccountID: f.accountID, RootPubKey: f.rootPub, DeviceCert: *cert}
	if err := group.SignDevice(e, signer, f.devPriv); err != nil {
		f.t.Fatalf("signing group event: %v", err)
	}
	if res := f.state.Apply([]*group.Event{e}); len(res.Rejected) > 0 {
		f.t.Fatalf("own %s rejected: %s", e.Type, res.Rejected[0].Reason)
	}
	return e
}

// invite adds an account and returns the whole fact set, which is what an
// invitee gets: they have nothing to merge a delta into.
func (f *founder) invite(accountID string) Content {
	f.t.Helper()
	f.sign(&group.Event{Type: group.EventMemberAdd, Subject: accountID, Server: "https://home.test"})
	return f.snapshot()
}

func (f *founder) snapshot() Content {
	return Content{
		Kind: ContentGroupControl, ControlKind: GroupSnapshot,
		GroupID: f.groupID, StateHash: f.state.Resolve().StateHash,
		Events: f.state.Events(),
	}
}

func (f *founder) events(evts ...*group.Event) Content {
	return Content{
		Kind: ContentGroupControl, ControlKind: GroupEvents,
		GroupID: f.groupID, StateHash: f.state.Resolve().StateHash,
		Events: evts,
	}
}

// groupClient is an account with an identity, without a server behind it: the
// receive half of groups touches no network at all.
func groupClient(t *testing.T) (*Client, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	accountID, err := address.DeriveID(pub)
	if err != nil {
		t.Fatalf("deriving account id: %v", err)
	}
	c, _ := newFixture(t, accountID, "unused-peer", nil)
	return c, accountID
}

// someAccount is a third party that only ever appears as a subject.
func someAccount(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	id, err := address.DeriveID(pub)
	if err != nil {
		t.Fatalf("deriving account id: %v", err)
	}
	return id
}

// An invitation is the one group event worth interrupting somebody for: it is a
// decision waiting on them, and their only sign that anything happened, since
// nothing is ever sent into a group before they accept.
func TestAnInvitationCreatesTheGroupAndNotifies(t *testing.T) {
	c, me := groupClient(t)
	f := newFounder(t)

	out, err := c.ApplyGroupControl(f.invite(me), f.accountID, time.Now())
	if err != nil {
		t.Fatalf("ApplyGroupControl: %v", err)
	}
	if !out.Invited {
		t.Fatal("a membership we did not hold, not yet accepted, is an invitation")
	}
	if out.GroupID != f.groupID {
		t.Errorf("group id: want %q, got %q", f.groupID, out.GroupID)
	}
	// Nothing to narrate on first contact: everything is new, and replaying
	// the whole membership history says nothing about what just happened.
	if len(out.Lines) != 0 {
		t.Errorf("a first snapshot must not narrate a history: %v", out.Lines)
	}

	membership, err := c.GroupMembership(f.groupID)
	if err != nil || membership == nil {
		t.Fatalf("GroupMembership: %v, %v", membership, err)
	}
	mine := memberOf(membership, me)
	if mine == nil || mine.Joined {
		t.Fatalf("want an unaccepted membership, got %+v", mine)
	}
	chat, err := c.GroupChat(f.groupID)
	if err != nil || chat == nil {
		t.Fatalf("GroupChat: %v, %v", chat, err)
	}
	if !chat.HasUnread {
		t.Error("the chat list is where they will come looking for the invitation")
	}

	// The same snapshot arriving again from another member is not a second
	// invitation.
	again, err := c.ApplyGroupControl(f.snapshot(), f.accountID, time.Now())
	if err != nil {
		t.Fatalf("ApplyGroupControl again: %v", err)
	}
	if again.Invited {
		t.Error("a redelivered snapshot must not read as a fresh invitation")
	}
}

// Being re-invited after a removal is an invitation too. The facts stay on this
// device when a moderator removes us, so the group is not new the second time
// round -- checking "is this group new to us" alone says nothing here.
func TestAReInvitationAfterRemovalNotifiesAgain(t *testing.T) {
	c, me := groupClient(t)
	f := newFounder(t)

	if _, err := c.ApplyGroupControl(f.invite(me), f.accountID, time.Now()); err != nil {
		t.Fatalf("invite: %v", err)
	}
	removed := f.sign(&group.Event{Type: group.EventMemberRemove, Subject: me})
	if _, err := c.ApplyGroupControl(f.events(removed), f.accountID, time.Now()); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if m, _ := c.GroupMembership(f.groupID); memberOf(m, me) != nil {
		t.Fatal("the removal did not take effect")
	}

	added := f.sign(&group.Event{Type: group.EventMemberAdd, Subject: me, Server: "https://home.test"})
	out, err := c.ApplyGroupControl(f.events(added), f.accountID, time.Now())
	if err != nil {
		t.Fatalf("re-invite: %v", err)
	}
	if !out.Invited {
		t.Fatal("a re-invitation is an invitation: the group is not new, but the membership is")
	}
}

// Delivery is unordered, so a membership change easily arrives before the
// snapshot carrying the genesis it rests on. It is held, not dropped.
func TestEventsThatOvertookTheirGenesisAreHeldAndAdmittedLater(t *testing.T) {
	c, me := groupClient(t)
	f := newFounder(t)

	f.sign(&group.Event{Type: group.EventMemberAdd, Subject: me, Server: "https://home.test"})
	// Captured before the event below exists, so the snapshot that arrives
	// second does *not* contain it. Without that the test proves nothing: a
	// snapshot carrying the same fact would admit it whether or not anything
	// was ever held.
	withoutIt := f.snapshot()

	otherID := someAccount(t)
	other := f.sign(&group.Event{Type: group.EventMemberAdd, Subject: otherID, Server: "https://home.test"})

	early, err := c.ApplyGroupControl(f.events(other), f.accountID, time.Now())
	if err != nil {
		t.Fatalf("premature event: %v", err)
	}
	if early.StateHash != "" {
		t.Error("nothing can be folded without a genesis")
	}
	if st, _ := c.GroupState(f.groupID); st != nil {
		t.Error("no facts may be stored for a group whose genesis has not arrived")
	}

	// The genesis arrives, and the held event goes in with it -- it is in no
	// other batch, so admitting it is only possible if it was kept.
	out, err := c.ApplyGroupControl(withoutIt, f.accountID, time.Now())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	membership, err := c.GroupMembership(out.GroupID)
	if err != nil || membership == nil {
		t.Fatalf("GroupMembership: %v, %v", membership, err)
	}
	if memberOf(membership, otherID) == nil {
		t.Error("the held event was not admitted once its genesis arrived")
	}
	if memberOf(membership, me) == nil {
		t.Error("our own membership is missing")
	}
}

// An event rejected for a reason no later fact can change is dropped rather
// than held: retrying it forever is pointless, and is what a hostile peer
// would want.
func TestAnUnverifiableEventIsDroppedRatherThanHeld(t *testing.T) {
	c, me := groupClient(t)
	f := newFounder(t)
	stranger := newFounder(t)

	// A perfectly well-formed event, for a different group.
	foreign := stranger.sign(&group.Event{Type: group.EventMemberAdd, Subject: me, Server: "https://home.test"})
	control := f.events(foreign)
	if _, err := c.ApplyGroupControl(control, f.accountID, time.Now()); err != nil {
		t.Fatalf("ApplyGroupControl: %v", err)
	}

	// Now the real genesis arrives. If the foreign event had been held, it
	// would be retried here -- and it must still not be admitted.
	out, err := c.ApplyGroupControl(f.snapshot(), f.accountID, time.Now())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	membership, err := c.GroupMembership(out.GroupID)
	if err != nil || membership == nil {
		t.Fatalf("GroupMembership: %v, %v", membership, err)
	}
	if memberOf(membership, me) != nil {
		t.Error("an event from another group was admitted into this one")
	}
}

// What changed is said in words, derived from the fold rather than from
// whoever made the change -- so every device writes the same transcript.
func TestMembershipChangesAreNarrated(t *testing.T) {
	c, me := groupClient(t)
	f := newFounder(t)

	if _, err := c.ApplyGroupControl(f.invite(me), f.accountID, time.Now()); err != nil {
		t.Fatalf("invite: %v", err)
	}

	// Somebody else is invited and accepts. An acceptance is signed by its own
	// subject -- nobody can join on another account's behalf -- so this needs
	// an identity of its own inside the group.
	other := newFounder(t)
	invited := f.sign(&group.Event{Type: group.EventMemberAdd, Subject: other.accountID, Server: "https://home.test"})
	other.groupID, other.groupKey, other.state, other.now = f.groupID, f.groupKey, f.state, f.now
	joined := other.sign(&group.Event{Type: group.EventJoinAccept, Subject: other.accountID})
	f.now = other.now
	named := f.sign(&group.Event{Type: group.EventMeta, Name: "Wandergruppe"})

	out, err := c.ApplyGroupControl(f.events(invited, joined, named), f.accountID, time.Now())
	if err != nil {
		t.Fatalf("ApplyGroupControl: %v", err)
	}

	// An invitation and its acceptance are two facts and read as two lines,
	// which is what makes an outstanding invitation visible at all.
	want := []string{
		memberLabel(other.accountID) + " was invited.",
		memberLabel(other.accountID) + " joined the group.",
		`The group is now called "Wandergruppe".`,
	}
	if len(out.Lines) != len(want) {
		t.Fatalf("lines: want %v, got %v", want, out.Lines)
	}
	for i := range want {
		if out.Lines[i] != want[i] {
			t.Errorf("line %d: want %q, got %q", i, want[i], out.Lines[i])
		}
	}

	// They are in the transcript, as system lines, seconds apart so that
	// several changes in one batch keep their order under any later sorting.
	msgs, err := c.Messages(f.groupID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != len(want) {
		t.Fatalf("transcript: want %d lines, got %d", len(want), len(msgs))
	}
	for i, m := range msgs {
		if m.Kind != MessageSystemInfo {
			t.Errorf("line %d is %q, not a system line", i, m.Kind)
		}
		if i > 0 && !m.Timestamp.After(msgs[i-1].Timestamp) {
			t.Errorf("line %d shares a timestamp with the one before it", i)
		}
	}
}

// Leaving and being removed are different stories, and the batch is what tells
// them apart.
func TestLeavingAndBeingRemovedReadDifferently(t *testing.T) {
	for _, tc := range []struct {
		name  string
		event group.EventType
		want  string
	}{
		{"left", group.EventLeave, " left the group."},
		{"removed", group.EventMemberRemove, " was removed from the group."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, me := groupClient(t)
			f := newFounder(t)
			// The departing member signs their own leave, so they need an
			// identity of their own inside this group.
			other := newFounder(t)
			f.sign(&group.Event{Type: group.EventMemberAdd, Subject: me, Server: "https://home.test"})
			f.sign(&group.Event{Type: group.EventMemberAdd, Subject: other.accountID, Server: "https://home.test"})
			if _, err := c.ApplyGroupControl(f.snapshot(), f.accountID, time.Now()); err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			// Spliced in only now, so their clock starts after the event that
			// made them a member -- leaving before being added would be applied
			// in that order by the fold, and correctly rejected.
			other.groupID, other.groupKey, other.state, other.now = f.groupID, f.groupKey, f.state, f.now

			gone := f.sign(&group.Event{Type: group.EventMemberRemove, Subject: other.accountID})
			if tc.event == group.EventLeave {
				gone = other.sign(&group.Event{Type: group.EventLeave, Subject: other.accountID})
			}
			want := memberLabel(other.accountID) + tc.want

			out, err := c.ApplyGroupControl(f.events(gone), f.accountID, time.Now())
			if err != nil {
				t.Fatalf("ApplyGroupControl: %v", err)
			}
			if len(out.Lines) != 1 || out.Lines[0] != want {
				t.Errorf("want %q, got %v", want, out.Lines)
			}
		})
	}
}

// A sync request applies nothing and asks for everything.
func TestASyncRequestOnlyAsks(t *testing.T) {
	c, _ := groupClient(t)
	f := newFounder(t)

	out, err := c.ApplyGroupControl(Content{
		Kind: ContentGroupControl, ControlKind: GroupSyncRequest,
		GroupID: f.groupID, StateHash: "theirs",
	}, f.accountID, time.Now())
	if err != nil {
		t.Fatalf("ApplyGroupControl: %v", err)
	}
	if !out.WantsSnapshot {
		t.Error("a sync request has to be reported, since answering it is a send")
	}
	if st, _ := c.GroupState(f.groupID); st != nil {
		t.Error("a sync request carries no facts and must create none")
	}
	// Their view is still worth remembering: it is what the send path compares
	// against.
	hashes, _ := c.GroupPeerStateHashes(f.groupID)
	if hashes[f.accountID] != "theirs" {
		t.Errorf("peer state hash: want %q, got %q", "theirs", hashes[f.accountID])
	}
}

// A group transcript is shared, so a message dropped for a blocked sender needs
// a trace -- otherwise the replies to it read as delivery loss.
func TestABlockedMembersGroupMessageLeavesOneCollapsedLine(t *testing.T) {
	c, p := newFixture(t, "fz1me", "fz1them", nil)
	if err := c.BlockPeer("fz1them", ""); err != nil {
		t.Fatalf("BlockPeer: %v", err)
	}
	// A group with a transcript already: a shell whose only content would be
	// "somebody blocked wrote" is deliberately not worth creating.
	if err := c.PutGroupChat(GroupChat{GroupID: "grp-1"}); err != nil {
		t.Fatalf("PutGroupChat: %v", err)
	}

	groupMsg := func(id, text string) []byte {
		return mustJSON(t, map[string]any{
			"v": 4, "group_id": "grp-1", "state_hash": "h1", "id": id, "text": text,
		})
	}
	first := mustHandle(t, c, p.msg("g1", p.send(groupMsg("m1", "one"))), ReceiveOptions{})
	p.settled()
	mustHandle(t, c, p.msg("g2", p.send(groupMsg("m2", "two"))), ReceiveOptions{})
	mustHandle(t, c, p.msg("g3", p.send(groupMsg("m3", "three"))), ReceiveOptions{})

	if first.StoredMessageID != "" || first.ShouldNotify {
		t.Error("a blocked member's message is neither stored nor notified")
	}

	msgs, err := c.Messages("grp-1")
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("three hidden messages must collapse into one line, got %d: %+v", len(msgs), msgs)
	}
	if msgs[0].Kind != MessageSystemInfo || !strings.Contains(msgs[0].Text, "hidden") {
		t.Errorf("line: %+v", msgs[0])
	}
	if !strings.Contains(msgs[0].Text, "fz1th") {
		t.Errorf("the line names the sender the way a bubble would: %q", msgs[0].Text)
	}

	// A blocked member must not be able to push the group up the chat list or
	// put a badge on it.
	chat, err := c.GroupChat("grp-1")
	if err != nil || chat == nil {
		t.Fatalf("GroupChat: %v, %v", chat, err)
	}
	if chat.HasUnread || chat.LastActivityAt != nil {
		t.Errorf("a hidden message moved the chat: unread=%v activity=%v", chat.HasUnread, chat.LastActivityAt)
	}
}

// A message can overtake the snapshot that introduces its group. Storing it
// anyway is the only option: the ratchet has already moved past it.
func TestAMessageForAnUnknownGroupIsStoredAnyway(t *testing.T) {
	c, p := newFixture(t, "fz1me", "fz1them", nil)

	res := mustHandle(t, c, p.msg("g1", p.send(mustJSON(t, map[string]any{
		"v": 4, "group_id": "grp-unknown", "id": "m1", "text": "who are these people",
	}))), ReceiveOptions{})
	if res.StoredMessageID != "m1" {
		t.Fatalf("stored id: want %q, got %q", "m1", res.StoredMessageID)
	}
	msgs, err := c.Messages("grp-unknown")
	if err != nil || len(msgs) != 1 {
		t.Fatalf("transcript: %v, %+v", err, msgs)
	}
	if m, _ := c.GroupMembership("grp-unknown"); m != nil {
		t.Error("a message must not invent facts about a group")
	}
}

// The group id follows from the genesis inside a snapshot, not from what the
// sender wrote on the outside.
func TestASnapshotsIdComesFromItsGenesis(t *testing.T) {
	c, me := groupClient(t)
	f := newFounder(t)

	control := f.invite(me)
	control.GroupID = "fz1somethingelse" // what the sender claims

	out, err := c.ApplyGroupControl(control, f.accountID, time.Now())
	if err != nil {
		t.Fatalf("ApplyGroupControl: %v", err)
	}
	if out.GroupID != f.groupID {
		t.Errorf("group id: want the genesis' %q, got the envelope's %q", f.groupID, out.GroupID)
	}
	if st, _ := c.GroupState("fz1somethingelse"); st != nil {
		t.Error("facts were filed under the id the sender claimed")
	}
}

// Held events are bounded: an unbounded buffer is somewhere for a hostile peer
// to put things.
func TestHeldEventsAreBounded(t *testing.T) {
	c, _ := groupClient(t)
	f := newFounder(t)

	var premature []*group.Event
	for i := 0; i < MaxHeldGroupEvents+20; i++ {
		premature = append(premature, f.sign(&group.Event{
			Type: group.EventMemberAdd, Subject: someAccount(t), Server: "https://home.test",
		}))
	}
	if _, err := c.ApplyGroupControl(f.events(premature...), f.accountID, time.Now()); err != nil {
		t.Fatalf("ApplyGroupControl: %v", err)
	}

	held, err := c.heldEventsLocked(f.groupID)
	if err != nil {
		t.Fatalf("reading held events: %v", err)
	}
	if len(held) != MaxHeldGroupEvents {
		t.Errorf("held: want the cap of %d, got %d", MaxHeldGroupEvents, len(held))
	}
}

// The fact set survives a reopen, and is re-verified on the way in: a stored
// event that no longer checks out must not be loadable.
func TestStoredFactsAreReVerifiedOnLoad(t *testing.T) {
	c, me := groupClient(t)
	f := newFounder(t)
	if _, err := c.ApplyGroupControl(f.invite(me), f.accountID, time.Now()); err != nil {
		t.Fatalf("invite: %v", err)
	}

	reopened, err := Open(c.Path())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	membership, err := reopened.GroupMembership(f.groupID)
	if err != nil || membership == nil {
		t.Fatalf("the facts did not survive a reopen: %v, %v", membership, err)
	}
	if memberOf(membership, me) == nil {
		t.Error("our membership did not survive")
	}

	// Damage one signature on disk. Loading must fail rather than quietly
	// accept a fact nobody signed.
	path, err := c.store.groupPath(f.groupID, fileFacts)
	if err != nil {
		t.Fatalf("groupPath: %v", err)
	}
	var facts struct {
		Events []map[string]any `json:"events"`
	}
	raw, err := readFileForTest(path)
	if err != nil {
		t.Fatalf("reading facts: %v", err)
	}
	if err := json.Unmarshal(raw, &facts); err != nil {
		t.Fatalf("decoding facts: %v", err)
	}
	facts.Events[0]["signature"] = "AAAA"
	tampered, err := json.Marshal(facts)
	if err != nil {
		t.Fatalf("encoding facts: %v", err)
	}
	if err := writeFileAtomic(path, tampered); err != nil {
		t.Fatalf("writing facts: %v", err)
	}

	broken, err := Open(c.Path())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = broken.Close() })
	if _, err := broken.GroupState(f.groupID); err == nil {
		t.Error("a fact set with a broken signature must not load")
	}
}

// readFileForTest reads a store file directly, for the tests that damage one.
func readFileForTest(path string) ([]byte, error) { return os.ReadFile(path) }
