package client

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/pkg/ratchet"
)

func openTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := Open(filepath.Join(t.TempDir(), "account.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestOpenIsIdempotentAndSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.db")

	c, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := c.MarkPeerKnown("peer-1"); err != nil {
		t.Fatalf("MarkPeerKnown: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-opening must re-run migrations harmlessly and still see the data.
	c2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer c2.Close()

	known, err := c2.IsPeerKnown("peer-1")
	if err != nil {
		t.Fatalf("IsPeerKnown: %v", err)
	}
	if !known {
		t.Error("peer marked known before close is not known after reopen")
	}
}

func TestIdentityReportsMissingBeforeSetup(t *testing.T) {
	c := openTestClient(t)
	if _, err := c.Identity(); err != ErrNoIdentity {
		t.Fatalf("Identity on a fresh database: want ErrNoIdentity, got %v", err)
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	c := openTestClient(t)
	registered := time.Date(2026, 8, 7, 12, 30, 0, 0, time.UTC)
	want := Identity{
		AccountID:           "fz1account",
		Server:              "https://example.invalid",
		RootPub:             []byte{1, 2, 3},
		RootPriv:            []byte{4, 5, 6},
		DeviceID:            "device-1",
		DevicePub:           []byte{7, 8},
		DevicePriv:          []byte{9, 10},
		DHIdentityPub:       []byte{11},
		DHIdentityPriv:      []byte{12},
		SignedPrekeyID:      3,
		SignedPrekeyPub:     []byte{13},
		SignedPrekeyPriv:    []byte{14},
		NextSignedPrekeyID:  4,
		NextOneTimePrekeyID: 17,
		RecoveryBackupDone:  true,
		PushRegisteredAt:    &registered,
		PushMechanism:       "unifiedpush:org.example.distributor",
	}
	if err := c.SetIdentity(want); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}

	got, err := c.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if got.PushRegisteredAt == nil || !got.PushRegisteredAt.Equal(registered) {
		t.Errorf("PushRegisteredAt: want %v, got %v", registered, got.PushRegisteredAt)
	}
	got.PushRegisteredAt, want.PushRegisteredAt = nil, nil
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("identity round trip:\n got %+v\nwant %+v", got, want)
	}
}

// SetIdentity is also the restore path -- same root key, fresh device key --
// so it has to replace rather than refuse.
func TestSetIdentityReplaces(t *testing.T) {
	c := openTestClient(t)
	base := Identity{
		AccountID: "a", Server: "s",
		RootPub: []byte{1}, RootPriv: []byte{2},
		DeviceID: "old", DevicePub: []byte{3}, DevicePriv: []byte{4},
	}
	if err := c.SetIdentity(base); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}
	base.DeviceID = "new"
	if err := c.SetIdentity(base); err != nil {
		t.Fatalf("SetIdentity again: %v", err)
	}
	got, err := c.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if got.DeviceID != "new" {
		t.Errorf("device id after replace: want %q, got %q", "new", got.DeviceID)
	}
}

// --- sessions ---------------------------------------------------------------

func newTestSession(t *testing.T) *ratchet.Session {
	t.Helper()
	curve := ecdh.X25519()
	initiatorDH, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating dh identity: %v", err)
	}
	responderDH, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating peer dh identity: %v", err)
	}
	spk, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating signed prekey: %v", err)
	}
	s, _, err := ratchet.InitiateSession(initiatorDH, ratchet.RemoteBundle{
		DHIdentityPubKey: responderDH.PublicKey(),
		SignedPrekeyID:   1,
		SignedPrekeyPub:  spk.PublicKey(),
	})
	if err != nil {
		t.Fatalf("InitiateSession: %v", err)
	}
	return s
}

func TestSessionRoundTripAndKindsAreIndependent(t *testing.T) {
	c := openTestClient(t)

	got, err := c.Session("peer", Sending)
	if err != nil {
		t.Fatalf("Session on empty store: %v", err)
	}
	if got != nil {
		t.Fatal("a peer with no session should read back nil, not an empty session")
	}

	sending, inbound := newTestSession(t), newTestSession(t)
	if err := c.SetSession("peer", Sending, sending); err != nil {
		t.Fatalf("SetSession sending: %v", err)
	}
	if err := c.SetSession("peer", Inbound, inbound); err != nil {
		t.Fatalf("SetSession inbound: %v", err)
	}

	readSending, err := c.Session("peer", Sending)
	if err != nil {
		t.Fatalf("Session sending: %v", err)
	}
	readInbound, err := c.Session("peer", Inbound)
	if err != nil {
		t.Fatalf("Session inbound: %v", err)
	}
	if string(readSending.RK) != string(sending.RK) {
		t.Error("sending session did not round trip")
	}
	if string(readInbound.RK) != string(inbound.RK) {
		t.Error("inbound session did not round trip")
	}
	if string(readSending.RK) == string(readInbound.RK) {
		t.Error("the two kinds are sharing one row")
	}

	// Deleting one kind must leave the other alone -- adopting a peer's session
	// drops ours for sending while the read-only one stays.
	if err := c.DeleteSession("peer", Inbound); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if s, _ := c.Session("peer", Inbound); s != nil {
		t.Error("inbound session survived deletion")
	}
	if s, _ := c.Session("peer", Sending); s == nil {
		t.Error("deleting the inbound session also removed the sending one")
	}
}

// --- one-time prekeys -------------------------------------------------------

func TestOneTimePrekeyLookupDoesNotConsume(t *testing.T) {
	c := openTestClient(t)
	if err := c.PutOneTimePrekeys([]OneTimePrekey{
		{KeyID: 1, Pub: []byte{1}, Priv: []byte{2}},
		{KeyID: 2, Pub: []byte{3}, Priv: []byte{4}},
	}); err != nil {
		t.Fatalf("PutOneTimePrekeys: %v", err)
	}

	// The whole point: a responder attempt that fails must cost nothing. Looking
	// up repeatedly leaves the pool untouched.
	for i := 0; i < 3; i++ {
		got, err := c.OneTimePrekey(1)
		if err != nil {
			t.Fatalf("OneTimePrekey: %v", err)
		}
		if got == nil {
			t.Fatal("prekey 1 vanished without being consumed")
		}
	}
	if n, _ := c.CountOneTimePrekeys(); n != 2 {
		t.Errorf("pool after lookups: want 2, got %d", n)
	}

	if err := c.ConsumeOneTimePrekey(1); err != nil {
		t.Fatalf("ConsumeOneTimePrekey: %v", err)
	}
	if n, _ := c.CountOneTimePrekeys(); n != 1 {
		t.Errorf("pool after consume: want 1, got %d", n)
	}

	// An initial referencing a prekey already used is routine, not an error.
	got, err := c.OneTimePrekey(1)
	if err != nil {
		t.Fatalf("OneTimePrekey after consume: %v", err)
	}
	if got != nil {
		t.Error("consumed prekey is still readable")
	}
}

// --- processed ids ----------------------------------------------------------

func TestMarkMessageProcessedEvictsOldestFirst(t *testing.T) {
	c := openTestClient(t)
	total := MaxProcessedMessageIDs + 10
	for i := 0; i < total; i++ {
		if err := c.MarkMessageProcessed(fmt.Sprintf("m%04d", i)); err != nil {
			t.Fatalf("MarkMessageProcessed: %v", err)
		}
	}

	n, err := c.CountProcessedMessages()
	if err != nil {
		t.Fatalf("CountProcessedMessages: %v", err)
	}
	if n != MaxProcessedMessageIDs {
		t.Errorf("remembered ids: want %d, got %d", MaxProcessedMessageIDs, n)
	}

	oldest, err := c.WasMessageProcessed("m0000")
	if err != nil {
		t.Fatalf("WasMessageProcessed: %v", err)
	}
	if oldest {
		t.Error("the oldest id should have been evicted first")
	}
	newest, err := c.WasMessageProcessed(fmt.Sprintf("m%04d", total-1))
	if err != nil {
		t.Fatalf("WasMessageProcessed: %v", err)
	}
	if !newest {
		t.Error("the newest id was evicted")
	}
}

// Re-marking must not refresh an id's position. The app stores these in an
// insertion-ordered set where re-adding an existing element leaves it where it
// was, and an eviction order that disagrees would forget a different id.
func TestReMarkingDoesNotRefreshPosition(t *testing.T) {
	c := openTestClient(t)
	for i := 0; i < MaxProcessedMessageIDs; i++ {
		if err := c.MarkMessageProcessed(fmt.Sprintf("m%04d", i)); err != nil {
			t.Fatalf("MarkMessageProcessed: %v", err)
		}
	}
	// Touch the oldest again, then push exactly one new id in.
	if err := c.MarkMessageProcessed("m0000"); err != nil {
		t.Fatalf("re-marking oldest: %v", err)
	}
	if err := c.MarkMessageProcessed("fresh"); err != nil {
		t.Fatalf("MarkMessageProcessed: %v", err)
	}

	stillThere, err := c.WasMessageProcessed("m0000")
	if err != nil {
		t.Fatalf("WasMessageProcessed: %v", err)
	}
	if stillThere {
		t.Error("re-marking moved the oldest id to the end; it should have been the one evicted")
	}
}

func TestMarkMessageProcessedClearsFailureHistory(t *testing.T) {
	c := openTestClient(t)
	if _, err := c.RecordDecryptFailure("m1"); err != nil {
		t.Fatalf("RecordDecryptFailure: %v", err)
	}
	if err := c.MarkMessageProcessed("m1"); err != nil {
		t.Fatalf("MarkMessageProcessed: %v", err)
	}
	// With the history cleared, the next failure starts from one again rather
	// than resuming a count that no longer means anything.
	for i := 0; i < MaxDecryptAttempts-1; i++ {
		giveUp, err := c.RecordDecryptFailure("m1")
		if err != nil {
			t.Fatalf("RecordDecryptFailure: %v", err)
		}
		if giveUp {
			t.Fatalf("gave up after %d fresh failures", i+1)
		}
	}
}

func TestRecordDecryptFailureGivesUpAtTheLimit(t *testing.T) {
	c := openTestClient(t)
	for i := 1; i < MaxDecryptAttempts; i++ {
		giveUp, err := c.RecordDecryptFailure("m1")
		if err != nil {
			t.Fatalf("RecordDecryptFailure: %v", err)
		}
		if giveUp {
			t.Fatalf("gave up at attempt %d, before the limit of %d", i, MaxDecryptAttempts)
		}
	}
	giveUp, err := c.RecordDecryptFailure("m1")
	if err != nil {
		t.Fatalf("RecordDecryptFailure: %v", err)
	}
	if !giveUp {
		t.Errorf("did not give up at attempt %d", MaxDecryptAttempts)
	}

	// Reaching the limit clears the counter, so a caller that re-queues the
	// envelope gets a fresh budget instead of giving up instantly forever.
	giveUp, err = c.RecordDecryptFailure("m1")
	if err != nil {
		t.Fatalf("RecordDecryptFailure after give-up: %v", err)
	}
	if giveUp {
		t.Error("counter was not reset when the limit was reported")
	}
}

// --- session health ---------------------------------------------------------

func TestDesyncEvidenceNeedsAConversation(t *testing.T) {
	c := openTestClient(t)
	now := time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC)

	// A stranger sending undecryptable envelopes must not be able to grow the
	// database one row per account id they invent.
	recorded, err := c.RecordDesyncEvidence("stranger", now)
	if err != nil {
		t.Fatalf("RecordDesyncEvidence: %v", err)
	}
	if recorded {
		t.Error("evidence recorded for a peer with no conversation")
	}
	if h, _ := c.PeerSessionHealth("stranger"); h != nil {
		t.Error("a health row was created for a peer with no conversation")
	}

	if err := c.PutConversation(Conversation{PeerAccountID: "friend"}); err != nil {
		t.Fatalf("PutConversation: %v", err)
	}
	recorded, err = c.RecordDesyncEvidence("friend", now)
	if err != nil {
		t.Fatalf("RecordDesyncEvidence: %v", err)
	}
	if !recorded {
		t.Fatal("evidence not recorded for a peer with a conversation")
	}
}

func TestDesyncEvidenceAccumulatesThenClears(t *testing.T) {
	c := openTestClient(t)
	first := time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC)
	later := first.Add(time.Minute)
	if err := c.PutConversation(Conversation{PeerAccountID: "friend"}); err != nil {
		t.Fatalf("PutConversation: %v", err)
	}

	for _, at := range []time.Time{first, later} {
		if _, err := c.RecordDesyncEvidence("friend", at); err != nil {
			t.Fatalf("RecordDesyncEvidence: %v", err)
		}
	}

	h, err := c.PeerSessionHealth("friend")
	if err != nil {
		t.Fatalf("PeerSessionHealth: %v", err)
	}
	if h.DesyncEvidence != 2 {
		t.Errorf("evidence count: want 2, got %d", h.DesyncEvidence)
	}
	// The anchor is the *first* failure, so the grace period is measured from
	// when things started going wrong, not from the latest symptom.
	if h.FirstFailureAt == nil || !h.FirstFailureAt.Equal(first) {
		t.Errorf("first failure: want %v, got %v", first, h.FirstFailureAt)
	}

	if err := c.ClearDesyncEvidence("friend"); err != nil {
		t.Fatalf("ClearDesyncEvidence: %v", err)
	}
	if h, _ := c.PeerSessionHealth("friend"); h != nil {
		t.Error("health survived a successful decrypt")
	}
}

func TestRecordAutoRekeySpendsEvidenceButKeepsTheTimestamp(t *testing.T) {
	c := openTestClient(t)
	at := time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC)
	if err := c.PutConversation(Conversation{PeerAccountID: "friend"}); err != nil {
		t.Fatalf("PutConversation: %v", err)
	}
	if _, err := c.RecordDesyncEvidence("friend", at); err != nil {
		t.Fatalf("RecordDesyncEvidence: %v", err)
	}
	if err := c.RecordAutoRekey("friend", at.Add(time.Minute)); err != nil {
		t.Fatalf("RecordAutoRekey: %v", err)
	}

	h, err := c.PeerSessionHealth("friend")
	if err != nil {
		t.Fatalf("PeerSessionHealth: %v", err)
	}
	if h.DesyncEvidence != 0 || h.FirstFailureAt != nil {
		t.Errorf("evidence should be spent by the re-key: %+v", h)
	}
	if h.LastRekeyAt == nil {
		t.Error("re-key timestamp missing -- nothing would space out the next attempt")
	}
}

// --- conversations ----------------------------------------------------------

func TestConversationsAreOrderedByActivity(t *testing.T) {
	c := openTestClient(t)
	base := time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC)
	older, newer := base, base.Add(time.Hour)

	for _, convo := range []Conversation{
		{PeerAccountID: "quiet", LastActivityAt: &older},
		{PeerAccountID: "busy", LastActivityAt: &newer},
		{PeerAccountID: "never"},
	} {
		if err := c.PutConversation(convo); err != nil {
			t.Fatalf("PutConversation: %v", err)
		}
	}

	convos, err := c.Conversations()
	if err != nil {
		t.Fatalf("Conversations: %v", err)
	}
	got := []string{}
	for _, convo := range convos {
		got = append(got, convo.PeerAccountID)
	}
	want := []string{"busy", "quiet", "never"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("chat list order: want %v, got %v", want, got)
	}
}

// Deleting a conversation clears the transcript, nothing else. Without this, a
// blocked peer would be silently unblocked by deleting their chat, and a known
// contact would turn back into a stranger.
func TestDeleteConversationKeepsSessionBlockAndKnownMark(t *testing.T) {
	c := openTestClient(t)
	if err := c.PutConversation(Conversation{PeerAccountID: "peer"}); err != nil {
		t.Fatalf("PutConversation: %v", err)
	}
	if err := c.SetSession("peer", Sending, newTestSession(t)); err != nil {
		t.Fatalf("SetSession: %v", err)
	}
	if err := c.MarkPeerKnown("peer"); err != nil {
		t.Fatalf("MarkPeerKnown: %v", err)
	}
	if err := c.BlockPeer("peer", "https://peer.invalid"); err != nil {
		t.Fatalf("BlockPeer: %v", err)
	}

	if err := c.DeleteConversation("peer"); err != nil {
		t.Fatalf("DeleteConversation: %v", err)
	}

	if convo, _ := c.Conversation("peer"); convo != nil {
		t.Error("conversation survived deletion")
	}
	if s, _ := c.Session("peer", Sending); s == nil {
		t.Error("ratchet session was deleted along with the conversation")
	}
	if known, _ := c.IsPeerKnown("peer"); !known {
		t.Error("peer stopped being known -- they would come back as a message request")
	}
	if blocked, _ := c.IsPeerBlocked("peer"); !blocked {
		t.Error("peer was silently unblocked by deleting their chat")
	}
}

// --- concurrency and isolation ---------------------------------------------

func TestConcurrentUseIsSafe(t *testing.T) {
	c := openTestClient(t)
	if err := c.PutConversation(Conversation{PeerAccountID: "friend"}); err != nil {
		t.Fatalf("PutConversation: %v", err)
	}
	at := time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC)

	const writers, each = 8, 20
	var wg sync.WaitGroup
	errs := make(chan error, writers*each)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := c.MarkMessageProcessed(fmt.Sprintf("w%d-m%d", w, i)); err != nil {
					errs <- err
					return
				}
				if _, err := c.RecordDesyncEvidence("friend", at); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent use: %v", err)
	}

	n, err := c.CountProcessedMessages()
	if err != nil {
		t.Fatalf("CountProcessedMessages: %v", err)
	}
	if n != writers*each {
		t.Errorf("processed ids after concurrent writes: want %d, got %d", writers*each, n)
	}
	h, err := c.PeerSessionHealth("friend")
	if err != nil {
		t.Fatalf("PeerSessionHealth: %v", err)
	}
	if h.DesyncEvidence != writers*each {
		t.Errorf("evidence count lost increments: want %d, got %d", writers*each, h.DesyncEvidence)
	}
}

// A bot bridge runs many identities in one process. One database per account is
// what keeps that from needing a discriminator on every query -- and what makes
// two accounts genuinely unable to see each other's state.
func TestTwoAccountsAreIndependent(t *testing.T) {
	dir := t.TempDir()
	a, err := Open(filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatalf("Open a: %v", err)
	}
	defer a.Close()
	b, err := Open(filepath.Join(dir, "b.db"))
	if err != nil {
		t.Fatalf("Open b: %v", err)
	}
	defer b.Close()

	minimal := func(account string) Identity {
		return Identity{
			AccountID: account, Server: "s",
			RootPub: []byte{1}, RootPriv: []byte{2},
			DeviceID: "d", DevicePub: []byte{3}, DevicePriv: []byte{4},
		}
	}
	if err := a.SetIdentity(minimal("account-a")); err != nil {
		t.Fatalf("SetIdentity a: %v", err)
	}
	if err := b.SetIdentity(minimal("account-b")); err != nil {
		t.Fatalf("SetIdentity b: %v", err)
	}
	if err := a.MarkMessageProcessed("shared-id"); err != nil {
		t.Fatalf("MarkMessageProcessed: %v", err)
	}

	idA, err := a.Identity()
	if err != nil {
		t.Fatalf("Identity a: %v", err)
	}
	idB, err := b.Identity()
	if err != nil {
		t.Fatalf("Identity b: %v", err)
	}
	if idA.AccountID == idB.AccountID {
		t.Fatal("two clients are sharing one identity row")
	}
	seen, err := b.WasMessageProcessed("shared-id")
	if err != nil {
		t.Fatalf("WasMessageProcessed: %v", err)
	}
	if seen {
		t.Error("one account's processed ids are visible to another")
	}
}
