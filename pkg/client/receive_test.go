package client

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/pkg/ratchet"
	"github.com/behringer24/freizone-server/pkg/wire"
)

// What the conformance vectors do not cover. They pin the session decisions --
// which session decrypts, which one is kept, when a prekey is spent -- and stop
// there, deliberately, because that is the part two implementations have to
// agree on down to the byte. Everything after a successful decrypt is this
// client's own behaviour: what is stored, what the user is told about, and what
// is confirmed back to the sender. It is also where a mistake is quietest --
// nothing fails, a message simply never appears, or interrupts someone it
// should not have.

// peer is a correspondent that can establish a session with a Client and send
// it envelopes, which is the only way to exercise the receive path honestly:
// building an envelope by hand would let a test assert against a ciphertext no
// real sender would produce.
type peer struct {
	t         *testing.T
	accountID string
	dhPriv    *ecdh.PrivateKey
	session   *ratchet.Session
	initial   *ratchet.InitialMessage
	withBlock bool // still attaching the prekey block to every envelope
}

// newFixture opens a client with a usable identity and a peer already able to
// reach it. otpkID, when set, puts one one-time prekey in the pool and has the
// peer use it.
func newFixture(t *testing.T, myAccount, peerAccount string, otpkID *uint32) (*Client, *peer) {
	t.Helper()

	c, err := Open(filepath.Join(t.TempDir(), "account"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	dhPriv := generateKey(t)
	spkPriv := generateKey(t)
	if err := c.SetIdentity(Identity{
		AccountID:        myAccount,
		Server:           "https://home.test",
		DHIdentityPub:    dhPriv.PublicKey().Bytes(),
		DHIdentityPriv:   dhPriv.Bytes(),
		SignedPrekeyID:   1,
		SignedPrekeyPub:  spkPriv.PublicKey().Bytes(),
		SignedPrekeyPriv: spkPriv.Bytes(),
	}); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}

	bundle := ratchet.RemoteBundle{
		DHIdentityPubKey: dhPriv.PublicKey(),
		SignedPrekeyID:   1,
		SignedPrekeyPub:  spkPriv.PublicKey(),
	}
	if otpkID != nil {
		otpkPriv := generateKey(t)
		if err := c.PutOneTimePrekeys([]OneTimePrekey{{
			KeyID: *otpkID,
			Pub:   otpkPriv.PublicKey().Bytes(),
			Priv:  otpkPriv.Bytes(),
		}}); err != nil {
			t.Fatalf("PutOneTimePrekeys: %v", err)
		}
		bundle.OneTimePrekeyID = otpkID
		bundle.OneTimePrekeyPub = otpkPriv.PublicKey()
	}

	p := &peer{t: t, accountID: peerAccount, dhPriv: generateKey(t), withBlock: true}
	p.session, p.initial, err = ratchet.InitiateSession(p.dhPriv, bundle)
	if err != nil {
		t.Fatalf("InitiateSession: %v", err)
	}
	return c, p
}

func generateKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return k
}

// send encrypts plaintext into an envelope. The prekey block rides along until
// [peer.settled] is called, mirroring a real initiator: it keeps announcing
// itself until it has heard back, since it cannot know its first message
// arrived.
func (p *peer) send(plaintext []byte) json.RawMessage {
	p.t.Helper()
	header, ciphertext, err := p.session.Encrypt(plaintext)
	if err != nil {
		p.t.Fatalf("encrypting: %v", err)
	}
	var initial *ratchet.InitialMessage
	if p.withBlock {
		initial = p.initial
	}
	payload, err := wire.NewEnvelope(initial, header, ciphertext).MarshalPayload()
	if err != nil {
		p.t.Fatalf("marshalling envelope: %v", err)
	}
	return payload
}

// settled stops attaching the prekey block, as a real sender does once a reply
// proves the session is established on both sides.
func (p *peer) settled() { p.withBlock = false }

func (p *peer) msg(id string, payload json.RawMessage) IncomingMessage {
	return IncomingMessage{MessageID: id, SenderAccountID: p.accountID, Payload: payload}
}

// corrupt flips a byte of the ciphertext, which is what a desynced session
// looks like from the outside: the AEAD tag simply does not verify.
func corrupt(t *testing.T, payload json.RawMessage) json.RawMessage {
	t.Helper()
	env, err := wire.ParseEnvelope(payload)
	if err != nil {
		t.Fatalf("parsing envelope: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		t.Fatalf("decoding ciphertext: %v", err)
	}
	raw[0] ^= 0xff
	env.Ciphertext = base64.StdEncoding.EncodeToString(raw)
	out, err := env.MarshalPayload()
	if err != nil {
		t.Fatalf("re-marshalling envelope: %v", err)
	}
	return out
}

func textPayload(t *testing.T, id, text string, sentAt string) []byte {
	t.Helper()
	m := map[string]any{"v": 1, "id": id, "text": text}
	if sentAt != "" {
		m["sent_at"] = sentAt
	}
	return mustJSON(t, m)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encoding plaintext: %v", err)
	}
	return b
}

func mustHandle(t *testing.T, c *Client, msg IncomingMessage, opts ReceiveOptions) ReceiveResult {
	t.Helper()
	res, err := c.HandleIncoming(msg, opts)
	if err != nil {
		t.Fatalf("HandleIncoming: %v", err)
	}
	return res
}

// A stranger's first message is a request: it is stored, it notifies once, and
// the conversation it creates is marked as awaiting the user's decision.
func TestFirstMessageFromAStrangerNotifiesOnce(t *testing.T) {
	otpk := uint32(7)
	c, p := newFixture(t, "me", "them", &otpk)

	res := mustHandle(t, c, p.msg("m1", p.send(textPayload(t, "id-1", "hello", ""))), ReceiveOptions{})
	if !res.ShouldNotify {
		t.Error("the message that starts a request must notify -- you should learn somebody wants to talk to you")
	}
	if res.StoredMessageID != "id-1" {
		t.Errorf("stored message id: want %q, got %q", "id-1", res.StoredMessageID)
	}

	convo, err := c.Conversation("them")
	if err != nil || convo == nil {
		t.Fatalf("Conversation: %v, %v", convo, err)
	}
	if !convo.PendingApproval {
		t.Error("a conversation opened by an unknown peer must await approval")
	}
	if !convo.HasUnread {
		t.Error("a message that did not arrive into an open chat must leave the chat unread")
	}

	// The follow-up is the point: once told a request exists, the user must not
	// be interrupted again until they have accepted or blocked it.
	second := mustHandle(t, c, p.msg("m2", p.send(textPayload(t, "id-2", "still there?", ""))), ReceiveOptions{})
	if second.ShouldNotify {
		t.Error("a follow-up from an unaccepted sender must not notify again")
	}
	if second.StoredMessageID == "" {
		t.Error("...but it must still be stored: it shows up in the request, just quietly")
	}

	msgs, err := c.Messages("them")
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("transcript: want 2 lines, got %d", len(msgs))
	}
	if msgs[0].Text != "hello" || msgs[1].Text != "still there?" {
		t.Errorf("transcript reads %q, %q", msgs[0].Text, msgs[1].Text)
	}
}

// A peer the user has already accepted notifies on every message.
func TestKnownPeerNotifiesOnEveryMessage(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	if err := c.MarkPeerKnown("them"); err != nil {
		t.Fatalf("MarkPeerKnown: %v", err)
	}

	first := mustHandle(t, c, p.msg("m1", p.send(textPayload(t, "id-1", "one", ""))), ReceiveOptions{})
	p.settled()
	second := mustHandle(t, c, p.msg("m2", p.send(textPayload(t, "id-2", "two", ""))), ReceiveOptions{})
	if !first.ShouldNotify || !second.ShouldNotify {
		t.Errorf("a known peer must notify every time (got %v, %v)", first.ShouldNotify, second.ShouldNotify)
	}
	convo, _ := c.Conversation("them")
	if convo.PendingApproval {
		t.Error("a known peer's conversation must not be a request")
	}
}

// A peer on this side's own server still states sender_server on every
// message (send.go's encodeText sends it unconditionally, not only when
// federated -- it is how a peer who lost local state finds its way back).
// Taking that at face value would leave Conversation.PeerServer non-empty for
// a same-server peer, and PeerEndpoint.Federated's whole contract is "empty
// means our own": every later send to them would then run the federated path
// and build a device certificate this send path has no reason to get right
// for a local peer. Found live (SRV-23): a same-server contact's first reply
// silently broke every send to them from that point on.
func TestSameServerSenderNeverMarksThePeerAsFederated(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	if err := c.MarkPeerKnown("them"); err != nil {
		t.Fatalf("MarkPeerKnown: %v", err)
	}

	payload, err := json.Marshal(map[string]any{
		"v": 1, "id": "id-1", "text": "hi", "sender_server": "https://home.test",
	})
	if err != nil {
		t.Fatalf("encoding plaintext: %v", err)
	}
	mustHandle(t, c, p.msg("m1", p.send(payload)), ReceiveOptions{})

	convo, err := c.Conversation("them")
	if err != nil || convo == nil {
		t.Fatalf("Conversation: %v, %v", convo, err)
	}
	if convo.PeerServer != "" {
		t.Errorf("PeerServer: want empty (same server as us), got %q", convo.PeerServer)
	}
}

// The self-heal above must run in reverse too: a PeerServer already wrongly
// set to this side's own server (exactly what the bug above left behind on
// disk before it was fixed) is cleared by the peer's very next message, not
// just left stale until something else notices.
func TestSameServerSenderClearsAPreviouslyWrongPeerServer(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	if err := c.MarkPeerKnown("them"); err != nil {
		t.Fatalf("MarkPeerKnown: %v", err)
	}
	if err := c.PutConversation(Conversation{PeerAccountID: "them", PeerServer: "https://home.test"}); err != nil {
		t.Fatalf("PutConversation: %v", err)
	}

	payload, err := json.Marshal(map[string]any{
		"v": 1, "id": "id-1", "text": "hi", "sender_server": "https://home.test",
	})
	if err != nil {
		t.Fatalf("encoding plaintext: %v", err)
	}
	mustHandle(t, c, p.msg("m1", p.send(payload)), ReceiveOptions{})

	convo, err := c.Conversation("them")
	if err != nil || convo == nil {
		t.Fatalf("Conversation: %v, %v", convo, err)
	}
	if convo.PeerServer != "" {
		t.Errorf("PeerServer: want cleared, got %q", convo.PeerServer)
	}
}

// A message into the chat the user is looking at must neither notify nor mark
// it unread.
func TestMessageIntoTheOpenChatIsSilent(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	if err := c.MarkPeerKnown("them"); err != nil {
		t.Fatalf("MarkPeerKnown: %v", err)
	}

	res := mustHandle(t, c, p.msg("m1", p.send(textPayload(t, "id-1", "hi", ""))), ReceiveOptions{OpenChatID: "them"})
	if res.ShouldNotify {
		t.Error("a message into the open chat must not notify")
	}
	convo, _ := c.Conversation("them")
	if convo.HasUnread {
		t.Error("a message into the open chat must not mark it unread")
	}
	if res.StoredMessageID == "" {
		t.Error("it must still be stored")
	}
}

// A blocked peer's message is decrypted -- the ratchet has to stay in step and
// the server queue has to drain -- and then dropped without a trace.
func TestBlockedPeersMessageIsDecryptedThenDropped(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	if err := c.BlockPeer("them", "https://elsewhere.test"); err != nil {
		t.Fatalf("BlockPeer: %v", err)
	}

	res := mustHandle(t, c, p.msg("m1", p.send(textPayload(t, "id-1", "let me in", ""))), ReceiveOptions{})
	if !res.Blocked {
		t.Error("the result must say the sender is blocked")
	}
	if res.ShouldNotify || res.StoredMessageID != "" {
		t.Errorf("a blocked message must be neither stored nor notified (stored %q, notify %v)", res.StoredMessageID, res.ShouldNotify)
	}
	if res.DeliveredUpTo != nil {
		t.Error("nothing may be confirmed back to a blocked sender -- a receipt would tell them they are still being read")
	}
	if msgs, _ := c.Messages("them"); len(msgs) != 0 {
		t.Errorf("transcript: want empty, got %d lines", len(msgs))
	}

	// The ratchet still advanced, which is the whole reason for decrypting it:
	// unblocking must not leave the session a message behind.
	if seen, _ := c.WasMessageProcessed("m1"); !seen {
		t.Error("a blocked peer's envelope must still be marked processed, or it is retried forever")
	}
	p.settled()
	if err := c.UnblockPeer("them"); err != nil {
		t.Fatalf("UnblockPeer: %v", err)
	}
	after := mustHandle(t, c, p.msg("m2", p.send(textPayload(t, "id-2", "hello again", ""))), ReceiveOptions{})
	if after.StoredMessageID != "id-2" {
		t.Error("the next message after unblocking must decrypt, which it only can if the session kept up")
	}
}

// A receipt moves the peer's watermark and never becomes a visible line.
func TestReceiptMovesTheWatermarkMonotonically(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	if err := c.PutConversation(Conversation{PeerAccountID: "them"}); err != nil {
		t.Fatalf("PutConversation: %v", err)
	}

	// The literal shape the app puts on the wire, milliseconds and all: this is
	// the interop that a Go client parsing its own output would never check.
	later := "2026-08-09T10:05:00.000Z"
	earlier := "2026-08-09T10:00:00.000Z"

	res := mustHandle(t, c, p.msg("r1", p.send(mustJSON(t, map[string]any{
		"v": 2, "kind": "receipt", "status": "read", "up_to_sent_at": later,
	}))), ReceiveOptions{})
	p.settled()
	if res.ShouldNotify || res.StoredMessageID != "" {
		t.Error("a receipt is never shown and never notifies")
	}
	if res.Content.Kind != ContentReceipt {
		t.Fatalf("content kind: want %q, got %q", ContentReceipt, res.Content.Kind)
	}

	convo, _ := c.Conversation("them")
	if convo.PeerReadUpTo == nil || !convo.PeerReadUpTo.Equal(mustTime(t, later)) {
		t.Fatalf("read watermark: want %s, got %v", later, convo.PeerReadUpTo)
	}

	// An older receipt arriving late must not walk the watermark backwards.
	mustHandle(t, c, p.msg("r2", p.send(mustJSON(t, map[string]any{
		"v": 2, "kind": "receipt", "status": "read", "up_to_sent_at": earlier,
	}))), ReceiveOptions{})
	convo, _ = c.Conversation("them")
	if !convo.PeerReadUpTo.Equal(mustTime(t, later)) {
		t.Errorf("an out-of-order receipt regressed the watermark to %v", convo.PeerReadUpTo)
	}
}

// Receipts the user has switched off are still decrypted and acknowledged --
// they just leave no mark.
func TestDisabledReceiptsAreDroppedNotRecorded(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	if err := c.PutConversation(Conversation{PeerAccountID: "them"}); err != nil {
		t.Fatalf("PutConversation: %v", err)
	}

	mustHandle(t, c, p.msg("r1", p.send(mustJSON(t, map[string]any{
		"v": 2, "kind": "receipt", "status": "delivered", "up_to_sent_at": "2026-08-09T10:00:00.000Z",
	}))), ReceiveOptions{ReceiptsDisabled: true})

	convo, _ := c.Conversation("them")
	if convo.PeerDeliveredUpTo != nil {
		t.Errorf("receipts are off, yet a watermark was recorded: %v", convo.PeerDeliveredUpTo)
	}
	if seen, _ := c.WasMessageProcessed("r1"); !seen {
		t.Error("it must still count as processed, or the sender's receipt is retried forever")
	}
}

// A receipt must not conjure a conversation out of nothing: with no local
// record of the peer there is nothing to update, and minting one would let
// anybody who can address us appear in the chat list without saying anything.
func TestReceiptDoesNotCreateAConversation(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)

	mustHandle(t, c, p.msg("r1", p.send(mustJSON(t, map[string]any{
		"v": 2, "kind": "receipt", "status": "read", "up_to_sent_at": "2026-08-09T10:00:00.000Z",
	}))), ReceiveOptions{})

	convo, err := c.Conversation("them")
	if err != nil {
		t.Fatalf("Conversation: %v", err)
	}
	if convo != nil {
		t.Error("a receipt from a peer with no conversation must leave the chat list alone")
	}
}

// A confirmation has to be in the sender's clock domain, or the two sides
// cannot agree on what "everything up to here" means.
func TestDeliveredUpToUsesTheSendersClock(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	sentAt := "2026-08-09T09:59:00.000Z"

	res := mustHandle(t, c, p.msg("m1", p.send(textPayload(t, "id-1", "hi", sentAt))), ReceiveOptions{
		Now: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
	})
	if res.DeliveredUpTo == nil || !res.DeliveredUpTo.Equal(mustTime(t, sentAt)) {
		t.Fatalf("delivered watermark: want the sender's %s, got %v", sentAt, res.DeliveredUpTo)
	}

	// A sender that predates the field leaves arrival time as the only anchor.
	p.settled()
	legacy := mustHandle(t, c, p.msg("m2", p.send(textPayload(t, "id-2", "hi", ""))), ReceiveOptions{
		Now: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
	})
	if legacy.DeliveredUpTo == nil || !legacy.DeliveredUpTo.Equal(time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("without a sender stamp the fallback is arrival time, got %v", legacy.DeliveredUpTo)
	}
}

// A re-key signal is invisible, but accepting it must leave a mark: the
// automatic path carries the recovery on a bare signal, so this marker is the
// only thing there ever is to show for it.
func TestAcceptedRekeyLeavesATranscriptMarker(t *testing.T) {
	c, first := newFixture(t, "zzz-me", "aaa-them", nil)
	if err := c.MarkPeerKnown("aaa-them"); err != nil {
		t.Fatalf("MarkPeerKnown: %v", err)
	}
	mustHandle(t, c, first.msg("m1", first.send(textPayload(t, "id-1", "hello", ""))), ReceiveOptions{})

	// The peer throws its session away and re-establishes: a brand new session,
	// announcing itself as a deliberate re-key.
	id, err := c.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	reborn := &peer{t: t, accountID: "aaa-them", dhPriv: generateKey(t), withBlock: true}
	reborn.session, reborn.initial, err = ratchet.InitiateSession(reborn.dhPriv, ratchet.RemoteBundle{
		DHIdentityPubKey: pubKey(t, id.DHIdentityPub),
		SignedPrekeyID:   id.SignedPrekeyID,
		SignedPrekeyPub:  pubKey(t, id.SignedPrekeyPub),
	})
	if err != nil {
		t.Fatalf("InitiateSession: %v", err)
	}

	res := mustHandle(t, c, reborn.msg("m2", reborn.sendRekey(mustJSON(t, map[string]any{
		"v": 3, "kind": "rekey", "reason": "decrypt_failures",
	}))), ReceiveOptions{})

	if !res.AdoptedPeerSession {
		t.Fatal("a deliberate re-key must be adopted")
	}
	if res.ShouldNotify || res.StoredMessageID != "" {
		t.Error("a re-key signal is never stored and never notifies")
	}

	msgs, err := c.Messages("aaa-them")
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("transcript: want the message plus a marker, got %d lines", len(msgs))
	}
	marker := msgs[1]
	if marker.Kind != MessageSystemInfo || marker.Text != AutomaticRekeyMarker {
		t.Errorf("marker: want a system line %q, got %q / %q", AutomaticRekeyMarker, marker.Kind, marker.Text)
	}
	// Recovering a session is maintenance, not activity: it must not jump the
	// chat to the top of the list.
	convo, _ := c.Conversation("aaa-them")
	if convo.LastActivityAt == nil || !convo.LastActivityAt.Equal(*lastActivityOf(t, c, "aaa-them")) {
		t.Error("last activity moved on a re-key")
	}
}

// A peer that lost its ratchet state entirely (no rekey flag -- from its own
// point of view this is an ordinary first establishment, not a deliberate
// one) must still be adopted once this side has actually confirmed the
// session it is holding, whatever the account-id tie-break says. Found live
// (SRV-23's "one-time reset, no migration path" left exactly this shape): the
// higher-sorting id kept sending on a session the peer had just proven it
// could not read, and never self-healed.
func TestOrdinaryReestablishmentIsAdoptedOverAConfirmedSession(t *testing.T) {
	// "zzz-them" sorts above "aaa-me", so the old account-id tie-break would
	// have this side keep its own (stale) session -- the exact failure mode.
	c, p := newFixture(t, "aaa-me", "zzz-them", nil)
	if err := c.MarkPeerKnown("zzz-them"); err != nil {
		t.Fatalf("MarkPeerKnown: %v", err)
	}

	// A real, working, mutually confirmed session: this side has actually
	// decrypted something on it, which a coincidental race could never have
	// -- both sides of a genuine race start from nothing.
	mustHandle(t, c, p.msg("m1", p.send(textPayload(t, "id-1", "hello", ""))), ReceiveOptions{})
	p.settled()

	// The peer's local session is gone -- same DH identity key (nothing about
	// who they are changed), a brand new ratchet session, and critically no
	// rekey flag: it has no idea anything is wrong.
	id, err := c.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	lost := &peer{t: t, accountID: "zzz-them", dhPriv: p.dhPriv, withBlock: true}
	lost.session, lost.initial, err = ratchet.InitiateSession(lost.dhPriv, ratchet.RemoteBundle{
		DHIdentityPubKey: pubKey(t, id.DHIdentityPub),
		SignedPrekeyID:   id.SignedPrekeyID,
		SignedPrekeyPub:  pubKey(t, id.SignedPrekeyPub),
	})
	if err != nil {
		t.Fatalf("InitiateSession: %v", err)
	}

	res := mustHandle(t, c, lost.msg("m2", lost.send(textPayload(t, "id-2", "hi again", ""))), ReceiveOptions{})
	if !res.AdoptedPeerSession {
		t.Fatal("a peer that lost its session must be adopted even though its account id sorts higher and it never said 'rekey'")
	}
	if res.StoredMessageID == "" {
		t.Error("the message riding the re-established session must still be stored")
	}
}

// Mirror image of the above: two sides genuinely establish within the same
// breath (a group's "everyone reaches back at once", see send.go), so neither
// has confirmed anything on the sessions currently competing -- the
// account-id tie-break must still decide it, exactly as before this change.
func TestGenuineRaceStillUsesTheAccountIDTieBreak(t *testing.T) {
	// "aaa-me" sorts below "zzz-them", so this side's session should win the
	// tie-break and be kept for sending.
	c, mine := newFixture(t, "zzz-me", "aaa-them", nil)
	if err := c.MarkPeerKnown("aaa-them"); err != nil {
		t.Fatalf("MarkPeerKnown: %v", err)
	}

	// A second, independent initiator session for the same pair, standing in
	// for our own outstanding attempt -- what makes this a race rather than
	// the scenario above is that nothing has been decrypted on either side
	// yet.
	id, err := c.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	other := &peer{t: mine.t, accountID: "aaa-them", dhPriv: generateKey(mine.t), withBlock: true}
	other.session, other.initial, err = ratchet.InitiateSession(other.dhPriv, ratchet.RemoteBundle{
		DHIdentityPubKey: pubKey(mine.t, id.DHIdentityPub),
		SignedPrekeyID:   id.SignedPrekeyID,
		SignedPrekeyPub:  pubKey(mine.t, id.SignedPrekeyPub),
	})
	if err != nil {
		t.Fatalf("InitiateSession: %v", err)
	}

	res := mustHandle(t, c, other.msg("m1", other.send(textPayload(t, "id-1", "hi", ""))), ReceiveOptions{})
	if res.AdoptedPeerSession {
		t.Fatal("a genuine race with nothing confirmed on either side must still resolve by account id, not adopt automatically")
	}
}

// sendRekey is [peer.send] with the prekey block flagged as a deliberate
// re-key, which is what tells the receiver to adopt it whatever the tie-break
// would have said.
func (p *peer) sendRekey(plaintext []byte) json.RawMessage {
	p.t.Helper()
	header, ciphertext, err := p.session.Encrypt(plaintext)
	if err != nil {
		p.t.Fatalf("encrypting: %v", err)
	}
	yes := true
	payload, err := wire.NewEnvelopeRekey(p.initial, header, ciphertext, &yes).MarshalPayload()
	if err != nil {
		p.t.Fatalf("marshalling envelope: %v", err)
	}
	return payload
}

// An envelope that cannot be decrypted is retried, then given up on, and only
// then counted as evidence that the session is broken.
func TestRepeatedFailureGivesUpAndBecomesEvidence(t *testing.T) {
	c, p := newFixture(t, "zzz-me", "aaa-them", nil)
	if err := c.PutConversation(Conversation{PeerAccountID: "aaa-them"}); err != nil {
		t.Fatalf("PutConversation: %v", err)
	}
	broken := corrupt(t, p.send(textPayload(t, "id-1", "unreadable", "")))

	var last *DecryptError
	for attempt := 1; attempt <= MaxDecryptAttempts; attempt++ {
		_, err := c.HandleIncoming(p.msg("m1", broken), ReceiveOptions{})
		if !errors.As(err, &last) {
			t.Fatalf("attempt %d: want a DecryptError, got %v", attempt, err)
		}
		if !last.DesyncEvidence {
			t.Errorf("attempt %d: an authentication failure means diverged keys and must count", attempt)
		}
		if gaveUp := attempt == MaxDecryptAttempts; last.GaveUp != gaveUp {
			t.Errorf("attempt %d: GaveUp = %v, want %v", attempt, last.GaveUp, gaveUp)
		}
		// The classification has to survive being wrapped, or a redelivery
		// cannot be told apart from a real desync.
		if code := ratchet.FailureCode(err); code != ratchet.FailureAuthentication {
			t.Errorf("attempt %d: want failure code %q, got %q -- the classification must survive being wrapped", attempt, ratchet.FailureAuthentication, code)
		}
	}

	health, err := c.PeerSessionHealth("aaa-them")
	if err != nil || health == nil {
		t.Fatalf("PeerSessionHealth: %v, %v", health, err)
	}
	if health.DesyncEvidence != 1 {
		t.Errorf("evidence: want 1 for one broken envelope retried %d times, got %d -- counting retries reaches any threshold on a single message", MaxDecryptAttempts, health.DesyncEvidence)
	}
	// Lower id on our side would re-key at once; ours is higher, so it waits.
	if last.RekeyNeeded {
		t.Error("the higher-id side must hold back and let the other side's re-key arrive first")
	}
}

// The desync with no cryptographic error at all: our session is simply gone,
// and the peer keeps sending into the one they still hold.
func TestMissingSessionCountsAsEvidence(t *testing.T) {
	c, p := newFixture(t, "aaa-me", "zzz-them", nil)
	if err := c.PutConversation(Conversation{PeerAccountID: "zzz-them"}); err != nil {
		t.Fatalf("PutConversation: %v", err)
	}
	p.settled() // no prekey block: nothing to build a session from

	var fail *DecryptError
	for attempt := 1; attempt <= MaxDecryptAttempts; attempt++ {
		_, err := c.HandleIncoming(p.msg("m1", p.send(textPayload(t, "id-1", "hello?", ""))), ReceiveOptions{})
		if !errors.As(err, &fail) {
			t.Fatalf("attempt %d: want a DecryptError, got %v", attempt, err)
		}
	}
	if !errors.Is(fail, ErrNoSessionMaterial) {
		t.Fatalf("want ErrNoSessionMaterial, got %v", fail.Err)
	}
	if !fail.DesyncEvidence {
		t.Fatal("nothing failed to verify, but the session is provably gone -- without counting this, recovery never sees the case it exists for")
	}
	// Ours is the lower id, so this side goes first and does not wait.
	if !fail.RekeyNeeded {
		t.Error("the lower-id side re-keys immediately")
	}
}

// A group message goes into the group's own transcript, never into a
// one-to-one chat with whoever happened to send it. That is the whole reason
// group content has its own version rather than being an ordinary message with
// a group id attached: an older build meeting one shows a placeholder instead
// of filing it under the sender.
func TestGroupMessageGoesIntoTheGroupTranscript(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)

	res := mustHandle(t, c, p.msg("g1", p.send(mustJSON(t, map[string]any{
		"v": 4, "group_id": "grp-1", "state_hash": "h1", "id": "gid-1", "text": "in the group",
	}))), ReceiveOptions{})

	if res.Content.Kind != ContentGroupText {
		t.Fatalf("content kind: want %q, got %q", ContentGroupText, res.Content.Kind)
	}
	if res.Group == nil || res.Group.GroupID != "grp-1" || res.Group.PeerStateHash != "h1" {
		t.Fatalf("the result must name the group and the sender's view, got %+v", res.Group)
	}
	if res.StoredMessageID != "gid-1" {
		t.Errorf("stored message id: want %q, got %q", "gid-1", res.StoredMessageID)
	}
	if msgs, _ := c.Messages("them"); len(msgs) != 0 {
		t.Errorf("one-to-one transcript: want empty, got %d lines", len(msgs))
	}

	msgs, err := c.Messages("grp-1")
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Text != "in the group" {
		t.Fatalf("group transcript: %+v", msgs)
	}
	// In a group the chat does not answer who wrote a line, so the line has to.
	if msgs[0].SenderAccountID != "them" {
		t.Errorf("sender: want %q, got %q", "them", msgs[0].SenderAccountID)
	}
	if seen, _ := c.WasMessageProcessed("g1"); !seen {
		t.Error("it was decrypted, so it must be marked processed like anything else")
	}

	// The sender's view is remembered even for a plain message: the send path
	// reads it to decide whether they are behind on facts.
	hashes, err := c.GroupPeerStateHashes("grp-1")
	if err != nil {
		t.Fatalf("GroupPeerStateHashes: %v", err)
	}
	if hashes["them"] != "h1" {
		t.Errorf("peer state hash: want %q, got %q", "h1", hashes["them"])
	}
}

// The oldest senders wrapped nothing around the message body. One still has to
// be readable, and needs an id minted so it can be replied to and deleted.
func TestLegacyPlaintextIsStoredWithAMintedID(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)

	res := mustHandle(t, c, p.msg("m1", p.send([]byte("just some text"))), ReceiveOptions{})
	if res.Content.Text != "just some text" {
		t.Errorf("text: want %q, got %q", "just some text", res.Content.Text)
	}
	if res.StoredMessageID == "" {
		t.Fatal("a legacy message must still get an id of its own")
	}
	msgs, _ := c.Messages("them")
	if len(msgs) != 1 || msgs[0].ID != res.StoredMessageID {
		t.Errorf("transcript: want one line with the minted id, got %+v", msgs)
	}
}

// A message from a build newer than this one says so, rather than showing
// nothing at all -- which reads as a message that was lost.
func TestUnknownVersionRendersAsAPlaceholder(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)

	res := mustHandle(t, c, p.msg("m1", p.send(mustJSON(t, map[string]any{
		"v": 99, "id": "id-1", "text": "something from the future",
	}))), ReceiveOptions{})
	if res.Content.Text != unsupportedContentText {
		t.Errorf("text: want the placeholder, got %q", res.Content.Text)
	}
	if res.StoredMessageID != "id-1" {
		t.Error("it is still a message and still belongs in the transcript")
	}
}

// The recovery policy, across the tie-break and the two timers. Pure, so the
// clock is an argument rather than something to wait for.
func TestShouldAutoRekeyPolicy(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) *time.Time { at := now.Add(-d); return &at }

	cases := []struct {
		name   string
		health *PeerSessionHealth
		me     string
		peer   string
		want   bool
	}{
		{"nothing recorded", nil, "aaa", "zzz", false},
		{"no evidence yet", &PeerSessionHealth{}, "aaa", "zzz", false},
		{
			"lower id goes immediately",
			&PeerSessionHealth{DesyncEvidence: 1, FirstFailureAt: ago(time.Second)},
			"aaa", "zzz", true,
		},
		{
			"higher id waits out the grace period",
			&PeerSessionHealth{DesyncEvidence: 1, FirstFailureAt: ago(time.Minute)},
			"zzz", "aaa", false,
		},
		{
			"higher id goes once it has waited",
			&PeerSessionHealth{DesyncEvidence: 1, FirstFailureAt: ago(AutoRekeyResponderGrace + time.Minute)},
			"zzz", "aaa", true,
		},
		{
			"a recent attempt spaces out the next one",
			&PeerSessionHealth{DesyncEvidence: 1, FirstFailureAt: ago(time.Second), LastRekeyAt: ago(time.Minute)},
			"aaa", "zzz", false,
		},
		{
			"an old attempt does not",
			&PeerSessionHealth{DesyncEvidence: 1, FirstFailureAt: ago(time.Second), LastRekeyAt: ago(MinAutoRekeyInterval + time.Minute)},
			"aaa", "zzz", true,
		},
		{
			"evidence without a timestamp makes the higher id wait, not guess",
			&PeerSessionHealth{DesyncEvidence: 1},
			"zzz", "aaa", false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldAutoRekey(tc.health, tc.me, tc.peer, now); got != tc.want {
				t.Errorf("shouldAutoRekey = %v, want %v", got, tc.want)
			}
		})
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return at.UTC()
}

func pubKey(t *testing.T, raw []byte) *ecdh.PublicKey {
	t.Helper()
	k, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		t.Fatalf("reading public key: %v", err)
	}
	return k
}

func lastActivityOf(t *testing.T, c *Client, peer string) *time.Time {
	t.Helper()
	msgs, err := c.Messages(peer)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Kind == MessageNormal {
			at := msgs[i].Timestamp
			return &at
		}
	}
	t.Fatal("no ordinary message in the transcript")
	return nil
}
