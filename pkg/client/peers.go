package client

import (
	"sort"
	"time"
)

// PeerSessionHealth is the evidence that a session with one peer has gone
// wrong. Present only for peers something has actually happened to.
type PeerSessionHealth struct {
	// DesyncEvidence counts distinct envelopes given up on since the last
	// successful decrypt, and only those whose failure code implies diverged
	// keys. A redelivery or an undiagnosed error is evidence of nothing.
	DesyncEvidence int

	// FirstFailureAt anchors the grace period before this side re-keys. Nil
	// exactly when DesyncEvidence is 0.
	FirstFailureAt *time.Time

	// LastRekeyAt outlives the evidence that triggered it, because it exists to
	// space out *future* attempts rather than to justify the last one.
	LastRekeyAt *time.Time
}

type healthFile struct {
	DesyncEvidence int    `json:"desync_evidence"`
	FirstFailureAt string `json:"first_failure_at,omitempty"`
	LastRekeyAt    string `json:"last_rekey_at,omitempty"`
}

// PeerSessionHealth returns what is recorded about peer, or nil when nothing
// has gone wrong -- the normal case, and the reason this is its own small file
// per peer rather than a map everyone shares: most peers never have one.
func (c *Client) PeerSessionHealth(peer string) (*PeerSessionHealth, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.healthLocked(peer)
}

func (c *Client) healthLocked(peer string) (*PeerSessionHealth, error) {
	path, err := c.store.peerPath(peer, fileHealth)
	if err != nil {
		return nil, err
	}
	var stored healthFile
	found, err := readJSON(path, &stored)
	if err != nil || !found {
		return nil, err
	}

	h := &PeerSessionHealth{DesyncEvidence: stored.DesyncEvidence}
	if h.FirstFailureAt, err = parseTime(stored.FirstFailureAt); err != nil {
		return nil, err
	}
	if h.LastRekeyAt, err = parseTime(stored.LastRekeyAt); err != nil {
		return nil, err
	}
	return h, nil
}

func (c *Client) writeHealth(peer string, h *PeerSessionHealth) error {
	path, err := c.store.peerPath(peer, fileHealth)
	if err != nil {
		return err
	}
	return writeJSON(path, healthFile{
		DesyncEvidence: h.DesyncEvidence,
		FirstFailureAt: formatTime(h.FirstFailureAt),
		LastRekeyAt:    formatTime(h.LastRekeyAt),
	})
}

// RecordDesyncEvidence counts one envelope from peer given up on for a reason
// that implies diverged keys, and reports whether it was counted.
//
// Call once per envelope, and only when the failure was both exhausted and
// classified as a desync: counting every attempt reaches any threshold three
// times over, and counting a redelivery or an undiagnosed error recovers
// sessions that were never broken.
//
// Ignored, returning false, for a peer with no conversation. That bounds this
// to conversations that exist -- recovery has nowhere to send without one
// anyway, and without the guard a stranger sending undecryptable envelopes
// could grow the store by one directory per account id they invent.
func (c *Client) RecordDesyncEvidence(peer string, at time.Time) (recorded bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	convo, err := c.conversationLocked(peer)
	if err != nil || convo == nil {
		return false, err
	}

	h, err := c.healthLocked(peer)
	if err != nil {
		return false, err
	}
	if h == nil {
		h = &PeerSessionHealth{}
	}
	h.DesyncEvidence++
	if h.FirstFailureAt == nil {
		when := at
		h.FirstFailureAt = &when
	}
	if err := c.writeHealth(peer, h); err != nil {
		return false, err
	}
	return true, nil
}

// ClearDesyncEvidence forgets everything recorded about peer's session going
// wrong. Called whenever a message from them decrypts, which is the only proof
// the session works. Drops the re-key spacing along with it, deliberately: a
// healthy session needs no protection against re-keying too often.
func (c *Client) ClearDesyncEvidence(peer string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.peerPath(peer, fileHealth)
	if err != nil {
		return err
	}
	return removeFile(path)
}

// RecordAutoRekey notes that an automatic re-key with peer has just been sent:
// the evidence that triggered it is spent, but the timestamp stays to space out
// any further attempt.
func (c *Client) RecordAutoRekey(peer string, at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	when := at
	return c.writeHealth(peer, &PeerSessionHealth{LastRekeyAt: &when})
}

// Conversation is the per-peer metadata around a transcript.
type Conversation struct {
	PeerAccountID string
	PeerServer    string

	LastActivityAt *time.Time
	HasUnread      bool

	// Blocked mirrors the block on this conversation; the blocked list is the
	// copy that survives the conversation being deleted.
	Blocked bool

	// PendingApproval marks a conversation opened by a stranger, awaiting the
	// user's accept.
	PendingApproval bool

	// PeerGone records that the peer's *account*, not merely a device, was
	// confirmed gone by asking their server (see [Client.markPeerGone]) --
	// set once so every later send refuses at no network cost instead of
	// asking the same question again. Permanent in practice: an account id is
	// derived from the key material behind it, so a deleted account never
	// returns under the same id for someone new to inherit.
	PeerGone bool

	// Receipts are cumulative watermarks, not per-message marks: a receipt says
	// "everything up to this instant". That is what makes one arriving late
	// harmless -- it moves a monotonic value and touches no message, so newer
	// lines appended in between simply fall under it, which is correct.
	PeerDeliveredUpTo        *time.Time
	PeerReadUpTo             *time.Time
	SentDeliveredReceiptUpTo *time.Time
	SentReadReceiptUpTo      *time.Time
}

type conversationFile struct {
	PeerAccountID string `json:"peer_account_id"`
	PeerServer    string `json:"peer_server,omitempty"`

	LastActivityAt string `json:"last_activity_at,omitempty"`
	HasUnread      bool   `json:"has_unread,omitempty"`

	Blocked         bool `json:"blocked,omitempty"`
	PendingApproval bool `json:"pending_approval,omitempty"`
	PeerGone        bool `json:"peer_gone,omitempty"`

	PeerDeliveredUpTo        string `json:"peer_delivered_up_to,omitempty"`
	PeerReadUpTo             string `json:"peer_read_up_to,omitempty"`
	SentDeliveredReceiptUpTo string `json:"sent_delivered_receipt_up_to,omitempty"`
	SentReadReceiptUpTo      string `json:"sent_read_receipt_up_to,omitempty"`
}

// Conversation returns the conversation with peer, or nil if there is none.
func (c *Client) Conversation(peer string) (*Conversation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conversationLocked(peer)
}

func (c *Client) conversationLocked(peer string) (*Conversation, error) {
	path, err := c.store.chatPath(peer, fileMeta)
	if err != nil {
		return nil, err
	}
	var stored conversationFile
	found, err := readJSON(path, &stored)
	if err != nil || !found {
		return nil, err
	}
	return stored.resolve()
}

func (f conversationFile) resolve() (*Conversation, error) {
	convo := &Conversation{
		PeerAccountID:   f.PeerAccountID,
		PeerServer:      f.PeerServer,
		HasUnread:       f.HasUnread,
		Blocked:         f.Blocked,
		PendingApproval: f.PendingApproval,
		PeerGone:        f.PeerGone,
	}
	var err error
	for _, field := range []struct {
		src string
		dst **time.Time
	}{
		{f.LastActivityAt, &convo.LastActivityAt},
		{f.PeerDeliveredUpTo, &convo.PeerDeliveredUpTo},
		{f.PeerReadUpTo, &convo.PeerReadUpTo},
		{f.SentDeliveredReceiptUpTo, &convo.SentDeliveredReceiptUpTo},
		{f.SentReadReceiptUpTo, &convo.SentReadReceiptUpTo},
	} {
		if *field.dst, err = parseTime(field.src); err != nil {
			return nil, err
		}
	}
	return convo, nil
}

// Conversations returns every conversation, most recently active first, so the
// chat list can be drawn without touching a single transcript.
//
// One small file read per chat rather than one query. That is a handful of
// reads for a handful of chats and, unlike the old single-file store, it does
// not grow with the number of messages behind them -- which is the cost that
// actually mattered.
func (c *Client) Conversations() ([]Conversation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	dir, err := c.store.chatsDir()
	if err != nil {
		return nil, err
	}
	ids, err := listDirs(dir)
	if err != nil {
		return nil, err
	}

	convos := make([]Conversation, 0, len(ids))
	for _, id := range ids {
		convo, err := c.conversationLocked(id)
		if err != nil {
			return nil, err
		}
		if convo != nil {
			convos = append(convos, *convo)
		}
	}

	sort.SliceStable(convos, func(i, j int) bool {
		a, b := convos[i].LastActivityAt, convos[j].LastActivityAt
		switch {
		case a == nil && b == nil:
			return convos[i].PeerAccountID < convos[j].PeerAccountID
		case a == nil:
			return false // never active sorts last
		case b == nil:
			return true
		case a.Equal(*b):
			return convos[i].PeerAccountID < convos[j].PeerAccountID
		default:
			return a.After(*b)
		}
	})
	return convos, nil
}

// PutConversation inserts or replaces a conversation.
func (c *Client) PutConversation(convo Conversation) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.chatPath(convo.PeerAccountID, fileMeta)
	if err != nil {
		return err
	}
	return writeJSON(path, conversationFile{
		PeerAccountID:            convo.PeerAccountID,
		PeerServer:               convo.PeerServer,
		LastActivityAt:           formatTime(convo.LastActivityAt),
		HasUnread:                convo.HasUnread,
		Blocked:                  convo.Blocked,
		PendingApproval:          convo.PendingApproval,
		PeerGone:                 convo.PeerGone,
		PeerDeliveredUpTo:        formatTime(convo.PeerDeliveredUpTo),
		PeerReadUpTo:             formatTime(convo.PeerReadUpTo),
		SentDeliveredReceiptUpTo: formatTime(convo.SentDeliveredReceiptUpTo),
		SentReadReceiptUpTo:      formatTime(convo.SentReadReceiptUpTo),
	})
}

// DeleteConversation removes a conversation's metadata. The ratchet session,
// the known-peer mark and any block deliberately survive: clearing a chat must
// not silently unblock someone or turn a known contact back into a stranger.
func (c *Client) DeleteConversation(peer string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.chatPath(peer, fileMeta)
	if err != nil {
		return err
	}
	return removeFile(path)
}

// --- known and blocked peers ------------------------------------------------

// Both lists are small, change rarely, and never grow with history, so a whole
// file is the right shape. They live outside chats/ on purpose: each has to
// outlive the conversation being deleted.

type blockedEntry struct {
	PeerAccountID string `json:"peer_account_id"`
	PeerServer    string `json:"peer_server,omitempty"`
}

func (c *Client) readSet(path string) (map[string]bool, error) {
	var ids []string
	if _, err := readJSON(path, &ids); err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set, nil
}

func (c *Client) writeSet(path string, set map[string]bool) error {
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids) // stable on disk, so a diff of the file means a real change
	return writeJSON(path, ids)
}

// MarkPeerKnown records that this peer is not a stranger -- accepted from a
// message request, or reached out to first. Outlives the conversation.
func (c *Client) MarkPeerKnown(peer string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.knownPath()
	if err != nil {
		return err
	}
	set, err := c.readSet(path)
	if err != nil {
		return err
	}
	if set[peer] {
		return nil
	}
	set[peer] = true
	return c.writeSet(path, set)
}

// IsPeerKnown reports whether peer has ever been accepted or reached out to.
func (c *Client) IsPeerKnown(peer string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.knownPath()
	if err != nil {
		return false, err
	}
	set, err := c.readSet(path)
	if err != nil {
		return false, err
	}
	return set[peer], nil
}

// BlockPeer blocks peer locally, snapshotting their server for the blocked list
// in case the conversation is later deleted. Purely local: the server is never
// told, and the peer cannot tell they were blocked.
func (c *Client) BlockPeer(peer, server string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.blockedPath()
	if err != nil {
		return err
	}
	entries, err := c.readBlocked(path)
	if err != nil {
		return err
	}
	entries[peer] = blockedEntry{PeerAccountID: peer, PeerServer: server}
	return c.writeBlocked(path, entries)
}

// UnblockPeer lifts a local block.
func (c *Client) UnblockPeer(peer string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.blockedPath()
	if err != nil {
		return err
	}
	entries, err := c.readBlocked(path)
	if err != nil {
		return err
	}
	if _, ok := entries[peer]; !ok {
		return nil
	}
	delete(entries, peer)
	return c.writeBlocked(path, entries)
}

// PeerAccountGoneMarker is the one-to-one counterpart to a group's own line
// (recordMemberGone) -- worded without a name, since a one-to-one chat has
// exactly one other party and repeating who they are would be noise.
const PeerAccountGoneMarker = "This account no longer exists on their server, so nothing sent here will ever arrive"

// markPeerGone records that a peer's account, confirmed gone by asking their
// server (see accountIsGone), is not coming back.
//
// Set once, not on every failed retry: the flag is what lets [Client.deliver]
// refuse at no network cost afterwards, instead of asking the same question on
// every attempt. Local only, like a group's recordMemberGone -- nothing
// signed can say this about a one-to-one peer either, their server said so and
// only this device asked. Deliberately its own field rather than piggybacking
// on Blocked or PendingApproval: this is neither a decision the user made nor
// a stranger's first contact, it is a fact about the other side.
func (c *Client) markPeerGone(peer string) error {
	convo, err := c.Conversation(peer)
	if err != nil {
		return err
	}
	if convo == nil {
		// Nothing to mark and nowhere to notify into -- the chat was deleted
		// between the failed send and this call.
		return nil
	}
	if convo.PeerGone {
		return nil
	}
	convo.PeerGone = true
	if err := c.PutConversation(*convo); err != nil {
		return err
	}

	// De-duplicated by text as well as by the flag above, the same defence
	// recordMemberGone uses: two sends racing before the flag is visible must
	// not double the line.
	msgs, err := c.Messages(peer)
	if err != nil {
		return err
	}
	for i := range msgs {
		if msgs[i].Kind == MessageSystemInfo && msgs[i].Text == PeerAccountGoneMarker {
			return nil
		}
	}
	id, err := newMessageID()
	if err != nil {
		return err
	}
	return c.AppendMessage(peer, Message{
		ID: id, Text: PeerAccountGoneMarker, Timestamp: time.Now().UTC(),
		Kind: MessageSystemInfo, SendState: SendSent,
	})
}

// IsPeerBlocked reports whether peer is locally blocked.
func (c *Client) IsPeerBlocked(peer string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.blockedPath()
	if err != nil {
		return false, err
	}
	entries, err := c.readBlocked(path)
	if err != nil {
		return false, err
	}
	_, blocked := entries[peer]
	return blocked, nil
}

func (c *Client) readBlocked(path string) (map[string]blockedEntry, error) {
	var list []blockedEntry
	if _, err := readJSON(path, &list); err != nil {
		return nil, err
	}
	entries := make(map[string]blockedEntry, len(list))
	for _, e := range list {
		entries[e.PeerAccountID] = e
	}
	return entries, nil
}

func (c *Client) writeBlocked(path string, entries map[string]blockedEntry) error {
	list := make([]blockedEntry, 0, len(entries))
	for _, e := range entries {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].PeerAccountID < list[j].PeerAccountID })
	return writeJSON(path, list)
}
