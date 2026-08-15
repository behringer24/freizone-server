package client

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/group"
)

// The receiving half of groups: what happens to a control envelope once it has
// been decrypted.
//
// Whoever decrypts a group envelope has to act on it. The ratchet has already
// advanced and the id is already marked processed by the time the payload is
// even looked at, and both of those are irreversible -- so an envelope that is
// merely handed somewhere and dropped takes its facts with it for good. That is
// why this lives here rather than above: a background wake with nothing else
// attached still has to be able to finish the job.
//
// Membership is never a message. Nothing here is stored in a transcript except
// the narration of what changed, and nothing here notifies -- with one
// exception, an invitation addressed to this account, which is a decision
// waiting on the user and their only sign that anything happened at all, since
// nothing is ever sent into a group before they accept.

// MaxHeldGroupEvents bounds how many not-yet-admissible events one group may
// hold.
//
// Holding is for events that overtook the ones they depend on -- delivery is
// unordered, so a membership change easily arrives before the snapshot
// carrying the genesis it rests on. That is a handful in practice. An
// unbounded buffer would mostly be somewhere for a hostile peer to put things.
const MaxHeldGroupEvents = 64

// GroupControlKind is what a control envelope is doing.
type GroupControlKind string

const (
	// GroupSnapshot carries the sender's whole fact set. The answer to
	// everything: two members reconcile by one sending all of it, because the
	// fold is order-independent and a fact already known is simply known.
	GroupSnapshot GroupControlKind = "snapshot"

	// GroupEvents carries a few new facts, the ordinary case.
	GroupEvents GroupControlKind = "events"

	// GroupSyncRequest asks for a snapshot and carries none.
	GroupSyncRequest GroupControlKind = "sync_request"
)

// GroupOutcome is what applying one control envelope changed.
type GroupOutcome struct {
	GroupID string

	// PeerStateHash is the sender's own view, so a divergence is visible
	// without anyone having to ask about it.
	PeerStateHash string

	// StateHash is ours after applying, empty for a group we hold no facts
	// about.
	StateHash string

	// WantsSnapshot: they asked for our fact set outright.
	WantsSnapshot bool

	// Invited: this envelope was an invitation *to us*, into a membership we
	// did not hold before. The one group event worth waking someone for.
	Invited bool

	// Lines are the transcript lines the change produced, already appended.
	// Returned so a caller can show them without re-reading the transcript.
	Lines []string

	// DeliveredUpTo is the watermark to confirm back for a group *message*,
	// in the sender.s clock. Its own field rather than the one-to-one one,
	// because a receipt travels over a conversation: reporting a group anchor
	// through that field would confirm the member.s unrelated direct messages.
	DeliveredUpTo *time.Time
}

// groupPeers is what each member last told us about their own view, and what
// we still owe them.
type groupPeers struct {
	// StateHashes maps an account id to the state hash it last stated. The
	// send path reads it to decide whether that member needs the whole fact
	// set before their next copy.
	StateHashes map[string]string `json:"state_hashes,omitempty"`

	// Owed names members who are due the whole fact set: an unreachable
	// recipient of a broadcast, or somebody whose request could not be
	// answered. Persisted, because the point of a debt is that it outlives the
	// attempt that created it.
	Owed map[string]bool `json:"owed,omitempty"`

	// Answered maps an account id to the last foreign state hash we sent a
	// snapshot in reply to, so two peers that stay divergent for a reason a
	// snapshot cannot fix do not trade snapshots forever.
	//
	// Persisted rather than kept for the run, which the Dart original does not
	// do: a restart would otherwise re-open exactly that loop. Safe, because a
	// peer who genuinely still needs the facts asks outright, and a sync
	// request bypasses this check.
	Answered map[string]string `json:"answered,omitempty"`

	// LastSyncRequest is when this group was last asked about, for the
	// cooldown. Per group rather than per member: the point is to get the facts
	// once, and a group whose every member writes would otherwise produce one
	// request per message.
	LastSyncRequest string `json:"last_sync_request,omitempty"`
}

// oweGroupSnapshot records that a member is due the whole fact set.
func (c *Client) oweGroupSnapshot(groupID, accountID string) error {
	return c.updateGroupPeers(groupID, func(p *groupPeers) bool {
		if p.Owed[accountID] {
			return false
		}
		if p.Owed == nil {
			p.Owed = map[string]bool{}
		}
		p.Owed[accountID] = true
		return true
	})
}

func (c *Client) clearGroupSnapshotDebt(groupID, accountID string) error {
	return c.updateGroupPeers(groupID, func(p *groupPeers) bool {
		if !p.Owed[accountID] {
			return false
		}
		delete(p.Owed, accountID)
		return true
	})
}

// markGroupHashAnswered reports whether this peer's hash has already been
// answered with a snapshot, recording it if not.
func (c *Client) markGroupHashAnswered(groupID, accountID, stateHash string) (already bool, err error) {
	err = c.updateGroupPeers(groupID, func(p *groupPeers) bool {
		if p.Answered[accountID] == stateHash {
			already = true
			return false
		}
		if p.Answered == nil {
			p.Answered = map[string]string{}
		}
		p.Answered[accountID] = stateHash
		return true
	})
	return already, err
}

// markGroupSyncRequested reports whether this group was asked about too
// recently to ask again, recording the attempt if not.
func (c *Client) markGroupSyncRequested(groupID string, now time.Time) (tooSoon bool, err error) {
	err = c.updateGroupPeers(groupID, func(p *groupPeers) bool {
		if last, perr := parseTime(p.LastSyncRequest); perr == nil && last != nil {
			if now.Sub(*last) < GroupSyncRequestCooldown {
				tooSoon = true
				return false
			}
		}
		p.LastSyncRequest = formatTime(&now)
		return true
	})
	return tooSoon, err
}

// groupPeersFor is groupPeers read under the lock.
func (c *Client) groupPeersFor(groupID string) (groupPeers, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.groupPeersLocked(groupID)
}

// updateGroupPeers applies mutate and writes only if it changed something.
// Not writing on the no-change path matters: most of these run on every
// envelope, and a group's peer file would otherwise be rewritten per message.
func (c *Client) updateGroupPeers(groupID string, mutate func(*groupPeers) bool) error {
	if groupID == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	peers, err := c.groupPeersLocked(groupID)
	if err != nil {
		return err
	}
	if !mutate(&peers) {
		return nil
	}
	path, err := c.store.groupPath(groupID, filePeers)
	if err != nil {
		return err
	}
	return writeJSON(path, peers)
}

// GroupState returns the fact set held for a group, or nil for one this
// account knows nothing about.
func (c *Client) GroupState(groupID string) (*group.State, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.groupStateLocked(groupID)
}

func (c *Client) groupStateLocked(groupID string) (*group.State, error) {
	path, err := c.store.groupPath(groupID, fileFacts)
	if err != nil {
		return nil, err
	}
	st := group.NewState()
	found, err := readJSON(path, st)
	if err != nil || !found {
		return nil, err
	}
	return st, nil
}

// PutGroupState replaces the fact set held for a group.
func (c *Client) PutGroupState(groupID string, st *group.State) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.putGroupStateLocked(groupID, st)
}

func (c *Client) putGroupStateLocked(groupID string, st *group.State) error {
	path, err := c.store.groupPath(groupID, fileFacts)
	if err != nil {
		return err
	}
	return writeJSON(path, st)
}

// Groups lists every group this account holds facts about, by id.
func (c *Client) Groups() ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	dir, err := c.store.groupsDir()
	if err != nil {
		return nil, err
	}
	ids, err := listDirs(dir)
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	return ids, nil
}

// ForgetGroup discards everything this account holds *about* a group: its
// facts, the events waiting on facts that never arrived, what each member last
// said their view was, and the chat state a list reads. The transcript and the
// media are not here and are the caller's to clear -- a group chat lives under
// dirChats keyed by group id like any other (see layout.go).
//
// Only ever right for a group this account is no longer in. While still a
// member the others keep sending, and an arriving message rebuilds a chat whose
// facts are gone: no name, no member list, and a send that fails with "no
// group". So the caller has to have left, been removed, or seen it dissolved
// first -- this makes no such check, because the fold cannot distinguish
// "left" from "never joined" for a group whose facts are already gone.
//
// [Client.Groups] is a directory listing, so this is what actually makes a
// group disappear from the chat list. Leaving alone does not: a member who
// left is still a member the fold knows about, deliberately, so a message that
// arrives afterwards is recognised rather than treated as a stranger's.
func (c *Client) ForgetGroup(groupID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// store.path rejects any id that could escape the store, which is the
	// whole check this needs -- a group id arrives from the wire.
	dir, err := c.store.path(dirGroups, groupID)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("client: forgetting group: %w", err)
	}
	return nil
}

// GroupMembership folds a group's facts into its current membership, or
// returns nil for a group this account knows nothing about.
func (c *Client) GroupMembership(groupID string) (*group.Resolved, error) {
	st, err := c.GroupState(groupID)
	if err != nil || st == nil {
		return nil, err
	}
	return st.Resolve(), nil
}

// ApplyGroupControl folds a control envelope into this account's facts.
//
// The envelope's own claim about which group it belongs to is not trusted for
// a snapshot: a snapshot carries the genesis, and the id follows from the key
// inside it rather than from whatever the sender wrote on the outside.
func (c *Client) ApplyGroupControl(content Content, senderAccountID string, now time.Time) (GroupOutcome, error) {
	if content.Kind != ContentGroupControl {
		return GroupOutcome{}, fmt.Errorf("client: %q is not a group control envelope", content.Kind)
	}
	now = now.UTC()
	out := GroupOutcome{GroupID: content.GroupID, PeerStateHash: content.StateHash}

	if content.ControlKind == GroupSyncRequest {
		// Nothing to apply: answering is a send, and the caller owns that.
		out.WantsSnapshot = true
		return out, c.RecordGroupPeerStateHash(content.GroupID, senderAccountID, content.StateHash)
	}

	c.mu.Lock()
	stored, err := c.groupStateLocked(content.GroupID)
	if err != nil {
		c.mu.Unlock()
		return out, err
	}
	held, err := c.heldEventsLocked(content.GroupID)
	if err != nil {
		c.mu.Unlock()
		return out, err
	}

	// Whether this account held *any* facts about this group before now. The
	// same snapshot legitimately arrives from several members, so this is what
	// tells a first invitation apart from a redelivery of one.
	isNewToUs := stored == nil
	st := stored
	if st == nil {
		st = group.NewState()
	}
	// Retried together with the new facts: delivery is unordered, so something
	// held back earlier may become admissible only now.
	batch := append(append([]*group.Event(nil), held...), content.Events...)

	// Folded before applying, so the transcript can say what actually changed.
	// One extra fold of facts already held, and only on a control envelope --
	// membership changes are rare next to messages, and membership changing
	// silently is exactly the thing that needs saying.
	var before *group.Resolved
	if stored != nil {
		before = stored.Resolve()
	}
	result := st.Apply(batch)

	groupID := st.GroupID()
	if groupID == "" {
		groupID = content.GroupID
	}
	out.GroupID = groupID

	if st.GroupID() != "" {
		if err := c.putGroupStateLocked(groupID, st); err != nil {
			c.mu.Unlock()
			return out, err
		}
	}
	if err := c.holdPrematureLocked(groupID, batch, result); err != nil {
		c.mu.Unlock()
		return out, err
	}
	c.mu.Unlock()

	if st.GroupID() == "" {
		// Facts about a group whose genesis has not arrived: everything is
		// held, and there is nothing to narrate or notify about yet.
		return out, c.RecordGroupPeerStateHash(groupID, senderAccountID, content.StateHash)
	}

	after := st.Resolve()
	out.StateHash = after.StateHash

	// An outstanding invitation for us: a membership we did not hold before and
	// have not accepted, so nothing will ever be sent into this group until the
	// user answers.
	//
	// "Did not hold before" rather than "the group is new to us", because being
	// re-invited after a removal is an invitation too -- the facts stay on this
	// device when a moderator removes us, so the group is not new the second
	// time round.
	me, err := c.Identity()
	if err != nil {
		return out, err
	}
	mine := memberOf(after, me.AccountID)
	wasMine := memberOf(before, me.AccountID)
	if mine != nil && !mine.Joined && (isNewToUs || wasMine == nil) {
		out.Invited = true
	}

	// Being told about a group is how an invitation arrives, so the chat is
	// created here rather than when a message first lands in it.
	chat, err := c.GroupChat(groupID)
	if err != nil {
		return out, err
	}
	if chat == nil {
		chat = &GroupChat{GroupID: groupID}
	}
	if out.Invited {
		// Unread as well as notified: the chat list is where they will come
		// looking for it.
		chat.HasUnread = true
	}

	out.Lines = groupStateChangeLines(before, after, me.AccountID, batch)
	if err := c.appendGroupSystemLines(groupID, out.Lines, now); err != nil {
		return out, err
	}
	if len(out.Lines) > 0 {
		// Worth recording where it happened, not worth a badge -- the
		// invitation above is the one exception and has its own reason.
		at := now
		chat.LastActivityAt = &at
	}
	if err := c.PutGroupChat(*chat); err != nil {
		return out, err
	}
	return out, c.RecordGroupPeerStateHash(groupID, senderAccountID, content.StateHash)
}

// appendGroupSystemLines writes narration into a group's transcript, one
// second apart.
//
// A transcript renders in insertion order, so the offsets are not what keeps
// these in sequence -- they keep the timestamps from being identical, since
// several changes can land in one batch ("invited" before "joined" is not the
// same story as the other way round) and identical stamps would make any
// ordering by time arbitrary.
func (c *Client) appendGroupSystemLines(groupID string, lines []string, at time.Time) error {
	for i, line := range lines {
		id, err := newMessageID()
		if err != nil {
			return err
		}
		if err := c.AppendMessage(groupID, Message{
			ID:        id,
			Text:      line,
			Timestamp: at.Add(time.Duration(i) * time.Second),
			Kind:      MessageSystemInfo,
			SendState: SendSent,
		}); err != nil {
			return err
		}
	}
	return nil
}

// heldEventsLocked reads the events waiting on facts that have not arrived.
func (c *Client) heldEventsLocked(groupID string) ([]*group.Event, error) {
	path, err := c.store.groupPath(groupID, fileHeld)
	if err != nil {
		return nil, err
	}
	var held []*group.Event
	if _, err := readJSON(path, &held); err != nil {
		return nil, err
	}
	return held, nil
}

// holdPrematureLocked keeps the events that could not be admitted *yet*, so a
// later arrival can unblock them.
//
// An event rejected for a reason no later fact can change -- a bad signature,
// another group's id -- is dropped rather than held. Retrying it forever would
// be pointless, and is exactly what a hostile peer would want.
func (c *Client) holdPrematureLocked(groupID string, batch []*group.Event, result group.ApplyResult) error {
	keep := make([]*group.Event, 0, len(result.Rejected))
	for _, rejection := range result.Rejected {
		if rejection.Reason != group.RejectNoGenesis {
			continue
		}
		if len(keep) >= MaxHeldGroupEvents {
			break
		}
		if rejection.Index >= 0 && rejection.Index < len(batch) {
			keep = append(keep, batch[rejection.Index])
		}
	}
	path, err := c.store.groupPath(groupID, fileHeld)
	if err != nil {
		return err
	}
	if len(keep) == 0 {
		return removeFile(path)
	}
	return writeJSON(path, keep)
}

// RecordGroupPeerStateHash remembers what a member said their own view was.
//
// Written on every group envelope, control or message, by whoever handles it.
// The send path reads it to decide whether that member needs the whole fact set
// before their next copy. An empty hash is not recorded: it means the sender did
// not say, which is not the same as having nothing.
func (c *Client) RecordGroupPeerStateHash(groupID, accountID, stateHash string) error {
	if accountID == "" || stateHash == "" {
		return nil
	}
	return c.updateGroupPeers(groupID, func(p *groupPeers) bool {
		if p.StateHashes[accountID] == stateHash {
			return false // nothing changed, so nothing is written
		}
		if p.StateHashes == nil {
			p.StateHashes = map[string]string{}
		}
		p.StateHashes[accountID] = stateHash
		return true
	})
}

// GroupPeerStateHashes is every member's last stated view of a group.
func (c *Client) GroupPeerStateHashes(groupID string) (map[string]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	peers, err := c.groupPeersLocked(groupID)
	if err != nil || peers.StateHashes == nil {
		return map[string]string{}, err
	}
	return peers.StateHashes, nil
}

func (c *Client) groupPeersLocked(groupID string) (groupPeers, error) {
	path, err := c.store.groupPath(groupID, filePeers)
	if err != nil {
		return groupPeers{}, err
	}
	var peers groupPeers
	if _, err := readJSON(path, &peers); err != nil {
		return groupPeers{}, err
	}
	return peers, nil
}

// GroupChat is a group's transcript-adjacent state: what a chat list needs
// that the fact set does not answer.
//
// Separate from [Conversation] rather than reusing it, because the two share
// only the fields around the transcript. A group has no peer server, no
// approval to give, and no single correspondent to hold receipt watermarks
// for; a one-to-one chat has no membership. Name and topic are not here either
// -- they are facts, and live in the fold.
type GroupChat struct {
	GroupID        string
	LastActivityAt *time.Time
	HasUnread      bool

	// MemberReceipts is how far each member has got with *our* messages in
	// this group -- filed per member and never passed on. Who has read what
	// stays between reader and author, which is why a group receipt is sent to
	// the author alone rather than into the group.
	MemberReceipts map[string]MemberReceipt
}

// MemberReceipt is one member.s pair of watermarks. Cumulative, so one
// arriving late is harmless: it moves a monotonic value and touches no message.
// The Sent* pair is the mirror image: how far we have already told *them*
// about *their* messages. Kept for the same reason [Conversation] keeps it, so
// an identical receipt is not re-sent every time the group is opened.
type MemberReceipt struct {
	DeliveredUpTo *time.Time
	ReadUpTo      *time.Time

	SentDeliveredReceiptUpTo *time.Time
	SentReadReceiptUpTo      *time.Time
}

type memberReceiptFile struct {
	DeliveredUpTo string `json:"delivered_up_to,omitempty"`
	ReadUpTo      string `json:"read_up_to,omitempty"`

	SentDeliveredReceiptUpTo string `json:"sent_delivered_receipt_up_to,omitempty"`
	SentReadReceiptUpTo      string `json:"sent_read_receipt_up_to,omitempty"`
}

type groupChatFile struct {
	GroupID        string                       `json:"group_id"`
	LastActivityAt string                       `json:"last_activity_at,omitempty"`
	HasUnread      bool                         `json:"has_unread,omitempty"`
	MemberReceipts map[string]memberReceiptFile `json:"member_receipts,omitempty"`
}

// GroupChat returns a group's chat state, or nil when there is none.
func (c *Client) GroupChat(groupID string) (*GroupChat, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.groupChatLocked(groupID)
}

func (c *Client) groupChatLocked(groupID string) (*GroupChat, error) {
	path, err := c.store.groupPath(groupID, fileChat)
	if err != nil {
		return nil, err
	}
	var stored groupChatFile
	found, err := readJSON(path, &stored)
	if err != nil || !found {
		return nil, err
	}
	chat := &GroupChat{GroupID: stored.GroupID, HasUnread: stored.HasUnread}
	if chat.LastActivityAt, err = parseTime(stored.LastActivityAt); err != nil {
		return nil, err
	}
	for account, r := range stored.MemberReceipts {
		var receipt MemberReceipt
		if receipt.DeliveredUpTo, err = parseTime(r.DeliveredUpTo); err != nil {
			return nil, err
		}
		if receipt.ReadUpTo, err = parseTime(r.ReadUpTo); err != nil {
			return nil, err
		}
		if receipt.SentDeliveredReceiptUpTo, err = parseTime(r.SentDeliveredReceiptUpTo); err != nil {
			return nil, err
		}
		if receipt.SentReadReceiptUpTo, err = parseTime(r.SentReadReceiptUpTo); err != nil {
			return nil, err
		}
		if chat.MemberReceipts == nil {
			chat.MemberReceipts = map[string]MemberReceipt{}
		}
		chat.MemberReceipts[account] = receipt
	}
	if chat.GroupID == "" {
		chat.GroupID = groupID
	}
	return chat, nil
}

// PutGroupChat replaces a group's chat state.
func (c *Client) PutGroupChat(chat GroupChat) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.groupPath(chat.GroupID, fileChat)
	if err != nil {
		return err
	}
	var receipts map[string]memberReceiptFile
	for account, r := range chat.MemberReceipts {
		if receipts == nil {
			receipts = map[string]memberReceiptFile{}
		}
		receipts[account] = memberReceiptFile{
			DeliveredUpTo:            formatTime(r.DeliveredUpTo),
			ReadUpTo:                 formatTime(r.ReadUpTo),
			SentDeliveredReceiptUpTo: formatTime(r.SentDeliveredReceiptUpTo),
			SentReadReceiptUpTo:      formatTime(r.SentReadReceiptUpTo),
		}
	}
	return writeJSON(path, groupChatFile{
		GroupID:        chat.GroupID,
		LastActivityAt: formatTime(chat.LastActivityAt),
		HasUnread:      chat.HasUnread,
		MemberReceipts: receipts,
	})
}

// storeGroupMessage files a decrypted group message into its transcript.
//
// The group may be one this device has never heard of: delivery is unordered,
// so a message can overtake the snapshot that introduces its group. The
// transcript is created anyway rather than dropping the message -- the ratchet
// has already advanced past this envelope, so there is no second chance at it
// -- and it simply shows an unnamed group until the facts catch up.
// stored is false for a message this transcript already holds, which is not an
// error and not a second line: the caller uses it to keep a duplicate from
// being announced a second time.
func (c *Client) storeGroupMessage(content Content, senderAccountID string, now time.Time, openChatID string) (line Message, stored bool, err error) {
	id := content.ID
	if id == "" {
		if id, err = newMessageID(); err != nil {
			return Message{}, false, err
		}
	} else {
		// Same message, second envelope. Their copy still gets confirmed --
		// they clearly did not hear the first confirmation -- but the
		// transcript keeps one line and the user is interrupted once.
		seen, err := c.MessageExists(content.GroupID, id)
		if err != nil {
			return Message{}, false, err
		}
		if seen {
			// Only what the caller needs of it: which line this was, and the
			// anchor to confirm back. The line itself is already in place and
			// must not be rewritten from a second copy.
			return Message{ID: id, SenderSentAt: content.SentAt}, false, nil
		}
	}
	line = Message{
		ID:           id,
		Text:         content.Text,
		Timestamp:    now,
		SenderSentAt: content.SentAt,
		// What a one-to-one transcript never needs: in a group the chat does
		// not answer who wrote this, so the line has to.
		SenderAccountID:      senderAccountID,
		ReplyToID:            content.ReplyToID,
		ReplyPreviewText:     content.ReplyPreviewText,
		ReplyPreviewMine:     content.ReplyPreviewMine,
		ReplyPreviewAuthorID: content.ReplyPreviewAuthorID,
		Kind:                 MessageNormal,
		SendState:            SendSent,
		Attachments:          content.Attachments,
	}
	if err := c.AppendMessage(content.GroupID, line); err != nil {
		return Message{}, false, err
	}
	for _, att := range content.Attachments {
		if err := c.WriteAttachmentThumb(content.GroupID, id, att.Thumb); err != nil {
			return Message{}, false, err
		}
	}

	chat, err := c.GroupChat(content.GroupID)
	if err != nil {
		return Message{}, false, err
	}
	if chat == nil {
		chat = &GroupChat{GroupID: content.GroupID}
	}
	at := now
	chat.LastActivityAt = &at
	if openChatID != content.GroupID {
		chat.HasUnread = true
	}
	return line, true, c.PutGroupChat(*chat)
}

// recordBlockedGroupMessage leaves a visible trace of a message dropped
// because its sender is blocked.
//
// A one-to-one chat with a blocked peer can stay silent: its blocked state is
// the standing explanation. A group transcript is shared, though -- the other
// members go on replying to messages this account never saw, and without a
// trace those replies read as non-sequiturs, indistinguishable from delivery
// loss.
//
// One line per run rather than per message: consecutive drops from the same
// sender collapse into the line already there, so a chatty blocked member
// costs one line and not a column. How *much* they wrote stays as unknowable
// as what they wrote, which is the point of blocking.
//
// Deliberately moves neither last activity nor unread: a blocked member must
// not be able to push a group up the chat list or put a badge on it. And a
// group with no transcript yet gets nothing minted -- a shell group whose only
// content is "somebody blocked wrote" is not worth creating.
func (c *Client) recordBlockedGroupMessage(groupID, senderAccountID string, now time.Time) error {
	chat, err := c.GroupChat(groupID)
	if err != nil || chat == nil {
		return err
	}
	line := fmt.Sprintf("A message from %s was hidden (blocked contact).", memberLabel(senderAccountID))

	last, err := c.LastMessage(groupID)
	if err != nil {
		return err
	}
	if last != nil && last.Kind == MessageSystemInfo && last.Text == line {
		return nil
	}
	id, err := newMessageID()
	if err != nil {
		return err
	}
	return c.AppendMessage(groupID, Message{
		ID: id, Text: line, Timestamp: now,
		Kind: MessageSystemInfo, SendState: SendSent,
	})
}

// recordMemberGone leaves a line in the group saying an account has ceased to
// exist, so the one thing nobody else will ever mention is at least written
// down where it happened.
//
// Local, like [Client.recordBlockedGroupMessage] and unlike every other system
// line here: those are diffed from the signed fact set, and no fact can say
// "this account is gone" -- their server did, and only this device asked. The
// row stays in the member list either way, because only a moderator's signed
// removal can take it out, so a reader who finds nothing said about it is left
// with a member who never answers and no reason given.
//
// Once, not once per pass: the debt this comes from is cleared in the same
// breath, so there is nothing left to discover a second time. The check against
// an identical line is for a member owed facts in this group again later --
// re-invited, re-created -- where saying it twice would be noise.
func (c *Client) recordMemberGone(groupID, accountID string) error {
	line := fmt.Sprintf(
		"%s no longer exists on their server, so they can no longer receive anything here.",
		memberLabel(accountID),
	)
	msgs, err := c.Messages(groupID)
	if err != nil {
		return err
	}
	for i := range msgs {
		if msgs[i].Kind == MessageSystemInfo && msgs[i].Text == line {
			return nil
		}
	}
	id, err := newMessageID()
	if err != nil {
		return err
	}
	return c.AppendMessage(groupID, Message{
		ID: id, Text: line, Timestamp: time.Now().UTC(),
		Kind: MessageSystemInfo, SendState: SendSent,
	})
}

func memberOf(r *group.Resolved, accountID string) *group.Member {
	if r == nil {
		return nil
	}
	for i := range r.Members {
		if r.Members[i].AccountID == accountID {
			return &r.Members[i]
		}
	}
	return nil
}

// recordMemberReceipt moves one member's watermark for this group.
//
// Monotonic, like the one-to-one watermarks: an out-of-order or duplicated
// older receipt never regresses a status that has already moved on. A group
// this device has no chat for gets nothing minted -- there is nothing to
// confirm against.
func (c *Client) recordMemberReceipt(groupID, accountID string, content Content) error {
	chat, err := c.GroupChat(groupID)
	if err != nil || chat == nil {
		return err
	}
	upTo := content.ReceiptUpTo
	receipt := chat.MemberReceipts[accountID]
	switch content.ReceiptStatus {
	case ReceiptDelivered:
		if receipt.DeliveredUpTo != nil && !upTo.After(*receipt.DeliveredUpTo) {
			return nil
		}
		receipt.DeliveredUpTo = &upTo
	case ReceiptRead:
		if receipt.ReadUpTo != nil && !upTo.After(*receipt.ReadUpTo) {
			return nil
		}
		receipt.ReadUpTo = &upTo
	default:
		return nil
	}
	if chat.MemberReceipts == nil {
		chat.MemberReceipts = map[string]MemberReceipt{}
	}
	chat.MemberReceipts[accountID] = receipt
	return c.PutGroupChat(*chat)
}

// IsGroupID reports whether a chat id names a group rather than a peer.
//
// Account and group ids share every line of their encoding and differ only in
// a version marker, which is what makes one call able to take a "chat id" and
// dispatch on it -- and what makes confusing the two impossible rather than
// merely unlikely.
func IsGroupID(id string) bool {
	version, err := address.VersionOf(id)
	return err == nil && version == address.VersionGroup
}
