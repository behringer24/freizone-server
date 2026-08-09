package client

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/behringer24/freizone-server/pkg/group"
	"github.com/behringer24/freizone-server/pkg/ratchet"
	"github.com/behringer24/freizone-server/pkg/wire"
)

// The sending half of groups.
//
// There is no group session and no group key: a group message is encrypted
// once per member, into that member's own one-to-one ratchet. The group is a
// fact set, not a channel. That costs one copy per member and buys the
// property that matters -- adding somebody grants no access to what was said
// before them, and removing somebody ends their access immediately, without
// re-keying anything.
//
// Everything here is best-effort per recipient and never all-or-nothing. One
// unreachable member must not stop the others hearing about something, so a
// failure is recorded against that member and retried later rather than
// aborting the fan-out.

// GroupSyncRequestCooldown is how long to wait before asking the same group
// for its facts again. Asking is cheap but not free, and a group nobody can
// answer for would otherwise be asked about on every reconnect.
const GroupSyncRequestCooldown = 5 * time.Minute

// SendGroupText encrypts a message once per member and delivers it.
//
// The transcript line is written first and carries one delivery record per
// recipient, so a partial failure is visible as exactly that: the message is
// sent, to these members, not yet to those.
func (c *Client) SendGroupText(ctx context.Context, groupID, text string, opts SendOptions) (SendResult, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	id, err := c.Identity()
	if err != nil {
		return SendResult{}, err
	}
	membership, err := c.GroupMembership(groupID)
	if err != nil {
		return SendResult{}, err
	}
	if membership == nil {
		return SendResult{}, fmt.Errorf("client: no facts about group %s", groupID)
	}
	if membership.Dissolved {
		return SendResult{}, fmt.Errorf("client: group %s has been dissolved", groupID)
	}
	mine := memberOf(membership, id.AccountID)
	if mine == nil || !mine.Joined {
		// Sending into a group we have been invited to but not accepted would
		// disclose our address to everyone in it before we agreed to be there.
		return SendResult{}, fmt.Errorf("client: not a joined member of group %s", groupID)
	}

	messageID, err := newMessageID()
	if err != nil {
		return SendResult{}, err
	}
	recipients := joinedMembers(membership, id.AccountID)
	// Written with the line itself, so a partial failure is visible as exactly
	// that -- sent, to these members, not yet to those -- rather than as one
	// opaque state for the whole message.
	pending := make([]GroupDelivery, 0, len(recipients))
	for _, m := range recipients {
		pending = append(pending, GroupDelivery{AccountID: m.AccountID, State: SendPending})
	}

	var attachments []Attachment
	if opts.Media != nil {
		if err := c.WriteAttachmentFile(groupID, messageID, opts.Media.Bytes); err != nil {
			return SendResult{}, err
		}
		if err := c.WriteAttachmentThumb(groupID, messageID, opts.Media.Thumb); err != nil {
			return SendResult{}, err
		}
		attachments = []Attachment{placeholderFor(*opts.Media)}
	} else {
		attachments = opts.Attachments
	}

	line := Message{
		ID: messageID, Text: text, Mine: true, Timestamp: now,
		ReplyToID: opts.ReplyToID, ReplyPreviewText: opts.ReplyPreviewText,
		ReplyPreviewMine: opts.ReplyPreviewMine,
		Kind:             MessageNormal, SendState: SendPending,
		Attachments: attachments, Deliveries: pending,
	}
	if err := c.AppendMessage(groupID, line); err != nil {
		return SendResult{}, err
	}
	res := SendResult{Message: line}

	// One upload for the whole group rather than one per member: the blob is
	// stored once and granted to every recipient device, which is why the
	// recipient set is part of the upload.
	if opts.Media != nil {
		uploaded, err := c.uploadForGroup(ctx, recipients, *opts.Media)
		if err != nil {
			if markErr := c.SetMessageSendState(groupID, messageID, SendFailed); markErr != nil {
				return res, fmt.Errorf("%w (and marking it failed: %v)", err, markErr)
			}
			return res, err
		}
		if err := c.SetMessageAttachments(groupID, messageID, []Attachment{uploaded}); err != nil {
			return res, err
		}
		line.Attachments = []Attachment{uploaded}
	}

	plaintext, err := encodeGroupText(line, groupID, membership.StateHash, now)
	if err != nil {
		return res, err
	}
	deliveries, err := c.fanOut(ctx, groupID, plaintext, recipients)
	if err != nil {
		return res, err
	}
	line.Deliveries = deliveries
	res.Message = line

	if err := c.recordDeliveries(groupID, messageID, deliveries); err != nil {
		return res, err
	}
	state := SendFailed
	for _, d := range deliveries {
		if d.State == SendSent {
			// Delivered to somebody is delivered: a group message is not
			// pending because one member's server is down.
			state = SendSent
			break
		}
	}
	if err := c.SetMessageSendState(groupID, messageID, state); err != nil {
		return res, err
	}
	res.Message.SendState = state

	chat, err := c.GroupChat(groupID)
	if err != nil {
		return res, err
	}
	if chat == nil {
		chat = &GroupChat{GroupID: groupID}
	}
	at := now
	chat.LastActivityAt = &at
	return res, c.PutGroupChat(*chat)
}

// preparedCopy is one recipient's copy, encrypted and waiting to be posted.
type preparedCopy struct {
	member    group.Member
	endpoint  PeerEndpoint
	messageID string
	payload   json.RawMessage

	// established: this copy carries a prekey block, because the session was
	// built for it. If the post then fails, the session has to go: the peer
	// never saw the establishment, so every later message on it would be
	// undecryptable to them forever. That is the one advance worth rolling
	// back here -- an advance on a session they already know about is not,
	// since other copies of the same message may have gone out on it.
	established bool
}

// fanOut encrypts plaintext once per recipient and delivers the copies.
//
// Encrypt first, persist second, send third. Encrypting advances each
// recipient's ratchet, and that advance has to reach disk even if the network
// half then fails -- otherwise a retry re-uses a message number and desyncs
// that peer for good. The one-to-one path can roll an advance back because it
// has exactly one recipient to be consistent with; here a partial success
// means some peers have moved on and some have not, so nothing is rolled back
// and the delivery record carries who is behind.
func (c *Client) fanOut(ctx context.Context, groupID string, plaintext []byte, recipients []group.Member) ([]GroupDelivery, error) {
	id, err := c.Identity()
	if err != nil {
		return nil, err
	}

	copies := make([]preparedCopy, 0, len(recipients))
	deliveries := make([]GroupDelivery, 0, len(recipients))
	for _, m := range recipients {
		blocked, err := c.IsPeerBlocked(m.AccountID)
		if err != nil {
			return nil, err
		}
		if blocked {
			// Blocked is about the person, not the room: their copy is simply
			// never prepared, and the rest of the group is unaffected.
			continue
		}
		copy, err := c.prepareCopy(ctx, m, id.Server, plaintext)
		if err != nil {
			deliveries = append(deliveries, GroupDelivery{AccountID: m.AccountID, State: SendFailed})
			continue
		}
		copies = append(copies, copy)
		deliveries = append(deliveries, GroupDelivery{
			AccountID: m.AccountID, WireMessageID: copy.messageID, State: SendPending,
		})
	}

	// Grouped by target server, which is the unit a batch can cover.
	byServer := map[string][]preparedCopy{}
	for _, copy := range copies {
		byServer[copy.endpoint.Server] = append(byServer[copy.endpoint.Server], copy)
	}
	servers := make([]string, 0, len(byServer))
	for s := range byServer {
		servers = append(servers, s)
	}
	sort.Strings(servers)

	sent := map[string]bool{}
	for _, server := range servers {
		for account, ok := range c.deliverToServer(ctx, server, byServer[server]) {
			sent[account] = ok
		}
	}
	// A session built for a copy that never left has to go with it. The peer
	// never saw the prekey block, so keeping it would mean every later message
	// to them is encrypted into a session they cannot open -- silently, and for
	// good. Only the establishment is undone; an advance on a session they
	// already hold is left, because other copies rode on it.
	for _, copy := range copies {
		if copy.established && !sent[copy.member.AccountID] {
			if err := c.DeleteSession(copy.member.AccountID, Sending); err != nil {
				return deliveries, err
			}
		}
	}
	for i := range deliveries {
		if deliveries[i].State != SendPending {
			continue
		}
		if sent[deliveries[i].AccountID] {
			deliveries[i].State = SendSent
		} else {
			deliveries[i].State = SendFailed
			// A member who did not get this copy has also not heard whatever
			// facts rode with it, so they are owed the whole set.
			if err := c.oweGroupSnapshot(groupID, deliveries[i].AccountID); err != nil {
				return deliveries, err
			}
		}
	}
	return deliveries, nil
}

// prepareCopy resolves one member's device and encrypts for them, persisting
// the advanced session before returning.
func (c *Client) prepareCopy(ctx context.Context, m group.Member, ownServer string, plaintext []byte) (preparedCopy, error) {
	server := m.Server
	if server == ownServer {
		// Our own server is addressed as "no server": that emptiness is what
		// selects the local route rather than the federated one.
		server = ""
	}
	endpoint, err := c.endpointOn(ctx, m.AccountID, server)
	if err != nil {
		return preparedCopy{}, err
	}

	unlock := c.lockPeer(m.AccountID)
	defer unlock()

	session, err := c.Session(m.AccountID, Sending)
	if err != nil {
		return preparedCopy{}, err
	}
	var initial *ratchet.InitialMessage
	if session == nil {
		bundle, err := c.ClaimBundle(ctx, endpoint)
		if err != nil {
			return preparedCopy{}, err
		}
		dhPriv, err := c.dhIdentityKey()
		if err != nil {
			return preparedCopy{}, err
		}
		if session, initial, err = ratchet.InitiateSession(dhPriv, bundle.RemoteBundle); err != nil {
			return preparedCopy{}, fmt.Errorf("client: establishing a session with %s: %w", m.AccountID, err)
		}
	}

	header, ciphertext, err := session.Encrypt(plaintext)
	if err != nil {
		return preparedCopy{}, fmt.Errorf("client: encrypting for %s: %w", m.AccountID, err)
	}
	var rekey *bool
	if initial != nil {
		no := false
		rekey = &no
	}
	payload, err := wire.NewEnvelopeRekey(initial, header, ciphertext, rekey).MarshalPayload()
	if err != nil {
		return preparedCopy{}, fmt.Errorf("client: building envelope for %s: %w", m.AccountID, err)
	}
	// Persisted before anything is posted, and deliberately not rolled back if
	// the post fails: see fanOut.
	if err := c.SetSession(m.AccountID, Sending, session); err != nil {
		return preparedCopy{}, err
	}

	messageID, err := newMessageID()
	if err != nil {
		return preparedCopy{}, err
	}
	return preparedCopy{
		member: m, endpoint: endpoint, messageID: messageID,
		payload: payload, established: initial != nil,
	}, nil
}

// deliverToServer posts every copy bound for one server, in one batch where
// that server takes them. Returns which accounts were delivered to.
func (c *Client) deliverToServer(ctx context.Context, server string, copies []preparedCopy) map[string]bool {
	sent := make(map[string]bool, len(copies))

	batchSize := 1
	if len(copies) > 1 {
		if status, err := c.ServerStatus(ctx, server); err == nil && status.BatchMessages {
			batchSize = status.MaxBatchMessages
			if batchSize <= 0 {
				batchSize = 1
			}
		}
		// An older server has no such field and the documented fallback is one
		// post per message, which is why groups already work against every
		// server in the field.
	}

	if batchSize > 1 {
		for start := 0; start < len(copies); start += batchSize {
			end := min(start+batchSize, len(copies))
			for account, ok := range c.sendBatch(ctx, server, copies[start:end]) {
				sent[account] = ok
			}
		}
		return sent
	}
	for _, copy := range copies {
		sent[copy.member.AccountID] = c.postEnvelope(ctx, copy.endpoint, copy.messageID, copy.payload) == nil
	}
	return sent
}

// sendBatch posts several copies in one request, falling back to one at a time
// if the server refuses the batch outright.
func (c *Client) sendBatch(ctx context.Context, server string, copies []preparedCopy) map[string]bool {
	sent := make(map[string]bool, len(copies))

	items := make([]map[string]any, 0, len(copies))
	for _, copy := range copies {
		items = append(items, map[string]any{
			"message_id":          copy.messageID,
			"recipient_device_id": copy.endpoint.DeviceID,
			"payload":             copy.payload,
		})
	}

	req := request{method: http.MethodPost, path: "/v1/messages/batch", auth: authDevice}
	body := map[string]any{"messages": items}
	if server != "" {
		id, err := c.Identity()
		if err != nil {
			return sent
		}
		cert, err := signDeviceCert(id, time.Now().UTC())
		if err != nil {
			return sent
		}
		req.server = server
		req.auth = authFederated
		req.path = "/v1/federation/messages/batch"
		body = map[string]any{
			"sender_account_id":   id.AccountID,
			"sender_root_pub_key": base64.StdEncoding.EncodeToString(id.RootPub),
			"sender_device_cert":  cert,
			"messages":            items,
		}
	}
	req.body = body

	var resp struct {
		Results []struct {
			MessageID string `json:"message_id"`
			Status    string `json:"status"`
		} `json:"results"`
	}
	if err := c.do(ctx, req, &resp); err != nil {
		// The batch as a whole was refused -- an older server, or one that
		// stopped accepting them. Falling back one at a time is what keeps a
		// group working against a server that changed under us.
		for _, copy := range copies {
			sent[copy.member.AccountID] = c.postEnvelope(ctx, copy.endpoint, copy.messageID, copy.payload) == nil
		}
		return sent
	}

	byMessage := map[string]string{}
	for _, r := range resp.Results {
		byMessage[r.MessageID] = r.Status
	}
	for _, copy := range copies {
		status, answered := byMessage[copy.messageID]
		// A per-item status the server did not report is treated as delivered:
		// it accepted the batch, and inventing a failure would re-send a copy
		// the recipient already has.
		sent[copy.member.AccountID] = !answered || status == "accepted" || status == "duplicate"
		if answered && IsStaleRecipientStatus(status) {
			// Their device is gone. Forget it so the next attempt re-resolves
			// rather than failing against the same dead id forever.
			_ = c.ForgetPeerDevice(copy.member.AccountID)
		}
	}
	return sent
}

// BroadcastGroupEvents tells every member about new facts.
//
// skip names members who already have them -- an invitee who was just sent the
// whole set, typically. A member who cannot be reached is owed a snapshot
// rather than forgotten: the fact must not be lost with one failed attempt.
func (c *Client) BroadcastGroupEvents(ctx context.Context, groupID string, events []*group.Event, skip ...string) error {
	membership, err := c.GroupMembership(groupID)
	if err != nil || membership == nil {
		return err
	}
	id, err := c.Identity()
	if err != nil {
		return err
	}
	skipped := map[string]bool{id.AccountID: true}
	for _, s := range skip {
		skipped[s] = true
	}

	plaintext, err := encodeGroupControl(GroupEvents, groupID, membership.StateHash, events)
	if err != nil {
		return err
	}
	for _, m := range membership.Members {
		if skipped[m.AccountID] {
			continue
		}
		if err := c.sendGroupControl(ctx, m, id.Server, plaintext); err != nil {
			if oweErr := c.oweGroupSnapshot(groupID, m.AccountID); oweErr != nil {
				return oweErr
			}
		}
	}
	return nil
}

// SendGroupSnapshot hands one member the whole fact set.
//
// The answer to every kind of divergence, because the fold is order
// independent and a fact already known is simply known -- so reconciling two
// views never needs a delta protocol, a version vector or a sequencer.
func (c *Client) SendGroupSnapshot(ctx context.Context, groupID, toAccountID string) error {
	st, err := c.GroupState(groupID)
	if err != nil || st == nil {
		return err
	}
	membership := st.Resolve()
	member := memberOf(membership, toAccountID)
	if member == nil {
		return fmt.Errorf("client: %s is not a member of group %s", toAccountID, groupID)
	}
	id, err := c.Identity()
	if err != nil {
		return err
	}
	plaintext, err := encodeGroupControl(GroupSnapshot, groupID, membership.StateHash, st.Events())
	if err != nil {
		return err
	}
	if err := c.sendGroupControl(ctx, *member, id.Server, plaintext); err != nil {
		return err
	}
	return c.clearGroupSnapshotDebt(groupID, toAccountID)
}

// ReconcileGroup acts on what a group envelope said about the sender's view.
//
// Three cases, and the first is the one that is easy to miss: we hold no facts
// at all. Nothing tells the sender that -- our own hash only travels on
// messages we cannot send without a member list -- so the state would end only
// if some member happened to send a snapshot unprompted. Asking outright is the
// only way out, and the sender is the one member we know exists, because they
// just wrote to us.
func (c *Client) ReconcileGroup(ctx context.Context, outcome GroupOutcome, peerAccountID string) error {
	if outcome.GroupID == "" {
		return nil
	}
	st, err := c.GroupState(outcome.GroupID)
	if err != nil {
		return err
	}
	if st == nil {
		return c.AskForGroupFacts(ctx, outcome.GroupID, peerAccountID, "")
	}
	membership := st.Resolve()

	if !outcome.WantsSnapshot {
		if outcome.PeerStateHash == "" || outcome.PeerStateHash == membership.StateHash {
			return nil
		}
		// Answer any one foreign hash at most once, so two peers that stay
		// divergent for a reason a snapshot cannot fix do not trade snapshots
		// forever. Persisted rather than kept for the run: a restart would
		// otherwise re-open exactly that loop.
		answered, err := c.markGroupHashAnswered(outcome.GroupID, peerAccountID, outcome.PeerStateHash)
		if err != nil || answered {
			return err
		}
	}

	if memberOf(membership, peerAccountID) == nil {
		// Somebody who is not in the group asking about it gets nothing.
		return nil
	}
	if err := c.SendGroupSnapshot(ctx, outcome.GroupID, peerAccountID); err != nil {
		// They asked, or their hash said they need it: owe it to them, so the
		// answer is not lost with this one attempt.
		return c.oweGroupSnapshot(outcome.GroupID, peerAccountID)
	}
	return nil
}

// AskForGroupFacts sends a sync request to one member.
//
// Rate limited per group rather than per member: the point is to get the facts
// once, and a group whose every member writes would otherwise produce a request
// per message.
func (c *Client) AskForGroupFacts(ctx context.Context, groupID, peerAccountID, peerServer string) error {
	asked, err := c.markGroupSyncRequested(groupID, time.Now().UTC())
	if err != nil || asked {
		return err
	}
	id, err := c.Identity()
	if err != nil {
		return err
	}
	if peerServer == "" {
		if convo, err := c.Conversation(peerAccountID); err == nil && convo != nil {
			peerServer = convo.PeerServer
		}
	}
	plaintext, err := encodeGroupControl(GroupSyncRequest, groupID, "", nil)
	if err != nil {
		return err
	}
	return c.sendGroupControl(ctx, group.Member{AccountID: peerAccountID, Server: peerServer}, id.Server, plaintext)
}

// PayGroupSnapshotDebts sends the fact set to everyone owed one. Returns how
// many debts were settled.
func (c *Client) PayGroupSnapshotDebts(ctx context.Context) (int, error) {
	groups, err := c.Groups()
	if err != nil {
		return 0, err
	}
	var paid int
	for _, groupID := range groups {
		peers, err := c.groupPeersFor(groupID)
		if err != nil {
			return paid, err
		}
		owed := make([]string, 0, len(peers.Owed))
		for account := range peers.Owed {
			owed = append(owed, account)
		}
		sort.Strings(owed)

		membership, err := c.GroupMembership(groupID)
		if err != nil {
			return paid, err
		}
		for _, account := range owed {
			if membership == nil || memberOf(membership, account) == nil {
				// Not a member any more: nothing to pay, and the debt would
				// otherwise be retried on every reconnect forever.
				if err := c.clearGroupSnapshotDebt(groupID, account); err != nil {
					return paid, err
				}
				continue
			}
			if err := c.SendGroupSnapshot(ctx, groupID, account); err != nil {
				// Still unreachable. The debt stays, to be tried again on the
				// next reconnect -- uncapped, unlike a failed message, because
				// a member who never gets the facts is a member who can never
				// take part.
				continue
			}
			paid++
		}
	}
	return paid, nil
}

// SendGroupReceipt tells one member how far we have got with *their* messages
// in a group.
//
// Sent to the author alone and never re-broadcast: who has read what stays
// between reader and author. That is also why the receipt carries the group id
// -- without it the author would file it against their one-to-one chat with us
// and confirm messages we never mentioned.
func (c *Client) SendGroupReceipt(ctx context.Context, groupID, toAccountID string, status ReceiptStatus, upTo time.Time) error {
	if status != ReceiptDelivered && status != ReceiptRead {
		return fmt.Errorf("client: unknown receipt status %q", status)
	}
	membership, err := c.GroupMembership(groupID)
	if err != nil || membership == nil {
		return err
	}
	member := memberOf(membership, toAccountID)
	if member == nil {
		return nil
	}
	id, err := c.Identity()
	if err != nil {
		return err
	}
	plaintext, err := json.Marshal(map[string]any{
		"v": versionReceipt, "kind": "receipt",
		"status": string(status), "up_to_sent_at": upTo.UTC().Format(receiptTimeLayout),
		"group_id": groupID,
	})
	if err != nil {
		return fmt.Errorf("client: encoding group receipt: %w", err)
	}
	return c.sendGroupControl(ctx, *member, id.Server, plaintext)
}

// sendGroupControl encrypts one plaintext for one member and posts it.
func (c *Client) sendGroupControl(ctx context.Context, m group.Member, ownServer string, plaintext []byte) error {
	blocked, err := c.IsPeerBlocked(m.AccountID)
	if err != nil {
		return err
	}
	if blocked {
		return ErrPeerBlocked
	}
	copy, err := c.prepareCopy(ctx, m, ownServer, plaintext)
	if err != nil {
		return err
	}
	if err := c.postEnvelope(ctx, copy.endpoint, copy.messageID, copy.payload); err != nil {
		// Same rule as in fanOut: a session the peer never saw established is
		// worse than no session at all, because every later message would be
		// encrypted into one they cannot open.
		if copy.established {
			if rollback := c.DeleteSession(m.AccountID, Sending); rollback != nil {
				return rollback
			}
		}
		return err
	}
	return nil
}

// uploadForGroup uploads one blob granted to every recipient's device.
func (c *Client) uploadForGroup(ctx context.Context, recipients []group.Member, media OutgoingMedia) (Attachment, error) {
	id, err := c.Identity()
	if err != nil {
		return Attachment{}, err
	}
	endpoints := make([]PeerEndpoint, 0, len(recipients))
	for _, m := range recipients {
		server := m.Server
		if server == id.Server {
			server = ""
		}
		endpoint, err := c.endpointOn(ctx, m.AccountID, server)
		if err != nil {
			// A member whose device cannot be resolved cannot be granted the
			// blob. They still get the caption, which is better than nobody
			// getting the picture.
			continue
		}
		endpoints = append(endpoints, endpoint)
	}
	if len(endpoints) == 0 {
		return Attachment{}, fmt.Errorf("client: no reachable recipient for the attachment")
	}
	return c.UploadAttachment(ctx, endpoints, media)
}

func (c *Client) dhIdentityKey() (*ecdh.PrivateKey, error) {
	id, err := c.Identity()
	if err != nil {
		return nil, err
	}
	key, err := ecdh.X25519().NewPrivateKey(id.DHIdentityPriv)
	if err != nil {
		return nil, fmt.Errorf("client: reading own identity key: %w", err)
	}
	return key, nil
}

// joinedMembers is everyone a message goes to: joined, and not us.
//
// An invitee is deliberately excluded. Nothing is sent into a group before
// somebody accepts -- being added must not disclose the group's traffic to
// them, nor their address to the group, before they have agreed to be in it.
func joinedMembers(r *group.Resolved, except string) []group.Member {
	out := make([]group.Member, 0, len(r.Members))
	for _, m := range r.Members {
		if m.AccountID == except || !m.Joined {
			continue
		}
		out = append(out, m)
	}
	return out
}

func encodeGroupText(line Message, groupID, stateHash string, sentAt time.Time) ([]byte, error) {
	body := map[string]any{
		"v": versionGroupText, "group_id": groupID, "state_hash": stateHash,
		"id": line.ID, "text": line.Text,
		"sent_at": sentAt.UTC().Format(receiptTimeLayout),
	}
	if line.ReplyToID != "" {
		body["reply_to"] = line.ReplyToID
		preview := map[string]any{"text": line.ReplyPreviewText}
		if line.ReplyPreviewMine != nil {
			preview["mine"] = *line.ReplyPreviewMine
		}
		if line.ReplyPreviewAuthorID != "" {
			preview["author"] = line.ReplyPreviewAuthorID
		}
		body["reply_preview"] = preview
	}
	if wires := attachmentWires(line.Attachments); len(wires) > 0 {
		body["attachments"] = wires
	}
	out, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("client: encoding group message %s: %w", line.ID, err)
	}
	return out, nil
}

func encodeGroupControl(kind GroupControlKind, groupID, stateHash string, events []*group.Event) ([]byte, error) {
	body := map[string]any{
		"v": versionGroupControl, "kind": string(kind), "group_id": groupID,
	}
	if stateHash != "" {
		body["state_hash"] = stateHash
	}
	if len(events) > 0 {
		body["events"] = events
	}
	out, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("client: encoding group control: %w", err)
	}
	return out, nil
}

func (c *Client) recordDeliveries(groupID, messageID string, deliveries []GroupDelivery) error {
	for _, d := range deliveries {
		if err := c.SetGroupDeliveryState(groupID, messageID, d.AccountID, d.State); err != nil {
			return err
		}
	}
	return nil
}
