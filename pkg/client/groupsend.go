package client

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	now = receiptClock(now)

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
		// The sender's own line keeps the placeholder rather than an uploaded
		// reference: with a blob per recipient server there is no single id
		// that would be true for the whole message, and this device renders
		// the picture from the file it just wrote either way.
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

	// One upload per recipient server, and the reference each member gets for
	// their own -- a blob id is only meaningful where it was stored.
	var references map[string]Attachment
	if opts.Media != nil {
		references, err = c.uploadForGroup(ctx, recipients, *opts.Media)
		if err != nil {
			if markErr := c.SetMessageSendState(groupID, messageID, SendFailed); markErr != nil {
				return res, fmt.Errorf("%w (and marking it failed: %v)", err, markErr)
			}
			return res, err
		}
	}

	encode, err := groupPlaintextFor(line, groupID, membership.StateHash, now, references)
	if err != nil {
		return res, err
	}
	// No prior wire ids: nothing has been posted for this message yet.
	deliveries, err := c.fanOut(ctx, groupID, encode, recipients, nil)
	if err != nil {
		return res, err
	}
	markAttachmentSkipped(deliveries, opts.Media != nil, references)
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

// RetryGroupMessage re-sends a group message whose send failed, addressing
// only the members whose copy never arrived.
//
// Mirrors [Client.RetryMessage]'s shape and for the same reason: an attachment
// that never made it to the server is re-uploaded, one that did is simply
// named again, and the message must already be recorded [SendFailed]. It
// deliberately does not go back to everyone -- a member whose delivery is
// already [SendSent] is not revisited, or a retry would duplicate the text
// for whoever already has it. That is also why fanOut's own de-duplication
// (an advance is only persisted once the copy has actually gone out) is
// enough here too: a second attempt re-encrypts under the same message
// number, and a recipient who did receive the first copy recognises the
// retry as the duplicate it is.
//
// A member who joined after the original attempt is not retroactively sent
// it: they have no delivery record for this message at all, so they are
// never in the retried set -- joining grants no access to what was said
// before, and a retry is not an exception to that.
func (c *Client) RetryGroupMessage(ctx context.Context, groupID, messageID string) (SendResult, error) {
	msgs, err := c.Messages(groupID)
	if err != nil {
		return SendResult{}, err
	}
	var line *Message
	for i := range msgs {
		if msgs[i].ID == messageID {
			line = &msgs[i]
			break
		}
	}
	if line == nil {
		return SendResult{}, fmt.Errorf("client: no message %s in group %s", messageID, groupID)
	}
	// Unlike the one-to-one path, a group message's own SendState is not the
	// right gate: "delivered to somebody" already makes it [SendSent] (see
	// SendGroupText), so a partial failure looks exactly like success at that
	// granularity. Retryability is a per-delivery question, decided below from
	// which members are not yet [SendSent] -- the caller's own view of the
	// message (client-side, StoredMessage.aggregateSendState) already reads it
	// the same way.
	if line.SendState == SendPending {
		return SendResult{}, fmt.Errorf("client: message %s is still sending", messageID)
	}

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

	joined := map[string]group.Member{}
	for _, m := range joinedMembers(membership, id.AccountID) {
		joined[m.AccountID] = m
	}
	var recipients []group.Member
	for i := range line.Deliveries {
		d := &line.Deliveries[i]
		if d.State == SendSent {
			continue
		}
		m, owed := joined[d.AccountID]
		if !owed {
			// Not a member this device knows to be in the group any more --
			// removed, gone, or an accept that never reached these facts. Their
			// copy is no longer owed, and sending it would be group traffic to
			// somebody outside the group.
			//
			// Settled here rather than left alone, because a delivery no retry
			// will ever address again is a failure with no way out: the caller
			// reads the message's state off these records (see
			// StoredMessage.aggregateSendState), so one stuck copy means a
			// permanently failed message and a retry button that does nothing
			// however often it is pressed.
			d.State = SendSent
			d.Error = ""
			if err := c.SetGroupDelivery(groupID, messageID, *d); err != nil {
				return SendResult{}, err
			}
			continue
		}
		recipients = append(recipients, m)
	}
	if len(recipients) == 0 {
		// Every recorded delivery already succeeded, or every member who was
		// behind has since left -- in which case the loop above has just
		// settled their records, so this really is nothing left to send rather
		// than a failure being papered over. Report it as sent rather than
		// doing nothing silently.
		if err := c.SetMessageSendState(groupID, messageID, SendSent); err != nil {
			return SendResult{}, err
		}
		line.SendState = SendSent
		return SendResult{Message: *line}, nil
	}

	// A picture goes up again for whoever is being retried.
	//
	// Always, rather than only when the first attempt never uploaded: since a
	// group's blob is per recipient server there is no single id for the
	// message to have kept, so the sender's own line holds the placeholder and
	// the bytes on disk are the record. Re-uploading for a server that already
	// has a copy leaves one blob nobody references, which the server can
	// collect -- cheaper than remembering an id per server to save an upload
	// that only happens after a failure anyway.
	var references map[string]Attachment
	if len(line.Attachments) == 1 && line.Attachments[0].BlobID == "" {
		bytes, err := c.AttachmentFile(groupID, messageID)
		if err != nil {
			return SendResult{}, err
		}
		if bytes == nil {
			// Composed on a device that no longer has the file, or cleared since.
			// Sending the caption alone would deliver something the user never
			// wrote.
			return SendResult{}, ErrAttachmentNotResendable
		}
		placeholder := line.Attachments[0]
		// Re-uploaded for the servers of the members this attempt addresses,
		// not for the whole group: the ones who already have their copy are
		// not revisited, and their blob is on their own server regardless.
		references, err = c.uploadForGroup(ctx, recipients, OutgoingMedia{
			Bytes: bytes, MimeType: placeholder.MimeType, Kind: placeholder.Kind,
			Width: placeholder.Width, Height: placeholder.Height, Thumb: placeholder.Thumb,
		})
		if err != nil {
			return SendResult{}, err
		}
	}

	if err := c.SetMessageSendState(groupID, messageID, SendPending); err != nil {
		return SendResult{}, err
	}
	res := SendResult{Message: *line}

	encode, err := groupPlaintextFor(*line, groupID, membership.StateHash, line.Timestamp, references)
	if err != nil {
		return res, err
	}
	// Each retried member's copy goes out under the id their first attempt
	// used, so their server recognises it as the duplicate it is rather than
	// delivering the message to them a second time.
	wireIDs := make(map[string]string, len(line.Deliveries))
	for _, d := range line.Deliveries {
		if d.WireMessageID != "" {
			wireIDs[d.AccountID] = d.WireMessageID
		}
	}
	deliveries, err := c.fanOut(ctx, groupID, encode, recipients, wireIDs)
	if err != nil {
		if markErr := c.SetMessageSendState(groupID, messageID, SendFailed); markErr != nil {
			return res, errors.Join(err, markErr)
		}
		return res, err
	}
	markAttachmentSkipped(deliveries, references != nil, references)
	if err := c.recordDeliveries(groupID, messageID, deliveries); err != nil {
		return res, err
	}

	// Merged in the transcript's own order, deliberately not the map iteration
	// order fanOut returns: a member already [SendSent] keeps that record
	// untouched, a retried member takes whatever this attempt produced.
	byAccount := make(map[string]GroupDelivery, len(deliveries))
	for _, d := range deliveries {
		byAccount[d.AccountID] = d
	}
	final := make([]GroupDelivery, len(line.Deliveries))
	state := SendFailed
	for i, d := range line.Deliveries {
		if updated, ok := byAccount[d.AccountID]; ok {
			final[i] = updated
		} else {
			final[i] = d
		}
		if final[i].State == SendSent {
			state = SendSent
		}
	}
	res.Message.Deliveries = final
	if err := c.SetMessageSendState(groupID, messageID, state); err != nil {
		return res, err
	}
	res.Message.SendState = state
	return res, nil
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
// plaintextFor gives one member's copy of a message. Per member rather than
// one shared blob of bytes because a picture is stored per recipient server
// (see uploadForGroup): everything else in the copy is identical, and the
// attachment reference cannot be.
type plaintextFor func(m group.Member) ([]byte, error)

// groupPlaintextFor encodes line for each member, giving each the attachment
// reference minted for their own server.
//
// With no picture -- or with an already-uploaded one carried in line, which is
// the [Client.SendGroupText] caller that passes Attachments rather than Media
// -- every copy is identical and encoded once. A member with no reference is
// sent the message without an attachment at all rather than with one they
// cannot fetch: they see the text, and their delivery says the picture was
// skipped.
func groupPlaintextFor(
	line Message,
	groupID, stateHash string,
	sentAt time.Time,
	references map[string]Attachment,
) (plaintextFor, error) {
	if references == nil {
		plaintext, err := encodeGroupText(line, groupID, stateHash, sentAt)
		if err != nil {
			return nil, err
		}
		return func(group.Member) ([]byte, error) { return plaintext, nil }, nil
	}

	// Encoded once per member, but cached by account id: a retry addresses a
	// subset of the same people, and two members on one server share a
	// reference and therefore a copy.
	cache := map[string][]byte{}
	return func(m group.Member) ([]byte, error) {
		if plaintext, ok := cache[m.AccountID]; ok {
			return plaintext, nil
		}
		theirs := line
		if reference, ok := references[m.AccountID]; ok {
			theirs.Attachments = []Attachment{reference}
		} else {
			theirs.Attachments = nil
		}
		plaintext, err := encodeGroupText(theirs, groupID, stateHash, sentAt)
		if err != nil {
			return nil, err
		}
		cache[m.AccountID] = plaintext
		return plaintext, nil
	}, nil
}

// markAttachmentSkipped records, per member, that they got the caption but not
// the picture.
//
// Not a delivery failure and never retried: the message itself arrived, and a
// copy that counts as sent is never revisited -- so this is a statement of
// fact for the sender to read, which is exactly what
// [GroupDelivery.AttachmentSkipped] is for.
func markAttachmentSkipped(deliveries []GroupDelivery, hadMedia bool, references map[string]Attachment) {
	if !hadMedia {
		return
	}
	for i := range deliveries {
		if _, granted := references[deliveries[i].AccountID]; !granted {
			deliveries[i].AttachmentSkipped = true
		}
	}
}

func (c *Client) fanOut(
	ctx context.Context,
	groupID string,
	encode plaintextFor,
	recipients []group.Member,
	wireIDs map[string]string,
) ([]GroupDelivery, error) {
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
		plaintext, err := encode(m)
		if err != nil {
			return nil, err
		}
		copy, err := c.prepareCopy(ctx, m, id.Server, plaintext, wireIDs[m.AccountID])
		if err != nil {
			// Never even encrypted: their device could not be resolved, or no
			// session could be built. Worth saying so, since it is a different
			// problem from a copy the network lost.
			deliveries = append(deliveries, GroupDelivery{
				AccountID: m.AccountID, State: SendFailed,
				Error: fmt.Sprintf("preparing their copy: %v", err),
			})
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

	// nil for a copy the recipient's server took, the refusal itself otherwise.
	// Every prepared copy has an entry, which is what lets a missing one below
	// be treated as a failure rather than read as success.
	posted := map[string]error{}
	for _, server := range servers {
		for account, err := range c.deliverToServer(ctx, server, byServer[server]) {
			posted[account] = err
		}
	}
	sent := func(account string) bool {
		err, attempted := posted[account]
		return attempted && err == nil
	}
	// A session built for a copy that never left has to go with it. The peer
	// never saw the prekey block, so keeping it would mean every later message
	// to them is encrypted into a session they cannot open -- silently, and for
	// good. Only the establishment is undone; an advance on a session they
	// already hold is left, because other copies rode on it.
	for _, copy := range copies {
		if copy.established && !sent(copy.member.AccountID) {
			if err := c.DeleteSession(copy.member.AccountID, Sending); err != nil {
				return deliveries, err
			}
		}
	}
	for i := range deliveries {
		if deliveries[i].State != SendPending {
			continue
		}
		account := deliveries[i].AccountID
		if sent(account) {
			deliveries[i].State = SendSent
			// Cleared, not left: this copy is no longer failing, and a reason
			// that outlives its failure is worse than none.
			deliveries[i].Error = ""
			continue
		}
		deliveries[i].State = SendFailed
		deliveries[i].Error = postFailureReason(posted, account)
		// A member who did not get this copy has also not heard whatever
		// facts rode with it, so they are owed the whole set.
		if err := c.oweGroupSnapshot(groupID, account); err != nil {
			return deliveries, err
		}
	}
	return deliveries, nil
}

// postFailureReason phrases why one prepared copy did not arrive.
func postFailureReason(posted map[string]error, account string) string {
	err, attempted := posted[account]
	switch {
	case !attempted:
		// Their copy was encrypted and then never handed to a server at all.
		// Should not happen -- every prepared copy is passed to deliverToServer
		// -- so say that rather than inventing a network error.
		return "their copy was prepared but never posted"
	case err == nil:
		return "posting their copy failed for no stated reason"
	default:
		return fmt.Sprintf("posting their copy: %v", err)
	}
}

// prepareCopy resolves one member's device and encrypts for them, persisting
// the advanced session before returning.
// wireID is the id this recipient's copy is posted under, empty for a first
// attempt. Reusing the one a previous attempt recorded is what makes a retry
// idempotent for them: their server de-duplicates by it and answers 409, which
// counts as delivered. Minting a fresh one instead delivers the same message a
// second time -- a second transcript line and a second notification, on every
// attempt.
func (c *Client) prepareCopy(ctx context.Context, m group.Member, ownServer string, plaintext []byte, wireID string) (preparedCopy, error) {
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

	if wireID == "" {
		if wireID, err = newMessageID(); err != nil {
			return preparedCopy{}, err
		}
	}
	return preparedCopy{
		member: m, endpoint: endpoint, messageID: wireID,
		payload: payload, established: initial != nil,
	}, nil
}

// deliverToServer posts every copy bound for one server, in one batch where
// that server takes them. Returns which accounts were delivered to.
func (c *Client) deliverToServer(ctx context.Context, server string, copies []preparedCopy) map[string]error {
	sent := make(map[string]error, len(copies))

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
			for account, err := range c.sendBatch(ctx, server, copies[start:end]) {
				sent[account] = err
			}
		}
		return sent
	}
	for _, copy := range copies {
		sent[copy.member.AccountID] = c.postEnvelope(ctx, copy.endpoint, copy.messageID, copy.payload)
	}
	return sent
}

// sendBatch posts several copies in one request, falling back to one at a time
// if the server refuses the batch outright.
func (c *Client) sendBatch(ctx context.Context, server string, copies []preparedCopy) map[string]error {
	sent := make(map[string]error, len(copies))

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
			return failAll(copies, fmt.Errorf("reading this device's identity: %w", err))
		}
		cert, err := signDeviceCert(id, time.Now().UTC())
		if err != nil {
			return failAll(copies, fmt.Errorf("signing this device's certificate: %w", err))
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
			sent[copy.member.AccountID] = c.postEnvelope(ctx, copy.endpoint, copy.messageID, copy.payload)
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
		switch {
		case !answered || IsDeliveredStatus(status):
			sent[copy.member.AccountID] = nil
		default:
			sent[copy.member.AccountID] = fmt.Errorf("their server answered %q", status)
		}
		if answered && IsStaleRecipientStatus(status) {
			// Their device is gone. Forget it so the next attempt re-resolves
			// rather than failing against the same dead id forever.
			_ = c.ForgetPeerDevice(copy.member.AccountID)
		}
	}
	return sent
}

// failAll blames one error on every copy in a batch that never left.
func failAll(copies []preparedCopy, err error) map[string]error {
	out := make(map[string]error, len(copies))
	for _, copy := range copies {
		out[copy.member.AccountID] = err
	}
	return out
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

// RequestGroupSync asks one member of a group we already hold facts about to
// send us the whole set.
//
// The active half of reconciliation, and the one easily left out: a state hash
// says "we differ", never who is behind, so a device that missed a fact finds
// out only when somebody next sends into the group -- and if that somebody is
// *us*, and we are the one behind, nothing happens at all. This asks outright.
// [Client.ReconcileGroup] covers only the case where there are no facts here
// whatsoever, which is a different and much louder failure.
//
// One member rather than all: the fact set is grow-only, so any member holds
// the whole of it and one answer is as good as ten -- where ten would put a
// snapshot in every member's queue each time somebody opens a group screen.
// The founder first because they are the one member who cannot have left, then
// anybody who has joined; a pending invitee may hold nothing yet.
//
// Asked only where there is reason to think we are behind, which is what
// keeps this from being pure traffic: a group everybody agrees about is left
// alone. See groupSyncWorthAsking -- the first version fired on every open,
// and on a device holding a dozen accounts that were members of the same
// group it turned each chat switch into a burst of envelopes to accounts on
// the same phone, every one of them costing the recipient a push wake.
//
// Best-effort by design: no debt is recorded and nothing is owed to anyone,
// because this asks for something we lack rather than sending something
// somebody else needs. The per-group cooldown is [AskForGroupFacts]'s.
func (c *Client) RequestGroupSync(ctx context.Context, groupID string) error {
	membership, err := c.GroupMembership(groupID)
	if err != nil || membership == nil {
		return err
	}
	if membership.Dissolved {
		// Nothing left to converge on, and nobody left who should answer.
		return nil
	}
	id, err := c.Identity()
	if err != nil {
		return err
	}
	target := syncTargetFor(membership, id.AccountID)
	if target == nil {
		return nil
	}
	worth, err := c.groupSyncWorthAsking(groupID, membership.StateHash)
	if err != nil || !worth {
		return err
	}
	return c.AskForGroupFacts(ctx, groupID, target.AccountID, target.Server)
}

// groupSyncWorthAsking reports whether anything suggests this device is behind
// on a group's facts.
//
// The evidence is the state hash each member last stated, which every group
// envelope carries and [Client.RecordGroupPeerStateHash] files. One that
// differs from ours means the two of us hold different fact sets -- it never
// says which of us is behind, which is exactly why asking is worth an envelope.
// Every member we have heard from agreeing with us means there is nothing to
// ask for, and the cheapest thing to send is nothing.
//
// Having heard from nobody counts as worth asking: a device that has just been
// set up, or a group nobody has spoken in since, is the case this exists for.
// The per-group cooldown is what keeps that from repeating.
func (c *Client) groupSyncWorthAsking(groupID, ours string) (bool, error) {
	if ours == "" {
		return true, nil
	}
	hashes, err := c.GroupPeerStateHashes(groupID)
	if err != nil {
		return false, err
	}
	if len(hashes) == 0 {
		return true, nil
	}
	for _, theirs := range hashes {
		if theirs != "" && theirs != ours {
			return true, nil
		}
	}
	return false, nil
}

// syncTargetFor picks the one member worth asking, or nil for a group with
// nobody else in it yet.
func syncTargetFor(r *group.Resolved, except string) *group.Member {
	var fallback *group.Member
	for i := range r.Members {
		m := &r.Members[i]
		if m.AccountID == except || !m.Joined {
			continue
		}
		if m.AccountID == r.Founder {
			return m
		}
		if fallback == nil {
			fallback = m
		}
	}
	return fallback
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
// gone names the members dropped because their account no longer exists, so a
// caller can say so once rather than leaving the user with a member row that
// never settles.
func (c *Client) PayGroupSnapshotDebts(ctx context.Context) (paid int, gone []string, err error) {
	groups, err := c.Groups()
	if err != nil {
		return 0, nil, err
	}
	for _, groupID := range groups {
		peers, err := c.groupPeersFor(groupID)
		if err != nil {
			return paid, gone, err
		}
		owed := make([]string, 0, len(peers.Owed))
		for account := range peers.Owed {
			owed = append(owed, account)
		}
		sort.Strings(owed)

		membership, err := c.GroupMembership(groupID)
		if err != nil {
			return paid, gone, err
		}
		for _, account := range owed {
			member := (*group.Member)(nil)
			if membership != nil {
				member = memberOf(membership, account)
			}
			if member == nil {
				// Not a member any more: nothing to pay, and the debt would
				// otherwise be retried on every reconnect forever.
				if err := c.clearGroupSnapshotDebt(groupID, account); err != nil {
					return paid, gone, err
				}
				continue
			}
			sendErr := c.SendGroupSnapshot(ctx, groupID, account)
			if sendErr == nil {
				paid++
				continue
			}
			// Still unreachable. The debt stays, to be tried again on the next
			// reconnect -- uncapped, unlike a failed message, because a member
			// who never gets the facts is a member who can never take part.
			//
			// Unless there is nobody left to reach. Nothing in a group's signed
			// facts can say "this account ceased to exist", so that one case
			// would be retried forever with no attempt that could ever succeed,
			// and the member row stays until a moderator removes it either way.
			absent, err := c.accountIsGone(ctx, member.Server, account)
			if err != nil || !absent {
				continue
			}
			if err := c.clearGroupSnapshotDebt(groupID, account); err != nil {
				return paid, gone, err
			}
			gone = append(gone, account)
		}
	}
	return paid, gone, nil
}

// accountIsGone asks the server that would hold an account whether it still
// knows it.
//
// Asked rather than inferred from the failure, and that distinction is the
// whole of it. A 404 does not say what was missing: this server answers the
// catch-all `not_found` for an unknown account and for an unknown device
// alike, and reading the second as the first would drop a debt for a member
// who had merely replaced their phone -- silently, permanently, and exactly
// where the code above is careful never to give up. The account endpoint's own
// 404 is unambiguous, so it is worth the one request, and only ever on a path
// that has already failed.
//
// An account that exists but has no usable device is not gone: ResolvePeer
// says so with an error of its own rather than a 404, and that keeps the debt.
func (c *Client) accountIsGone(ctx context.Context, server, accountID string) (bool, error) {
	id, err := c.Identity()
	if err != nil {
		return false, err
	}
	if server == id.Server {
		// Our own server is addressed as "no server", the same emptiness the
		// send path uses to choose the local route.
		server = ""
	}
	if _, err := c.ResolvePeer(ctx, accountID, server); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// SendGroupReceipt tells one member how far we have got with *their* messages
// in a group.
//
// Sent to the author alone and never re-broadcast: who has read what stays
// between reader and author. That is also why the receipt carries the group id
// -- without it the author would file it against their one-to-one chat with us
// and confirm messages we never mentioned.
//
// upTo is a cumulative watermark in the *author's* clock, so confirming their
// newest message confirms every earlier one they wrote: one marker per member
// answers for the whole transcript, and nothing has to be tracked per message.
// One that would say nothing new is skipped entirely, since opening a group
// twice must not cost a second round of receipts -- see [Client.SendReceipt],
// which follows the same rule for a one-to-one conversation.
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
	upTo = upTo.UTC()

	chat, err := c.GroupChat(groupID)
	if err != nil {
		return err
	}
	if chat != nil {
		receipt := chat.MemberReceipts[toAccountID]
		if sent := sentReceiptUpTo(receipt, status); sent != nil && !upTo.After(*sent) {
			return nil
		}
	}

	plaintext, err := json.Marshal(map[string]any{
		"v": versionReceipt, "kind": "receipt",
		"status": string(status), "up_to_sent_at": upTo.Format(receiptTimeLayout),
		"group_id": groupID,
	})
	if err != nil {
		return fmt.Errorf("client: encoding group receipt: %w", err)
	}
	if err := c.sendGroupControl(ctx, *member, id.Server, plaintext); err != nil {
		return err
	}

	// Re-read rather than write back the copy loaded above: the receive loop
	// files *their* watermarks into the same record, from another goroutine,
	// and the send in between is a network call -- long enough to lose one.
	if chat, err = c.GroupChat(groupID); err != nil {
		return err
	}
	if chat == nil {
		// Nothing to record it against, and minting a chat for a group with no
		// transcript would invent one. The receipt still went out.
		return nil
	}

	// Recorded only once it is actually gone. A receipt recorded as sent but
	// never delivered is never re-sent, and the author's ticks stay wrong for
	// good.
	receipt := chat.MemberReceipts[toAccountID]
	at := upTo
	switch status {
	case ReceiptDelivered:
		receipt.SentDeliveredReceiptUpTo = &at
	case ReceiptRead:
		receipt.SentReadReceiptUpTo = &at
	}
	if chat.MemberReceipts == nil {
		chat.MemberReceipts = map[string]MemberReceipt{}
	}
	chat.MemberReceipts[toAccountID] = receipt
	return c.PutGroupChat(*chat)
}

// sentReceiptUpTo is how far this member has already been told, for status.
func sentReceiptUpTo(receipt MemberReceipt, status ReceiptStatus) *time.Time {
	if status == ReceiptRead {
		return receipt.SentReadReceiptUpTo
	}
	return receipt.SentDeliveredReceiptUpTo
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
	// A fresh id every time: a control envelope carries no transcript line, so
	// there is nothing for a recipient to receive twice.
	copy, err := c.prepareCopy(ctx, m, ownServer, plaintext, "")
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

// uploadForGroup uploads the picture once per recipient *server* and returns
// the reference each member is to be sent, by account id.
//
// A blob id means nothing off the server that minted it, so a group spanning
// servers cannot share one: the members on each server are granted a blob
// stored there, and every member is sent the reference for their own. One
// upload per server rather than per member is what SRV-18 buys -- a group of
// twenty on two servers costs two uploads, not twenty.
//
// A member missing from the result gets the caption without the picture, which
// is why nothing here is an error: their device would not resolve, or their
// server would not take the blob. One member's server refusing pictures must
// not decide what the rest of the group receives.
func (c *Client) uploadForGroup(ctx context.Context, recipients []group.Member, media OutgoingMedia) (map[string]Attachment, error) {
	id, err := c.Identity()
	if err != nil {
		return nil, err
	}

	// Grouped by the endpoint's own server string rather than the fact set's:
	// endpointOn fills a blank in from the device cache, so the same server can
	// arrive spelled two ways, and the upload has to agree with whichever one
	// its members actually carry.
	byServer := map[string][]PeerEndpoint{}
	for _, m := range recipients {
		server := m.Server
		if server == id.Server {
			server = ""
		}
		endpoint, err := c.endpointOn(ctx, m.AccountID, server)
		if err != nil {
			continue
		}
		byServer[endpoint.Server] = append(byServer[endpoint.Server], endpoint)
	}
	if len(byServer) == 0 {
		return nil, fmt.Errorf("client: no reachable recipient for the attachment")
	}

	servers := make([]string, 0, len(byServer))
	for server := range byServer {
		servers = append(servers, server)
	}
	sort.Strings(servers)

	references := make(map[string]Attachment, len(recipients))
	for _, server := range servers {
		endpoints := byServer[server]
		// Encrypted afresh per server, deliberately: a distinct key per stored
		// object means the key that reached one server's members cannot open
		// another server's copy.
		uploaded, err := c.UploadAttachment(ctx, endpoints, media)
		if err != nil {
			continue
		}
		for _, endpoint := range endpoints {
			references[endpoint.AccountID] = uploaded
		}
	}
	if len(references) == 0 {
		return nil, fmt.Errorf("client: no server would store the attachment")
	}
	return references, nil
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
		if err := c.SetGroupDelivery(groupID, messageID, d); err != nil {
			return err
		}
	}
	return nil
}
