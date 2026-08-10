package client

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/ratchet"
	"github.com/behringer24/freizone-server/pkg/wire"
)

// The send path: turning something to say into an envelope somebody else's
// device can open.
//
// The asymmetry with the receive path is worth stating, because it drives
// nearly every decision here. Receiving is forgiving -- an envelope that
// cannot be read can be retried, and the ratchet refuses to move until one
// works. Sending is not: encrypting *advances* the ratchet, and an advance
// committed for a message the peer never received burns a message number they
// will never see used. They observe a gap, which their ratchet bridges only so
// far before it counts as a desync. So the rule that shapes this file is that
// no advance is kept unless the envelope carrying it left the building.

// ErrFederationDisabled reports a send to another server from an account whose
// own server has federation switched off. Blocking it here rather than letting
// the POST fail is the honest thing: replies are blocked inbound too, so the
// conversation is a dead end in both directions and saying so early is better
// than a message that sits failed with a network error.
var ErrFederationDisabled = errors.New("client: this server has federation switched off, so contacts on other servers cannot be reached")

// ErrAttachmentNotResendable reports a retry of a message whose attachment
// never reached the server and is no longer on this device either. Re-sending
// the caption alone would quietly deliver something other than what was
// composed, so it refuses instead.
var ErrAttachmentNotResendable = errors.New("client: the attachment for this message is no longer available to re-send")

// ErrPeerBlocked reports an attempt to send to a peer the user has blocked.
//
// Refused in the core rather than left to whatever is driving it. The app
// happens to disable its composer, but the rule is not a property of a screen:
// a background retry, a queued receipt, a bot with no interface at all would
// each otherwise go on talking to somebody the user has cut off. The peer is
// never told either way -- blocking is silent in both directions.
var ErrPeerBlocked = errors.New("client: this contact is blocked, so nothing is sent to them")

// SendOptions carries the parts of a message that are not its text. The zero
// value is an ordinary message sent now.
type SendOptions struct {
	ReplyToID        string
	ReplyPreviewText string
	ReplyPreviewMine *bool

	// Media is a file to attach, uploaded as part of the send. The transcript
	// line appears before the upload starts, carrying the inline preview, so a
	// picture is visible immediately rather than after however long the upload
	// takes.
	Media *OutgoingMedia

	// Attachments describes blobs that are already uploaded. Used by a caller
	// that manages its own upload -- a group fan-out, which uploads once for
	// every member -- and mutually exclusive with Media.
	Attachments []Attachment

	// Now overrides the clock, for tests. Zero means time.Now().
	Now time.Time
}

// SendResult is the transcript line a send produced, plus what establishing
// the session cost.
type SendResult struct {
	Message Message

	// EstablishedSession: this send ran X3DH rather than using a session that
	// already existed.
	EstablishedSession bool

	// WithoutOneTimePrekey: the session was established without a one-time
	// prekey, so its first message has no forward secrecy. Either the peer's
	// pool ran dry, or -- worth noticing -- our own credentials were refused
	// and the server withheld one. Never an error: a working conversation is
	// worth more than one message's forward secrecy. Worth reporting, because
	// the alternative is that it degrades silently forever.
	WithoutOneTimePrekey bool
}

// SendText records a message in the transcript and delivers it.
//
// The line is written *before* the network is touched and marked
// [SendPending], which is what lets a composer clear the instant the user hits
// send rather than freezing on a slow connection. A failure leaves it
// [SendFailed] and returns the error: the line is the durable feedback, and
// [Client.RetryMessage] is what acts on it.
func (c *Client) SendText(ctx context.Context, peerAccountID, text string, opts SendOptions) (SendResult, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	id, err := c.Identity()
	if err != nil {
		return SendResult{}, err
	}
	// Checked before anything is written, so a blocked peer leaves no trace of
	// a message that was never going to go anywhere.
	if blocked, err := c.IsPeerBlocked(peerAccountID); err != nil {
		return SendResult{}, err
	} else if blocked {
		return SendResult{}, ErrPeerBlocked
	}
	if opts.Media != nil && len(opts.Attachments) > 0 {
		return SendResult{}, fmt.Errorf("client: a message carries either Media to upload or Attachments already uploaded, not both")
	}
	messageID, err := newMessageID()
	if err != nil {
		return SendResult{}, err
	}
	line := Message{
		ID:               messageID,
		Text:             text,
		Mine:             true,
		Timestamp:        now,
		ReplyToID:        opts.ReplyToID,
		ReplyPreviewText: opts.ReplyPreviewText,
		ReplyPreviewMine: opts.ReplyPreviewMine,
		Kind:             MessageNormal,
		SendState:        SendPending,
		Attachments:      opts.Attachments,
	}
	if opts.Media != nil {
		// The sender's own copy is written first, before anything can fail.
		// That is what makes an unsent picture durable: a retry -- this run or
		// a later one -- has the bytes to upload again, and the bubble has
		// something to draw in the meantime.
		if err := c.WriteAttachmentFile(peerAccountID, messageID, opts.Media.Bytes); err != nil {
			return SendResult{}, err
		}
		if err := c.WriteAttachmentThumb(peerAccountID, messageID, opts.Media.Thumb); err != nil {
			return SendResult{}, err
		}
		// A placeholder: everything a bubble needs to draw, and nothing a
		// recipient could fetch with. The upload below fills in the rest.
		line.Attachments = []Attachment{placeholderFor(*opts.Media)}
	}
	if err := c.AppendMessage(peerAccountID, line); err != nil {
		return SendResult{}, err
	}

	res := SendResult{Message: line}
	if opts.Media != nil {
		uploaded, err := c.uploadFor(ctx, peerAccountID, *opts.Media)
		if err != nil {
			if markErr := c.SetMessageSendState(peerAccountID, messageID, SendFailed); markErr != nil {
				return res, errors.Join(err, markErr)
			}
			return res, err
		}
		if err := c.SetMessageAttachments(peerAccountID, messageID, []Attachment{uploaded}); err != nil {
			return res, err
		}
		line.Attachments = []Attachment{uploaded}
		res.Message = line
	}

	plaintext, err := encodeText(line, id.Server, now)
	if err != nil {
		return res, err
	}
	res.EstablishedSession, res.WithoutOneTimePrekey, err = c.deliver(ctx, peerAccountID, plaintext, false)
	if err != nil {
		if markErr := c.SetMessageSendState(peerAccountID, messageID, SendFailed); markErr != nil {
			return res, errors.Join(err, markErr)
		}
		return res, err
	}
	if err := c.SetMessageSendState(peerAccountID, messageID, SendSent); err != nil {
		return res, err
	}
	res.Message.SendState = SendSent

	// The conversation moves to the top of the list on our own message too --
	// unlike a re-key marker, this genuinely is activity.
	if err := c.touchConversation(peerAccountID, now); err != nil {
		return res, err
	}
	return res, nil
}

// RetryMessage re-sends a message whose send failed, including one composed in
// an earlier run.
//
// Safe to call after a send that may in fact have arrived. The failed attempt
// rolled the ratchet back, so a retry re-encrypts under the same message
// number -- and if the first copy did land, the peer's ratchet recognises the
// second as a duplicate and refuses it. The de-duplication that makes this
// safe is therefore the rollback in [Client.deliver], not the wire id, which
// is fresh on every attempt.
func (c *Client) RetryMessage(ctx context.Context, peerAccountID, messageID string) (SendResult, error) {
	msgs, err := c.Messages(peerAccountID)
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
		return SendResult{}, fmt.Errorf("client: no message %s in the chat with %s", messageID, peerAccountID)
	}
	if line.SendState != SendFailed {
		return SendResult{}, fmt.Errorf("client: message %s is %s, not a failed send", messageID, line.SendState)
	}

	id, err := c.Identity()
	if err != nil {
		return SendResult{}, err
	}
	if blocked, err := c.IsPeerBlocked(peerAccountID); err != nil {
		return SendResult{}, err
	} else if blocked {
		return SendResult{}, ErrPeerBlocked
	}

	// An attachment that never made it to the server has to go up before the
	// message can name it. One that did is simply named again: the blob is
	// still there under the same id, and re-uploading would leave a second
	// copy nobody references.
	if len(line.Attachments) == 1 && line.Attachments[0].BlobID == "" {
		bytes, err := c.AttachmentFile(peerAccountID, messageID)
		if err != nil {
			return SendResult{}, err
		}
		if bytes == nil {
			// Composed on a device that no longer has the file, or cleared
			// since. Sending the caption alone would deliver something the
			// user never wrote.
			return SendResult{}, ErrAttachmentNotResendable
		}
		placeholder := line.Attachments[0]
		uploaded, err := c.uploadFor(ctx, peerAccountID, OutgoingMedia{
			Bytes: bytes, MimeType: placeholder.MimeType, Kind: placeholder.Kind,
			Width: placeholder.Width, Height: placeholder.Height, Thumb: placeholder.Thumb,
		})
		if err != nil {
			return SendResult{}, err
		}
		if err := c.SetMessageAttachments(peerAccountID, messageID, []Attachment{uploaded}); err != nil {
			return SendResult{}, err
		}
		line.Attachments = []Attachment{uploaded}
	}

	if err := c.SetMessageSendState(peerAccountID, messageID, SendPending); err != nil {
		return SendResult{}, err
	}

	res := SendResult{Message: *line}
	plaintext, err := encodeText(*line, id.Server, line.Timestamp)
	if err != nil {
		return res, err
	}
	res.EstablishedSession, res.WithoutOneTimePrekey, err = c.deliver(ctx, peerAccountID, plaintext, false)
	if err != nil {
		if markErr := c.SetMessageSendState(peerAccountID, messageID, SendFailed); markErr != nil {
			return res, errors.Join(err, markErr)
		}
		return res, err
	}
	res.Message.SendState = SendSent
	return res, c.SetMessageSendState(peerAccountID, messageID, SendSent)
}

// SendReceipt confirms to peer how far we have got with their messages.
//
// upTo is a cumulative watermark in the *sender's* clock -- their own sent_at,
// echoed back -- which is what lets one arriving late be harmless: it moves a
// single monotonic value and touches no message. Sending one that would not
// move our own record of it is skipped entirely, since a receipt that says
// nothing new is pure traffic.
func (c *Client) SendReceipt(ctx context.Context, peerAccountID string, status ReceiptStatus, upTo time.Time) error {
	convo, err := c.Conversation(peerAccountID)
	if err != nil || convo == nil {
		return err
	}
	upTo = upTo.UTC()

	var sent **time.Time
	switch status {
	case ReceiptDelivered:
		sent = &convo.SentDeliveredReceiptUpTo
	case ReceiptRead:
		sent = &convo.SentReadReceiptUpTo
	default:
		return fmt.Errorf("client: unknown receipt status %q", status)
	}
	if *sent != nil && !upTo.After(**sent) {
		return nil
	}

	plaintext, err := json.Marshal(map[string]any{
		"v":             versionReceipt,
		"kind":          "receipt",
		"status":        string(status),
		"up_to_sent_at": upTo.Format(receiptTimeLayout),
	})
	if err != nil {
		return fmt.Errorf("client: encoding receipt: %w", err)
	}
	if _, _, err := c.deliver(ctx, peerAccountID, plaintext, false); err != nil {
		return err
	}

	// Recorded only once it is actually gone. A receipt recorded as sent but
	// never delivered is never re-sent, and the peer's ticks stay wrong for
	// good.
	at := upTo
	*sent = &at
	return c.PutConversation(*convo)
}

// ResetSession discards the local session with peer and re-establishes it.
//
// The signal that follows is almost empty on purpose: its whole job is to
// exist, because sending anything at all after discarding a session re-runs
// X3DH and puts a fresh prekey block on the wire, which is the only thing that
// can re-point the peer at a session this side can read.
//
// Waiting instead does not work, and the reason is that a desync is
// asymmetric. What breaks is *receiving* -- the peer goes on sending happily
// into a session that no longer opens here, and nothing they do fixes it.
// Waiting for the user to happen to type something leaves the conversation
// broken for as long as they stay quiet.
func (c *Client) ResetSession(ctx context.Context, peerAccountID string, reason RekeyReason) error {
	now := time.Now().UTC()

	if err := c.DeleteSession(peerAccountID, Sending); err != nil {
		return err
	}
	if err := c.DeleteSession(peerAccountID, Inbound); err != nil {
		return err
	}

	// Stamped before the attempt rather than after: if the send fails, the
	// spacing must still hold, or every reconnect retries immediately and
	// burns one of the peer's one-time prekeys each time.
	if reason == RekeyDecryptFailures {
		if err := c.RecordAutoRekey(peerAccountID, now); err != nil {
			return err
		}
	} else if err := c.ClearDesyncEvidence(peerAccountID); err != nil {
		return err
	}

	marker := SessionResetMarker
	if reason == RekeyDecryptFailures {
		marker = AutomaticRekeyMarker
	}
	if convo, err := c.Conversation(peerAccountID); err != nil {
		return err
	} else if convo != nil {
		markerID, err := newMessageID()
		if err != nil {
			return err
		}
		// Deliberately not touching last activity: recovering a session is
		// maintenance, not a message, and must not jump the chat to the top.
		if err := c.AppendMessage(peerAccountID, Message{
			ID: markerID, Text: marker, Timestamp: now,
			Kind: MessageSystemInfo, SendState: SendSent,
		}); err != nil {
			return err
		}
	}

	plaintext, err := json.Marshal(map[string]any{
		"v": versionRekey, "kind": "rekey", "reason": string(reason),
	})
	if err != nil {
		return fmt.Errorf("client: encoding re-key signal: %w", err)
	}
	// afterOwnReset: says outright that this prekey block is a deliberate
	// re-key, so the peer adopts it instead of running the tie-break. Stating
	// it is what lets the receiving side stop inferring re-keys from content.
	_, _, err = c.deliver(ctx, peerAccountID, plaintext, true)
	return err
}

// RecoverDesyncedSessions re-establishes every session the evidence says is
// broken. Returns the peers it re-keyed.
//
// The eligibility rules on top of [Client.ShouldAutoRekey] are all about
// whether sending to this peer makes sense at all: a blocked peer, an
// unaccepted request, or a conversation on another server while federation is
// off. The crypto question and the "is this worth a message" question are kept
// apart because only one of them is about the ratchet.
func (c *Client) RecoverDesyncedSessions(ctx context.Context) ([]string, error) {
	convos, err := c.Conversations()
	if err != nil {
		return nil, err
	}
	federated, err := c.federationAllowed(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()

	var recovered []string
	for _, convo := range convos {
		if convo.Blocked || convo.PendingApproval {
			continue
		}
		if convo.PeerServer != "" && !federated {
			continue
		}
		due, err := c.ShouldAutoRekey(convo.PeerAccountID, now)
		if err != nil {
			return recovered, err
		}
		if !due {
			continue
		}
		if err := c.ResetSession(ctx, convo.PeerAccountID, RekeyDecryptFailures); err != nil {
			// One peer being unreachable must not stop the others: the whole
			// point is to recover as many conversations as possible per
			// attempt, and this runs again on the next reconnect.
			continue
		}
		recovered = append(recovered, convo.PeerAccountID)
	}
	return recovered, nil
}

// deliver encrypts plaintext for peer and posts it, keeping the ratchet
// advance only if the post succeeded.
//
// The rollback is the important part. Encrypting moves the session forward; if
// the envelope never arrives, that advance is a message number the peer will
// never see used, and enough of those look exactly like a desync. Rolling back
// also makes a retry safe against a post that failed *after* the server stored
// it: the retry re-encrypts under the same number, and the peer's ratchet
// rejects the second copy as the duplicate it is.
func (c *Client) deliver(ctx context.Context, peerAccountID string, plaintext []byte, afterOwnReset bool) (established, weak bool, err error) {
	// The backstop for every path into here, not just the composed message:
	// a queued receipt, a retry, a re-key signal. Blocking has to hold for all
	// of them or it holds for none.
	if blocked, err := c.IsPeerBlocked(peerAccountID); err != nil {
		return false, false, err
	} else if blocked {
		return false, false, ErrPeerBlocked
	}

	peer, err := c.Endpoint(ctx, peerAccountID)
	if err != nil {
		return false, false, err
	}
	if peer.Federated() {
		allowed, err := c.federationAllowed(ctx)
		if err != nil {
			return false, false, err
		}
		if !allowed {
			return false, false, ErrFederationDisabled
		}
	}

	unlock := c.lockPeer(peerAccountID)
	defer unlock()

	// Two reads of the same file on purpose, and the duplication is the point:
	// Session unmarshals a fresh value every call, so these are independent
	// copies. Handing the same one to both roles would mean Encrypt advancing
	// the very object kept for the rollback -- which then restores the advance
	// it was there to undo, silently, leaving the failure mode this whole
	// function exists to prevent.
	//
	// A nil previous means there was no session, and rolling back to nil is
	// deliberate: the fresh one was built from a claimed prekey bundle the peer
	// never saw used, so a retry claims another. That costs one of their
	// one-time prekeys per failed first send, which is the price of never
	// leaving a half-established session behind.
	previous, err := c.Session(peerAccountID, Sending)
	if err != nil {
		return false, false, err
	}
	current, err := c.Session(peerAccountID, Sending)
	if err != nil {
		return false, false, err
	}

	session, initial, weak, err := c.sessionForSending(ctx, peer, current)
	if err != nil {
		return false, false, err
	}
	established = initial != nil

	header, ciphertext, err := session.Encrypt(plaintext)
	if err != nil {
		return established, weak, fmt.Errorf("client: encrypting for %s: %w", peerAccountID, err)
	}
	if err := c.SetSession(peerAccountID, Sending, session); err != nil {
		return established, weak, err
	}

	// Stated on every establishment, never left for the peer to guess: false is
	// as much an answer as true. Only meaningful alongside a prekey block,
	// which is exactly when the peer faces the ambiguity.
	var rekey *bool
	if initial != nil {
		flag := afterOwnReset
		rekey = &flag
	}
	payload, err := wire.NewEnvelopeRekey(initial, header, ciphertext, rekey).MarshalPayload()
	if err != nil {
		return established, weak, fmt.Errorf("client: building envelope for %s: %w", peerAccountID, err)
	}

	wireID, err := newMessageID()
	if err != nil {
		return established, weak, err
	}
	if err := c.postEnvelope(ctx, peer, wireID, payload); err != nil {
		if rollback := c.rollBackSession(peerAccountID, previous); rollback != nil {
			return established, weak, errors.Join(err, rollback)
		}
		// The stale-device rule at sending time: the post named a device the
		// server no longer knows. Nothing propagates a device being replaced
		// across servers, so the send that trips over the dead id is the one
		// that heals it -- drop the id and the session bound to it, and the
		// next attempt re-resolves instead of failing against it forever.
		if IsStaleDevice(err) {
			if forget := c.ForgetPeerDevice(peerAccountID); forget != nil {
				return established, weak, errors.Join(err, forget)
			}
		}
		return established, weak, err
	}
	return established, weak, nil
}

// uploadFor resolves the peer's device and uploads media for it, which is the
// only recipient a one-to-one attachment ever has.
func (c *Client) uploadFor(ctx context.Context, peerAccountID string, media OutgoingMedia) (Attachment, error) {
	peer, err := c.Endpoint(ctx, peerAccountID)
	if err != nil {
		return Attachment{}, err
	}
	return c.UploadAttachment(ctx, []PeerEndpoint{peer}, media)
}

// placeholderFor is what a bubble can draw before the upload finishes: shape,
// type and preview, but no blob id and no key, because neither exists yet.
func placeholderFor(media OutgoingMedia) Attachment {
	kind := media.Kind
	if kind == "" {
		kind = "image"
	}
	return Attachment{
		Kind:     kind,
		MimeType: media.MimeType,
		ByteSize: len(media.Bytes),
		Width:    media.Width,
		Height:   media.Height,
		Thumb:    media.Thumb,
	}
}

// sessionForSending returns the session to encrypt with, and the prekey block
// to announce alongside it when the session is new.
func (c *Client) sessionForSending(ctx context.Context, peer PeerEndpoint, existing *ratchet.Session) (*ratchet.Session, *ratchet.InitialMessage, bool, error) {
	if existing != nil {
		return existing, nil, false, nil
	}

	bundle, err := c.ClaimBundle(ctx, peer)
	if err != nil {
		// The first moment a replaced peer device becomes visible: nothing
		// propagates device revocations or re-created accounts across servers,
		// and the cached id never expires on its own. Forget it, re-resolve,
		// and try once more -- never more than once, because a second refusal
		// is a real answer rather than a worse cache.
		if !IsStaleDevice(err) {
			return nil, nil, false, err
		}
		if err := c.ForgetPeerDevice(peer.AccountID); err != nil {
			return nil, nil, false, err
		}
		fresh, rerr := c.Endpoint(ctx, peer.AccountID)
		if rerr != nil {
			return nil, nil, false, rerr
		}
		if bundle, err = c.ClaimBundle(ctx, fresh); err != nil {
			return nil, nil, false, err
		}
		peer = fresh
	}

	id, err := c.Identity()
	if err != nil {
		return nil, nil, false, err
	}
	dhPriv, err := ecdh.X25519().NewPrivateKey(id.DHIdentityPriv)
	if err != nil {
		return nil, nil, false, fmt.Errorf("client: reading own identity key: %w", err)
	}
	session, initial, err := ratchet.InitiateSession(dhPriv, bundle.RemoteBundle)
	if err != nil {
		return nil, nil, false, fmt.Errorf("client: establishing a session with %s: %w", peer.AccountID, err)
	}
	return session, initial, bundle.OneTimePrekeyID == nil, nil
}

// rollBackSession restores what the session was before an attempt that failed.
// A nil previous means there was none, and the fresh one is discarded whole.
func (c *Client) rollBackSession(peer string, previous *ratchet.Session) error {
	if previous == nil {
		return c.DeleteSession(peer, Sending)
	}
	return c.SetSession(peer, Sending, previous)
}

// postEnvelope hands one envelope to whichever server holds the recipient.
func (c *Client) postEnvelope(ctx context.Context, peer PeerEndpoint, wireMessageID string, payload json.RawMessage) error {
	if !peer.Federated() {
		return c.SendMessage(ctx, peer.AccountID, peer.DeviceID, wireMessageID, payload)
	}

	id, err := c.Identity()
	if err != nil {
		return err
	}
	issuedAt := time.Now().UTC()
	cert, err := signDeviceCert(id, issuedAt)
	if err != nil {
		return err
	}
	err = c.do(ctx, request{
		method: http.MethodPost,
		path:   "/v1/federation/messages",
		server: peer.Server,
		auth:   authFederated,
		body: map[string]any{
			"sender_account_id":    id.AccountID,
			"sender_root_pub_key":  base64.StdEncoding.EncodeToString(id.RootPub),
			"sender_device_cert":   cert,
			"recipient_account_id": peer.AccountID,
			"recipient_device_id":  peer.DeviceID,
			"message_id":           wireMessageID,
			"payload":              payload,
		},
	}, nil)

	// Same rule as the local path: the server de-duplicates by message id, so
	// a retry being refused is the retry working.
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict {
		return nil
	}
	return err
}

// federationAllowed reports whether this account's own server lets messages
// leave it. Asked of our own server, not the peer's: a server with federation
// off blocks replies inbound as well, so the conversation is dead in both
// directions regardless of what the other end permits.
func (c *Client) federationAllowed(ctx context.Context) (bool, error) {
	status, err := c.ServerStatus(ctx, "")
	if err != nil {
		return false, err
	}
	return status.FederationEnabled, nil
}

// touchConversation marks activity, creating nothing: a send into a
// conversation that does not exist has nowhere to be recorded, and the caller
// is the one that knows whether creating it is right.
func (c *Client) touchConversation(peer string, now time.Time) error {
	convo, err := c.Conversation(peer)
	if err != nil || convo == nil {
		return err
	}
	convo.LastActivityAt = &now
	return c.PutConversation(*convo)
}

// encodeText builds the v1 chat envelope for one of our own transcript lines.
func encodeText(line Message, ownServer string, sentAt time.Time) ([]byte, error) {
	body := map[string]any{
		"v":       versionText,
		"id":      line.ID,
		"text":    line.Text,
		"sent_at": sentAt.UTC().Format(receiptTimeLayout),
	}
	// Sent with every message, not just the first, so a peer whose local state
	// about us is lost can still find its way back to our server.
	if ownServer != "" {
		body["sender_server"] = ownServer
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
	if len(line.Attachments) > 0 {
		wires := make([]attachmentWire, 0, len(line.Attachments))
		for _, a := range line.Attachments {
			wires = append(wires, attachmentWire{
				Kind: a.Kind, Algorithm: a.Algorithm, BlobID: a.BlobID, Key: a.Key,
				MimeType: a.MimeType, ByteSize: a.ByteSize, Width: a.Width, Height: a.Height, Thumb: a.Thumb,
			})
		}
		body["attachments"] = wires
	}
	out, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("client: encoding message %s: %w", line.ID, err)
	}
	return out, nil
}

// attachmentWires is the wire form of a message.s attachments.
//
// A placeholder that never finished uploading is left out: sending it would
// describe a picture the recipient can never fetch, which reads as loss rather
// than as the failure it is.
func attachmentWires(atts []Attachment) []attachmentWire {
	wires := make([]attachmentWire, 0, len(atts))
	for _, a := range atts {
		if a.BlobID == "" {
			continue
		}
		wires = append(wires, attachmentWire{
			Kind: a.Kind, Algorithm: a.Algorithm, BlobID: a.BlobID, Key: a.Key,
			MimeType: a.MimeType, ByteSize: a.ByteSize, Width: a.Width, Height: a.Height, Thumb: a.Thumb,
		})
	}
	return wires
}

// signDeviceCertificate proves to a server with no row for this device that
// the account's root key vouches for it.
//
// This is what federation runs on. Our own server looks a device id up in its
// own table; a foreign one has nothing to look up, so the claim has to carry
// its own proof -- the root key, the device key, and a signature from the
// former over the latter.
func signDeviceCertificate(id Identity, issuedAt time.Time) ([]byte, error) {
	cert, err := devicecert.SignDeviceCertificate(
		id.AccountID, id.DeviceID, ed25519.PublicKey(id.DevicePub), issuedAt, ed25519.PrivateKey(id.RootPriv))
	if err != nil {
		return nil, fmt.Errorf("client: signing device certificate: %w", err)
	}
	return cert.Signature, nil
}

// signDeviceCert wraps that signature in the shape a federated request body
// expects.
//
// "device_pub_key", not the "device_pubkey" every other identity block on the
// wire uses (PROTOCOL.md §2) -- this one specific inline shape (§9's
// sender_device_cert, documented at PROTOCOL.md:781) really does spell it
// with the extra underscore, and internal/api/dto.go's
// federationDeviceCertDTO agrees. Get it wrong and the server's decode
// silently leaves the field at its zero value: "invalid
// sender_device_cert.device_pub_key: expected 32 bytes, got 0" -- which reads
// like a local identity problem, not a wire-shape typo, and is why this was
// never caught by anything short of an actual federated send.
func signDeviceCert(id Identity, issuedAt time.Time) (map[string]any, error) {
	sig, err := signDeviceCertificate(id, issuedAt)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"device_id":      id.DeviceID,
		"device_pub_key": base64.StdEncoding.EncodeToString(id.DevicePub),
		"issued_at":      issuedAt.Format(time.RFC3339),
		"signature":      base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// receiptTimeLayout matches what the app puts on the wire: millisecond
// precision, trailing Z. Both sides parse tolerantly, so this is not strictly
// required -- but emitting the same shape keeps comparisons unambiguous and a
// transcript readable by eye.
const receiptTimeLayout = "2006-01-02T15:04:05.000Z"
