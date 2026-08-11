package client

import (
	"encoding/json"
	"fmt"
	"time"
)

// The transcript is an append-only event log, one per chat.
//
// A new message costs one appended line, whatever the history behind it. So
// does deleting one, and so does a send-state change: they are appended as
// their own records naming the message they refer to, rather than edited into
// the line that holds it -- editing a line in a text file means rewriting
// everything after it, which is the very cost this store exists to avoid.
//
// That shape also answers a question worth stating: a record that arrives long
// after the message it concerns still finds it, because it carries that
// message's id rather than a position. Nothing about lateness matters. (Read
// receipts in a one-to-one chat never reach here at all -- they are a
// monotonic watermark on the conversation, see [Conversation].)
//
// Reading replays the log. Compaction rewrites it only when the record count
// has grown well past the number of live messages, and never on a write path.

// MessageKind distinguishes a chat line from a local notice.
type MessageKind string

const (
	// MessageNormal is an ordinary chat message, rendered as a bubble.
	MessageNormal MessageKind = "normal"

	// MessageSystemInfo is a local, never-transmitted line rendered centred --
	// "Secure session was reset" and the like. It has no sender and no clock
	// but its own.
	MessageSystemInfo MessageKind = "system_info"
)

// SendState is how far one of our own outgoing messages has got. Anything
// received is always [SendSent].
type SendState string

const (
	// SendPending: the line is already in the transcript while the upload
	// and/or the encrypted POST are still in flight. That is the point -- the
	// composer clears the instant the user hits send rather than looking frozen
	// on a slow connection.
	SendPending SendState = "pending"
	SendSent    SendState = "sent"
	SendFailed  SendState = "failed"
)

// Attachment is what describes a blob, never the blob itself: the bytes are
// fetched from the server encrypted and cached as a file.
type Attachment struct {
	// Kind is "image" today. An unknown kind must render as a placeholder
	// rather than break the message around it.
	Kind string `json:"kind"`

	// Algorithm names how the blob is encrypted, as a string so changing
	// ciphers stays a data question rather than a format break.
	Algorithm string `json:"algorithm,omitempty"`

	BlobID string `json:"blob_id"`

	// Key is this one blob's symmetric key, generated per attachment and
	// deliberately not derived from the ratchet: the blob outlives the message
	// on the server, so resetting a secure session must not make pictures
	// already received undownloadable.
	Key []byte `json:"key"`

	MimeType string `json:"mime_type,omitempty"`
	ByteSize int    `json:"byte_size,omitempty"`

	// Width and Height let a bubble reserve the right aspect ratio before the
	// download finishes, so the transcript does not jump.
	Width  int `json:"width,omitempty"`
	Height int `json:"height,omitempty"`

	// Thumb is a tiny JPEG shown blurred while the real file downloads, nil
	// when the sender included none.
	Thumb []byte `json:"thumb,omitempty"`
}

// GroupDelivery is one recipient's copy of a group message.
type GroupDelivery struct {
	AccountID string `json:"account_id"`

	// WireMessageID is what the recipient's server de-duplicates by, so a retry
	// cannot deliver a second copy. Random and per recipient: sharing the
	// message's own id would make two members on the same server collide.
	WireMessageID string `json:"wire_message_id"`

	State SendState `json:"state"`

	// Error is why this copy failed, in the words of whatever refused it, and
	// empty for one that did not fail. Persisted rather than kept for the run
	// that produced it: a fan-out that failed overnight is looked at in the
	// morning, and "failed" with no reason is a dead end for whoever has to act
	// on it. Local and diagnostic -- it never goes on the wire.
	Error string `json:"error,omitempty"`

	// AttachmentSkipped: they got the caption but not the picture, because
	// their server does not store attachments or would not take this one. Not a
	// delivery failure, and permanent -- a retry cannot fix it, since a
	// delivery that already counts as sent is never revisited.
	AttachmentSkipped bool `json:"attachment_skipped,omitempty"`
}

// Message is one line of a transcript. The server never stores plaintext or
// keeps history, so this is the only copy there is.
type Message struct {
	ID   string
	Text string

	// Mine distinguishes our own line from the peer's.
	Mine bool

	// Timestamp is when this device recorded the line. SenderSentAt is the
	// sender's own clock from inside the envelope -- absent for our own
	// messages and for senders predating the field.
	Timestamp    time.Time
	SenderSentAt *time.Time

	// SenderAccountID is empty for our own messages and in a one-to-one chat,
	// where the peer is the conversation. A group transcript needs it.
	SenderAccountID string

	// A reply carries a snapshot of what it answers rather than a live lookup:
	// the quoted message may since have been deleted locally, and a quote that
	// vanishes with the original is worse than a stale one.
	ReplyToID            string
	ReplyPreviewText     string
	ReplyPreviewMine     *bool
	ReplyPreviewAuthorID string

	Kind      MessageKind
	SendState SendState

	Attachments []Attachment
	Deliveries  []GroupDelivery
}

// logRecord is one line. T names what it is, so a reader can tell a message
// from a change to one without guessing, and an unknown T from a future build
// can be skipped instead of misread.
type logRecord struct {
	T string `json:"t"`

	ID string `json:"id"`

	// message
	Text                 string          `json:"text,omitempty"`
	Mine                 bool            `json:"mine,omitempty"`
	Timestamp            string          `json:"ts,omitempty"`
	SenderSentAt         string          `json:"sent_at,omitempty"`
	SenderAccountID      string          `json:"from,omitempty"`
	ReplyToID            string          `json:"reply_to,omitempty"`
	ReplyPreviewText     string          `json:"reply_text,omitempty"`
	ReplyPreviewMine     *bool           `json:"reply_mine,omitempty"`
	ReplyPreviewAuthorID string          `json:"reply_from,omitempty"`
	Kind                 MessageKind     `json:"kind,omitempty"`
	SendState            SendState       `json:"state,omitempty"`
	Attachments          []Attachment    `json:"attachments,omitempty"`
	Deliveries           []GroupDelivery `json:"deliveries,omitempty"`

	// delivery: which recipient's copy this concerns, and why it failed
	AccountID string `json:"to,omitempty"`
	Error     string `json:"error,omitempty"`

	// pin
	Pinned bool `json:"pinned,omitempty"`
}

const (
	recMessage  = "msg"
	recDelete   = "del"
	recState    = "state"
	recDelivery = "delivery"
	recPin      = "pin"

	// recAttach replaces a message.s attachments. Its own record rather than a
	// rewrite of the message, because it lands while the message is already on
	// screen: a picture is written locally and shown as pending before its blob
	// exists, and this is what fills in the blob id and key once the upload
	// finishes.
	recAttach = "attach"
)

// compactRatio decides when a log is rewritten: when its record count exceeds
// this multiple of the live messages it still describes. Above 1 by enough that
// ordinary use -- a send going pending then sent, the odd deletion -- never
// triggers it, and a chat that is only appended to never compacts at all.
const compactRatio = 3

// transcript is a log replayed into memory.
type transcript struct {
	order    []string
	messages map[string]*Message
	pins     []string
	pinned   map[string]bool
	records  int
}

func (c *Client) readTranscript(chatID string) (*transcript, error) {
	path, err := c.store.chatPath(chatID, fileLog)
	if err != nil {
		return nil, err
	}

	t := &transcript{messages: map[string]*Message{}, pinned: map[string]bool{}}
	err = readLines(path, func(raw []byte) error {
		var rec logRecord
		if err := json.Unmarshal(raw, &rec); err != nil || rec.ID == "" {
			return nil
		}
		t.records++

		switch rec.T {
		case recMessage:
			msg, err := rec.toMessage()
			if err != nil {
				return err
			}
			if _, seen := t.messages[rec.ID]; !seen {
				t.order = append(t.order, rec.ID)
			}
			t.messages[rec.ID] = msg

		case recDelete:
			if _, ok := t.messages[rec.ID]; ok {
				delete(t.messages, rec.ID)
				t.order = removeString(t.order, rec.ID)
				// A pin cannot outlive its message: it would render nothing and
				// only invite a later reader to trip over it.
				t.pins = removeString(t.pins, rec.ID)
				delete(t.pinned, rec.ID)
			}

		case recState:
			if msg, ok := t.messages[rec.ID]; ok {
				msg.SendState = rec.SendState
			}

		case recAttach:
			if msg, ok := t.messages[rec.ID]; ok {
				msg.Attachments = rec.Attachments
			}

		case recDelivery:
			if msg, ok := t.messages[rec.ID]; ok {
				for i := range msg.Deliveries {
					if msg.Deliveries[i].AccountID == rec.AccountID {
						msg.Deliveries[i].State = rec.SendState
						// Written unconditionally, so a copy that succeeds on
						// a later attempt loses the reason the earlier one
						// failed rather than carrying it forever.
						msg.Deliveries[i].Error = rec.Error
						break
					}
				}
			}

		case recPin:
			if _, ok := t.messages[rec.ID]; !ok {
				return nil
			}
			switch {
			case rec.Pinned && !t.pinned[rec.ID]:
				t.pinned[rec.ID] = true
				t.pins = append(t.pins, rec.ID)
			case !rec.Pinned && t.pinned[rec.ID]:
				delete(t.pinned, rec.ID)
				t.pins = removeString(t.pins, rec.ID)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (r logRecord) toMessage() (*Message, error) {
	ts, err := time.Parse(time.RFC3339Nano, r.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("client: parsing message timestamp %q: %w", r.Timestamp, err)
	}
	sentAt, err := parseTime(r.SenderSentAt)
	if err != nil {
		return nil, err
	}
	return &Message{
		ID: r.ID, Text: r.Text, Mine: r.Mine,
		Timestamp: ts, SenderSentAt: sentAt,
		SenderAccountID:  r.SenderAccountID,
		ReplyToID:        r.ReplyToID,
		ReplyPreviewText: r.ReplyPreviewText,
		ReplyPreviewMine: r.ReplyPreviewMine, ReplyPreviewAuthorID: r.ReplyPreviewAuthorID,
		Kind: r.Kind, SendState: r.SendState,
		Attachments: r.Attachments, Deliveries: r.Deliveries,
	}, nil
}

func messageRecord(m Message) logRecord {
	return logRecord{
		T: recMessage, ID: m.ID, Text: m.Text, Mine: m.Mine,
		Timestamp:       m.Timestamp.UTC().Format(time.RFC3339Nano),
		SenderSentAt:    formatTime(m.SenderSentAt),
		SenderAccountID: m.SenderAccountID,
		ReplyToID:       m.ReplyToID, ReplyPreviewText: m.ReplyPreviewText,
		ReplyPreviewMine: m.ReplyPreviewMine, ReplyPreviewAuthorID: m.ReplyPreviewAuthorID,
		Kind: m.Kind, SendState: m.SendState,
		Attachments: m.Attachments, Deliveries: m.Deliveries,
	}
}

func (c *Client) appendRecord(chatID string, rec logRecord) error {
	path, err := c.store.chatPath(chatID, fileLog)
	if err != nil {
		return err
	}
	return appendLine(path, rec)
}

// AppendMessage adds a line to the end of a chat's transcript.
//
// Appended, never inserted by time: the transcript's order is arrival order,
// which is what the app does and what a message decrypted late depends on --
// sorting by timestamp would quietly rearrange exactly those transcripts.
func (c *Client) AppendMessage(chatID string, m Message) error {
	if m.ID == "" {
		return fmt.Errorf("client: refusing to append a message with no id to %s", chatID)
	}
	if m.Kind == "" {
		m.Kind = MessageNormal
	}
	if m.SendState == "" {
		m.SendState = SendSent
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.appendRecord(chatID, messageRecord(m))
}

// SetMessageSendState moves one of our own messages between pending, sent and
// failed as the send progresses or gives up.
func (c *Client) SetMessageSendState(chatID, messageID string, state SendState) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.appendRecord(chatID, logRecord{T: recState, ID: messageID, SendState: state})
}

// SetMessageAttachments replaces what a message says about its attachments.
//
// Exists because a picture is shown before it is uploaded: the transcript line
// appears with a local preview the moment the user picks the file, and only
// once the blob is stored does it gain the id and key a recipient needs. Doing
// it the other way round -- upload first, then show -- means a composer that
// sits frozen for the length of an upload.
func (c *Client) SetMessageAttachments(chatID, messageID string, attachments []Attachment) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.appendRecord(chatID, logRecord{T: recAttach, ID: messageID, Attachments: attachments})
}

// SetGroupDeliveryState moves one recipient.s copy of a group message, so a
// retry can address only the copies that failed.
//
// reason is why, for a copy that failed, and is cleared by passing "" -- which
// is what an attempt that finally succeeded does, so the record never keeps a
// stale explanation for a copy that has since arrived.
func (c *Client) SetGroupDeliveryState(chatID, messageID, accountID string, state SendState, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.appendRecord(chatID, logRecord{
		T: recDelivery, ID: messageID, AccountID: accountID,
		SendState: state, Error: truncateReason(reason),
	})
}

// reasonLimit caps what one failure may write into the log. An error carrying a
// server's response body is a diagnostic, not a transcript, and a transcript is
// replayed in full on every read.
const reasonLimit = 200

func truncateReason(reason string) string {
	if len(reason) <= reasonLimit {
		return reason
	}
	return reason[:reasonLimit] + "..."
}

// Messages returns a chat's whole transcript in arrival order.
func (c *Client) Messages(chatID string) ([]Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t, err := c.readTranscript(chatID)
	if err != nil {
		return nil, err
	}
	out := make([]Message, 0, len(t.order))
	for _, id := range t.order {
		out = append(out, *t.messages[id])
	}
	return out, nil
}

// LastMessage returns a chat's most recent line, or nil for an empty chat.
//
// This is the query the chat list is drawn from: one preview per conversation,
// and it must not depend on how much history sits behind it. Replaying the log
// is what that costs today, which is bounded by compaction rather than by the
// number of messages ever sent -- and unlike the old store, nothing here is
// *written* per message beyond a single line.
func (c *Client) LastMessage(chatID string) (*Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.chatPath(chatID, fileLog)
	if err != nil {
		return nil, err
	}
	lines, found, err := tailLines(path)
	if err != nil {
		return nil, err
	}

	// Newest first. A deletion always follows the message it removes, so any
	// deletion affecting a message in this window is in the window too, and is
	// seen before it -- which is what makes the answer from the tail alone
	// correct rather than merely quick.
	if found {
		deleted := map[string]bool{}
		for _, line := range lines {
			var rec logRecord
			if err := json.Unmarshal(line, &rec); err != nil || rec.ID == "" {
				continue
			}
			switch {
			case rec.T == recDelete:
				deleted[rec.ID] = true
			case rec.T == recMessage && !deleted[rec.ID]:
				msg, err := rec.toMessage()
				if err != nil {
					return nil, err
				}
				// State and delivery changes for it are newer, so they were
				// already passed over; replay the window forwards for them.
				applyLaterChanges(lines, msg)
				return msg, nil
			}
		}
	}

	// Nothing usable in the window: a log whose recent records are all larger
	// than it, or one holding only changes. Rare, and worth being right about.
	t, err := c.readTranscript(chatID)
	if err != nil || len(t.order) == 0 {
		return nil, err
	}
	last := *t.messages[t.order[len(t.order)-1]]
	return &last, nil
}

// applyLaterChanges folds the state and delivery records that follow msg in the
// window into it. lines is newest first, so "later" means earlier in the slice.
func applyLaterChanges(lines [][]byte, msg *Message) {
	for i := len(lines) - 1; i >= 0; i-- {
		var rec logRecord
		if err := json.Unmarshal(lines[i], &rec); err != nil || rec.ID != msg.ID {
			continue
		}
		switch rec.T {
		case recState:
			msg.SendState = rec.SendState
		case recDelivery:
			for j := range msg.Deliveries {
				if msg.Deliveries[j].AccountID == rec.AccountID {
					msg.Deliveries[j].State = rec.SendState
					msg.Deliveries[j].Error = rec.Error
				}
			}
		}
	}
}

// DeleteMessage removes one line, along with its attachments, its group
// deliveries and its pin. Local only -- the peer keeps their copy.
func (c *Client) DeleteMessage(chatID, messageID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.appendRecord(chatID, logRecord{T: recDelete, ID: messageID}); err != nil {
		return err
	}
	return c.maybeCompact(chatID)
}

// ClearTranscript empties a chat's history, leaving the conversation, its
// session and everything else about the peer in place.
//
// The one case where removing the file outright is right: nothing is being kept,
// so there is nothing to rewrite.
func (c *Client) ClearTranscript(chatID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.chatPath(chatID, fileLog)
	if err != nil {
		return err
	}
	return removeFile(path)
}

// PinMessage pins a message locally. Pinning one already pinned leaves its
// place in the order alone rather than moving it to the end.
func (c *Client) PinMessage(chatID, messageID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.appendRecord(chatID, logRecord{T: recPin, ID: messageID, Pinned: true})
}

// UnpinMessage removes a pin.
func (c *Client) UnpinMessage(chatID, messageID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.appendRecord(chatID, logRecord{T: recPin, ID: messageID, Pinned: false})
}

// PinnedMessageIDs lists a chat's pins, oldest-pinned first.
func (c *Client) PinnedMessageIDs(chatID string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t, err := c.readTranscript(chatID)
	if err != nil {
		return nil, err
	}
	return t.pins, nil
}

// maybeCompact rewrites a chat's log when its record count has grown well past
// the messages it still describes.
//
// Called only from paths that add records *without* adding a message -- a
// deletion, a state change -- because those are what make a log describe less
// than it holds. Appending a message keeps the ratio moving the other way, so
// the write path that runs per message never pays for this.
func (c *Client) maybeCompact(chatID string) error {
	t, err := c.readTranscript(chatID)
	if err != nil {
		return err
	}
	if t.records <= compactRatio*max(len(t.order), 1) {
		return nil
	}

	path, err := c.store.chatPath(chatID, fileLog)
	if err != nil {
		return err
	}
	return rewriteLog(path, func(write func(any) error) error {
		for _, id := range t.order {
			if err := write(messageRecord(*t.messages[id])); err != nil {
				return err
			}
		}
		for _, id := range t.pins {
			if err := write(logRecord{T: recPin, ID: id, Pinned: true}); err != nil {
				return err
			}
		}
		return nil
	})
}

// failInFlightSends rewrites anything left mid-send by a process that is gone.
//
// Run once when the account is opened, deliberately not on every read: nothing
// is in flight in a process that no longer exists, but a send genuinely in
// flight in *this* process must keep reading back as pending until it finishes.
// The app gets the same effect from parsing its state file on load; doing it on
// read instead would report a live upload as already failed.
func (c *Client) failInFlightSends() error {
	dir, err := c.store.chatsDir()
	if err != nil {
		return err
	}
	ids, err := listDirs(dir)
	if err != nil {
		return err
	}

	for _, chatID := range ids {
		t, err := c.readTranscript(chatID)
		if err != nil {
			return err
		}
		for _, id := range t.order {
			msg := t.messages[id]
			if msg.SendState == SendPending {
				if err := c.appendRecord(chatID, logRecord{T: recState, ID: id, SendState: SendFailed}); err != nil {
					return err
				}
			}
			for _, d := range msg.Deliveries {
				if d.State == SendPending {
					if err := c.appendRecord(chatID, logRecord{
						T: recDelivery, ID: id, AccountID: d.AccountID, SendState: SendFailed,
					}); err != nil {
						return err
					}
				}
			}
		}
		if err := c.maybeCompact(chatID); err != nil {
			return err
		}
	}
	return nil
}

func removeString(list []string, want string) []string {
	for i, s := range list {
		if s == want {
			return append(list[:i:i], list[i+1:]...)
		}
	}
	return list
}
