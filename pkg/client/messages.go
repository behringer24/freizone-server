package client

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

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
	Kind string

	// Algorithm names how the blob is encrypted, as a string so changing
	// ciphers stays a data question rather than a format break.
	Algorithm string

	BlobID string

	// Key is this one blob's symmetric key, generated per attachment and
	// deliberately not derived from the ratchet: the blob outlives the message
	// on the server, so resetting a secure session must not make pictures
	// already received undownloadable.
	Key []byte

	MimeType string
	ByteSize int

	// Width and Height let a bubble reserve the right aspect ratio before the
	// download finishes, so the transcript does not jump.
	Width  int
	Height int

	// Thumb is a tiny JPEG shown blurred while the real file downloads, nil
	// when the sender included none.
	Thumb []byte
}

// GroupDelivery is one recipient's copy of a group message.
type GroupDelivery struct {
	AccountID string

	// WireMessageID is what the recipient's server de-duplicates by, so a retry
	// cannot deliver a second copy. Random and per recipient: sharing the
	// message's own id would make two members on the same server collide.
	WireMessageID string

	State SendState

	// AttachmentSkipped: they got the caption but not the picture, because
	// their server does not store attachments or would not take this one. Not a
	// delivery failure, and permanent -- a retry cannot fix it, since a
	// delivery that already counts as sent is never revisited.
	AttachmentSkipped bool
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

	tx, err := c.db.Begin()
	if err != nil {
		return fmt.Errorf("client: appending message to %s: %w", chatID, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	if _, err := tx.Exec(`
		INSERT INTO messages (
			chat_id, message_id, seq, text, mine, timestamp, sender_sent_at,
			sender_account_id, reply_to_id, reply_preview_text,
			reply_preview_mine, reply_preview_author_id, kind, send_state
		) VALUES (
			?, ?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM messages WHERE chat_id = ?),
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		)`,
		chatID, m.ID, chatID,
		m.Text, m.Mine, m.Timestamp.UTC().Format(time.RFC3339Nano), formatTime(m.SenderSentAt),
		nullString(m.SenderAccountID), nullString(m.ReplyToID), nullString(m.ReplyPreviewText),
		m.ReplyPreviewMine, nullString(m.ReplyPreviewAuthorID), string(m.Kind), string(m.SendState),
	); err != nil {
		return fmt.Errorf("client: appending message %s to %s: %w", m.ID, chatID, err)
	}

	for i, a := range m.Attachments {
		if _, err := tx.Exec(`
			INSERT INTO message_attachments (
				chat_id, message_id, position, kind, algorithm, blob_id, key,
				mime_type, byte_size, width, height, thumb
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			chatID, m.ID, i, a.Kind, a.Algorithm, a.BlobID, a.Key,
			a.MimeType, a.ByteSize, a.Width, a.Height, a.Thumb,
		); err != nil {
			return fmt.Errorf("client: storing attachment %d of %s: %w", i, m.ID, err)
		}
	}

	for _, d := range m.Deliveries {
		if _, err := tx.Exec(`
			INSERT INTO group_deliveries (
				chat_id, message_id, account_id, wire_message_id, state, attachment_skipped
			) VALUES (?, ?, ?, ?, ?, ?)`,
			chatID, m.ID, d.AccountID, d.WireMessageID, string(d.State), d.AttachmentSkipped,
		); err != nil {
			return fmt.Errorf("client: storing delivery to %s of %s: %w", d.AccountID, m.ID, err)
		}
	}

	return tx.Commit()
}

// SetMessageSendState moves one of our own messages between pending, sent and
// failed as the send progresses or gives up.
func (c *Client) SetMessageSendState(chatID, messageID string, state SendState) error {
	if _, err := c.db.Exec(
		`UPDATE messages SET send_state = ? WHERE chat_id = ? AND message_id = ?`,
		string(state), chatID, messageID,
	); err != nil {
		return fmt.Errorf("client: setting send state of %s: %w", messageID, err)
	}
	return nil
}

// SetGroupDeliveryState moves one recipient's copy of a group message, so a
// retry can address only the copies that failed.
func (c *Client) SetGroupDeliveryState(chatID, messageID, accountID string, state SendState) error {
	if _, err := c.db.Exec(`
		UPDATE group_deliveries SET state = ?
		 WHERE chat_id = ? AND message_id = ? AND account_id = ?`,
		string(state), chatID, messageID, accountID,
	); err != nil {
		return fmt.Errorf("client: setting delivery state to %s of %s: %w", accountID, messageID, err)
	}
	return nil
}

// Messages returns a chat's whole transcript in arrival order.
func (c *Client) Messages(chatID string) ([]Message, error) {
	rows, err := c.db.Query(messageSelect+` WHERE chat_id = ? ORDER BY seq`, chatID)
	if err != nil {
		return nil, fmt.Errorf("client: reading transcript of %s: %w", chatID, err)
	}
	msgs, err := scanMessages(rows)
	if err != nil {
		return nil, err
	}
	for i := range msgs {
		if err := c.loadMessageChildren(chatID, &msgs[i]); err != nil {
			return nil, err
		}
	}
	return msgs, nil
}

// LastMessage returns a chat's most recent line, or nil for an empty chat.
//
// This is the query the whole store exists for: a chat list draws one preview
// row per conversation, and doing that by loading every transcript in full is
// what made the single-JSON-file store cost more with every message ever sent.
func (c *Client) LastMessage(chatID string) (*Message, error) {
	rows, err := c.db.Query(messageSelect+` WHERE chat_id = ? ORDER BY seq DESC LIMIT 1`, chatID)
	if err != nil {
		return nil, fmt.Errorf("client: reading last message of %s: %w", chatID, err)
	}
	msgs, err := scanMessages(rows)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, nil
	}
	if err := c.loadMessageChildren(chatID, &msgs[0]); err != nil {
		return nil, err
	}
	return &msgs[0], nil
}

// DeleteMessage removes one line, along with its attachments, its group
// deliveries and its pin. Local only -- the peer keeps their copy.
func (c *Client) DeleteMessage(chatID, messageID string) error {
	if _, err := c.db.Exec(
		`DELETE FROM messages WHERE chat_id = ? AND message_id = ?`, chatID, messageID,
	); err != nil {
		return fmt.Errorf("client: deleting message %s: %w", messageID, err)
	}
	return nil
}

// ClearTranscript empties a chat's history, leaving the conversation, its
// session and everything else about the peer in place.
func (c *Client) ClearTranscript(chatID string) error {
	if _, err := c.db.Exec(`DELETE FROM messages WHERE chat_id = ?`, chatID); err != nil {
		return fmt.Errorf("client: clearing transcript of %s: %w", chatID, err)
	}
	return nil
}

// PinMessage pins a message locally. Pinning one already pinned leaves its
// place in the order alone rather than moving it to the end.
func (c *Client) PinMessage(chatID, messageID string) error {
	if _, err := c.db.Exec(`
		INSERT INTO pinned_messages (chat_id, message_id, seq)
		VALUES (?, ?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM pinned_messages WHERE chat_id = ?))
		ON CONFLICT (chat_id, message_id) DO NOTHING`,
		chatID, messageID, chatID,
	); err != nil {
		return fmt.Errorf("client: pinning %s: %w", messageID, err)
	}
	return nil
}

// UnpinMessage removes a pin.
func (c *Client) UnpinMessage(chatID, messageID string) error {
	if _, err := c.db.Exec(
		`DELETE FROM pinned_messages WHERE chat_id = ? AND message_id = ?`, chatID, messageID,
	); err != nil {
		return fmt.Errorf("client: unpinning %s: %w", messageID, err)
	}
	return nil
}

// PinnedMessageIDs lists a chat's pins, oldest-pinned first.
func (c *Client) PinnedMessageIDs(chatID string) ([]string, error) {
	rows, err := c.db.Query(
		`SELECT message_id FROM pinned_messages WHERE chat_id = ? ORDER BY seq`, chatID,
	)
	if err != nil {
		return nil, fmt.Errorf("client: reading pins of %s: %w", chatID, err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("client: scanning pin: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// failInFlightSends rewrites anything left mid-send by a process that is gone.
//
// Run once when the database is opened, deliberately not on every read:
// nothing is in flight in a process that no longer exists, but a send genuinely
// in flight in *this* process must keep reading back as pending until it
// finishes. The app gets the same effect from parsing its state file on load;
// doing it here on read instead would report a live upload as already failed.
func failInFlightSends(db *sql.DB) error {
	if _, err := db.Exec(`UPDATE messages SET send_state = 'failed' WHERE send_state = 'pending'`); err != nil {
		return fmt.Errorf("client: failing in-flight sends: %w", err)
	}
	if _, err := db.Exec(`UPDATE group_deliveries SET state = 'failed' WHERE state = 'pending'`); err != nil {
		return fmt.Errorf("client: failing in-flight group deliveries: %w", err)
	}
	return nil
}

const messageSelect = `
	SELECT message_id, text, mine, timestamp, sender_sent_at, sender_account_id,
	       reply_to_id, reply_preview_text, reply_preview_mine,
	       reply_preview_author_id, kind, send_state
	  FROM messages`

func scanMessages(rows *sql.Rows) ([]Message, error) {
	defer rows.Close()

	var out []Message
	for rows.Next() {
		var (
			m                          Message
			sentAt                     sql.NullString
			timestamp                  string
			sender, replyTo, replyText sql.NullString
			replyAuthor                sql.NullString
			replyMine                  sql.NullBool
			kind, sendState            string
		)
		if err := rows.Scan(
			&m.ID, &m.Text, &m.Mine, &timestamp, &sentAt, &sender,
			&replyTo, &replyText, &replyMine, &replyAuthor, &kind, &sendState,
		); err != nil {
			return nil, fmt.Errorf("client: scanning message: %w", err)
		}

		ts, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return nil, fmt.Errorf("client: parsing message timestamp %q: %w", timestamp, err)
		}
		m.Timestamp = ts
		if m.SenderSentAt, err = parseTime(sentAt); err != nil {
			return nil, err
		}
		m.SenderAccountID = sender.String
		m.ReplyToID, m.ReplyPreviewText = replyTo.String, replyText.String
		m.ReplyPreviewAuthorID = replyAuthor.String
		if replyMine.Valid {
			mine := replyMine.Bool
			m.ReplyPreviewMine = &mine
		}
		m.Kind, m.SendState = MessageKind(kind), SendState(sendState)

		out = append(out, m)
	}
	return out, rows.Err()
}

func (c *Client) loadMessageChildren(chatID string, m *Message) error {
	attachments, err := c.db.Query(`
		SELECT kind, algorithm, blob_id, key, mime_type, byte_size, width, height, thumb
		  FROM message_attachments
		 WHERE chat_id = ? AND message_id = ? ORDER BY position`, chatID, m.ID)
	if err != nil {
		return fmt.Errorf("client: reading attachments of %s: %w", m.ID, err)
	}
	for attachments.Next() {
		var a Attachment
		if err := attachments.Scan(
			&a.Kind, &a.Algorithm, &a.BlobID, &a.Key,
			&a.MimeType, &a.ByteSize, &a.Width, &a.Height, &a.Thumb,
		); err != nil {
			attachments.Close()
			return fmt.Errorf("client: scanning attachment of %s: %w", m.ID, err)
		}
		m.Attachments = append(m.Attachments, a)
	}
	if err := errors.Join(attachments.Err(), attachments.Close()); err != nil {
		return fmt.Errorf("client: reading attachments of %s: %w", m.ID, err)
	}

	deliveries, err := c.db.Query(`
		SELECT account_id, wire_message_id, state, attachment_skipped
		  FROM group_deliveries
		 WHERE chat_id = ? AND message_id = ? ORDER BY account_id`, chatID, m.ID)
	if err != nil {
		return fmt.Errorf("client: reading deliveries of %s: %w", m.ID, err)
	}
	for deliveries.Next() {
		var (
			d     GroupDelivery
			state string
		)
		if err := deliveries.Scan(&d.AccountID, &d.WireMessageID, &state, &d.AttachmentSkipped); err != nil {
			deliveries.Close()
			return fmt.Errorf("client: scanning delivery of %s: %w", m.ID, err)
		}
		d.State = SendState(state)
		m.Deliveries = append(m.Deliveries, d)
	}
	return errors.Join(deliveries.Err(), deliveries.Close())
}
