package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Message is one opaque, end-to-end-encrypted envelope queued for delivery
// to a single recipient device. The server never inspects Payload -- it's
// whatever the client's ratchet layer produced (header, ciphertext, and for
// the first message of a session, X3DH fields).
type Message struct {
	MessageID          string
	SenderAccountID    string
	SenderDeviceID     string
	RecipientAccountID string
	RecipientDeviceID  string
	Payload            string
	SentAt             time.Time
	ExpiresAt          time.Time
}

// CreateMessage enqueues a message. It returns ErrConflict if MessageID is
// already in use.
func CreateMessage(db DBTX, m Message) error {
	_, err := db.Exec(
		`INSERT INTO messages (message_id, sender_account_id, sender_device_id, recipient_account_id, recipient_device_id, payload, sent_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		m.MessageID, m.SenderAccountID, m.SenderDeviceID, m.RecipientAccountID, m.RecipientDeviceID, m.Payload, formatTime(m.SentAt), formatTime(m.ExpiresAt),
	)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: message %s", ErrConflict, m.MessageID)
		}
		return fmt.Errorf("store: creating message: %w", err)
	}
	return nil
}

// ListPendingMessages returns all messages queued for recipientDeviceID,
// oldest first.
func ListPendingMessages(db DBTX, recipientDeviceID string) ([]Message, error) {
	rows, err := db.Query(
		`SELECT message_id, sender_account_id, sender_device_id, recipient_account_id, recipient_device_id, payload, sent_at, expires_at
		 FROM messages WHERE recipient_device_id = ? ORDER BY sent_at ASC`,
		recipientDeviceID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing pending messages: %w", err)
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		messages = append(messages, *m)
	}
	return messages, rows.Err()
}

// DeleteMessage removes a message from the queue once the owning
// recipient device has durably processed it. It returns ErrNotFound if no
// such message exists for that recipient device.
func DeleteMessage(db DBTX, messageID, recipientDeviceID string) error {
	res, err := db.Exec(
		`DELETE FROM messages WHERE message_id = ? AND recipient_device_id = ?`,
		messageID, recipientDeviceID,
	)
	if err != nil {
		return fmt.Errorf("store: deleting message: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for message deletion: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// PurgeExpiredMessages deletes all messages whose retention window has
// passed, returning the number of rows removed.
func PurgeExpiredMessages(db DBTX, now time.Time) (int64, error) {
	res, err := db.Exec(`DELETE FROM messages WHERE expires_at < ?`, formatTime(now))
	if err != nil {
		return 0, fmt.Errorf("store: purging expired messages: %w", err)
	}
	return res.RowsAffected()
}

func scanMessage(rows *sql.Rows) (*Message, error) {
	var m Message
	var sentAt, expiresAt string
	if err := rows.Scan(&m.MessageID, &m.SenderAccountID, &m.SenderDeviceID, &m.RecipientAccountID, &m.RecipientDeviceID, &m.Payload, &sentAt, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scanning message: %w", err)
	}

	t, err := parseTime(sentAt)
	if err != nil {
		return nil, fmt.Errorf("store: parsing message sent_at: %w", err)
	}
	m.SentAt = t

	t, err = parseTime(expiresAt)
	if err != nil {
		return nil, fmt.Errorf("store: parsing message expires_at: %w", err)
	}
	m.ExpiresAt = t

	return &m, nil
}
