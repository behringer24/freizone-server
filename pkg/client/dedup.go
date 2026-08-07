package client

import (
	"database/sql"
	"errors"
	"fmt"
)

const (
	// MaxProcessedMessageIDs bounds how many handled ids are remembered.
	// Redelivery happens within a queue's lifetime, so remembering the recent
	// past is enough; the server caps a device's queue well below this.
	MaxProcessedMessageIDs = 500

	// MaxDecryptAttempts is how often one envelope may fail before it is given
	// up on and dropped from the server queue. A single failure can just be a
	// message that raced a session change; a repeated one never is, and must
	// not block the queue forever.
	MaxDecryptAttempts = 3
)

// WasMessageProcessed reports whether this envelope has already been handled.
//
// The check that has to happen before anything else touches the ratchet.
// Delivery is at-least-once and the server keeps a message queued until the
// client deletes it -- a delete that is lost when the app is killed, goes
// offline, or when a push wake races the live stream. Processing an envelope
// twice advances the ratchet twice for one message, and a redelivered X3DH
// initial rebuilds the responder session over the one that has since advanced.
func (c *Client) WasMessageProcessed(id string) (bool, error) {
	var one int
	err := c.db.QueryRow(`SELECT 1 FROM processed_messages WHERE message_id = ?`, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("client: checking processed message %s: %w", id, err)
	}
	return true, nil
}

// MarkMessageProcessed records an envelope as handled, evicts the oldest ids
// beyond [MaxProcessedMessageIDs], and clears any failure history for it --
// a message that finally succeeded has none worth keeping.
//
// Re-marking an id already present leaves its position alone rather than
// refreshing it, matching the app, where re-adding to an insertion-ordered set
// does not move the entry to the end.
func (c *Client) MarkMessageProcessed(id string) error {
	tx, err := c.db.Begin()
	if err != nil {
		return fmt.Errorf("client: marking %s processed: %w", id, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	if _, err := tx.Exec(`
		INSERT INTO processed_messages (message_id, seq)
		VALUES (?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM processed_messages))
		ON CONFLICT (message_id) DO NOTHING`, id,
	); err != nil {
		return fmt.Errorf("client: marking %s processed: %w", id, err)
	}

	if _, err := tx.Exec(`
		DELETE FROM processed_messages WHERE message_id IN (
			SELECT message_id FROM processed_messages
			 ORDER BY seq DESC LIMIT -1 OFFSET ?
		)`, MaxProcessedMessageIDs,
	); err != nil {
		return fmt.Errorf("client: evicting old processed ids: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM decrypt_failures WHERE message_id = ?`, id); err != nil {
		return fmt.Errorf("client: clearing failure history for %s: %w", id, err)
	}

	return tx.Commit()
}

// RecordDecryptFailure counts one failed decrypt and reports whether this
// envelope should now be given up on -- dropped from the server queue rather
// than retried forever.
//
// Persisted rather than counted in memory because a background push wake is
// torn down between deliveries: a counter living only in RAM restarts at zero
// every time and never reaches the limit, so an envelope that can never be
// decrypted would be refetched and refail on every single wake.
//
// Reaching the limit clears the counter as it reports true, so a caller that
// re-queues the envelope anyway starts counting afresh instead of giving up
// instantly forever after.
func (c *Client) RecordDecryptFailure(id string) (giveUp bool, err error) {
	tx, err := c.db.Begin()
	if err != nil {
		return false, fmt.Errorf("client: recording decrypt failure for %s: %w", id, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	var attempts int
	err = tx.QueryRow(`SELECT attempts FROM decrypt_failures WHERE message_id = ?`, id).Scan(&attempts)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("client: reading decrypt failures for %s: %w", id, err)
	}
	attempts++

	if attempts >= MaxDecryptAttempts {
		if _, err := tx.Exec(`DELETE FROM decrypt_failures WHERE message_id = ?`, id); err != nil {
			return false, fmt.Errorf("client: clearing exhausted failure count for %s: %w", id, err)
		}
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("client: recording decrypt failure for %s: %w", id, err)
		}
		return true, nil
	}

	if _, err := tx.Exec(`
		INSERT INTO decrypt_failures (message_id, attempts, seq)
		VALUES (?, ?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM decrypt_failures))
		ON CONFLICT (message_id) DO UPDATE SET attempts = excluded.attempts`,
		id, attempts,
	); err != nil {
		return false, fmt.Errorf("client: recording decrypt failure for %s: %w", id, err)
	}

	if _, err := tx.Exec(`
		DELETE FROM decrypt_failures WHERE message_id IN (
			SELECT message_id FROM decrypt_failures
			 ORDER BY seq DESC LIMIT -1 OFFSET ?
		)`, MaxProcessedMessageIDs,
	); err != nil {
		return false, fmt.Errorf("client: evicting old decrypt failures: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("client: recording decrypt failure for %s: %w", id, err)
	}
	return false, nil
}

// CountProcessedMessages reports how many ids are currently remembered. For
// tests and diagnostics; nothing in the protocol depends on it.
func (c *Client) CountProcessedMessages() (int, error) {
	var n int
	if err := c.db.QueryRow(`SELECT COUNT(*) FROM processed_messages`).Scan(&n); err != nil {
		return 0, fmt.Errorf("client: counting processed messages: %w", err)
	}
	return n, nil
}
