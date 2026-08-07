package client

import (
	"database/sql"
	"errors"
	"fmt"
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

// PeerSessionHealth returns what is recorded about peer, or nil when nothing
// has gone wrong -- the normal case.
func (c *Client) PeerSessionHealth(peer string) (*PeerSessionHealth, error) {
	var (
		h            PeerSessionHealth
		first, rekey sql.NullString
	)
	err := c.db.QueryRow(`
		SELECT desync_evidence, first_failure_at, last_rekey_at
		  FROM peer_session_health WHERE peer_account_id = ?`, peer,
	).Scan(&h.DesyncEvidence, &first, &rekey)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("client: reading session health for %s: %w", peer, err)
	}
	if h.FirstFailureAt, err = parseTime(first); err != nil {
		return nil, err
	}
	if h.LastRekeyAt, err = parseTime(rekey); err != nil {
		return nil, err
	}
	return &h, nil
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
// table to conversations that exist -- recovery has nowhere to send without
// one anyway, and without the guard a stranger sending undecryptable envelopes
// could grow the database by one row per account id they invent.
func (c *Client) RecordDesyncEvidence(peer string, at time.Time) (recorded bool, err error) {
	tx, err := c.db.Begin()
	if err != nil {
		return false, fmt.Errorf("client: recording desync evidence for %s: %w", peer, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	var one int
	err = tx.QueryRow(`SELECT 1 FROM conversations WHERE peer_account_id = ?`, peer).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("client: checking conversation with %s: %w", peer, err)
	}

	if _, err := tx.Exec(`
		INSERT INTO peer_session_health (peer_account_id, desync_evidence, first_failure_at)
		VALUES (?, 1, ?)
		ON CONFLICT (peer_account_id) DO UPDATE SET
			desync_evidence  = desync_evidence + 1,
			first_failure_at = COALESCE(first_failure_at, excluded.first_failure_at)`,
		peer, at.UTC().Format(time.RFC3339Nano),
	); err != nil {
		return false, fmt.Errorf("client: recording desync evidence for %s: %w", peer, err)
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("client: recording desync evidence for %s: %w", peer, err)
	}
	return true, nil
}

// ClearDesyncEvidence forgets everything recorded about peer's session going
// wrong. Called whenever a message from them decrypts, which is the only proof
// the session works. Drops the re-key spacing along with it, deliberately: a
// healthy session needs no protection against re-keying too often.
func (c *Client) ClearDesyncEvidence(peer string) error {
	if _, err := c.db.Exec(`DELETE FROM peer_session_health WHERE peer_account_id = ?`, peer); err != nil {
		return fmt.Errorf("client: clearing desync evidence for %s: %w", peer, err)
	}
	return nil
}

// RecordAutoRekey notes that an automatic re-key with peer has just been sent:
// the evidence that triggered it is spent, but the timestamp stays to space out
// any further attempt.
func (c *Client) RecordAutoRekey(peer string, at time.Time) error {
	if _, err := c.db.Exec(`
		INSERT INTO peer_session_health (peer_account_id, desync_evidence, first_failure_at, last_rekey_at)
		VALUES (?, 0, NULL, ?)
		ON CONFLICT (peer_account_id) DO UPDATE SET
			desync_evidence  = 0,
			first_failure_at = NULL,
			last_rekey_at    = excluded.last_rekey_at`,
		peer, at.UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("client: recording auto re-key with %s: %w", peer, err)
	}
	return nil
}

// Conversation is the per-peer metadata around a transcript. The transcript
// itself is not here yet -- see the note in migrations/001_initial.sql.
type Conversation struct {
	PeerAccountID    string
	PeerServer       string
	PeerDeviceID     string
	PeerDevicePubKey []byte

	LastActivityAt *time.Time
	HasUnread      bool

	// Blocked mirrors the block on this conversation; blocked_peers is the copy
	// that survives the conversation being deleted.
	Blocked bool

	// PendingApproval marks a conversation opened by a stranger, awaiting the
	// user's accept.
	PendingApproval bool

	PeerDeliveredUpTo        *time.Time
	PeerReadUpTo             *time.Time
	SentDeliveredReceiptUpTo *time.Time
	SentReadReceiptUpTo      *time.Time
}

// Conversation returns the conversation with peer, or nil if there is none.
func (c *Client) Conversation(peer string) (*Conversation, error) {
	rows, err := c.db.Query(conversationSelect+` WHERE peer_account_id = ?`, peer)
	if err != nil {
		return nil, fmt.Errorf("client: reading conversation with %s: %w", peer, err)
	}
	defer rows.Close()
	convos, err := scanConversations(rows)
	if err != nil {
		return nil, err
	}
	if len(convos) == 0 {
		return nil, nil
	}
	return &convos[0], nil
}

// Conversations returns every conversation, most recently active first, so the
// chat list can be drawn without loading a single transcript. That ordering in
// the query rather than in the caller is the whole reason this is a database
// and not one JSON file rewritten per message.
func (c *Client) Conversations() ([]Conversation, error) {
	rows, err := c.db.Query(conversationSelect + ` ORDER BY last_activity_at DESC NULLS LAST, peer_account_id`)
	if err != nil {
		return nil, fmt.Errorf("client: listing conversations: %w", err)
	}
	defer rows.Close()
	return scanConversations(rows)
}

// PutConversation inserts or replaces a conversation.
func (c *Client) PutConversation(convo Conversation) error {
	if _, err := c.db.Exec(`
		INSERT INTO conversations (
			peer_account_id, peer_server, peer_device_id, peer_device_pub_key,
			last_activity_at, has_unread, blocked, pending_approval,
			peer_delivered_up_to, peer_read_up_to,
			sent_delivered_receipt_up_to, sent_read_receipt_up_to
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (peer_account_id) DO UPDATE SET
			peer_server                  = excluded.peer_server,
			peer_device_id               = excluded.peer_device_id,
			peer_device_pub_key          = excluded.peer_device_pub_key,
			last_activity_at             = excluded.last_activity_at,
			has_unread                   = excluded.has_unread,
			blocked                      = excluded.blocked,
			pending_approval             = excluded.pending_approval,
			peer_delivered_up_to         = excluded.peer_delivered_up_to,
			peer_read_up_to              = excluded.peer_read_up_to,
			sent_delivered_receipt_up_to = excluded.sent_delivered_receipt_up_to,
			sent_read_receipt_up_to      = excluded.sent_read_receipt_up_to`,
		convo.PeerAccountID, nullString(convo.PeerServer), nullString(convo.PeerDeviceID),
		convo.PeerDevicePubKey, formatTime(convo.LastActivityAt), convo.HasUnread,
		convo.Blocked, convo.PendingApproval,
		formatTime(convo.PeerDeliveredUpTo), formatTime(convo.PeerReadUpTo),
		formatTime(convo.SentDeliveredReceiptUpTo), formatTime(convo.SentReadReceiptUpTo),
	); err != nil {
		return fmt.Errorf("client: writing conversation with %s: %w", convo.PeerAccountID, err)
	}
	return nil
}

// DeleteConversation removes a conversation. The ratchet session, the known-peer
// mark and any block deliberately survive: clearing a chat must not silently
// unblock someone or turn a known contact back into a stranger.
func (c *Client) DeleteConversation(peer string) error {
	if _, err := c.db.Exec(`DELETE FROM conversations WHERE peer_account_id = ?`, peer); err != nil {
		return fmt.Errorf("client: deleting conversation with %s: %w", peer, err)
	}
	return nil
}

const conversationSelect = `
	SELECT peer_account_id, peer_server, peer_device_id, peer_device_pub_key,
	       last_activity_at, has_unread, blocked, pending_approval,
	       peer_delivered_up_to, peer_read_up_to,
	       sent_delivered_receipt_up_to, sent_read_receipt_up_to
	  FROM conversations`

func scanConversations(rows *sql.Rows) ([]Conversation, error) {
	var out []Conversation
	for rows.Next() {
		var (
			convo                         Conversation
			server, deviceID              sql.NullString
			lastActivity, delivered, read sql.NullString
			sentDelivered, sentRead       sql.NullString
		)
		if err := rows.Scan(
			&convo.PeerAccountID, &server, &deviceID, &convo.PeerDevicePubKey,
			&lastActivity, &convo.HasUnread, &convo.Blocked, &convo.PendingApproval,
			&delivered, &read, &sentDelivered, &sentRead,
		); err != nil {
			return nil, fmt.Errorf("client: scanning conversation: %w", err)
		}
		convo.PeerServer, convo.PeerDeviceID = server.String, deviceID.String

		var err error
		for _, f := range []struct {
			src sql.NullString
			dst **time.Time
		}{
			{lastActivity, &convo.LastActivityAt},
			{delivered, &convo.PeerDeliveredUpTo},
			{read, &convo.PeerReadUpTo},
			{sentDelivered, &convo.SentDeliveredReceiptUpTo},
			{sentRead, &convo.SentReadReceiptUpTo},
		} {
			if *f.dst, err = parseTime(f.src); err != nil {
				return nil, err
			}
		}
		out = append(out, convo)
	}
	return out, rows.Err()
}

// MarkPeerKnown records that this peer is not a stranger -- accepted from a
// message request, or reached out to first. Outlives the conversation.
func (c *Client) MarkPeerKnown(peer string) error {
	if _, err := c.db.Exec(
		`INSERT INTO known_peers (peer_account_id) VALUES (?) ON CONFLICT DO NOTHING`, peer,
	); err != nil {
		return fmt.Errorf("client: marking %s known: %w", peer, err)
	}
	return nil
}

// IsPeerKnown reports whether peer has ever been accepted or reached out to.
func (c *Client) IsPeerKnown(peer string) (bool, error) {
	return c.exists(`SELECT 1 FROM known_peers WHERE peer_account_id = ?`, peer)
}

// BlockPeer blocks peer locally, snapshotting their server for the blocked list
// in case the conversation is later deleted. Purely local: the server is never
// told, and the peer cannot tell they were blocked.
func (c *Client) BlockPeer(peer, server string) error {
	if _, err := c.db.Exec(`
		INSERT INTO blocked_peers (peer_account_id, peer_server) VALUES (?, ?)
		ON CONFLICT (peer_account_id) DO UPDATE SET peer_server = excluded.peer_server`,
		peer, nullString(server),
	); err != nil {
		return fmt.Errorf("client: blocking %s: %w", peer, err)
	}
	return nil
}

// UnblockPeer lifts a local block.
func (c *Client) UnblockPeer(peer string) error {
	if _, err := c.db.Exec(`DELETE FROM blocked_peers WHERE peer_account_id = ?`, peer); err != nil {
		return fmt.Errorf("client: unblocking %s: %w", peer, err)
	}
	return nil
}

// IsPeerBlocked reports whether peer is locally blocked.
func (c *Client) IsPeerBlocked(peer string) (bool, error) {
	return c.exists(`SELECT 1 FROM blocked_peers WHERE peer_account_id = ?`, peer)
}

func (c *Client) exists(query string, args ...any) (bool, error) {
	var one int
	err := c.db.QueryRow(query, args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("client: %w", err)
	}
	return true, nil
}
