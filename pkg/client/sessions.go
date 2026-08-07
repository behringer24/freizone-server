package client

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/behringer24/freizone-server/pkg/ratchet"
)

// SessionKind distinguishes the session this device sends on from one kept
// only for reading.
type SessionKind string

const (
	// Sending is the session outgoing messages are encrypted with.
	Sending SessionKind = "sending"

	// Inbound is a session kept for READING only. When two sides establish at
	// the same moment, each holds its own initiator session and neither can
	// read the other's; the lower account id's session wins for sending
	// (PROTOCOL.md §5) and the loser is kept here. Discarding it instead
	// strands every message already in flight on it, and those look exactly
	// like a desync.
	Inbound SessionKind = "inbound"
)

// Session returns the stored session with peer, or nil if there is none.
// A missing session is an ordinary state -- first contact -- not an error.
func (c *Client) Session(peer string, kind SessionKind) (*ratchet.Session, error) {
	var raw []byte
	err := c.db.QueryRow(
		`SELECT session FROM sessions WHERE peer_account_id = ? AND kind = ?`,
		peer, string(kind),
	).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("client: reading %s session with %s: %w", kind, peer, err)
	}
	var s ratchet.Session
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("client: decoding %s session with %s: %w", kind, peer, err)
	}
	return &s, nil
}

// SetSession stores a session, replacing any previous one of the same kind.
func (c *Client) SetSession(peer string, kind SessionKind, s *ratchet.Session) error {
	if s == nil {
		return fmt.Errorf("client: refusing to store a nil %s session with %s", kind, peer)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("client: encoding %s session with %s: %w", kind, peer, err)
	}
	if _, err := c.db.Exec(`
		INSERT INTO sessions (peer_account_id, kind, session) VALUES (?, ?, ?)
		ON CONFLICT (peer_account_id, kind) DO UPDATE SET session = excluded.session`,
		peer, string(kind), raw,
	); err != nil {
		return fmt.Errorf("client: writing %s session with %s: %w", kind, peer, err)
	}
	return nil
}

// DeleteSession removes a session. Deleting one that is not there is not an
// error -- callers reach for this to guarantee absence, not to assert presence.
func (c *Client) DeleteSession(peer string, kind SessionKind) error {
	if _, err := c.db.Exec(
		`DELETE FROM sessions WHERE peer_account_id = ? AND kind = ?`,
		peer, string(kind),
	); err != nil {
		return fmt.Errorf("client: deleting %s session with %s: %w", kind, peer, err)
	}
	return nil
}

// OneTimePrekey is one uploaded prekey pair, held until a peer claims it. The
// server never says which one it handed out.
type OneTimePrekey struct {
	KeyID uint32
	Pub   []byte
	Priv  []byte
}

// OneTimePrekey looks a prekey up **without consuming it**, returning nil when
// the pool has no such entry -- an initial referencing one already used, or
// never held, is a routine case rather than a fault.
//
// Looking up and consuming are deliberately separate calls, because the order
// matters and getting it wrong is invisible: the prekey may only be marked used
// once a session built from it has actually decrypted something. Consuming up
// front means every stale, damaged or redelivered initial drains the pool, and
// an empty pool silently downgrades later first contacts to the weaker
// no-one-time-prekey path. cmd/devclient does exactly that today; see
// pkg/conformance's failed-responder-attempt-must-not-burn-prekey.
func (c *Client) OneTimePrekey(id uint32) (*OneTimePrekey, error) {
	otpk := OneTimePrekey{KeyID: id}
	err := c.db.QueryRow(
		`SELECT pub, priv FROM one_time_prekeys WHERE key_id = ?`, id,
	).Scan(&otpk.Pub, &otpk.Priv)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("client: reading one-time prekey %d: %w", id, err)
	}
	return &otpk, nil
}

// PutOneTimePrekeys stores a freshly generated batch, in one transaction so a
// partial write cannot leave keys uploaded to the server but unknown here.
func (c *Client) PutOneTimePrekeys(keys []OneTimePrekey) error {
	if len(keys) == 0 {
		return nil
	}
	tx, err := c.db.Begin()
	if err != nil {
		return fmt.Errorf("client: storing one-time prekeys: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	for _, k := range keys {
		if _, err := tx.Exec(`
			INSERT INTO one_time_prekeys (key_id, pub, priv) VALUES (?, ?, ?)
			ON CONFLICT (key_id) DO UPDATE SET pub = excluded.pub, priv = excluded.priv`,
			k.KeyID, k.Pub, k.Priv,
		); err != nil {
			return fmt.Errorf("client: storing one-time prekey %d: %w", k.KeyID, err)
		}
	}
	return tx.Commit()
}

// ConsumeOneTimePrekey drops a prekey from the pool. Call it only once a
// session built from it has decrypted -- see [Client.OneTimePrekey].
func (c *Client) ConsumeOneTimePrekey(id uint32) error {
	if _, err := c.db.Exec(`DELETE FROM one_time_prekeys WHERE key_id = ?`, id); err != nil {
		return fmt.Errorf("client: consuming one-time prekey %d: %w", id, err)
	}
	return nil
}

// CountOneTimePrekeys reports how many unclaimed prekeys remain, which is what
// decides whether the pool needs topping up.
func (c *Client) CountOneTimePrekeys() (int, error) {
	var n int
	if err := c.db.QueryRow(`SELECT COUNT(*) FROM one_time_prekeys`).Scan(&n); err != nil {
		return 0, fmt.Errorf("client: counting one-time prekeys: %w", err)
	}
	return n, nil
}
