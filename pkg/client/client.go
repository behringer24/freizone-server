// Package client is Freizone's protocol client: the state, persistence and
// decisions that sit between pkg/{ratchet,group,wire,...} and whatever is
// driving them (SRV-23, see docs/design/23-shared-client-core.md).
//
// It exists because that layer was written twice -- once in Go for
// cmd/devclient, once in Dart for freizone-app -- on top of identical
// primitives, so the cryptography could not diverge but every decision around
// it could. Measured against the shared vectors in pkg/conformance, the app
// satisfies all nine and devclient four, so the app's behaviour is the
// specification this package reproduces.
//
// # Shape
//
// This is an ordinary Go library and must stay one: Go types, Go errors,
// context where something blocks. No JSON envelopes, no integer handles, no
// trace of FFI -- freizone-app's native/ wrapper owns all of that and exists
// precisely to absorb it. Encoding the boundary's shape here would hand every
// other consumer an awkward API for the convenience of one.
//
// One *Client per account, no package-level state. The app runs a single
// account per process; a bot bridge may run many, concurrently, and neither
// should have to know about the other. Each account is a separate database
// file, which is what keeps "many identities" from meaning "every query
// carries a discriminator".
package client

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrNoIdentity reports a database that has been created and migrated but not
// yet given an identity. A normal state, not a fault: setup opens the store
// first and generates keys second.
var ErrNoIdentity = errors.New("client: no identity in this database")

// Identity is an account's own key material and per-account settings -- the
// single-row part of the state.
type Identity struct {
	AccountID string
	Server    string

	RootPub  []byte
	RootPriv []byte

	DeviceID   string
	DevicePub  []byte
	DevicePriv []byte

	DHIdentityPub  []byte
	DHIdentityPriv []byte

	SignedPrekeyID   uint32
	SignedPrekeyPub  []byte
	SignedPrekeyPriv []byte

	// NextSignedPrekeyID and NextOneTimePrekeyID are allocation counters, kept
	// so a reissued key never reuses an id a peer may still be referencing.
	NextSignedPrekeyID  uint32
	NextOneTimePrekeyID uint32

	// RecoveryBackupDone is set once the user has written down (or explicitly
	// dismissed) the recovery phrase. True from the start for an account that
	// was itself restored from one.
	RecoveryBackupDone bool

	// PushRegisteredAt and PushMechanism record when this account last told its
	// own server where to send wakes, and how ("fcm", or "unifiedpush:<pkg>").
	// Per account rather than per install: one account's server can be
	// unreachable while another's is fine.
	PushRegisteredAt *time.Time
	PushMechanism    string
}

// Client is one account's state. Safe for concurrent use: every operation is a
// single statement or a transaction, and the underlying pool is held to one
// connection so writes serialise in-process rather than contending on SQLite's
// write lock.
type Client struct {
	db   *sql.DB
	path string
}

// Open opens the account database at path, creating and migrating it if it
// does not exist. A fresh database has no identity yet -- [Client.Identity]
// reports [ErrNoIdentity] until [Client.SetIdentity] is called.
func Open(path string) (*Client, error) {
	db, err := openDB(path)
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Client{db: db, path: path}, nil
}

// Close releases the database. Further use of the Client is an error.
func (c *Client) Close() error {
	if err := c.db.Close(); err != nil {
		return fmt.Errorf("client: closing database: %w", err)
	}
	return nil
}

// Path is the database file this Client was opened from.
func (c *Client) Path() string { return c.path }

// SetIdentity writes the account's key material, replacing whatever was there.
// Used both by first-time setup and by a restore from a recovery phrase, which
// keeps the root key and mints a fresh device key.
func (c *Client) SetIdentity(id Identity) error {
	_, err := c.db.Exec(`
		INSERT INTO identity (
			id, account_id, server, root_pub, root_priv,
			device_id, device_pub, device_priv,
			dh_identity_pub, dh_identity_priv,
			signed_prekey_id, signed_prekey_pub, signed_prekey_priv,
			next_signed_prekey_id, next_otpk_key_id,
			recovery_backup_done, push_registered_at, push_mechanism
		) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			account_id            = excluded.account_id,
			server                = excluded.server,
			root_pub              = excluded.root_pub,
			root_priv             = excluded.root_priv,
			device_id             = excluded.device_id,
			device_pub            = excluded.device_pub,
			device_priv           = excluded.device_priv,
			dh_identity_pub       = excluded.dh_identity_pub,
			dh_identity_priv      = excluded.dh_identity_priv,
			signed_prekey_id      = excluded.signed_prekey_id,
			signed_prekey_pub     = excluded.signed_prekey_pub,
			signed_prekey_priv    = excluded.signed_prekey_priv,
			next_signed_prekey_id = excluded.next_signed_prekey_id,
			next_otpk_key_id      = excluded.next_otpk_key_id,
			recovery_backup_done  = excluded.recovery_backup_done,
			push_registered_at    = excluded.push_registered_at,
			push_mechanism        = excluded.push_mechanism`,
		id.AccountID, id.Server, id.RootPub, id.RootPriv,
		id.DeviceID, id.DevicePub, id.DevicePriv,
		id.DHIdentityPub, id.DHIdentityPriv,
		id.SignedPrekeyID, id.SignedPrekeyPub, id.SignedPrekeyPriv,
		id.NextSignedPrekeyID, id.NextOneTimePrekeyID,
		id.RecoveryBackupDone, formatTime(id.PushRegisteredAt), nullString(id.PushMechanism),
	)
	if err != nil {
		return fmt.Errorf("client: writing identity: %w", err)
	}
	return nil
}

// Identity reads the account's key material, or [ErrNoIdentity] if setup has
// not run yet.
func (c *Client) Identity() (Identity, error) {
	var (
		id           Identity
		pushAt       sql.NullString
		pushMech     sql.NullString
		dhPub, dhPri []byte
		spkPub, spkP []byte
	)
	err := c.db.QueryRow(`
		SELECT account_id, server, root_pub, root_priv,
		       device_id, device_pub, device_priv,
		       dh_identity_pub, dh_identity_priv,
		       signed_prekey_id, signed_prekey_pub, signed_prekey_priv,
		       next_signed_prekey_id, next_otpk_key_id,
		       recovery_backup_done, push_registered_at, push_mechanism
		  FROM identity WHERE id = 1`,
	).Scan(
		&id.AccountID, &id.Server, &id.RootPub, &id.RootPriv,
		&id.DeviceID, &id.DevicePub, &id.DevicePriv,
		&dhPub, &dhPri,
		&id.SignedPrekeyID, &spkPub, &spkP,
		&id.NextSignedPrekeyID, &id.NextOneTimePrekeyID,
		&id.RecoveryBackupDone, &pushAt, &pushMech,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Identity{}, ErrNoIdentity
	}
	if err != nil {
		return Identity{}, fmt.Errorf("client: reading identity: %w", err)
	}

	id.DHIdentityPub, id.DHIdentityPriv = dhPub, dhPri
	id.SignedPrekeyPub, id.SignedPrekeyPriv = spkPub, spkP
	id.PushMechanism = pushMech.String
	if pushAt.Valid {
		t, err := time.Parse(time.RFC3339Nano, pushAt.String)
		if err != nil {
			return Identity{}, fmt.Errorf("client: parsing push_registered_at: %w", err)
		}
		id.PushRegisteredAt = &t
	}
	return id, nil
}

// --- shared helpers --------------------------------------------------------

// formatTime renders an optional instant for storage. UTC and RFC3339Nano
// throughout, so string ordering matches chronological ordering and a value
// written here reads back identically.
func formatTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s sql.NullString) (*time.Time, error) {
	if !s.Valid {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s.String)
	if err != nil {
		return nil, fmt.Errorf("client: parsing timestamp %q: %w", s.String, err)
	}
	return &t, nil
}

// nullString stores "" as SQL NULL, so "unset" has one representation rather
// than two.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
