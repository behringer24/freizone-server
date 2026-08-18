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
// should have to know about the other. Each account is a separate directory,
// which is what keeps "many identities" from meaning "every read carries a
// discriminator".
//
// Storage is plain files -- see store.go for what that costs and buys, and
// layout.go for the shape and the rule it keeps.
package client

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"
)

// ErrNoIdentity reports an account directory that exists but has not been given
// an identity. A normal state, not a fault: setup opens the store first and
// generates keys second.
var ErrNoIdentity = errors.New("client: no identity in this account")

// Identity is an account's own key material and per-account settings.
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

// Client is one account's state.
//
// Safe for concurrent use. A single mutex serialises everything, which is the
// right trade here: the work behind it is a few small file operations, and one
// account is driven by one app or one bot identity rather than by contending
// writers. Several accounts run several Clients over several directories and
// never meet.
type Client struct {
	mu    sync.Mutex
	store *store
	path  string

	// key is the resolved form of path, and the registry entry this Client
	// belongs to -- see lock.go. Held rather than recomputed so Close cannot
	// release a different entry than Open took, however the caller spelled the
	// directory.
	key string

	// processedIDs and processedOrder mirror the handled-message log in memory:
	// bounded to MaxProcessedMessageIDs, checked on every incoming envelope, and
	// far too hot to read from disk each time. The log on disk is append-only,
	// so persisting one more id costs one line no matter how long the history.
	processedIDs   map[string]bool
	processedOrder []string
	processedLines int

	// failures is the decrypt-failure count per message. Held in memory and
	// written only when it actually changes -- which is rare, and specifically
	// not on the success path, where the common case is "this id was never in
	// here" and must cost no write at all.
	failures     map[string]int
	failureOrder []string

	// peerLocks serialise the read-modify-write cycles around one peer's
	// session -- see Client.lockPeer. Guarded by mu, held without it.
	peerLocks map[string]*sync.Mutex

	// media is where attachment bytes live, which is deliberately not the
	// account directory by default's own choice -- see media.go.
	media mediaStore
}

// Options configure an account beyond where it lives. The zero value is what
// [Open] uses.
type Options struct {
	// MediaPath is where attachment bytes are stored, defaulting to a "media"
	// directory inside the account. Separable because pictures are the one
	// thing here that is large, disposable and platform-opinionated: a phone
	// may want them in storage the system can reclaim, a server on another
	// disk, a bot nowhere in particular. See media.go.
	MediaPath string
}

// Open opens the account directory at path, creating it if it does not exist.
// A fresh account has no identity yet -- [Client.Identity] reports
// [ErrNoIdentity] until [Client.SetIdentity] is called.
//
// Opening also settles anything the previous process left mid-send: a message
// still marked pending belonged to a send that cannot still be running, so it
// becomes a failure to retry rather than a spinner nobody will ever resolve.
//
// The account is owned for as long as it is open. A second process gets
// [ErrAccountInUse]; a second opener *in this process* gets the same Client
// back, and the account is released when the last of them closes it. Both
// halves are explained in lock.go.
func Open(path string) (*Client, error) { return OpenWith(path, Options{}) }

// OpenWith is [Open] with the settings that are not the account's location.
func OpenWith(path string, opts Options) (*Client, error) {
	mediaPath := opts.MediaPath
	if mediaPath == "" {
		mediaPath = filepath.Join(path, dirMedia)
	}

	entry, first, err := acquireAccount(path, mediaPath)
	if err != nil {
		return nil, err
	}
	if !first {
		return entry.client, nil
	}

	// From here on the account is held, so every failure has to give it back
	// or the directory stays locked until the process exits.
	c, err := newClient(path, mediaPath)
	if err != nil {
		if release := releaseAccount(accountKey(path)); release != nil {
			return nil, errors.Join(err, release)
		}
		return nil, err
	}
	entry.client = c
	return c, nil
}

func newClient(path, mediaPath string) (*Client, error) {
	st, err := openStore(path)
	if err != nil {
		return nil, err
	}
	c := &Client{
		store:     st,
		path:      path,
		key:       accountKey(path),
		peerLocks: make(map[string]*sync.Mutex),
		media:     mediaStore{root: mediaPath},
	}

	if err := c.loadProcessed(); err != nil {
		return nil, err
	}
	if err := c.loadFailures(); err != nil {
		return nil, err
	}
	if err := c.failInFlightSends(); err != nil {
		return nil, err
	}
	return c, nil
}

// Close gives up this caller's hold on the account. Nothing is buffered --
// every write was synced by the time the call that made it returned -- so what
// this releases is the ownership, and only once every opener in this process
// has let go.
//
// Safe to call more than once, and safe to call on a Client another opener is
// still using: that is the whole point of counting them.
func (c *Client) Close() error { return releaseAccount(c.key) }

// Path is the account directory this Client was opened from.
func (c *Client) Path() string { return c.path }

// identityFile is the stored form. Kept separate from [Identity] so the wire
// names are fixed independently of the Go field names.
type identityFile struct {
	AccountID string `json:"account_id"`
	Server    string `json:"server"`

	RootPub  []byte `json:"root_pub"`
	RootPriv []byte `json:"root_priv"`

	DeviceID   string `json:"device_id"`
	DevicePub  []byte `json:"device_pub"`
	DevicePriv []byte `json:"device_priv"`

	DHIdentityPub  []byte `json:"dh_identity_pub,omitempty"`
	DHIdentityPriv []byte `json:"dh_identity_priv,omitempty"`

	SignedPrekeyID   uint32 `json:"signed_prekey_id,omitempty"`
	SignedPrekeyPub  []byte `json:"signed_prekey_pub,omitempty"`
	SignedPrekeyPriv []byte `json:"signed_prekey_priv,omitempty"`

	NextSignedPrekeyID  uint32 `json:"next_signed_prekey_id,omitempty"`
	NextOneTimePrekeyID uint32 `json:"next_otpk_key_id,omitempty"`

	RecoveryBackupDone bool   `json:"recovery_backup_done,omitempty"`
	PushRegisteredAt   string `json:"push_registered_at,omitempty"`
	PushMechanism      string `json:"push_mechanism,omitempty"`
}

// SetIdentity writes the account's key material, replacing whatever was there.
// Used both by first-time setup and by a restore from a recovery phrase, which
// keeps the root key and mints a fresh device key.
func (c *Client) SetIdentity(id Identity) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.identityPath()
	if err != nil {
		return err
	}
	stored := identityFile{
		AccountID: id.AccountID, Server: id.Server,
		RootPub: id.RootPub, RootPriv: id.RootPriv,
		DeviceID: id.DeviceID, DevicePub: id.DevicePub, DevicePriv: id.DevicePriv,
		DHIdentityPub: id.DHIdentityPub, DHIdentityPriv: id.DHIdentityPriv,
		SignedPrekeyID: id.SignedPrekeyID, SignedPrekeyPub: id.SignedPrekeyPub,
		SignedPrekeyPriv:   id.SignedPrekeyPriv,
		NextSignedPrekeyID: id.NextSignedPrekeyID, NextOneTimePrekeyID: id.NextOneTimePrekeyID,
		RecoveryBackupDone: id.RecoveryBackupDone, PushMechanism: id.PushMechanism,
	}
	if id.PushRegisteredAt != nil {
		stored.PushRegisteredAt = id.PushRegisteredAt.UTC().Format(time.RFC3339Nano)
	}
	return writeJSON(path, stored)
}

// Identity reads the account's key material, or [ErrNoIdentity] if setup has
// not run yet.
func (c *Client) Identity() (Identity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.identityLocked()
}

func (c *Client) identityLocked() (Identity, error) {
	path, err := c.store.identityPath()
	if err != nil {
		return Identity{}, err
	}
	var stored identityFile
	found, err := readJSON(path, &stored)
	if err != nil {
		return Identity{}, err
	}
	if !found {
		return Identity{}, ErrNoIdentity
	}

	id := Identity{
		AccountID: stored.AccountID, Server: stored.Server,
		RootPub: stored.RootPub, RootPriv: stored.RootPriv,
		DeviceID: stored.DeviceID, DevicePub: stored.DevicePub, DevicePriv: stored.DevicePriv,
		DHIdentityPub: stored.DHIdentityPub, DHIdentityPriv: stored.DHIdentityPriv,
		SignedPrekeyID: stored.SignedPrekeyID, SignedPrekeyPub: stored.SignedPrekeyPub,
		SignedPrekeyPriv:   stored.SignedPrekeyPriv,
		NextSignedPrekeyID: stored.NextSignedPrekeyID, NextOneTimePrekeyID: stored.NextOneTimePrekeyID,
		RecoveryBackupDone: stored.RecoveryBackupDone, PushMechanism: stored.PushMechanism,
	}
	if stored.PushRegisteredAt != "" {
		t, err := time.Parse(time.RFC3339Nano, stored.PushRegisteredAt)
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
func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil, fmt.Errorf("client: parsing timestamp %q: %w", s, err)
	}
	return &t, nil
}
