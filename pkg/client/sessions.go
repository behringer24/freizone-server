package client

import (
	"fmt"
	"os"
	"strconv"
	"strings"

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

func (k SessionKind) file() (string, error) {
	switch k {
	case Sending:
		return fileSession, nil
	case Inbound:
		return fileInbound, nil
	default:
		return "", fmt.Errorf("client: unknown session kind %q", k)
	}
}

// Session returns the stored session with peer, or nil if there is none.
// A missing session is an ordinary state -- first contact -- not an error.
func (c *Client) Session(peer string, kind SessionKind) (*ratchet.Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.sessionPath(peer, kind)
	if err != nil {
		return nil, err
	}
	var s ratchet.Session
	found, err := readJSON(path, &s)
	if err != nil || !found {
		return nil, err
	}
	return &s, nil
}

// SetSession stores a session, replacing any previous one of the same kind.
//
// One file per peer and kind, which is the point: a session advances on every
// message, and writing it must cost that session and nothing else. A single
// file holding every peer's sessions would rewrite them all for one message --
// the same defect, one level up.
func (c *Client) SetSession(peer string, kind SessionKind, s *ratchet.Session) error {
	if s == nil {
		return fmt.Errorf("client: refusing to store a nil %s session with %s", kind, peer)
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.sessionPath(peer, kind)
	if err != nil {
		return err
	}
	return writeJSON(path, s)
}

// DeleteSession removes a session. Deleting one that is not there is not an
// error -- callers reach for this to guarantee absence, not to assert presence.
func (c *Client) DeleteSession(peer string, kind SessionKind) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.sessionPath(peer, kind)
	if err != nil {
		return err
	}
	return removeFile(path)
}

func (c *Client) sessionPath(peer string, kind SessionKind) (string, error) {
	name, err := kind.file()
	if err != nil {
		return "", err
	}
	return c.store.peerPath(peer, name)
}

// OneTimePrekey is one uploaded prekey pair, held until a peer claims it. The
// server never says which one it handed out.
type OneTimePrekey struct {
	KeyID uint32
	Pub   []byte
	Priv  []byte
}

type prekeyFile struct {
	KeyID uint32 `json:"key_id"`
	Pub   []byte `json:"pub"`
	Priv  []byte `json:"priv"`
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
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.prekeyPath(prekeyName(id))
	if err != nil {
		return nil, err
	}
	var stored prekeyFile
	found, err := readJSON(path, &stored)
	if err != nil || !found {
		return nil, err
	}
	return &OneTimePrekey{KeyID: stored.KeyID, Pub: stored.Pub, Priv: stored.Priv}, nil
}

// PutOneTimePrekeys stores a freshly generated batch, one file each.
//
// Not one file for the pool: consuming a single prekey then rewrites the whole
// pool, and a top-up writes every key that was already there. One file per key
// makes both operations cost exactly what they touch.
func (c *Client) PutOneTimePrekeys(keys []OneTimePrekey) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, k := range keys {
		path, err := c.store.prekeyPath(prekeyName(k.KeyID))
		if err != nil {
			return err
		}
		if err := writeJSON(path, prekeyFile{KeyID: k.KeyID, Pub: k.Pub, Priv: k.Priv}); err != nil {
			return err
		}
	}
	return nil
}

// ConsumeOneTimePrekey drops a prekey from the pool. Call it only once a
// session built from it has decrypted -- see [Client.OneTimePrekey].
func (c *Client) ConsumeOneTimePrekey(id uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path, err := c.store.prekeyPath(prekeyName(id))
	if err != nil {
		return err
	}
	return removeFile(path)
}

// CountOneTimePrekeys reports how many unclaimed prekeys remain, which is what
// decides whether the pool needs topping up.
func (c *Client) CountOneTimePrekeys() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	dir, err := c.store.prekeysDir()
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("client: counting one-time prekeys: %w", err)
	}

	count := 0
	for _, e := range entries {
		// Ignore anything that is not a prekey: a temporary file left by a
		// write that died mid-rename would otherwise be counted as a key the
		// server thinks it can hand out.
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") && !strings.Contains(e.Name(), ".tmp") {
			count++
		}
	}
	return count, nil
}

func prekeyName(id uint32) string {
	return strconv.FormatUint(uint64(id), 10) + ".json"
}
