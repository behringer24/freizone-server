package client

import (
	"time"

	"github.com/behringer24/freizone-server/pkg/profileclaim"
)

// Account settings the protocol itself has to honour, as opposed to the ones
// that only change how a screen looks.
//
// They live here, in the core's own file, rather than being passed in per call
// for one reason that decides it: a background push wake opens this account
// without any of the app's own settings loaded, and a rule the wake does not
// know is a rule that does not hold. Kept out of [Identity] deliberately --
// that is rewritten wholesale every time an app opens an account, so a value
// the caller did not think to pass would be silently reset on the next launch.

// settingsFile is what is on disk. Absent means "never set", which is not the
// same as "off": receipts are on unless somebody turned them off, so the zero
// value has to read as enabled.
type settingsFile struct {
	// ReceiptsDisabled is stored inverted for exactly that reason -- a missing
	// file, an older account directory and a fresh one all decode to false,
	// which is receipts enabled.
	ReceiptsDisabled bool `json:"receipts_disabled,omitempty"`

	// ProfileName is the name this account asserts about itself (SRV-32), and
	// ProfileNameSetAt is when it was last changed. The timestamp is stored
	// rather than taken at send time so that re-stating the same name produces
	// the *same* claim every time: a claim minted fresh per message would be
	// newer than the copy a peer already holds, so every message would displace
	// it and fill their history with identical entries.
	//
	// A name that was set and then cleared keeps its timestamp, because the
	// withdrawal is itself a claim that has to be able to supersede the name it
	// retracts. Both absent means this account has never had one, and nothing
	// is sent at all.
	ProfileName      string `json:"profile_name,omitempty"`
	ProfileNameSetAt string `json:"profile_name_set_at,omitempty"`
}

// ReceiptsEnabled reports whether this account confirms anything to anybody.
//
// Reciprocal by design, and that is the whole of the setting: with it off this
// account neither tells a peer their message arrived or was read, nor records
// what a peer says about its own. Both statuses, not only "read" -- a delivery
// tick still says somebody's device is awake and holding their messages, which
// is the thing being declined.
//
// Watermarks already recorded are left alone. Turning the setting off stops
// what happens next; it does not rewrite what was true before, and a peer whose
// ticks are already showing has already been told.
func (c *Client) ReceiptsEnabled() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	settings, err := c.settingsLocked()
	if err != nil {
		return false, err
	}
	return !settings.ReceiptsDisabled, nil
}

// SetReceiptsEnabled records the account's answer, for every consumer of this
// directory and every process that opens it.
func (c *Client) SetReceiptsEnabled(enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Read-modify-write, not a fresh struct: this file has held more than one
	// setting since SRV-32, and writing a whole one would silently clear the
	// others.
	settings, err := c.settingsLocked()
	if err != nil {
		return err
	}
	settings.ReceiptsDisabled = !enabled

	path, err := c.store.settingsPath()
	if err != nil {
		return err
	}
	return writeJSON(path, settings)
}

// ProfileName is the name this account asserts about itself, and when it was
// last changed. Empty with a non-nil time means it was set and then withdrawn.
func (c *Client) ProfileName() (string, *time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	settings, err := c.settingsLocked()
	if err != nil {
		return "", nil, err
	}
	setAt, err := parseTime(settings.ProfileNameSetAt)
	return settings.ProfileName, setAt, err
}

// SetProfileName records the name and stamps it. Passing an empty name is the
// withdrawal, and it keeps a timestamp for the reason settingsFile explains.
//
// Nothing is sent from here: the claim rides on the next envelope to each peer
// (SRV-32), so a rename costs no delivery of its own and reaches the people it
// is relevant to at the moment it becomes relevant.
func (c *Client) SetProfileName(name string) error {
	name = profileclaim.NormalizeName(name)
	if err := profileclaim.ValidateName(name); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	settings, err := c.settingsLocked()
	if err != nil {
		return err
	}
	if settings.ProfileName == name && settings.ProfileNameSetAt != "" {
		// Re-saving the same name must not restamp it: that would make every
		// peer's stored claim stale and cost a rewrite everywhere for nothing.
		return nil
	}
	settings.ProfileName = name

	// Truncated to the second, because that is the precision the claim's
	// signing bytes carry (PROTOCOL §6) -- and then forced strictly forward of
	// the previous stamp.
	//
	// Without that last step two renames inside one second produce the same
	// timestamp, and since ordering is "strictly newer", the second one is
	// never sent and never adopted: somebody who mistypes their name and
	// corrects it immediately would be stuck with the typo for good, on every
	// peer, with no way to dislodge it. The stamp is really a version number
	// for the claim rather than a time, so stepping it is honest.
	now := time.Now().UTC().Truncate(time.Second)
	if previous, err := parseTime(settings.ProfileNameSetAt); err == nil && previous != nil && !now.After(*previous) {
		now = previous.Add(time.Second)
	}
	settings.ProfileNameSetAt = formatTime(&now)

	path, err := c.store.settingsPath()
	if err != nil {
		return err
	}
	return writeJSON(path, settings)
}

func (c *Client) settingsLocked() (settingsFile, error) {
	path, err := c.store.settingsPath()
	if err != nil {
		return settingsFile{}, err
	}
	var stored settingsFile
	if _, err := readJSON(path, &stored); err != nil {
		return settingsFile{}, err
	}
	return stored, nil
}
