package client

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

	path, err := c.store.settingsPath()
	if err != nil {
		return err
	}
	return writeJSON(path, settingsFile{ReceiptsDisabled: !enabled})
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
