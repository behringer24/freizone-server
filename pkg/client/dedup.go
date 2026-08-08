package client

import "encoding/json"

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

	// processedCompactAt is when the append-only log is rewritten: at twice the
	// bound, so half of every rewrite's cost is already amortised over that many
	// messages. Compaction is the only whole-file write on this path, and it
	// must stay off the per-message one -- rewriting the log on every message is
	// exactly the O(n)-per-message defect this store exists to remove.
	processedCompactAt = 2 * MaxProcessedMessageIDs
)

// processedRecord is one line of the handled-message log.
type processedRecord struct {
	ID string `json:"id"`
}

// loadProcessed replays the log into memory and compacts it if it has grown.
func (c *Client) loadProcessed() error {
	path, err := c.store.processedPath()
	if err != nil {
		return err
	}

	c.processedIDs = make(map[string]bool, MaxProcessedMessageIDs)
	c.processedOrder = make([]string, 0, MaxProcessedMessageIDs)
	c.processedLines = 0

	// First appearance wins the position, so re-marking an id already present
	// leaves it where it was -- matching the app, where re-adding to an
	// insertion-ordered set moves nothing.
	if err := readLines(path, func(raw []byte) error {
		var rec processedRecord
		if err := json.Unmarshal(raw, &rec); err != nil || rec.ID == "" {
			return nil
		}
		c.processedLines++
		if !c.processedIDs[rec.ID] {
			c.processedIDs[rec.ID] = true
			c.processedOrder = append(c.processedOrder, rec.ID)
		}
		return nil
	}); err != nil {
		return err
	}

	c.evictProcessed()
	if c.processedLines > processedCompactAt {
		return c.compactProcessed()
	}
	return nil
}

// evictProcessed drops the oldest ids past the bound, in memory.
func (c *Client) evictProcessed() {
	if len(c.processedOrder) <= MaxProcessedMessageIDs {
		return
	}
	drop := len(c.processedOrder) - MaxProcessedMessageIDs
	for _, id := range c.processedOrder[:drop] {
		delete(c.processedIDs, id)
	}
	c.processedOrder = append([]string(nil), c.processedOrder[drop:]...)
}

// compactProcessed rewrites the log to exactly what is still remembered.
func (c *Client) compactProcessed() error {
	path, err := c.store.processedPath()
	if err != nil {
		return err
	}
	if err := rewriteLog(path, func(write func(any) error) error {
		for _, id := range c.processedOrder {
			if err := write(processedRecord{ID: id}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	c.processedLines = len(c.processedOrder)
	return nil
}

// WasMessageProcessed reports whether this envelope has already been handled.
//
// The check that has to happen before anything else touches the ratchet.
// Delivery is at-least-once and the server keeps a message queued until the
// client deletes it -- a delete that is lost when the app is killed, goes
// offline, or when a push wake races the live stream. Processing an envelope
// twice advances the ratchet twice for one message, and a redelivered X3DH
// initial rebuilds the responder session over the one that has since advanced.
//
// Answered from memory: it runs for every incoming envelope, and a disk read
// per envelope would be a needless cost on the hottest path there is.
func (c *Client) WasMessageProcessed(id string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.processedIDs[id], nil
}

// MarkMessageProcessed records an envelope as handled and clears any failure
// history for it -- a message that finally succeeded has none worth keeping.
//
// Costs one appended line, whatever the history behind it. The failure history
// is touched only when there actually is one, which on the success path is
// almost never: the common case must not pay for the rare one.
func (c *Client) MarkMessageProcessed(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.processedIDs[id] {
		path, err := c.store.processedPath()
		if err != nil {
			return err
		}
		if err := appendLine(path, processedRecord{ID: id}); err != nil {
			return err
		}
		c.processedIDs[id] = true
		c.processedOrder = append(c.processedOrder, id)
		c.processedLines++
		c.evictProcessed()

		if c.processedLines > processedCompactAt {
			if err := c.compactProcessed(); err != nil {
				return err
			}
		}
	}

	if _, failed := c.failures[id]; failed {
		delete(c.failures, id)
		return c.saveFailures()
	}
	return nil
}

// CountProcessedMessages reports how many ids are currently remembered. For
// tests and diagnostics; nothing in the protocol depends on it.
func (c *Client) CountProcessedMessages() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.processedOrder), nil
}

// --- decrypt failures -------------------------------------------------------

// failuresFile is the stored form: a plain map, bounded by the same limit as
// the processed ids, so it never grows with history and a whole-file write is
// the right shape for it.
type failuresFile struct {
	Order  []string       `json:"order"`
	Counts map[string]int `json:"counts"`
}

func (c *Client) loadFailures() error {
	path, err := c.store.failuresPath()
	if err != nil {
		return err
	}
	var stored failuresFile
	if _, err := readJSON(path, &stored); err != nil {
		return err
	}
	c.failures = stored.Counts
	if c.failures == nil {
		c.failures = make(map[string]int)
	}
	c.failureOrder = stored.Order
	return nil
}

func (c *Client) saveFailures() error {
	path, err := c.store.failuresPath()
	if err != nil {
		return err
	}
	// Keep the order list to the entries that still exist, so it cannot grow
	// unboundedly through ids that have since succeeded.
	order := make([]string, 0, len(c.failures))
	for _, id := range c.failureOrder {
		if _, ok := c.failures[id]; ok {
			order = append(order, id)
		}
	}
	c.failureOrder = order
	return writeJSON(path, failuresFile{Order: order, Counts: c.failures})
}

// RecordDecryptFailure counts one failed decrypt and reports whether this
// envelope should now be given up on -- dropped from the server queue rather
// than retried forever.
//
// Persisted rather than counted in memory alone because a background push wake
// is torn down between deliveries: a counter living only in RAM restarts at
// zero every time and never reaches the limit, so an envelope that can never be
// decrypted would be refetched and refail on every single wake.
//
// Reaching the limit clears the counter as it reports true, so a caller that
// re-queues the envelope anyway starts counting afresh instead of giving up
// instantly forever after.
func (c *Client) RecordDecryptFailure(id string) (giveUp bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	attempts := c.failures[id] + 1
	if attempts >= MaxDecryptAttempts {
		delete(c.failures, id)
		if err := c.saveFailures(); err != nil {
			return false, err
		}
		return true, nil
	}

	if _, existing := c.failures[id]; !existing {
		c.failureOrder = append(c.failureOrder, id)
	}
	c.failures[id] = attempts

	// Bounded like the processed ids, oldest first, so a peer sending endless
	// undecryptable envelopes cannot grow this without limit.
	for len(c.failureOrder) > MaxProcessedMessageIDs {
		delete(c.failures, c.failureOrder[0])
		c.failureOrder = c.failureOrder[1:]
	}

	if err := c.saveFailures(); err != nil {
		return false, err
	}
	return false, nil
}
