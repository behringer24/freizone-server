package client

import "time"

// Automatic recovery from a ratchet desync: the policy that decides when the
// evidence collected about a peer justifies throwing the local session away and
// re-establishing it.
//
// Kept apart from anything that acts on it, because a policy made of thresholds
// and tie-breaks is the part that can be wrong in ways nothing notices --
// re-keying too eagerly loses queued messages, too reluctantly leaves a
// conversation dead. Here it is a decision over stored evidence and a clock,
// with no session, no server and no network in reach of it.
//
// Recovery is a last resort, not a routine correction: it discards whatever is
// still queued on the old chain, so the bar is "this session provably cannot
// decrypt any more", never "something looked odd once".

const (
	// MinDesyncEvidence is how many distinct envelopes from one peer must be
	// given up on before the session is presumed desynced.
	//
	// One, deliberately. An envelope only counts here after failing
	// [MaxDecryptAttempts] times with a code that means diverged keys, and
	// decrypting the same ciphertext against the same session is
	// deterministic -- so one is already proof rather than suspicion. Waiting
	// for a second would strand every conversation where the peer sent one
	// message and then reasonably waited for an answer.
	MinDesyncEvidence = 1

	// AutoRekeyResponderGrace is how long the higher-id side waits before
	// re-keying on its own initiative.
	//
	// Both sides can detect the same desync, and if both re-key at once each
	// adopts a fresh responder session built from the other's prekey block
	// while discarding the session the other just adopted -- leaving both
	// broken again, symmetrically, round after round. So the order is fixed by
	// comparing account ids: the lower id re-keys immediately, the higher only
	// if that has not already fixed things.
	//
	// Five minutes because the lower-id side's re-key lands within seconds when
	// it is online at all, and any successful decrypt -- including adopting
	// that very re-key -- clears the evidence and cancels this side's attempt.
	// Long enough to make an overlap rare, short enough that a peer who is
	// simply offline does not leave this side waiting indefinitely.
	AutoRekeyResponderGrace = 5 * time.Minute

	// MinAutoRekeyInterval is the minimum spacing between two automatic
	// re-keys with the same peer: the backstop for everything the ordering rule
	// does not catch. If a re-key somehow does not fix the conversation, this
	// bounds the damage to one attempt per interval rather than a tight loop of
	// X3DH establishments, each of which burns one of the peer's one-time
	// prekeys.
	MinAutoRekeyInterval = 15 * time.Minute
)

// ShouldAutoRekey reports whether the evidence recorded about peer justifies
// discarding the local session and re-establishing it.
//
// Answers only the crypto-state question. A caller applies its own eligibility
// rules on top -- a blocked peer, an unaccepted message request, or a
// conversation whose server has federation switched off is never worth sending
// to, whatever the ratchet says.
func (c *Client) ShouldAutoRekey(peer string, now time.Time) (bool, error) {
	health, err := c.PeerSessionHealth(peer)
	if err != nil || health == nil {
		return false, err
	}
	id, err := c.Identity()
	if err != nil {
		return false, err
	}
	return shouldAutoRekey(health, id.AccountID, peer, now.UTC()), nil
}

// shouldAutoRekey is the policy itself: pure, so it can be tested across the
// clock and the tie-break without a store behind it.
//
// myAccountID only breaks the tie over who goes first. Account ids are
// globally unique hashes of a root key, so the comparison is total and both
// sides compute the same answer without exchanging anything.
func shouldAutoRekey(health *PeerSessionHealth, myAccountID, peerAccountID string, now time.Time) bool {
	if health == nil || health.DesyncEvidence < MinDesyncEvidence {
		return false
	}
	if health.LastRekeyAt != nil && now.Sub(*health.LastRekeyAt) < MinAutoRekeyInterval {
		return false
	}
	if myAccountID > peerAccountID {
		// Higher id: hold back and give the other side's re-key time to land.
		if health.FirstFailureAt == nil {
			return false // evidence without a timestamp: wait for one.
		}
		if now.Sub(*health.FirstFailureAt) < AutoRekeyResponderGrace {
			return false
		}
	}
	return true
}
