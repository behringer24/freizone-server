package ratchet

import "errors"

// Decrypt failure codes: short, stable identifiers for the ways
// Session.Decrypt can refuse a message. They exist so a *consumer* can act on
// the distinction — most importantly, tell "this conversation's ratchet has
// desynced, recover it" apart from "this was a harmless redelivery" — without
// matching on error text. Text is for humans and may be reworded at any time;
// these strings are a contract, notably across the mobile app's cgo boundary
// (freizone-app's native/ core marshals FailureCode into its JSON result
// envelope, since a Go error value cannot cross it).
//
// Kept deliberately coarse. A caller only needs to know whether the failure
// implies the session is beyond saving, not which internal step noticed.
const (
	// FailureDuplicateMessage: already handled, drop it. Not a fault at all —
	// delivery is at-least-once (see ErrDuplicateMessage).
	FailureDuplicateMessage = "duplicate_message"

	// FailureAuthentication: the AEAD tag did not verify. With an established
	// session this is *the* desync symptom — the message key this side derived
	// is not the one the sender encrypted under. Cryptographically it cannot
	// happen by chance, so it means either the ratchets have diverged or the
	// ciphertext was corrupted/tampered with in transit.
	FailureAuthentication = "authentication_failed"

	// FailureTooManySkipped: the header claims a message number so far ahead of
	// this side's receiving chain that honouring it would exceed
	// maxSkippedMessageKeys. Either a very long gap in delivery or, again,
	// diverged chains.
	FailureTooManySkipped = "too_many_skipped"

	// FailureNoReceivingChain: a message arrived for a chain this side has not
	// established yet — a straggler from before the current DH step, or state
	// that has been rolled back.
	FailureNoReceivingChain = "no_receiving_chain"
)

// ErrAuthentication reports a message whose AEAD tag did not verify. See
// FailureAuthentication.
var ErrAuthentication = errors.New("ratchet: message authentication failed")

// ErrTooManySkipped reports a header too far ahead of the receiving chain to
// buffer keys for. See FailureTooManySkipped.
var ErrTooManySkipped = errors.New("ratchet: too many skipped messages")

// ErrNoReceivingChain reports a message for a receiving chain that does not
// exist yet. See FailureNoReceivingChain.
var ErrNoReceivingChain = errors.New("ratchet: no receiving chain established yet")

// FailureCode classifies a Session.Decrypt error into one of the Failure*
// codes, or returns "" for anything else (a malformed header, a bad persisted
// key, an unexpected internal error) — cases a caller should log rather than
// interpret. Never treat "" as healthy: it only means "no specific diagnosis".
func FailureCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrDuplicateMessage):
		return FailureDuplicateMessage
	case errors.Is(err, ErrAuthentication):
		return FailureAuthentication
	case errors.Is(err, ErrTooManySkipped):
		return FailureTooManySkipped
	case errors.Is(err, ErrNoReceivingChain):
		return FailureNoReceivingChain
	default:
		return ""
	}
}

// SuggestsDesync reports whether err means the session with this peer is
// unlikely to ever decrypt again, so a caller should stop retrying and
// re-establish it (X3DH) instead. False for a duplicate (nothing is wrong) and
// for an unclassified error (no diagnosis — don't throw a working session away
// on a hunch).
//
// A single occurrence is not proof: a message can fail once because it raced a
// session change that a retry would see. What makes it conclusive is
// *repetition* — decrypting the same envelope against the same session is
// deterministic, so an envelope that has failed this way several times never
// will succeed. Callers are expected to require that repetition; this function
// only says "this kind of failure is the kind that counts".
func SuggestsDesync(err error) bool {
	switch FailureCode(err) {
	case FailureAuthentication, FailureTooManySkipped, FailureNoReceivingChain:
		return true
	default:
		return false
	}
}
