package client

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/behringer24/freizone-server/pkg/ratchet"
	"github.com/behringer24/freizone-server/pkg/wire"
)

// The receive path: everything that happens between an envelope arriving and
// the state it leaves behind.
//
// This is where the two existing implementations drifted apart, which is why
// pkg/conformance exists and why receive_conformance_test.go runs its vectors
// against exactly this file. The decisions here are not obvious ones -- what to
// do with a prekey block that arrives while a session already exists, when a
// failure is evidence of a broken session rather than a lost race, when a
// one-time prekey is spent -- and each of them is wrong in a way that only
// shows up as a conversation that stops working days later.

// The transcript markers for a session that was re-established. Both sides
// show one: the side that reset writes it when it does so, this side when it
// accepts the peer's re-key. Worded apart on purpose -- the user pressed
// something for one of them and nothing at all for the other, and being told
// "you reset this" when you did not is worse than not being told.
const (
	SessionResetMarker   = "Secure session was reset"
	AutomaticRekeyMarker = "Secure session was re-established automatically"
)

// ErrNoSessionMaterial reports an envelope there is nothing to decrypt with:
// no session with this sender, and no prekey block to build one from.
//
// It is the one desync shape that produces no cryptographic error at all --
// this side's session is simply gone while the peer keeps sending into the one
// they still hold -- so it counts as evidence of a desync even though nothing
// failed to verify. Without that, the very case automatic recovery exists for
// would be the one case it never sees.
var ErrNoSessionMaterial = errors.New("client: no session with this peer and no prekey block to start one")

// ReceiveOptions are the caller's context for one envelope. The zero value is
// meaningful: no chat on screen, receipts recorded, clock is now.
type ReceiveOptions struct {
	// OpenChatID is the chat the user is currently looking at, which is the
	// only thing that suppresses a notification. A caller with no screen -- a
	// background push wake, a bot -- leaves it empty, which is always right for
	// them.
	OpenChatID string

	// ReceiptsDisabled drops incoming receipts instead of recording them,
	// mirroring the user's read-receipts setting. Negative because the default
	// is on: a zero ReceiveOptions must behave like the app's default, not like
	// a privacy setting nobody chose.
	ReceiptsDisabled bool

	// Now overrides the clock, for tests. Zero means time.Now().
	Now time.Time
}

// ReceiveResult is what one envelope turned out to be and what was done about
// it. A caller acknowledges the envelope to the server on any result -- and on
// a [DecryptError] with GaveUp set -- but never otherwise.
type ReceiveResult struct {
	PeerAccountID string

	// Content is the decoded payload. Zero for a duplicate, which is not
	// decrypted again: the point of recognising one is that the ratchet must
	// not advance a second time.
	Content Content

	// Duplicate marks an envelope that had already been processed. Nothing is
	// wrong -- delivery is at-least-once -- so it must neither be retried nor
	// counted as evidence of anything.
	Duplicate bool

	// StoredMessageID is the transcript line this produced, empty for the
	// control envelopes -- receipt, re-key, group membership -- that are never
	// stored, and for a blocked peer.s message, which is decrypted and dropped.
	StoredMessageID string

	ShouldNotify bool

	// DeliveredUpTo is the watermark to confirm back to the sender, in *their*
	// clock domain (see Content.SentAt): a receipt says "everything up to this
	// instant", and the two sides can only agree on that if it is stated in the
	// clock the sender used. Nil when there is nothing to confirm.
	DeliveredUpTo *time.Time

	// AdoptedPeerSession: the peer re-keyed, or won the tie-break, and their
	// session is now the one this side sends on.
	AdoptedPeerSession bool

	// InboundSessionKept: this side won the tie-break and keeps the peer's
	// session for reading only, so their in-flight messages are not stranded.
	InboundSessionKept bool

	// Group is set for every group envelope: what folding it changed, or -- for
	// a group message -- which group it belongs to and how far the sender has
	// got. Nil for one-to-one traffic.
	Group *GroupOutcome

	// Blocked: the sender is blocked. The envelope was still decrypted (the
	// ratchet must stay in step, and the server queue must still drain) and
	// then dropped.
	Blocked bool
}

// DecryptError is a failed attempt at one envelope, carrying the decision that
// goes with it. It wraps the underlying error rather than describing it, so
// [ratchet.FailureCode] and [ratchet.SuggestsDesync] still work on it -- losing
// that classification is what makes a harmless redelivery indistinguishable
// from a session that has genuinely diverged.
type DecryptError struct {
	MessageID     string
	PeerAccountID string
	Err           error

	// DesyncEvidence: this failure means diverged keys, so it counts towards
	// re-establishing the session. False for an undiagnosed failure -- damaged
	// JSON, a storage error -- which says nothing about the ratchet, and
	// discarding a working session over one would lose messages for nothing.
	DesyncEvidence bool

	// GaveUp: this envelope has now failed often enough to stop retrying it.
	// A decrypt failure is deterministic -- the same ciphertext against the
	// same session fails identically -- so a poison envelope would otherwise
	// block the queue behind it forever. The caller acknowledges it away.
	GaveUp bool

	// RekeyNeeded: the evidence now justifies discarding the local session and
	// re-establishing it (see [ShouldAutoRekey]). Reported rather than acted
	// on, because acting means sending.
	RekeyNeeded bool
}

func (e *DecryptError) Error() string {
	return fmt.Sprintf("client: message %s from %s: %v", e.MessageID, e.PeerAccountID, e.Err)
}

func (e *DecryptError) Unwrap() error { return e.Err }

// HandleIncoming decrypts one envelope and applies everything that follows
// from it: session adoption, the processed-id record, desync accounting, the
// transcript, and whether the user should be told.
//
// Deliberately does no network I/O. The envelope is not acknowledged and
// nothing is fetched -- a caller processing a batch acknowledges each one
// itself, and one that has just been woken by a push does the same work with
// nothing to send from. That also keeps this callable while offline, which is
// exactly when a queue is longest.
//
// Group envelopes are folded in here too, not handed up. The ratchet has
// advanced and the id is marked by the time the payload is even read, so an
// envelope nobody folds takes its facts with it -- which is why this has to
// work with nothing else attached, including on a background wake.
func (c *Client) HandleIncoming(msg IncomingMessage, opts ReceiveOptions) (ReceiveResult, error) {
	peer := msg.SenderAccountID
	unlock := c.lockPeer(peer)
	defer unlock()

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	res, err := c.receive(msg, opts, now)
	if err == nil {
		return res, nil
	}
	return res, c.giveUpOnEnvelope(msg, now, err)
}

// giveUpOnEnvelope counts one failed attempt and decides what follows from it.
//
// The evidence is recorded only once the envelope is given up on, not on every
// attempt: the same envelope retried three times is one broken envelope, and
// counting each retry would reach any threshold on a single message.
func (c *Client) giveUpOnEnvelope(msg IncomingMessage, now time.Time, cause error) error {
	fail := &DecryptError{
		MessageID:     msg.MessageID,
		PeerAccountID: msg.SenderAccountID,
		Err:           cause,
		// Both shapes of "the session has diverged": one the ratchet
		// diagnosed, and one that produced no error at all because there was
		// nothing left to try (see ErrNoSessionMaterial).
		DesyncEvidence: ratchet.SuggestsDesync(cause) || errors.Is(cause, ErrNoSessionMaterial),
	}

	giveUp, err := c.RecordDecryptFailure(msg.MessageID)
	if err != nil {
		return errors.Join(fail, err)
	}
	fail.GaveUp = giveUp
	if !giveUp || !fail.DesyncEvidence {
		return fail
	}

	if _, err := c.RecordDesyncEvidence(msg.SenderAccountID, now); err != nil {
		return errors.Join(fail, err)
	}
	rekey, err := c.ShouldAutoRekey(msg.SenderAccountID, now)
	if err != nil {
		return errors.Join(fail, err)
	}
	fail.RekeyNeeded = rekey
	return fail
}

// receive is HandleIncoming's body, minus the failure accounting. Every path
// out of here either succeeded or must be counted, which is what keeps a
// poison envelope from blocking the queue behind it: an error escaping is not
// a special case, it is the input to that decision.
func (c *Client) receive(msg IncomingMessage, opts ReceiveOptions, now time.Time) (ReceiveResult, error) {
	peer := msg.SenderAccountID
	res := ReceiveResult{PeerAccountID: peer}

	// Handled before: acknowledge it without touching the ratchet. Processing
	// it twice is actively destructive -- it advances the ratchet a second time
	// for one message, and a redelivered prekey block would rebuild the
	// responder session on top of the advanced one, which loses the
	// conversation rather than merely repeating a line.
	seen, err := c.WasMessageProcessed(msg.MessageID)
	if err != nil {
		return res, err
	}
	if seen {
		res.Duplicate = true
		return res, nil
	}

	dec, effect, err := c.decrypt(msg)
	if err != nil {
		if errors.Is(err, ratchet.ErrDuplicateMessage) {
			// The ratchet has already moved past this exact envelope: it was
			// decrypted before and the acknowledgement was lost. Only
			// reachable once the processed-id above has been evicted by age,
			// since that check catches the common case first -- and distinct
			// from every other failure, because nothing is wrong.
			if err := c.MarkMessageProcessed(msg.MessageID); err != nil {
				return res, err
			}
			res.Duplicate = true
			return res, nil
		}
		return res, err
	}
	res.AdoptedPeerSession = effect.adoptedPeer
	res.InboundSessionKept = effect.keepOwnSending

	// Recorded the moment the ratchet has actually advanced -- before any of
	// the paths below diverge, and never for a failed decrypt, which leaves the
	// session untouched and must stay retryable.
	if err := c.MarkMessageProcessed(msg.MessageID); err != nil {
		return res, err
	}
	// A decrypt that worked is the only proof this session is healthy, so
	// every piece of desync evidence about this peer is now void -- including
	// evidence that had already crossed the threshold, which is what stops a
	// re-key firing after the conversation has recovered on its own.
	if err := c.ClearDesyncEvidence(peer); err != nil {
		return res, err
	}
	// A one-time prekey is spent only now that a session built from it has
	// actually decrypted something -- never on an attempt that failed.
	if effect.consumePrekey != nil {
		if err := c.ConsumeOneTimePrekey(*effect.consumePrekey); err != nil {
			return res, err
		}
	}

	// Blocked and known are read from the lists, not from the conversation:
	// a conversation deleted and recreated must pick the right state back up
	// rather than treat a blocked or long-known peer as a stranger.
	blocked, err := c.IsPeerBlocked(peer)
	if err != nil {
		return res, err
	}
	res.Blocked = blocked

	// The peer re-keyed and it was accepted above: mark it in the transcript
	// before whatever this envelope turns out to carry. Here rather than beside
	// the stored message, because a re-key routinely arrives on an *invisible*
	// envelope -- the automatic path sends a bare signal -- and this marker is
	// then the only thing there is to show for it. Deliberately does not touch
	// LastActivityAt: recovering a session is maintenance, not activity, and
	// must not jump the chat to the top of the list.
	if effect.adoptedPeer && !blocked {
		if err := c.markRekeyInTranscript(peer, dec.content, now); err != nil {
			return res, err
		}
	}

	res.Content = dec.content
	switch dec.content.Kind {
	case ContentRekey:
		// Nothing further to do: its whole purpose was the fresh prekey block
		// on the envelope around it, which the code above has already acted on.
		// Never stored, never notified -- but still acknowledged like anything
		// else that was processed.
		return res, nil

	case ContentGroupControl:
		// Acted on here rather than handed up, and that is not a preference:
		// the ratchet has advanced and the id is marked, so an envelope
		// nobody folds takes its facts with it.
		//
		// A blocked sender is no exception. Membership is not a message --
		// refusing their facts would leave this device with a view of the
		// group that disagrees with everyone else's, which is a worse outcome
		// than hearing a fact from somebody whose chat you have muted.
		outcome, err := c.ApplyGroupControl(dec.content, peer, now)
		if err != nil {
			return res, err
		}
		res.Group = &outcome
		// The one group event worth interrupting somebody for, and only when
		// they are not already looking at it.
		res.ShouldNotify = outcome.Invited && opts.OpenChatID != outcome.GroupID
		return res, nil

	case ContentGroupText:
		if err := c.RecordGroupPeerStateHash(dec.content.GroupID, peer, dec.content.StateHash); err != nil {
			return res, err
		}
		res.Group = &GroupOutcome{
			GroupID:       dec.content.GroupID,
			PeerStateHash: dec.content.StateHash,
		}
		if blocked {
			// Decrypted so the ratchet and the queue stay clean, then dropped
			// -- but unlike a blocked peer's one-to-one message, not without a
			// trace. See Client.recordBlockedGroupMessage.
			return res, c.recordBlockedGroupMessage(dec.content.GroupID, peer, now)
		}
		stored, err := c.storeGroupMessage(dec.content, peer, now, opts.OpenChatID)
		if err != nil {
			return res, err
		}
		res.StoredMessageID = stored.ID
		res.ShouldNotify = opts.OpenChatID != dec.content.GroupID
		// Its own field rather than DeliveredUpTo: a receipt travels over a
		// *conversation*, so reporting a group anchor through the one-to-one
		// field would confirm that member's unrelated direct messages.
		if stored.SenderSentAt != nil {
			res.Group.DeliveredUpTo = stored.SenderSentAt
		} else {
			at := now
			res.Group.DeliveredUpTo = &at
		}
		return res, nil

	case ContentReceipt:
		if dec.content.ReceiptGroupID != "" {
			// One member telling *us*, the author, how far they have got with
			// our messages in that group. Filed against them and never passed
			// on: who has read what stays between reader and author.
			res.Group = &GroupOutcome{GroupID: dec.content.ReceiptGroupID}
			if opts.ReceiptsDisabled {
				return res, nil
			}
			return res, c.recordMemberReceipt(dec.content.ReceiptGroupID, peer, dec.content)
		}
		if !opts.ReceiptsDisabled {
			if err := c.recordReceipt(peer, dec.content); err != nil {
				return res, err
			}
		}
		return res, nil
	}

	return c.storeIncomingText(res, msg, dec.content, opts, now)
}

// decryptResult is one successful decrypt and what it took.
type decryptResult struct {
	content Content
}

// sessionEffect is what the decrypt did to the sessions held for a peer, kept
// apart from the decrypt itself so the write-back happens in exactly one place.
type sessionEffect struct {
	// adoptedPeer: the peer's session replaced the one this side sends on.
	adoptedPeer bool
	// keepOwnSending: their session was used for reading only, because this
	// side's own won the tie-break. Stored as [Inbound].
	keepOwnSending bool
	// consumePrekey names the one-time prekey a responder session was built
	// from, once that session has proved itself by decrypting.
	consumePrekey *uint32
}

// decrypt opens one envelope, choosing between the sessions available and
// deciding which of them this side keeps.
//
// Nothing is written before something has decrypted. Every attempt below works
// on a session value read from the store, and [ratchet.Session.Decrypt] commits
// to its receiver only on success, so a failed attempt cannot damage a working
// session -- which is what lets a merely redelivered prekey block be tried and
// then abandoned.
func (c *Client) decrypt(msg IncomingMessage) (decryptResult, sessionEffect, error) {
	peer := msg.SenderAccountID
	var effect sessionEffect

	env, err := wire.ParseEnvelope(msg.Payload)
	if err != nil {
		return decryptResult{}, effect, fmt.Errorf("client: parsing envelope: %w", err)
	}
	header, err := env.Header.ToHeader()
	if err != nil {
		return decryptResult{}, effect, fmt.Errorf("client: reading envelope header: %w", err)
	}
	ciphertext, err := env.DecodeCiphertext()
	if err != nil {
		return decryptResult{}, effect, fmt.Errorf("client: decoding ciphertext: %w", err)
	}
	var initial *ratchet.InitialMessage
	if env.Prekey != nil {
		if initial, err = env.Prekey.ToInitialMessage(); err != nil {
			return decryptResult{}, effect, fmt.Errorf("client: reading prekey block: %w", err)
		}
	}

	id, err := c.Identity()
	if err != nil {
		return decryptResult{}, effect, err
	}
	dhPriv, err := ecdh.X25519().NewPrivateKey(id.DHIdentityPriv)
	if err != nil {
		return decryptResult{}, effect, fmt.Errorf("client: reading own identity key: %w", err)
	}
	spkPriv, err := ecdh.X25519().NewPrivateKey(id.SignedPrekeyPriv)
	if err != nil {
		return decryptResult{}, effect, fmt.Errorf("client: reading own signed prekey: %w", err)
	}

	// Looked up but NOT consumed: a responder attempt that fails -- a stale or
	// redelivered prekey block -- must not cost a prekey. See
	// Client.OneTimePrekey.
	var otpkPriv *ecdh.PrivateKey
	var otpkID *uint32
	if initial != nil && initial.OneTimePrekeyID != nil {
		otpk, err := c.OneTimePrekey(*initial.OneTimePrekeyID)
		if err != nil {
			return decryptResult{}, effect, err
		}
		if otpk != nil {
			if otpkPriv, err = ecdh.X25519().NewPrivateKey(otpk.Priv); err != nil {
				return decryptResult{}, effect, fmt.Errorf("client: reading one-time prekey %d: %w", otpk.KeyID, err)
			}
			keyID := otpk.KeyID
			otpkID = &keyID
		}
	}

	session, err := c.Session(peer, Sending)
	if err != nil {
		return decryptResult{}, effect, err
	}

	// decrypted rather than a nil check on plaintext: an empty message body is
	// a legitimate decrypt, and "it came back empty" must not read as "nothing
	// opened it".
	var plaintext []byte
	var decrypted bool
	// Set only on the one path that discards its own error deliberately (see
	// the "initial != nil" case below) so the fallback that follows can still
	// report why the prekey block it tried first did not apply, instead of
	// only the unrelated failure of the session it fell back to.
	var initialAttemptErr error
	switch {
	case session == nil:
		// First contact: a prekey block is the only way to start a session.
		if initial == nil {
			return decryptResult{}, effect, ErrNoSessionMaterial
		}
		fresh, err := ratchet.RespondToSession(dhPriv, spkPriv, otpkPriv, initial)
		if err != nil {
			return decryptResult{}, effect, fmt.Errorf("client: responding to first contact: %w", err)
		}
		if plaintext, err = fresh.Decrypt(header, ciphertext); err != nil {
			return decryptResult{}, effect, err
		}
		decrypted = true
		session = fresh
		effect.consumePrekey = otpkID

	case initial != nil:
		// A session exists, yet the peer sent a fresh prekey block. That is
		// ambiguous: either they threw their session away and re-keyed, or the
		// two sides simply established one at the same moment -- rare between
		// two people talking, routine in a group where a joining member reaches
		// for everyone at once and everyone reaches back. The two need opposite
		// handling, so a sender now says which it is in the prekey block; only
		// one predating that field leaves it to be inferred.
		fresh, ferr := ratchet.RespondToSession(dhPriv, spkPriv, otpkPriv, initial)
		if ferr == nil {
			plaintext, ferr = fresh.Decrypt(header, ciphertext)
		}
		if ferr != nil {
			// Not a re-key that applies to us -- a redelivered or stale prekey
			// block, *or* this account's own published pool has a hole (a
			// claimed one-time prekey this side never minted -- see SRV-23's
			// Dart/core prekey-minting overlap). Nothing has been touched;
			// fall through to the session we already hold. Kept rather than
			// discarded: if that fallback also fails, this is likely the more
			// informative of the two -- a generic "authentication failed"
			// from the old session says nothing about a poisoned prekey pool.
			initialAttemptErr = fmt.Errorf("client: a fresh prekey block from %s did not apply: %w", peer, ferr)
			break
		}
		decrypted = true

		// What the peer said, if anything. A false is an answer too and is
		// trusted as one: it means "not a re-key", so the tie-break decides and
		// the content is never sniffed. Only a peer predating the field falls
		// back to the old inference, where a re-key signal in the plaintext
		// stands for "I threw my session away".
		deliberate := env.Prekey.Rekey != nil && *env.Prekey.Rekey
		if env.Prekey.Rekey == nil {
			deliberate = DecodeContent(plaintext).Kind == ContentRekey
		}

		// A prekey block from a peer who genuinely raced us arrives before
		// either side has confirmed anything: a race is two sides each
		// starting fresh within the same breath, and until a message has
		// actually been *received* on one of the two competing sessions,
		// neither side has any confirmation of the other's, which is exactly
		// what the tie-break below is for. Sent-but-unconfirmed does not
		// disqualify it -- reaching for a new member and immediately sending
		// is routine (see the group case above) and proves nothing about who
		// is racing whom. Once this side has actually decrypted something on
		// the session it is holding, though, that is no longer an open
		// question: the peer has a working, mutually-confirmed session and
		// still sent an "ordinary" prekey block instead of a deliberate one,
		// which only happens when their own copy of it is gone (a reset that
		// predates this field, a reinstall, a device migrated onto state that
		// never carried sessions across -- see SRV-23). Keeping our side of
		// that conversation on a session they have just proven they cannot
		// read, merely because our account id happens to sort lower, strands
		// every message either of us sends from here on: they cannot read
		// ours, and RecordDecryptFailure/RecoverDesyncedSessions has no way to
		// tell "corrupted" apart from "the peer moved on", so nothing
		// self-heals.
		sessionWasConfirmed := session.Nr > 0
		// Otherwise it is a race, settled by the rule re-keying already uses:
		// the lower account id's session wins. Both sides compute the same
		// answer without exchanging anything.
		peerWins := peer < id.AccountID

		if deliberate || sessionWasConfirmed || peerWins {
			session = fresh
			effect.adoptedPeer = true
		} else {
			// Ours wins, so we keep sending on it -- but they go on sending
			// from theirs until our next message reaches them. Keeping this one
			// for reading is what stops those in-flight messages being
			// stranded.
			session = fresh
			effect.keepOwnSending = true
		}
		effect.consumePrekey = otpkID
	}

	// Either an ordinary message, or a prekey block that turned out not to
	// apply: decrypt with the session already held.
	if !decrypted {
		if session == nil {
			return decryptResult{}, effect, ErrNoSessionMaterial
		}
		var derr error
		if plaintext, derr = session.Decrypt(header, ciphertext); derr != nil {
			if errors.Is(derr, ratchet.ErrDuplicateMessage) {
				return decryptResult{}, effect, derr
			}
			// One session left to try: the losing half of a simultaneous
			// establishment, kept for reading. The peer goes on sending from it
			// until our next message reaches them, and those follow-ups carry
			// no prekey block -- so this is the only thing that can read them,
			// and without it they would look exactly like a desync.
			inbound, err := c.Session(peer, Inbound)
			if err != nil {
				return decryptResult{}, effect, err
			}
			if inbound == nil {
				return decryptResult{}, effect, joinInitialAttempt(initialAttemptErr, derr)
			}
			if plaintext, err = inbound.Decrypt(header, ciphertext); err != nil {
				// The original failure, not this one -- except "original" is
				// initialAttemptErr when there is one: a fresh prekey block
				// this side could not use at all is a more informative reason
				// than the generic authentication failure of whichever session
				// this side fell back to trying instead.
				return decryptResult{}, effect, joinInitialAttempt(initialAttemptErr, derr)
			}
			session = inbound
			effect.keepOwnSending = true
		}
	}

	// The advance is written to whichever half it belongs to: our own session
	// stays untouched when it won the tie-break, and the read-only one carries
	// the advance instead.
	kind := Sending
	if effect.keepOwnSending {
		kind = Inbound
	}
	if err := c.SetSession(peer, kind, session); err != nil {
		return decryptResult{}, effect, err
	}
	return decryptResult{content: DecodeContent(plaintext)}, effect, nil
}

// joinInitialAttempt folds a discarded prekey-block failure back in when the
// session decrypt it fell back to also failed, preferring it: a fresh
// prekey block this side could not use at all -- most often this account's
// own published pool naming a one-time prekey it never actually minted a
// private half for (see SRV-23) -- says why in a way "message
// authentication failed" against an unrelated session never does. initial
// may be nil (nothing was discarded; the ordinary case), in which case this
// is just sessionErr.
func joinInitialAttempt(initial, sessionErr error) error {
	if initial == nil {
		return sessionErr
	}
	return errors.Join(initial, sessionErr)
}

// markRekeyInTranscript writes the "session was re-established" line, if there
// is a conversation to write it into. There being none -- deleted locally while
// the session lived on -- means there is nothing to mark; a message arriving
// after it recreates the conversation on its own.
func (c *Client) markRekeyInTranscript(peer string, content Content, now time.Time) error {
	convo, err := c.Conversation(peer)
	if err != nil || convo == nil {
		return err
	}
	marker := SessionResetMarker
	if content.Kind == ContentRekey && content.RekeyReason == RekeyDecryptFailures {
		marker = AutomaticRekeyMarker
	}
	id, err := newMessageID()
	if err != nil {
		return err
	}
	return c.AppendMessage(peer, Message{
		ID:        id,
		Text:      marker,
		Timestamp: now,
		Kind:      MessageSystemInfo,
		SendState: SendSent,
	})
}

// recordReceipt moves a peer's watermark for this conversation.
//
// A receipt never creates a conversation: with no local record of this peer
// there is nothing to update, and minting one would let anybody who can address
// us conjure a chat out of nothing.
func (c *Client) recordReceipt(peer string, content Content) error {
	convo, err := c.Conversation(peer)
	if err != nil || convo == nil {
		return err
	}
	// Monotonic, so an out-of-order or duplicated older receipt never regresses
	// a status that has already moved on.
	upTo := content.ReceiptUpTo
	switch content.ReceiptStatus {
	case ReceiptDelivered:
		if convo.PeerDeliveredUpTo != nil && !upTo.After(*convo.PeerDeliveredUpTo) {
			return nil
		}
		convo.PeerDeliveredUpTo = &upTo
	case ReceiptRead:
		if convo.PeerReadUpTo != nil && !upTo.After(*convo.PeerReadUpTo) {
			return nil
		}
		convo.PeerReadUpTo = &upTo
	default:
		return nil
	}
	return c.PutConversation(*convo)
}

// storeIncomingText files an ordinary one-to-one message and decides whether
// the user hears about it.
func (c *Client) storeIncomingText(res ReceiveResult, msg IncomingMessage, content Content, opts ReceiveOptions, now time.Time) (ReceiveResult, error) {
	peer := msg.SenderAccountID

	known, err := c.IsPeerKnown(peer)
	if err != nil {
		return res, err
	}
	existing, err := c.Conversation(peer)
	if err != nil {
		return res, err
	}
	// Captured before the conversation is created: this distinguishes the
	// message that actually starts a new message request from a follow-up while
	// it is still sitting there unactioned.
	isNew := existing == nil

	convo := existing
	if convo == nil {
		convo = &Conversation{
			PeerAccountID:   peer,
			PendingApproval: !known && !res.Blocked,
		}
	}
	// The conversation's flag is only a mirror of the blocked list; resynced
	// here so a stale one cannot make this path disagree with itself about the
	// same sender.
	convo.Blocked = res.Blocked
	// Refreshed on every message that carries one, not just the first, so this
	// self-heals if local state is ever lost -- including, deliberately, this
	// side's own past mistake about it: SenderServer travels on every message a
	// peer sends, including one on our own server (see send.go's encodeText --
	// it is unconditional, not federation-only), so it is compared against this
	// account's own server rather than believed outright. A same-server peer
	// clears a stale non-empty PeerServer the same way a genuinely federated
	// one would refresh a correct one. PeerEndpoint.Federated's whole contract
	// is "empty means our own" -- getting that wrong routes every later send
	// through the federated path, which requires a device certificate this
	// send path never had a reason to build correctly for a local peer, and
	// fails outright.
	myID, err := c.Identity()
	if err != nil {
		return res, err
	}
	if content.SenderServer != "" {
		if content.SenderServer == myID.Server {
			convo.PeerServer = ""
		} else {
			convo.PeerServer = content.SenderServer
		}
	}

	if res.Blocked {
		// Decrypted above so the ratchet stays in step and the server queue
		// still drains, then dropped: not stored, not notified, nothing
		// confirmed back.
		return res, c.PutConversation(*convo)
	}

	id := content.ID
	if id == "" {
		// A legacy envelope carried no id of its own. One is minted so the line
		// can still be replied to and deleted locally.
		if id, err = newMessageID(); err != nil {
			return res, err
		}
	}
	line := Message{
		ID:                   id,
		Text:                 content.Text,
		Timestamp:            now,
		SenderSentAt:         content.SentAt,
		ReplyToID:            content.ReplyToID,
		ReplyPreviewText:     content.ReplyPreviewText,
		ReplyPreviewMine:     content.ReplyPreviewMine,
		ReplyPreviewAuthorID: content.ReplyPreviewAuthorID,
		Kind:                 MessageNormal,
		SendState:            SendSent,
		Attachments:          content.Attachments,
	}
	if err := c.AppendMessage(peer, line); err != nil {
		return res, err
	}
	res.StoredMessageID = id

	// Only the inline preview is written now, never the blob. It is a kilobyte,
	// so it costs nothing even on a background wake with no screen to draw on,
	// and it means a picture shows *something* the moment it arrives instead of
	// an empty bubble that reads as a message with nothing in it. The blob is
	// fetched later, by whoever is looking (see Client.EnsureAttachment): a
	// wake must not delay a notification for a download.
	for _, att := range content.Attachments {
		if err := c.WriteAttachmentThumb(peer, id, att.Thumb); err != nil {
			return res, err
		}
	}

	convo.LastActivityAt = &now
	if peer != opts.OpenChatID {
		convo.HasUnread = true
		// The message that creates a new request still notifies once -- you
		// should learn that somebody wants to talk to you -- but a follow-up
		// from that same unaccepted sender does not: once you have been told a
		// request exists, it must not keep interrupting you before you have
		// accepted or blocked it.
		res.ShouldNotify = isNew || !convo.PendingApproval
	}
	if err := c.PutConversation(*convo); err != nil {
		return res, err
	}

	// The sender's own stamp when it carried one, arrival time only as the
	// legacy fallback: a receipt has to be in the sender's clock domain to mean
	// anything to them.
	upTo := now
	if content.SentAt != nil {
		upTo = *content.SentAt
	}
	res.DeliveredUpTo = &upTo
	return res, nil
}

// lockPeer serialises everything that reads-modifies-writes one peer's
// session. Decrypting and sending touch the same session file, and interleaving
// them loses the ratchet advance of whichever wrote first.
//
// Per peer rather than one lock for all of them, because the alternative makes
// a bot sending to a thousand devices serialise on one mutex for work that
// never overlaps.
func (c *Client) lockPeer(peer string) func() {
	c.mu.Lock()
	mu, ok := c.peerLocks[peer]
	if !ok {
		mu = &sync.Mutex{}
		c.peerLocks[peer] = mu
	}
	c.mu.Unlock()

	mu.Lock()
	return mu.Unlock
}

// newMessageID mints a local id for a line that arrived without one.
func newMessageID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("client: generating a message id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
