package client

import (
	"time"

	"github.com/behringer24/freizone-server/pkg/profileclaim"
)

// maxProfileClaims bounds the history kept per peer. It exists for two
// readers: the transcript line that says somebody renamed themselves, and the
// evidence a report carries (SRV-33), where the *sequence* is often the point
// -- an account that called itself one thing while it was doing something and
// another thing by the time it was reported. Bounded because a peer renaming
// itself in a loop must not grow a file without limit.
const maxProfileClaims = 10

// PeerProfile is what a peer has asserted about its own name, newest first.
//
// Every claim here has been verified: applyProfileClaim refuses to store one
// it could not check, so a caller never has to ask whether these are
// trustworthy statements *by that account* -- only whether the account is
// telling the truth, which is a question no signature can answer.
type PeerProfile struct {
	Claims []profileclaim.Claim

	// SentAt is when the claim this peer last received from us was issued.
	SentAt *time.Time
}

// Current is the claim in force, or nil when the peer has never sent one.
func (p *PeerProfile) Current() *profileclaim.Claim {
	if p == nil || len(p.Claims) == 0 {
		return nil
	}
	return &p.Claims[0]
}

// Name is the asserted name, empty when there is none or it was withdrawn.
func (p *PeerProfile) Name() string {
	if c := p.Current(); c != nil {
		return c.Name
	}
	return ""
}

type profileFile struct {
	Claims []profileclaim.Claim `json:"claims,omitempty"`

	// SentAt is the IssuedAt of the last claim we sent *this* peer about
	// ourselves -- the other direction, kept in the same file because both are
	// touched on the same paths.
	SentAt *time.Time `json:"sent_at,omitempty"`
}

// PeerProfile returns the stored claims for peer, or nil when there are none.
func (c *Client) PeerProfile(peer string) (*PeerProfile, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerProfileLocked(peer)
}

func (c *Client) peerProfileLocked(peer string) (*PeerProfile, error) {
	path, err := c.store.peerPath(peer, fileProfile)
	if err != nil {
		return nil, err
	}
	var stored profileFile
	found, err := readJSON(path, &stored)
	if err != nil || !found {
		return nil, err
	}
	return &PeerProfile{Claims: stored.Claims, SentAt: stored.SentAt}, nil
}

// applyProfileClaim verifies a claim that arrived from peer and stores it when
// it supersedes what is already there. It reports whether the displayed name
// changed, which is what the transcript line is written from.
//
// Nothing here fails a message. A claim that cannot be checked, breaks its own
// rules or arrives out of order is dropped and the envelope it rode on is
// delivered as usual: a name is never worth losing a message over.
func (c *Client) applyProfileClaim(peer string, claim *profileclaim.Claim) (changed bool, err error) {
	if claim == nil {
		return false, nil
	}

	// The cached device is the one key we hold for this peer, and holding it is
	// why this works offline -- the receive path runs in the push isolate, with
	// no opportunity to go and fetch anything. A claim from some *other* device
	// of theirs is dropped rather than fetched for: after a device change the
	// cache is refreshed by the ordinary unknown-recipient path (PROTOCOL §5),
	// and the next claim from the new device lands normally. The cost is a
	// rename going unseen until then, which is the right thing to trade for
	// never blocking on the network here.
	cached, err := c.peerDevice(peer)
	if err != nil {
		return false, err
	}
	if cached == nil || cached.DeviceID != claim.DeviceID || len(cached.DevicePub) == 0 {
		return false, nil
	}
	if err := claim.Verify(peer, cached.DevicePub); err != nil {
		return false, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	stored, err := c.peerProfileLocked(peer)
	if err != nil {
		return false, err
	}
	if current := stored.Current(); current != nil && !claim.SupersedesTime(current.IssuedAt) {
		return false, nil
	}

	before := stored.Name()
	file := profileFile{Claims: []profileclaim.Claim{*claim}}
	if stored != nil {
		file.Claims = append(file.Claims, stored.Claims...)
		// Carried over, not dropped: this file holds both directions, and
		// forgetting what we last sent them would re-attach our own claim to
		// the next envelope for no reason.
		file.SentAt = stored.SentAt
	}
	if len(file.Claims) > maxProfileClaims {
		file.Claims = file.Claims[:maxProfileClaims]
	}

	path, err := c.store.peerPath(peer, fileProfile)
	if err != nil {
		return false, err
	}
	if err := writeJSON(path, file); err != nil {
		return false, err
	}
	return claim.Name != before, nil
}

// profileClaimFor mints the claim to attach to the next envelope for peer, or
// nil when there is nothing to say.
//
// Nothing to say covers three cases, and the third is what keeps this cheap:
// this account has never set a name; peer's device is not known well enough to
// track what it has been told; or peer already has this exact claim. Only a
// name that has actually changed since we last told *this* peer travels, so
// the field costs a signature on a rename and nothing at all afterwards.
func (c *Client) profileClaimFor(peer string) (*profileclaim.Claim, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	claim, err := c.ownProfileClaimLocked()
	if err != nil || claim == nil {
		return nil, err
	}

	stored, err := c.peerProfileLocked(peer)
	if err != nil {
		return nil, err
	}
	if stored != nil && stored.SentAt != nil && !claim.SupersedesTime(*stored.SentAt) {
		return nil, nil
	}
	return claim, nil
}

// profileClaimSent records that peer has been told, so the claim is not
// attached again. Called after the envelope is actually away: marking it
// beforehand would lose a rename to any failed send.
func (c *Client) profileClaimSent(peer string, claim *profileclaim.Claim) error {
	if claim == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	stored, err := c.peerProfileLocked(peer)
	if err != nil {
		return err
	}
	file := profileFile{}
	if stored != nil {
		file.Claims = stored.Claims
	}
	sent := claim.IssuedAt
	file.SentAt = &sent

	path, err := c.store.peerPath(peer, fileProfile)
	if err != nil {
		return err
	}
	return writeJSON(path, file)
}

// ownProfileClaimLocked signs this account's current name, or returns nil when
// no name has ever been set -- saying nothing is different from asserting an
// empty one, and spending a signature and a wire field to state an absence on
// every conversation would be the wrong default for the many accounts that
// never set a name at all.
func (c *Client) ownProfileClaimLocked() (*profileclaim.Claim, error) {
	settings, err := c.settingsLocked()
	if err != nil {
		return nil, err
	}
	if settings.ProfileNameSetAt == "" {
		return nil, nil
	}
	setAt, err := parseTime(settings.ProfileNameSetAt)
	if err != nil || setAt == nil {
		return nil, err
	}

	id, err := c.identityLocked()
	if err != nil {
		return nil, err
	}
	// Dated when the name was set rather than when it is sent, so that telling
	// a new contact an old name cannot displace a newer one they already have
	// from another of this account's devices.
	return profileclaim.Sign(id.AccountID, id.DeviceID, settings.ProfileName, *setAt, id.DevicePriv)
}

// attachProfile puts a claim into an envelope body under the one key every
// version that carries one uses. Absent when there is nothing to say, which is
// the common case after the first message.
func attachProfile(body map[string]any, claim *profileclaim.Claim) {
	if claim != nil {
		body["profile"] = claim
	}
}

// profileClaimForAny mints the claim to attach to a group fan-out, or nil when
// every recipient already has it.
//
// One claim for the whole room rather than one decision per member: the copies
// are encoded once and shared wherever nothing forces them apart, and a member
// who already holds this claim discards the duplicate by its timestamp anyway.
// Attaching for all when any one of them is behind keeps that sharing intact
// at the cost of a field a few members did not need.
func (c *Client) profileClaimForAny(recipients []string) (*profileclaim.Claim, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	claim, err := c.ownProfileClaimLocked()
	if err != nil || claim == nil {
		return nil, err
	}
	for _, peer := range recipients {
		stored, err := c.peerProfileLocked(peer)
		if err != nil {
			return nil, err
		}
		if stored == nil || stored.SentAt == nil || claim.SupersedesTime(*stored.SentAt) {
			return claim, nil
		}
	}
	return nil, nil
}

// profileClaimDelivered records the claim against every member whose copy
// actually left, and only those: a member whose server refused theirs has not
// been told, and must be told on the next attempt.
func (c *Client) profileClaimDelivered(deliveries []GroupDelivery, claim *profileclaim.Claim) error {
	if claim == nil {
		return nil
	}
	for _, d := range deliveries {
		if d.State != SendSent {
			continue
		}
		if err := c.profileClaimSent(d.AccountID, claim); err != nil {
			return err
		}
	}
	return nil
}
