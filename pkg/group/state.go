package group

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// State is everything a member knows about a group: a grow-only set of signed
// events, keyed by event id.
//
// Grow-only is the whole trick. Union is idempotent and commutative, so two
// members who hold the same facts fold to the same membership no matter what
// order those facts arrived in, and reconciling two views is just "send me
// yours" -- no delta protocol, no version vectors, and no sequencer anywhere.
type State struct {
	groupID    string
	rootPubKey ed25519.PublicKey
	events     map[string]*Event
}

// RejectNoGenesis is the one rejection reason a later arrival can change: the
// event is fine, but the genesis it rests on has not been seen yet. Delivery is
// unordered, so this is routine rather than a fault -- a caller holds the event
// and retries it when more facts arrive, where every other reason means drop it.
//
// Exported because it is a contract, not a message: both clients decide what to
// retry by comparing against it, and one of them was matching the literal string.
const RejectNoGenesis = "no genesis event yet"

// Rejection explains why one event in a batch was not admitted.
type Rejection struct {
	// Index is the event's position in the submitted batch. It is the only
	// handle on an event whose id could not even be computed.
	Index  int    `json:"index"`
	ID     string `json:"id,omitempty"`
	Reason string `json:"reason"`
}

// ApplyResult reports what a batch did. Ids already known are neither applied
// nor rejected: re-delivering a fact is normal, not an error.
type ApplyResult struct {
	Applied  []string    `json:"applied"`
	Known    []string    `json:"known"`
	Rejected []Rejection `json:"rejected"`
}

// NewState creates an empty state. It has no group identity until a genesis
// event is applied.
func NewState() *State {
	return &State{events: map[string]*Event{}}
}

// GroupID is the group this state describes, or "" before genesis.
func (s *State) GroupID() string { return s.groupID }

// RootPubKey is the group's root public key, or nil before genesis.
func (s *State) RootPubKey() ed25519.PublicKey { return s.rootPubKey }

// Events returns the fact set, ordered by event id -- the canonical order used
// for hashing and for handing a full snapshot to a peer.
func (s *State) Events() []*Event {
	ids := make([]string, 0, len(s.events))
	for id := range s.events {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]*Event, len(ids))
	for i, id := range ids {
		out[i] = s.events[id]
	}
	return out
}

// Genesis returns the group's genesis event, or nil before it has arrived.
//
// Callers need it for the group nonce: a founder re-deriving the group root
// key after restoring from their recovery seed reads it from here, having
// received the state from any member.
func (s *State) Genesis() *Event {
	for _, e := range s.events {
		if e.Type == EventGenesis {
			return e
		}
	}
	return nil
}

// Apply admits a batch of events into the fact set.
//
// Admission is context-free on purpose: shape, signer chain and signature,
// nothing more. Whether the signer was *allowed* to do this depends on every
// other fact in the group and on when those facts arrive, so authority is
// decided by Resolve. An event that merely overtook the grant authorizing it
// must not be thrown away -- it would never come back.
func (s *State) Apply(events []*Event) ApplyResult {
	result := ApplyResult{}

	// Genesis first: it carries the root key every other signature check and
	// the group id itself depend on, and a snapshot delivers it in the same
	// batch as the rest.
	for i, e := range events {
		if e == nil || e.Type != EventGenesis {
			continue
		}
		s.admit(i, e, &result)
	}
	for i, e := range events {
		if e == nil {
			result.Rejected = append(result.Rejected, Rejection{Index: i, Reason: "nil event"})
			continue
		}
		if e.Type == EventGenesis {
			continue
		}
		s.admit(i, e, &result)
	}
	return result
}

func (s *State) admit(index int, e *Event, result *ApplyResult) {
	reject := func(reason string) {
		id, _ := e.ID()
		result.Rejected = append(result.Rejected, Rejection{Index: index, ID: id, Reason: reason})
	}

	if e.Type == EventGenesis {
		if err := e.Verify(e.RootPubKey); err != nil {
			reject(err.Error())
			return
		}
		if s.groupID != "" && s.groupID != e.GroupID {
			reject("genesis for a different group")
			return
		}
	} else {
		if s.groupID == "" {
			reject(RejectNoGenesis)
			return
		}
		if e.GroupID != s.groupID {
			reject("event belongs to a different group")
			return
		}
		if err := e.Verify(s.rootPubKey); err != nil {
			reject(err.Error())
			return
		}
	}

	id, err := e.ID()
	if err != nil {
		reject(err.Error())
		return
	}
	if _, ok := s.events[id]; ok {
		result.Known = append(result.Known, id)
		return
	}

	if e.Type == EventGenesis {
		s.groupID = e.GroupID
		s.rootPubKey = e.RootPubKey
	}
	s.events[id] = e
	result.Applied = append(result.Applied, id)
}

// StateHash is the fingerprint a member puts on every group message so a peer
// can tell, without exchanging anything, whether the two of them are missing
// each other's facts: SHA-256 over the event ids in canonical order.
//
// It says "we differ", never who is behind -- which is enough, because the
// answer to a mismatch is for both sides to send what they have.
func (s *State) StateHash() string {
	h := sha256.New()
	ids := make([]string, 0, len(s.events))
	for id := range s.events {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		raw, err := hex.DecodeString(id)
		if err != nil {
			continue
		}
		h.Write(raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Member is one account's standing in a group.
type Member struct {
	AccountID string    `json:"account_id"`
	Server    string    `json:"server"`
	Role      Role      `json:"-"`
	RoleName  string    `json:"role"`
	AddedAt   time.Time `json:"added_at"`

	// Joined is false for an invitee who has not accepted yet. They are shown,
	// so a moderator can see the invitation is outstanding, but nothing is
	// sent to them: being added must not disclose their address to the group
	// before they agree to it.
	Joined bool `json:"joined"`
}

// Resolved is the current membership: the fold over the fact set.
type Resolved struct {
	GroupID     string    `json:"group_id"`
	Founder     string    `json:"founder"`
	CreatedAt   time.Time `json:"created_at"`
	Name        string    `json:"name"`
	Topic       string    `json:"topic"`
	Members     []Member  `json:"members"`
	Dissolved   bool      `json:"dissolved"`
	DissolvedAt time.Time `json:"dissolved_at,omitempty"`
	StateHash   string    `json:"state_hash"`
}

// RoleOf returns an account's role, RoleNone if it is not a member.
func (r *Resolved) RoleOf(accountID string) Role {
	for _, m := range r.Members {
		if m.AccountID == accountID {
			return m.Role
		}
	}
	return RoleNone
}

// member is the mutable form used during the fold.
type member struct {
	server  string
	addedAt time.Time
	joined  bool
	founder bool
	// granted tracks each role separately rather than a single current rank,
	// so revoking moderator from an admin leaves the admin grant standing and
	// a re-grant after a revocation simply takes effect again.
	granted map[Role]bool
}

func (m *member) rank() Role {
	if m.founder {
		return RoleFounder
	}
	best := RoleMember
	for role, ok := range m.granted {
		if ok && role > best {
			best = role
		}
	}
	return best
}

// fold is the running state of a replay.
type fold struct {
	out     *Resolved
	members map[string]*member
}

func (f *fold) rankOf(accountID string) Role {
	if m, ok := f.members[accountID]; ok {
		return m.rank()
	}
	return RoleNone
}

// apply attempts one event, reporting whether it changed anything. It must
// leave the state untouched when it returns false, because an event that is
// merely not applicable *yet* is retried (see Resolve).
func (f *fold) apply(e *Event) bool {
	if f.out.Dissolved && !e.IssuedAt.Before(f.out.DissolvedAt) {
		return false
	}
	if e.Type != EventGenesis {
		// Nothing can predate the group it claims to be about.
		if f.out.Founder == "" || e.IssuedAt.Before(f.out.CreatedAt) {
			return false
		}
	}

	// No signer block means the group root key signed this, which only the
	// founder holds. Otherwise it is a device signature, and the account
	// behind it has to hold the required rank itself.
	actorRank := RoleFounder
	if e.Signer != nil {
		actorRank = f.rankOf(e.Signer.AccountID)
	}

	switch e.Type {
	case EventGenesis:
		if f.out.Founder != "" {
			return false
		}
		f.out.Founder = e.Subject
		f.out.CreatedAt = e.IssuedAt
		f.members[e.Subject] = &member{
			server:  e.Server,
			addedAt: e.IssuedAt,
			joined:  true,
			founder: true,
			granted: map[Role]bool{},
		}
		return true

	case EventMemberAdd:
		if actorRank < RoleModerator {
			return false
		}
		if _, ok := f.members[e.Subject]; ok {
			return false
		}
		f.members[e.Subject] = &member{
			server:  e.Server,
			addedAt: e.IssuedAt,
			granted: map[Role]bool{},
		}
		return true

	case EventJoinAccept:
		m, ok := f.members[e.Subject]
		if !ok || m.joined {
			return false
		}
		m.joined = true
		return true

	case EventMemberRemove:
		target, ok := f.members[e.Subject]
		if !ok {
			return false
		}
		// Only against strictly lower ranks, and never the founder -- whose
		// authority is key possession and cannot be voted away.
		if actorRank < RoleModerator || actorRank <= target.rank() {
			return false
		}
		delete(f.members, e.Subject)
		return true

	case EventLeave:
		target, ok := f.members[e.Subject]
		if !ok || target.founder {
			return false
		}
		delete(f.members, e.Subject)
		return true

	case EventRoleGrant:
		// Granting role R needs a rank above R: only the founder reaches
		// above admin, only an admin above moderator.
		if actorRank <= e.Role {
			return false
		}
		m, ok := f.members[e.Subject]
		if !ok || m.granted[e.Role] {
			return false
		}
		m.granted[e.Role] = true
		return true

	case EventRoleRevoke:
		if actorRank <= e.Role {
			return false
		}
		m, ok := f.members[e.Subject]
		if !ok || !m.granted[e.Role] {
			return false
		}
		m.granted[e.Role] = false
		return true

	case EventMeta:
		if actorRank < RoleModerator {
			return false
		}
		if f.out.Name == e.Name && f.out.Topic == e.Topic {
			return false
		}
		f.out.Name = e.Name
		f.out.Topic = e.Topic
		return true

	case EventDissolve:
		f.out.Dissolved = true
		f.out.DissolvedAt = e.IssuedAt
		return true
	}
	return false
}

// Resolve folds the fact set into the current membership.
//
// Events are replayed in timestamp order (ties broken by event id), and each
// is checked against the state built from everything before it. That is
// exactly the rule "the signer must have held the required role at the moment
// they signed", and it makes the result a pure function of the fact set: every
// member holding the same facts gets the same answer, in any arrival order.
//
// Events sharing a timestamp are *concurrent*, though, and hash order between
// them is arbitrary -- so within one timestamp the replay iterates to a
// fixpoint instead: repeat until a pass applies nothing new. Without that, a
// group founded and named in the same second could lose its name, because the
// name event's hash happened to sort ahead of the genesis it depends on. The
// fixpoint is still deterministic (the pending set shrinks in hash order every
// pass) and still a pure function of the fact set; it just refuses to let an
// arbitrary tie-break decide which of two same-second facts survives.
//
// The price, accepted deliberately, is that a fact arriving late can change
// the past -- a revocation that turns up after the act it invalidates removes
// that act's effect. Deterministically, and for everyone.
func (s *State) Resolve() *Resolved {
	f := &fold{
		out:     &Resolved{GroupID: s.groupID, StateHash: s.StateHash()},
		members: map[string]*member{},
	}
	if s.groupID == "" {
		return f.out
	}

	for _, bucket := range sameTimestampBuckets(s.orderedEvents()) {
		pending := bucket
		for len(pending) > 0 {
			var stalled []*Event
			for _, e := range pending {
				if !f.apply(e) {
					stalled = append(stalled, e)
				}
			}
			if len(stalled) == len(pending) {
				break // no progress: the rest of this bucket never applies
			}
			pending = stalled
		}
	}

	f.out.Members = make([]Member, 0, len(f.members))
	for id, m := range f.members {
		role := m.rank()
		f.out.Members = append(f.out.Members, Member{
			AccountID: id,
			Server:    m.server,
			Role:      role,
			RoleName:  role.String(),
			AddedAt:   m.addedAt,
			Joined:    m.joined,
		})
	}
	sort.Slice(f.out.Members, func(i, j int) bool {
		return f.out.Members[i].AccountID < f.out.Members[j].AccountID
	})
	return f.out
}

// sameTimestampBuckets splits an already-ordered event list into runs sharing
// one timestamp -- the granularity at which events are genuinely concurrent,
// since that is all the signing bytes record.
func sameTimestampBuckets(ordered []*Event) [][]*Event {
	var buckets [][]*Event
	for i := 0; i < len(ordered); {
		j := i + 1
		for j < len(ordered) && ordered[j].IssuedAt.Equal(ordered[i].IssuedAt) {
			j++
		}
		buckets = append(buckets, ordered[i:j])
		i = j
	}
	return buckets
}

// orderedEvents returns the fact set in replay order: by timestamp, ties
// broken by event id so the order is total and identical everywhere.
func (s *State) orderedEvents() []*Event {
	type entry struct {
		id string
		e  *Event
	}
	entries := make([]entry, 0, len(s.events))
	for id, e := range s.events {
		entries = append(entries, entry{id: id, e: e})
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].e.IssuedAt.Equal(entries[j].e.IssuedAt) {
			return entries[i].e.IssuedAt.Before(entries[j].e.IssuedAt)
		}
		return entries[i].id < entries[j].id
	})

	out := make([]*Event, len(entries))
	for i, entry := range entries {
		out[i] = entry.e
	}
	return out
}

// stateJSON is the persisted form: the fact set and nothing derived. Members,
// roles and the state hash are all recomputed by Resolve, so there is no
// second representation that could disagree with the events.
type stateJSON struct {
	Events []*Event `json:"events"`
}

// MarshalJSON writes the fact set in canonical order, so the same state
// serializes to the same bytes on every device.
func (s *State) MarshalJSON() ([]byte, error) {
	return json.Marshal(stateJSON{Events: s.Events()})
}

// UnmarshalJSON reloads a persisted state, re-verifying every event on the way
// in. Storage is not a trust boundary we want to assume: a state read back
// from disk gets the same checks it got on arrival.
func (s *State) UnmarshalJSON(data []byte) error {
	var raw stateJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	s.groupID = ""
	s.rootPubKey = nil
	s.events = map[string]*Event{}

	result := s.Apply(raw.Events)
	if len(result.Rejected) > 0 {
		return fmt.Errorf("group: %d stored event(s) failed to verify, first: %s",
			len(result.Rejected), result.Rejected[0].Reason)
	}
	if s.groupID == "" {
		return errors.New("group: stored state has no genesis event")
	}
	return nil
}
