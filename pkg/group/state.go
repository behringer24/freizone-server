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
			reject("no genesis event yet")
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

// Resolve folds the fact set into the current membership.
//
// Events are replayed in timestamp order (ties broken by event id), and each
// is checked against the state built from everything before it. That is
// exactly the rule "the signer must have held the required role at the moment
// they signed", and it makes the result a pure function of the fact set: every
// member holding the same facts gets the same answer, in any arrival order.
//
// The price, accepted deliberately, is that a fact arriving late can change
// the past -- a revocation that turns up after the act it invalidates removes
// that act's effect. Deterministically, and for everyone.
func (s *State) Resolve() *Resolved {
	out := &Resolved{GroupID: s.groupID, StateHash: s.StateHash()}
	if s.groupID == "" {
		return out
	}

	ordered := s.orderedEvents()
	members := map[string]*member{}

	// authorized reports whether the signer of e currently holds at least
	// need, and returns their rank so callers can compare against a target.
	rankOf := func(accountID string) Role {
		if m, ok := members[accountID]; ok {
			return m.rank()
		}
		return RoleNone
	}

	for _, e := range ordered {
		if out.Dissolved && !e.IssuedAt.Before(out.DissolvedAt) {
			continue
		}
		if e.Type != EventGenesis {
			if out.Founder == "" || e.IssuedAt.Before(out.CreatedAt) {
				// Nothing can predate the group it claims to be about.
				continue
			}
		}

		// No signer block means the group root key signed this, which only the
		// founder holds. Otherwise it is a device signature, and the account
		// behind it has to hold the required rank itself.
		actorRank := RoleFounder
		if e.Signer != nil {
			actorRank = rankOf(e.Signer.AccountID)
		}

		switch e.Type {
		case EventGenesis:
			if out.Founder != "" {
				continue
			}
			out.Founder = e.Subject
			out.CreatedAt = e.IssuedAt
			members[e.Subject] = &member{
				server:  e.Server,
				addedAt: e.IssuedAt,
				joined:  true,
				founder: true,
				granted: map[Role]bool{},
			}

		case EventMemberAdd:
			if actorRank < RoleModerator {
				continue
			}
			if _, ok := members[e.Subject]; ok {
				continue
			}
			members[e.Subject] = &member{
				server:  e.Server,
				addedAt: e.IssuedAt,
				granted: map[Role]bool{},
			}

		case EventJoinAccept:
			m, ok := members[e.Subject]
			if !ok {
				continue
			}
			m.joined = true

		case EventMemberRemove:
			target, ok := members[e.Subject]
			if !ok {
				continue
			}
			// Only against strictly lower ranks, and never the founder --
			// whose authority is key possession and cannot be voted away.
			if actorRank < RoleModerator || actorRank <= target.rank() {
				continue
			}
			delete(members, e.Subject)

		case EventLeave:
			target, ok := members[e.Subject]
			if !ok || target.founder {
				continue
			}
			delete(members, e.Subject)

		case EventRoleGrant:
			// Granting role R needs a rank above R: only the founder reaches
			// above admin, only an admin above moderator.
			if actorRank <= e.Role {
				continue
			}
			m, ok := members[e.Subject]
			if !ok {
				continue
			}
			m.granted[e.Role] = true

		case EventRoleRevoke:
			if actorRank <= e.Role {
				continue
			}
			m, ok := members[e.Subject]
			if !ok {
				continue
			}
			m.granted[e.Role] = false

		case EventMeta:
			if actorRank < RoleModerator {
				continue
			}
			out.Name = e.Name
			out.Topic = e.Topic

		case EventDissolve:
			out.Dissolved = true
			out.DissolvedAt = e.IssuedAt
		}
	}

	out.Members = make([]Member, 0, len(members))
	for id, m := range members {
		role := m.rank()
		out.Members = append(out.Members, Member{
			AccountID: id,
			Server:    m.server,
			Role:      role,
			RoleName:  role.String(),
			AddedAt:   m.addedAt,
			Joined:    m.joined,
		})
	}
	sort.Slice(out.Members, func(i, j int) bool {
		return out.Members[i].AccountID < out.Members[j].AccountID
	})
	return out
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
