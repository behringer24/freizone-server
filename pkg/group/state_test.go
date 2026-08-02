package group

import (
	"encoding/json"
	"testing"
)

// invite runs the full two-step join: an authorized member proposes, the
// invitee accepts. Returns both events.
func invite(t *testing.T, g *testGroup, by, who *testAccount, addAt, acceptAt int) []*Event {
	t.Helper()
	add := g.by(t, by, &Event{
		Type: EventMemberAdd, IssuedAt: at(addAt),
		Subject: who.accountID, Server: who.server,
	})
	accept := g.by(t, who, &Event{
		Type: EventJoinAccept, IssuedAt: at(acceptAt), Subject: who.accountID,
	})
	return []*Event{add, accept}
}

func TestFounderIsAMemberFromGenesisAlone(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	g := newGroup(t, founder)

	s := NewState()
	apply(t, s, g.genesis)

	r := s.Resolve()
	if r.GroupID != g.id || r.Founder != founder.accountID {
		t.Fatalf("genesis did not establish the group: %+v", r)
	}
	if len(r.Members) != 1 {
		t.Fatalf("want the founder as the only member, got %d", len(r.Members))
	}
	m := r.Members[0]
	if m.Role != RoleFounder || !m.Joined {
		t.Fatalf("founder must be a joined member with founder rank, got %+v", m)
	}
	// Without a server here the founder would be the one member nobody could
	// deliver to until they spoke first.
	if m.Server != founder.server {
		t.Fatalf("founder server = %q, want %q", m.Server, founder.server)
	}
}

func TestSameSecondEventsDoNotDependOnHashOrder(t *testing.T) {
	// Founding a group and naming it happen in the same second, and the
	// signing bytes only record seconds -- so the two events are concurrent
	// and their hash order is arbitrary. Before the fold iterated to a
	// fixpoint, a name whose hash sorted ahead of its own genesis was silently
	// dropped, which is exactly what the first real devclient run hit.
	//
	// The subject is generated fresh each run, so hashes differ every time:
	// over enough iterations this covers both orderings without having to
	// contrive one.
	for i := 0; i < 25; i++ {
		founder := newAccount(t, "a.example.org")
		invitee := newAccount(t, "b.example.org")
		g := newGroup(t, founder) // genesis at at(0)

		meta := g.by(t, founder, &Event{
			Type: EventMeta, IssuedAt: at(0), Name: "Wandergruppe", Topic: "Samstag",
		})
		// An invitation and its acceptance in the same second, too: the accept
		// depends on the add, and nothing in the timestamps says so.
		add := g.by(t, founder, &Event{
			Type: EventMemberAdd, IssuedAt: at(0), Subject: invitee.accountID, Server: invitee.server,
		})
		accept := g.by(t, invitee, &Event{
			Type: EventJoinAccept, IssuedAt: at(0), Subject: invitee.accountID,
		})

		s := NewState()
		apply(t, s, g.genesis, meta, add, accept)

		r := s.Resolve()
		if r.Name != "Wandergruppe" || r.Topic != "Samstag" {
			t.Fatalf("run %d: metadata lost to hash order: %+v", i, r)
		}
		if r.RoleOf(invitee.accountID) != RoleMember {
			t.Fatalf("run %d: same-second invitation lost", i)
		}
		for _, m := range r.Members {
			if m.AccountID == invitee.accountID && !m.Joined {
				t.Fatalf("run %d: same-second acceptance lost", i)
			}
		}
	}
}

func TestInviteNeedsAcceptanceBeforeItCounts(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	invitee := newAccount(t, "b.example.org")
	g := newGroup(t, founder)

	events := invite(t, g, founder, invitee, 1, 2)

	joinedFlag := func(s *State) bool {
		t.Helper()
		for _, m := range s.Resolve().Members {
			if m.AccountID == invitee.accountID {
				return m.Joined
			}
		}
		t.Fatal("invitee is not in the member list at all")
		return false
	}

	s := NewState()
	apply(t, s, g.genesis, events[0])
	if r := s.Resolve(); r.RoleOf(invitee.accountID) != RoleMember {
		t.Fatalf("an invitee must be listed as a member: %+v", r.Members)
	}
	if joinedFlag(s) {
		t.Fatal("an invitee must not count as joined before they accept")
	}

	apply(t, s, events[1])
	if !joinedFlag(s) {
		t.Fatal("after accepting, the invitee must be joined")
	}
}

func TestRolePrecedenceTable(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	admin := newAccount(t, "b.example.org")
	mod := newAccount(t, "c.example.org")
	plain := newAccount(t, "d.example.org")
	g := newGroup(t, founder)

	s := NewState()
	apply(t, s, g.genesis)
	apply(t, s, invite(t, g, founder, admin, 1, 2)...)
	apply(t, s, invite(t, g, founder, mod, 3, 4)...)
	apply(t, s, invite(t, g, founder, plain, 5, 6)...)

	// Only the founder may appoint an admin.
	apply(t, s, g.by(t, admin, &Event{
		Type: EventRoleGrant, IssuedAt: at(7), Subject: admin.accountID, Role: RoleAdmin,
	}))
	if s.Resolve().RoleOf(admin.accountID) != RoleMember {
		t.Fatal("a plain member must not be able to appoint themselves admin")
	}
	apply(t, s, g.root(t, &Event{
		Type: EventRoleGrant, IssuedAt: at(8), Subject: admin.accountID, Role: RoleAdmin,
	}))
	if s.Resolve().RoleOf(admin.accountID) != RoleAdmin {
		t.Fatal("the founder must be able to appoint an admin")
	}

	// Only an admin may appoint a moderator.
	apply(t, s, g.by(t, plain, &Event{
		Type: EventRoleGrant, IssuedAt: at(9), Subject: mod.accountID, Role: RoleModerator,
	}))
	if s.Resolve().RoleOf(mod.accountID) != RoleMember {
		t.Fatal("a plain member must not be able to appoint a moderator")
	}
	apply(t, s, g.by(t, admin, &Event{
		Type: EventRoleGrant, IssuedAt: at(10), Subject: mod.accountID, Role: RoleModerator,
	}))
	if s.Resolve().RoleOf(mod.accountID) != RoleModerator {
		t.Fatal("an admin must be able to appoint a moderator")
	}

	// A moderator removes a member but not another moderator, an admin, or
	// the founder -- only strictly lower ranks.
	apply(t, s, g.by(t, mod, &Event{
		Type: EventMemberRemove, IssuedAt: at(11), Subject: admin.accountID,
	}))
	apply(t, s, g.by(t, mod, &Event{
		Type: EventMemberRemove, IssuedAt: at(12), Subject: founder.accountID,
	}))
	r := s.Resolve()
	if r.RoleOf(admin.accountID) != RoleAdmin {
		t.Fatal("a moderator must not remove an admin")
	}
	if r.RoleOf(founder.accountID) != RoleFounder {
		t.Fatal("nobody removes the founder")
	}

	apply(t, s, g.by(t, mod, &Event{
		Type: EventMemberRemove, IssuedAt: at(13), Subject: plain.accountID,
	}))
	if s.Resolve().RoleOf(plain.accountID) != RoleNone {
		t.Fatal("a moderator must be able to remove a plain member")
	}

	// An admin may remove a moderator.
	apply(t, s, g.by(t, admin, &Event{
		Type: EventMemberRemove, IssuedAt: at(14), Subject: mod.accountID,
	}))
	if s.Resolve().RoleOf(mod.accountID) != RoleNone {
		t.Fatal("an admin must be able to remove a moderator")
	}
}

func TestFounderCannotLeaveButCanDissolve(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	g := newGroup(t, founder)

	s := NewState()
	apply(t, s, g.genesis)
	apply(t, s, g.by(t, founder, &Event{
		Type: EventLeave, IssuedAt: at(1), Subject: founder.accountID,
	}))
	if s.Resolve().RoleOf(founder.accountID) != RoleFounder {
		t.Fatal("the founder must not be able to leave -- that would leave an authority outside the member list")
	}

	apply(t, s, g.root(t, &Event{Type: EventDissolve, IssuedAt: at(2)}))
	r := s.Resolve()
	if !r.Dissolved {
		t.Fatal("the founder must be able to dissolve the group")
	}
}

func TestNothingTakesEffectAfterDissolve(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	late := newAccount(t, "b.example.org")
	g := newGroup(t, founder)

	s := NewState()
	apply(t, s, g.genesis)
	apply(t, s, g.root(t, &Event{Type: EventDissolve, IssuedAt: at(5)}))
	apply(t, s, g.by(t, founder, &Event{
		Type: EventMemberAdd, IssuedAt: at(6), Subject: late.accountID, Server: late.server,
	}))

	if s.Resolve().RoleOf(late.accountID) != RoleNone {
		t.Fatal("a dissolved group must not accept further members")
	}
}

func TestRegrantAfterRevocationTakesEffectAgain(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	mod := newAccount(t, "b.example.org")
	g := newGroup(t, founder)

	s := NewState()
	apply(t, s, g.genesis)
	apply(t, s, invite(t, g, founder, mod, 1, 2)...)
	apply(t, s,
		g.root(t, &Event{Type: EventRoleGrant, IssuedAt: at(3), Subject: mod.accountID, Role: RoleModerator}),
		g.root(t, &Event{Type: EventRoleRevoke, IssuedAt: at(4), Subject: mod.accountID, Role: RoleModerator}),
	)
	if s.Resolve().RoleOf(mod.accountID) != RoleMember {
		t.Fatal("a revoked moderator must fall back to member")
	}

	apply(t, s, g.root(t, &Event{
		Type: EventRoleGrant, IssuedAt: at(5), Subject: mod.accountID, Role: RoleModerator,
	}))
	if s.Resolve().RoleOf(mod.accountID) != RoleModerator {
		t.Fatal("a later grant must override an earlier revocation")
	}
}

func TestRevokingModeratorLeavesAnAdminGrantStanding(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	both := newAccount(t, "b.example.org")
	g := newGroup(t, founder)

	s := NewState()
	apply(t, s, g.genesis)
	apply(t, s, invite(t, g, founder, both, 1, 2)...)
	apply(t, s,
		g.root(t, &Event{Type: EventRoleGrant, IssuedAt: at(3), Subject: both.accountID, Role: RoleAdmin}),
		g.root(t, &Event{Type: EventRoleGrant, IssuedAt: at(4), Subject: both.accountID, Role: RoleModerator}),
		g.root(t, &Event{Type: EventRoleRevoke, IssuedAt: at(5), Subject: both.accountID, Role: RoleModerator}),
	)

	// Roles are tracked per grant, not as one current rank, so losing the
	// lesser one cannot silently demote away the greater.
	if got := s.Resolve().RoleOf(both.accountID); got != RoleAdmin {
		t.Fatalf("role = %s, want admin", got)
	}
}

func TestEqualRanksCannotRemoveEachOther(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	first := newAccount(t, "b.example.org")
	second := newAccount(t, "c.example.org")
	g := newGroup(t, founder)

	s := NewState()
	apply(t, s, g.genesis)
	apply(t, s, invite(t, g, founder, first, 1, 2)...)
	apply(t, s, invite(t, g, founder, second, 3, 4)...)
	apply(t, s,
		g.root(t, &Event{Type: EventRoleGrant, IssuedAt: at(5), Subject: first.accountID, Role: RoleModerator}),
		g.root(t, &Event{Type: EventRoleGrant, IssuedAt: at(6), Subject: second.accountID, Role: RoleModerator}),
	)

	// Two moderators fall out and each tries to remove the other. Neither can:
	// "only against strictly lower ranks" makes a mutual purge impossible in
	// the first place, so there is no race here to resolve and no state in
	// which the group loses both of them at once. Cleaning this up is an
	// admin's job, by design.
	apply(t, s,
		g.by(t, first, &Event{Type: EventMemberRemove, IssuedAt: at(10), Subject: second.accountID}),
		g.by(t, second, &Event{Type: EventMemberRemove, IssuedAt: at(11), Subject: first.accountID}),
	)

	r := s.Resolve()
	if r.RoleOf(first.accountID) != RoleModerator || r.RoleOf(second.accountID) != RoleModerator {
		t.Fatalf("neither moderator may remove the other, got %s and %s",
			r.RoleOf(first.accountID), r.RoleOf(second.accountID))
	}
}

func TestConcurrentPromotionAndRemovalResolveByTimestamp(t *testing.T) {
	// The genuine race: a moderator removes a member at the same moment an
	// admin promotes that member out of the moderator's reach. Whichever
	// timestamp is earlier decides, and every member decides the same way
	// because the fold replays in that order.
	run := func(t *testing.T, promoteAt int) Role {
		t.Helper()
		founder := newAccount(t, "a.example.org")
		admin := newAccount(t, "b.example.org")
		mod := newAccount(t, "c.example.org")
		target := newAccount(t, "d.example.org")
		g := newGroup(t, founder)

		s := NewState()
		apply(t, s, g.genesis)
		apply(t, s, invite(t, g, founder, admin, 1, 2)...)
		apply(t, s, invite(t, g, founder, mod, 3, 4)...)
		apply(t, s, invite(t, g, founder, target, 5, 6)...)
		apply(t, s,
			g.root(t, &Event{Type: EventRoleGrant, IssuedAt: at(7), Subject: admin.accountID, Role: RoleAdmin}),
			g.by(t, admin, &Event{Type: EventRoleGrant, IssuedAt: at(8), Subject: mod.accountID, Role: RoleModerator}),
		)
		apply(t, s,
			g.by(t, mod, &Event{Type: EventMemberRemove, IssuedAt: at(10), Subject: target.accountID}),
			g.by(t, admin, &Event{Type: EventRoleGrant, IssuedAt: at(promoteAt), Subject: target.accountID, Role: RoleModerator}),
		)
		return s.Resolve().RoleOf(target.accountID)
	}

	// Promotion lands first: the target is a moderator by the time the removal
	// is evaluated, and an equal rank cannot remove them.
	if got := run(t, 9); got != RoleModerator {
		t.Fatalf("promotion before removal: role = %s, want moderator", got)
	}
	// Removal lands first: the promotion then names someone who is no longer
	// a member and does nothing.
	if got := run(t, 11); got != RoleNone {
		t.Fatalf("removal before promotion: role = %s, want none", got)
	}
}

func TestLateRevocationInvalidatesAnActRetroactively(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	mod := newAccount(t, "b.example.org")
	victim := newAccount(t, "c.example.org")
	g := newGroup(t, founder)

	revoke := g.root(t, &Event{
		Type: EventRoleRevoke, IssuedAt: at(9), Subject: mod.accountID, Role: RoleModerator,
	})
	removal := g.by(t, mod, &Event{
		Type: EventMemberRemove, IssuedAt: at(10), Subject: victim.accountID,
	})

	s := NewState()
	apply(t, s, g.genesis)
	apply(t, s, invite(t, g, founder, mod, 1, 2)...)
	apply(t, s, invite(t, g, founder, victim, 3, 4)...)
	apply(t, s, g.root(t, &Event{
		Type: EventRoleGrant, IssuedAt: at(5), Subject: mod.accountID, Role: RoleModerator,
	}))

	// The removal arrives first and takes effect.
	apply(t, s, removal)
	if s.Resolve().RoleOf(victim.accountID) != RoleNone {
		t.Fatal("a moderator's removal must take effect")
	}

	// Then the revocation turns up, timestamped before it. The moderator was
	// not a moderator when they signed, so the removal was never valid --
	// documented as accepted behaviour, and it must be deterministic.
	apply(t, s, revoke)
	if s.Resolve().RoleOf(victim.accountID) != RoleMember {
		t.Fatal("a late revocation must undo the act it predates")
	}
}

func TestResolveIsIndependentOfArrivalOrder(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	admin := newAccount(t, "b.example.org")
	mod := newAccount(t, "c.example.org")
	gone := newAccount(t, "d.example.org")
	g := newGroup(t, founder)

	events := []*Event{g.genesis}
	events = append(events, invite(t, g, founder, admin, 1, 2)...)
	events = append(events, invite(t, g, founder, mod, 3, 4)...)
	events = append(events, invite(t, g, founder, gone, 5, 6)...)
	events = append(events,
		g.root(t, &Event{Type: EventRoleGrant, IssuedAt: at(7), Subject: admin.accountID, Role: RoleAdmin}),
		g.by(t, admin, &Event{Type: EventRoleGrant, IssuedAt: at(8), Subject: mod.accountID, Role: RoleModerator}),
		g.by(t, mod, &Event{Type: EventMemberRemove, IssuedAt: at(9), Subject: gone.accountID}),
		g.by(t, mod, &Event{Type: EventMeta, IssuedAt: at(10), Name: "Wandergruppe", Topic: "Samstag 9 Uhr"}),
	)

	reference := NewState()
	apply(t, reference, events...)
	want := reference.Resolve()
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	// Rotations stand in for arbitrary delivery orders: every member ends up
	// with the same fact set eventually, and must fold it the same way.
	for shift := 1; shift < len(events); shift++ {
		shuffled := append(append([]*Event{}, events[shift:]...), events[:shift]...)

		s := NewState()
		// Events ahead of the genesis in this order are rejected on the first
		// pass, so feed the batch twice -- which is exactly what a real client
		// does when a state_hash mismatch makes it ask for a snapshot.
		s.Apply(shuffled)
		apply(t, s, shuffled...)

		if got := s.StateHash(); got != reference.StateHash() {
			t.Fatalf("shift %d: state hash differs", shift)
		}
		gotJSON, err := json.Marshal(s.Resolve())
		if err != nil {
			t.Fatal(err)
		}
		if string(gotJSON) != string(wantJSON) {
			t.Fatalf("shift %d: resolved state differs\n got: %s\nwant: %s", shift, gotJSON, wantJSON)
		}
	}
}

func TestApplyingASnapshotTwiceChangesNothing(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	member := newAccount(t, "b.example.org")
	g := newGroup(t, founder)

	events := append([]*Event{g.genesis}, invite(t, g, founder, member, 1, 2)...)

	s := NewState()
	apply(t, s, events...)
	before := s.StateHash()

	result := s.Apply(events)
	if len(result.Applied) != 0 || len(result.Rejected) != 0 {
		t.Fatalf("a repeated snapshot must be a no-op, got %+v", result)
	}
	if len(result.Known) != len(events) {
		t.Fatalf("want %d known events, got %d", len(events), len(result.Known))
	}
	if s.StateHash() != before {
		t.Fatal("state hash must not change when nothing new arrived")
	}
}

func TestStateHashDiffersWhenAFactIsMissing(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	member := newAccount(t, "b.example.org")
	g := newGroup(t, founder)

	joined := invite(t, g, founder, member, 1, 2)

	full := NewState()
	apply(t, full, append([]*Event{g.genesis}, joined...)...)

	partial := NewState()
	apply(t, partial, g.genesis, joined[0])

	if full.StateHash() == partial.StateHash() {
		t.Fatal("a member missing one fact must see a different state hash -- that is the whole repair trigger")
	}
}

func TestEventsForAnotherGroupAreRejected(t *testing.T) {
	founderA := newAccount(t, "a.example.org")
	founderB := newAccount(t, "b.example.org")
	outsider := newAccount(t, "c.example.org")
	groupA := newGroup(t, founderA)
	groupB := newGroup(t, founderB)

	foreign := groupB.by(t, founderB, &Event{
		Type: EventMemberAdd, IssuedAt: at(1), Subject: outsider.accountID, Server: outsider.server,
	})

	s := NewState()
	apply(t, s, groupA.genesis)
	result := s.Apply([]*Event{foreign})
	if len(result.Rejected) != 1 {
		t.Fatalf("an event for another group must be rejected, got %+v", result)
	}
}

func TestEventsWithoutGenesisAreRejected(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	member := newAccount(t, "b.example.org")
	g := newGroup(t, founder)

	add := g.by(t, founder, &Event{
		Type: EventMemberAdd, IssuedAt: at(1), Subject: member.accountID, Server: member.server,
	})

	s := NewState()
	result := s.Apply([]*Event{add})
	if len(result.Rejected) != 1 {
		t.Fatalf("without a genesis there is no group root key to check against, got %+v", result)
	}
}

func TestStateJSONRoundTripReverifiesEverything(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	member := newAccount(t, "b.example.org")
	g := newGroup(t, founder)

	s := NewState()
	apply(t, s, append([]*Event{g.genesis}, invite(t, g, founder, member, 1, 2)...)...)
	apply(t, s, g.by(t, founder, &Event{
		Type: EventMeta, IssuedAt: at(3), Name: "Nachbarschaft", Topic: "Werkzeugverleih",
	}))

	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	restored := NewState()
	if err := json.Unmarshal(data, restored); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if restored.StateHash() != s.StateHash() {
		t.Fatal("a reloaded state must hash identically")
	}
	if restored.Resolve().Name != "Nachbarschaft" {
		t.Fatal("metadata lost in the round trip")
	}

	// Storage is not a trust boundary: a doctored file must not load.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	events := raw["events"].([]any)
	events[len(events)-1].(map[string]any)["topic"] = "tampered"
	doctored, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(doctored, NewState()); err == nil {
		t.Fatal("a tampered stored event must fail to load")
	}
}
