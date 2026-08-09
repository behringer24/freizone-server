package client

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/group"
)

// What a member can do to a group, and how each of those becomes a fact
// everyone else can check.
//
// Every action here follows the same three steps: sign an event, apply it
// locally, tell the others. Applying locally first is deliberate -- the fold
// is what says whether the action was allowed at all, so an event this device
// would reject is one it must not broadcast either.

// CreateGroup founds a group and returns its id.
//
// The group's root key is *derived* from this account's own recovery seed and
// a nonce stored in the genesis event, never generated and stored. That is
// what lets a founder who has lost every device re-derive it from their
// recovery phrase alone -- a group whose key lived only on a phone would die
// with the phone.
func (c *Client) CreateGroup(ctx context.Context, name string) (string, error) {
	id, err := c.Identity()
	if err != nil {
		return "", err
	}
	nonce, err := group.NewNonce()
	if err != nil {
		return "", fmt.Errorf("client: generating group nonce: %w", err)
	}
	rootPriv, err := group.DeriveRootKey(ed25519.PrivateKey(id.RootPriv).Seed(), nonce)
	if err != nil {
		return "", fmt.Errorf("client: deriving group key: %w", err)
	}
	rootPub := rootPriv.Public().(ed25519.PublicKey)
	groupID, err := group.DeriveID(rootPub)
	if err != nil {
		return "", fmt.Errorf("client: deriving group id: %w", err)
	}

	genesis := &group.Event{
		Type: group.EventGenesis, GroupID: groupID, IssuedAt: groupNow(),
		RootPubKey: rootPub, Nonce: nonce,
		// The founder's own server rides on the genesis: they have no
		// member_add of their own, and would otherwise be the one member
		// nobody could address until they happened to speak.
		Subject: id.AccountID, Server: id.Server,
	}
	if err := group.SignRoot(genesis, rootPriv); err != nil {
		return "", fmt.Errorf("client: signing genesis: %w", err)
	}

	st := group.NewState()
	if res := st.Apply([]*group.Event{genesis}); len(res.Rejected) > 0 {
		return "", fmt.Errorf("client: own genesis rejected: %s", res.Rejected[0].Reason)
	}
	if err := c.PutGroupState(groupID, st); err != nil {
		return "", err
	}
	if err := c.PutGroupChat(GroupChat{GroupID: groupID}); err != nil {
		return "", err
	}

	if name != "" {
		if err := c.SetGroupMeta(ctx, groupID, name, ""); err != nil {
			return groupID, err
		}
	}
	return groupID, nil
}

// InviteToGroup adds somebody, resolving the address first.
//
// Resolving is not only about finding their device: the event records their
// *full* account id, and the lookup is what proves the account exists at all.
// An invitation to an address nobody holds would otherwise become a permanent
// member row nobody can remove.
func (c *Client) InviteToGroup(ctx context.Context, groupID, addressOrPrefix, server string) error {
	endpoint, err := c.ResolvePeer(ctx, addressOrPrefix, server)
	if err != nil {
		return err
	}
	if err := c.putPeerDevice(endpoint); err != nil {
		return err
	}
	memberServer := server
	if memberServer == "" {
		id, err := c.Identity()
		if err != nil {
			return err
		}
		memberServer = id.Server
	}

	add, err := c.signGroupEvent(groupID, &group.Event{
		Type: group.EventMemberAdd, Subject: endpoint.AccountID, Server: memberServer,
	})
	if err != nil {
		return err
	}
	if err := c.applyOwnGroupEvents(groupID, add); err != nil {
		return err
	}

	// The invitee gets the whole fact set -- they have nothing to merge a
	// delta into. Everyone else gets the one new fact, with the chain that
	// authorises it riding inside the event itself.
	if err := c.SendGroupSnapshot(ctx, groupID, endpoint.AccountID); err != nil {
		if oweErr := c.oweGroupSnapshot(groupID, endpoint.AccountID); oweErr != nil {
			return oweErr
		}
	}
	return c.BroadcastGroupEvents(ctx, groupID, []*group.Event{add}, endpoint.AccountID)
}

// AcceptGroupInvitation joins a group this account was invited to.
//
// An acceptance is signed by its own subject and nobody else, which is what
// makes "was invited" and "is in the group" two different facts: until this
// event exists, nothing is sent into the group and the address is not shared
// with it.
func (c *Client) AcceptGroupInvitation(ctx context.Context, groupID string) error {
	id, err := c.Identity()
	if err != nil {
		return err
	}
	accept, err := c.signGroupEvent(groupID, &group.Event{
		Type: group.EventJoinAccept, Subject: id.AccountID,
	})
	if err != nil {
		return err
	}
	if err := c.applyOwnGroupEvents(groupID, accept); err != nil {
		return err
	}
	return c.BroadcastGroupEvents(ctx, groupID, []*group.Event{accept})
}

// SetGroupRole grants or revokes a role.
func (c *Client) SetGroupRole(ctx context.Context, groupID, accountID string, role group.Role, grant bool) error {
	kind := group.EventRoleRevoke
	if grant {
		kind = group.EventRoleGrant
	}
	event, err := c.signGroupEvent(groupID, &group.Event{
		Type: kind, Subject: accountID, Role: role,
	})
	if err != nil {
		return err
	}
	if err := c.applyOwnGroupEvents(groupID, event); err != nil {
		return err
	}
	return c.BroadcastGroupEvents(ctx, groupID, []*group.Event{event})
}

// RemoveFromGroup removes a member.
//
// They are told, which is the point: they hold the facts either way, and a
// member who is removed silently goes on trying to send into a group nobody
// will accept from them.
func (c *Client) RemoveFromGroup(ctx context.Context, groupID, accountID string) error {
	event, err := c.signGroupEvent(groupID, &group.Event{
		Type: group.EventMemberRemove, Subject: accountID,
	})
	if err != nil {
		return err
	}
	if err := c.applyOwnGroupEvents(groupID, event); err != nil {
		return err
	}
	// Broadcast before the fold takes them out of the member list on the
	// others' side too -- which it already has here, so they are named
	// explicitly rather than found in the membership.
	if err := c.sendGroupEventTo(ctx, groupID, accountID, event); err != nil {
		// They will find out from anyone else who tells them; a removal is not
		// worth a debt, since owing a snapshot to somebody removed makes no
		// sense.
		_ = err
	}
	return c.BroadcastGroupEvents(ctx, groupID, []*group.Event{event}, accountID)
}

// LeaveGroup leaves, telling everyone.
func (c *Client) LeaveGroup(ctx context.Context, groupID string) error {
	id, err := c.Identity()
	if err != nil {
		return err
	}
	event, err := c.signGroupEvent(groupID, &group.Event{
		Type: group.EventLeave, Subject: id.AccountID,
	})
	if err != nil {
		return err
	}
	// Broadcast *before* applying: once the fold has taken us out, the member
	// list this reads is the one without us -- and, more to the point, without
	// the servers of anyone we would still have to tell.
	if err := c.BroadcastGroupEvents(ctx, groupID, []*group.Event{event}); err != nil {
		return err
	}
	return c.applyOwnGroupEvents(groupID, event)
}

// SetGroupMeta renames a group or changes its topic.
//
// Both together, as one last-writer-wins record: two independently merged
// fields would produce a conflict case that buys nothing.
func (c *Client) SetGroupMeta(ctx context.Context, groupID, name, topic string) error {
	event, err := c.signGroupEvent(groupID, &group.Event{
		Type: group.EventMeta, Name: name, Topic: topic,
	})
	if err != nil {
		return err
	}
	if err := c.applyOwnGroupEvents(groupID, event); err != nil {
		return err
	}
	return c.BroadcastGroupEvents(ctx, groupID, []*group.Event{event})
}

// DissolveGroup ends a group for everyone. Signed with the group root key, so
// only the founder can do it.
func (c *Client) DissolveGroup(ctx context.Context, groupID string) error {
	st, err := c.GroupState(groupID)
	if err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("client: no facts about group %s", groupID)
	}
	genesis := st.Genesis()
	if genesis == nil {
		return fmt.Errorf("client: group %s has no genesis", groupID)
	}
	id, err := c.Identity()
	if err != nil {
		return err
	}
	// Re-derived rather than stored, from this account's own seed and the
	// nonce in the genesis -- which is also why only the founder can produce
	// it, and why they can still produce it on a device that has never seen
	// this group before.
	rootPriv, err := group.DeriveRootKey(ed25519.PrivateKey(id.RootPriv).Seed(), genesis.Nonce)
	if err != nil {
		return fmt.Errorf("client: deriving group key: %w", err)
	}
	if !rootPriv.Public().(ed25519.PublicKey).Equal(st.RootPubKey()) {
		return fmt.Errorf("client: only the founder can dissolve group %s", groupID)
	}

	event := &group.Event{Type: group.EventDissolve, GroupID: groupID, IssuedAt: groupNow()}
	if err := group.SignRoot(event, rootPriv); err != nil {
		return fmt.Errorf("client: signing dissolve: %w", err)
	}
	if err := c.applyOwnGroupEvents(groupID, event); err != nil {
		return err
	}
	return c.BroadcastGroupEvents(ctx, groupID, []*group.Event{event})
}

// signGroupEvent signs with this device's key, carrying the certificate chain
// that proves the device speaks for the account.
func (c *Client) signGroupEvent(groupID string, e *group.Event) (*group.Event, error) {
	id, err := c.Identity()
	if err != nil {
		return nil, err
	}
	e.GroupID = groupID
	if e.IssuedAt.IsZero() {
		e.IssuedAt = groupNow()
	}
	issuedAt := time.Now().UTC()
	cert, err := devicecert.SignDeviceCertificate(
		id.AccountID, id.DeviceID, ed25519.PublicKey(id.DevicePub), issuedAt, ed25519.PrivateKey(id.RootPriv))
	if err != nil {
		return nil, fmt.Errorf("client: signing device certificate: %w", err)
	}
	signer := &group.Signer{
		AccountID:  id.AccountID,
		RootPubKey: ed25519.PublicKey(id.RootPub),
		DeviceCert: *cert,
	}
	if err := group.SignDevice(e, signer, ed25519.PrivateKey(id.DevicePriv)); err != nil {
		return nil, fmt.Errorf("client: signing group event: %w", err)
	}
	return e, nil
}

// applyOwnGroupEvents folds our own events in, and refuses to go on if the
// fold rejects one.
//
// The fold is the authority on whether an action was allowed -- an event this
// device would reject is one every other member will reject too, so
// broadcasting it would produce nothing but a divergent view of the group.
func (c *Client) applyOwnGroupEvents(groupID string, events ...*group.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	st, err := c.groupStateLocked(groupID)
	if err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("client: no facts about group %s", groupID)
	}
	before := foldPrint(st)
	if res := st.Apply(events); len(res.Rejected) > 0 {
		return fmt.Errorf("client: %s not allowed: %s", events[0].Type, res.Rejected[0].Reason)
	}
	// Apply only checks that an event is well formed and signed; whether the
	// signer was *allowed* to do it is the fold.s decision, and the fold simply
	// ignores what it will not honour. So an event that changes nothing changed
	// nothing for a reason -- and broadcasting it would produce a divergent
	// view of the group and no error anywhere.
	//
	// Only for the types that must change something. Setting the name to what
	// it already is, or granting a role somebody already holds, is idempotent
	// rather than refused.
	if mustTakeEffect(events) && foldPrint(st) == before {
		return fmt.Errorf("client: %s had no effect -- this account is not allowed to do that", events[0].Type)
	}
	return c.putGroupStateLocked(groupID, st)
}

// sendGroupEventTo tells one named account about an event, used where the
// member list no longer contains them.
func (c *Client) sendGroupEventTo(ctx context.Context, groupID, accountID string, events ...*group.Event) error {
	st, err := c.GroupState(groupID)
	if err != nil || st == nil {
		return err
	}
	id, err := c.Identity()
	if err != nil {
		return err
	}
	server := ""
	if convo, err := c.Conversation(accountID); err == nil && convo != nil {
		server = convo.PeerServer
	}
	if cached, err := c.peerDevice(accountID); err == nil && cached != nil && server == "" {
		server = cached.Server
	}
	plaintext, err := encodeGroupControl(GroupEvents, groupID, st.Resolve().StateHash, events)
	if err != nil {
		return err
	}
	return c.sendGroupControl(ctx, group.Member{AccountID: accountID, Server: server}, id.Server, plaintext)
}

// groupNow is the clock group events are stamped with, truncated to the second
// -- the granularity the fold buckets by, so a finer stamp would only make two
// facts that happened together look ordered.
func groupNow() time.Time { return time.Now().UTC().Truncate(time.Second) }

// foldPrint is a comparable rendering of the membership, for telling an action
// that took effect from one the fold declined to honour.
//
// The state hash cannot answer that: it covers the fact *set*, so it changes
// whenever an event is added, whether or not the fold acted on it.
func foldPrint(st *group.State) string {
	resolved := st.Resolve()
	resolved.StateHash = ""
	out, err := json.Marshal(resolved)
	if err != nil {
		return ""
	}
	return string(out)
}

// mustTakeEffect reports whether these events are of a kind that has to change
// the membership to have meant anything.
func mustTakeEffect(events []*group.Event) bool {
	for _, e := range events {
		switch e.Type {
		case group.EventMemberAdd, group.EventMemberRemove, group.EventJoinAccept,
			group.EventLeave, group.EventDissolve:
			return true
		}
	}
	return false
}
