// Groups (SRV-01) for the reference client: found a group, invite, moderate,
// and send into it -- the whole design exercised end to end, across two local
// servers, before any UI exists.
//
// A group has no server behind it. Everything here is either a locally signed
// fact or an ordinary encrypted message fanned out to each member, so nothing
// in this file talks to a group endpoint: there is none.
package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/group"
)

// groupCtx is one group, opened for one command.
type groupCtx struct {
	state *State
	path  string
	id    string
	gs    *group.State

	// Per-run caches. A fan-out resolves the same member's device and asks the
	// same server about its capabilities repeatedly otherwise.
	devices map[string]resolvedDevice
	batch   map[string]*batchCapability

	// answered records which (peer, state hash) mismatches this run has
	// already answered with a snapshot, so two peers that stay divergent do
	// not trade snapshots forever.
	answered map[string]bool

	// held keeps facts that arrived before the ones they depend on -- delivery
	// is unordered, so an event can easily overtake the snapshot carrying the
	// genesis it needs.
	held []*group.Event
}

type resolvedDevice struct {
	accountID string
	deviceID  string
	devicePub ed25519.PublicKey
	server    string // "" when the member is on this client's own server
}

type batchCapability struct {
	supported bool
	max       int
}

func runGroup(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		printGroupUsage()
		return fmt.Errorf("group: an action is required")
	}
	action, rest := args[0], args[1:]

	fs := flag.NewFlagSet("group "+action, flag.ExitOnError)
	dataDir := fs.String("datadir", "./devclient-data", "local state directory")
	id := fs.String("id", "", "group id (not needed for create/list)")
	to := fs.String("to", "", "the account this action is about")
	toServer := fs.String("to-server", "", "that account's home server, if it differs from this one -- federated delivery (docs/PROTOCOL.md §9)")
	name := fs.String("name", "", "group name")
	topic := fs.String("topic", "", "group topic")
	role := fs.String("role", "moderator", "role to grant or revoke: moderator|admin")
	text := fs.String("text", "", "message text")
	once := fs.Bool("once", false, "watch: drain the queue once and exit, instead of polling until interrupted")
	verboseFlag := fs.Bool("verbose", false, "log every request to the server")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	verbose = *verboseFlag

	path := statePath(*dataDir)
	state, err := LoadState(path)
	if err != nil {
		return err
	}
	// Every group action ends up sending something encrypted, and a first
	// contact needs this client's own prekeys published first.
	if len(state.SignedPrekeyPriv) == 0 {
		fmt.Println("No prekeys uploaded yet -- uploading now...")
		if err := uploadPrekeys(state, defaultOneTimePrekeyBatch); err != nil {
			return err
		}
		if err := state.Save(path); err != nil {
			return err
		}
	}

	switch action {
	case "create":
		return groupCreate(state, path, *name)
	case "list":
		return groupList(state)
	case "watch":
		// Deliberately does NOT require -id: the first thing a new member ever
		// receives is a snapshot for a group they have never heard of, so
		// having to name it first would make an invitation impossible to
		// accept.
		return newGroupWatcher(state, path, resolveWatchID(state, *id)).watch(*once)
	}

	g, err := openGroup(state, path, *id)
	if err != nil {
		return err
	}

	switch action {
	case "show":
		g.show()
		return nil
	case "invite":
		return g.invite(*to, *toServer)
	case "accept":
		return g.accept()
	case "grant":
		return g.setRole(*to, *role, true)
	case "revoke":
		return g.setRole(*to, *role, false)
	case "remove":
		return g.remove(*to)
	case "meta":
		return g.setMeta(*name, *topic)
	case "leave":
		return g.leave()
	case "dissolve":
		return g.dissolve()
	case "send":
		return g.sendText(*text)
	case "sync":
		return g.syncAll()
	default:
		printGroupUsage()
		return fmt.Errorf("group: unknown action %q", action)
	}
}

func printGroupUsage() {
	fmt.Fprintln(os.Stderr, `devclient group ACTION -datadir DIR [flags]

  create   -name NAME                       found a group (this account becomes its founder)
  list                                      list the groups this account knows about
  show     -id GROUP_ID                     members, roles and the current state hash
  invite   -id GROUP_ID -to ACCOUNT [-to-server URL]
  accept   -id GROUP_ID                     accept an invitation addressed to this account
  grant    -id GROUP_ID -to ACCOUNT -role moderator|admin
  revoke   -id GROUP_ID -to ACCOUNT -role moderator|admin
  remove   -id GROUP_ID -to ACCOUNT
  meta     -id GROUP_ID [-name NAME] [-topic TOPIC]
  leave    -id GROUP_ID                     leave (the founder cannot; use dissolve)
  dissolve -id GROUP_ID                     end the group (founder only)
  send     -id GROUP_ID -text TEXT          fan out one message to every joined member
  sync     -id GROUP_ID                     push this client's full fact set to every member
  watch    -id GROUP_ID [-once]             receive loop: messages, state events, state_hash repair`)
}

// resolveWatchID expands a prefix to a known group id where it matches one,
// and otherwise passes it through -- including the empty string, which means
// "every group".
func resolveWatchID(state *State, id string) string {
	if id == "" {
		return ""
	}
	for known := range state.Groups {
		if strings.HasPrefix(known, id) {
			return known
		}
	}
	return id
}

// openGroup loads one group out of local state, accepting a unique id prefix
// so a 21-character id need not be retyped.
func openGroup(state *State, path, id string) (*groupCtx, error) {
	if id == "" {
		return nil, fmt.Errorf("group: -id is required")
	}
	var matches []string
	for known := range state.Groups {
		if strings.HasPrefix(known, id) {
			matches = append(matches, known)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("group: no known group with id %q -- run `group list`", id)
	case 1:
	default:
		return nil, fmt.Errorf("group: %q matches %d groups", id, len(matches))
	}

	return &groupCtx{
		state:   state,
		path:    path,
		id:      matches[0],
		gs:      state.Groups[matches[0]],
		devices: map[string]resolvedDevice{},
		batch:   map[string]*batchCapability{},
	}, nil
}

// groupCreate founds a group. The group root key is derived from this
// account's root key and a fresh nonce that lives in the genesis event, so it
// survives total device loss: restore the seed phrase, get the state back from
// any member, re-derive.
func groupCreate(state *State, path, name string) error {
	nonce, err := group.NewNonce()
	if err != nil {
		return err
	}
	rootPriv, err := group.DeriveRootKey(ed25519.PrivateKey(state.RootPriv).Seed(), nonce)
	if err != nil {
		return err
	}
	groupID, err := group.DeriveID(rootPriv.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}

	genesis := &group.Event{
		Type:       group.EventGenesis,
		GroupID:    groupID,
		IssuedAt:   groupNow(),
		RootPubKey: rootPriv.Public().(ed25519.PublicKey),
		Nonce:      nonce,
		Subject:    state.AccountID,
		Server:     state.Server,
	}
	if err := group.SignRoot(genesis, rootPriv); err != nil {
		return err
	}

	gs := group.NewState()
	if result := gs.Apply([]*group.Event{genesis}); len(result.Rejected) > 0 {
		return fmt.Errorf("group: own genesis rejected: %s", result.Rejected[0].Reason)
	}
	state.Groups[groupID] = gs

	g := &groupCtx{state: state, path: path, id: groupID, gs: gs,
		devices: map[string]resolvedDevice{}, batch: map[string]*batchCapability{}}

	if name != "" {
		meta := &group.Event{Type: group.EventMeta, IssuedAt: groupNow(), Name: name}
		if err := g.signDevice(meta); err != nil {
			return err
		}
		if err := g.applyLocal(meta); err != nil {
			return err
		}
	}
	if err := state.Save(path); err != nil {
		return err
	}

	fmt.Printf("Created group %s\n", groupID)
	g.show()
	return nil
}

func groupList(state *State) error {
	if len(state.Groups) == 0 {
		fmt.Println("No groups.")
		return nil
	}
	ids := make([]string, 0, len(state.Groups))
	for id := range state.Groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		r := state.Groups[id].Resolve()
		label := r.Name
		if label == "" {
			label = "(unnamed)"
		}
		fmt.Printf("%s  %-24s  %d member(s)  role=%s\n",
			id, label, len(r.Members), r.RoleOf(state.AccountID))
	}
	return nil
}

func (g *groupCtx) show() {
	r := g.gs.Resolve()
	fmt.Printf("Group      %s\n", r.GroupID)
	fmt.Printf("Name       %s\n", orPlaceholder(r.Name, "(unnamed)"))
	fmt.Printf("Topic      %s\n", orPlaceholder(r.Topic, "(none)"))
	fmt.Printf("Founder    %s\n", r.Founder)
	fmt.Printf("State hash %s\n", r.StateHash)
	fmt.Printf("Facts      %d\n", len(g.gs.Events()))
	if r.Dissolved {
		fmt.Printf("DISSOLVED  %s\n", r.DissolvedAt.Format(time.RFC3339))
	}
	fmt.Println("Members:")
	for _, m := range r.Members {
		marker := "  "
		if m.AccountID == g.state.AccountID {
			marker = "* "
		}
		pending := ""
		if !m.Joined {
			pending = "  (invited, not accepted)"
		}
		fmt.Printf("%s%s  %-10s %s%s\n", marker, m.AccountID, m.Role, m.Server, pending)
	}
}

func orPlaceholder(s, placeholder string) string {
	if s == "" {
		return placeholder
	}
	return s
}

// groupNow is the timestamp every event carries. Truncated to the second
// because that is the granularity the signing bytes have -- finer digits would
// be unsigned data that still influenced replay order.
func groupNow() time.Time { return time.Now().UTC().Truncate(time.Second) }

// signer builds the identity block an event carries: the account id, its root
// key, and a device certificate freshly signed under it -- the same
// self-describing block federated message delivery uses.
func (g *groupCtx) signer() (*group.Signer, error) {
	issuedAt := time.Now().UTC()
	cert, err := devicecert.SignDeviceCertificate(g.state.AccountID, g.state.DeviceID,
		ed25519.PublicKey(g.state.DevicePub), issuedAt, ed25519.PrivateKey(g.state.RootPriv))
	if err != nil {
		return nil, fmt.Errorf("signing device certificate: %w", err)
	}
	return &group.Signer{
		AccountID:  g.state.AccountID,
		RootPubKey: ed25519.PublicKey(g.state.RootPub),
		DeviceCert: *cert,
	}, nil
}

func (g *groupCtx) signDevice(e *group.Event) error {
	e.GroupID = g.id
	signer, err := g.signer()
	if err != nil {
		return err
	}
	return group.SignDevice(e, signer, ed25519.PrivateKey(g.state.DevicePriv))
}

// signRoot signs with the group root key, re-derived from this account's root
// key and the nonce in the genesis event. Only the founder can do this, and
// only because the derivation makes the key reproducible rather than stored.
func (g *groupCtx) signRoot(e *group.Event) error {
	genesis := g.gs.Genesis()
	if genesis == nil {
		return fmt.Errorf("group: no genesis event")
	}
	if genesis.Subject != g.state.AccountID {
		return fmt.Errorf("group: only the founder (%s) can do that", genesis.Subject)
	}
	rootPriv, err := group.DeriveRootKey(ed25519.PrivateKey(g.state.RootPriv).Seed(), genesis.Nonce)
	if err != nil {
		return err
	}
	e.GroupID = g.id
	return group.SignRoot(e, rootPriv)
}

// applyLocal admits this client's own events into its own fact set. A
// rejection here is a bug in this client, not a peer's problem, so it is an
// error rather than something to report and carry on from.
func (g *groupCtx) applyLocal(events ...*group.Event) error {
	result := g.gs.Apply(events)
	if len(result.Rejected) > 0 {
		return fmt.Errorf("group: own event rejected: %s", result.Rejected[0].Reason)
	}
	return nil
}

func (g *groupCtx) invite(to, toServer string) error {
	if to == "" {
		return fmt.Errorf("group: -to is required")
	}
	server := toServer
	if server == "" {
		server = g.state.Server
	}
	// Resolve first: the event records the invitee's FULL account id, and the
	// lookup is also what proves the account exists at all.
	dev, err := g.resolveMember(to, server)
	if err != nil {
		return err
	}

	add := &group.Event{
		Type:     group.EventMemberAdd,
		IssuedAt: groupNow(),
		Subject:  dev.accountID,
		Server:   server,
	}
	if err := g.signDevice(add); err != nil {
		return err
	}
	if err := g.applyLocal(add); err != nil {
		return err
	}
	if err := g.state.Save(g.path); err != nil {
		return err
	}

	// The invitee gets the whole fact set -- they have nothing to merge it
	// into. Everyone else gets just the new fact, with the chain that
	// authorizes it riding along inside the event itself.
	r := g.gs.Resolve()
	if err := g.sendSnapshotTo(memberByID(r, dev.accountID)); err != nil {
		return fmt.Errorf("sending snapshot to invitee: %w", err)
	}
	return g.broadcastEvents([]*group.Event{add}, dev.accountID)
}

func (g *groupCtx) accept() error {
	accept := &group.Event{
		Type:     group.EventJoinAccept,
		IssuedAt: groupNow(),
		Subject:  g.state.AccountID,
	}
	if err := g.signDevice(accept); err != nil {
		return err
	}
	if err := g.applyLocal(accept); err != nil {
		return err
	}
	if err := g.state.Save(g.path); err != nil {
		return err
	}
	fmt.Printf("Accepted the invitation to %s.\n", g.id)
	// Announcing this is the invitee's own job as much as the inviter's: they
	// have the strongest interest in every member knowing to send to them.
	return g.broadcastEvents([]*group.Event{accept})
}

func (g *groupCtx) setRole(to, roleName string, grant bool) error {
	if to == "" {
		return fmt.Errorf("group: -to is required")
	}
	var role group.Role
	switch roleName {
	case "moderator":
		role = group.RoleModerator
	case "admin":
		role = group.RoleAdmin
	default:
		return fmt.Errorf("group: -role must be moderator or admin, got %q", roleName)
	}

	subject, err := g.memberIDByPrefix(to)
	if err != nil {
		return err
	}

	eventType := group.EventRoleRevoke
	if grant {
		eventType = group.EventRoleGrant
	}
	e := &group.Event{Type: eventType, IssuedAt: groupNow(), Subject: subject, Role: role}

	// Admin is the founder's to give, so it needs the group root key; anything
	// below that an admin can sign with their own device. Both forms are
	// admissible -- the fold decides which was sufficient.
	if role == group.RoleAdmin {
		err = g.signRoot(e)
	} else {
		err = g.signDevice(e)
	}
	if err != nil {
		return err
	}
	return g.applyAndBroadcast(e)
}

func (g *groupCtx) remove(to string) error {
	if to == "" {
		return fmt.Errorf("group: -to is required")
	}
	subject, err := g.memberIDByPrefix(to)
	if err != nil {
		return err
	}
	e := &group.Event{Type: group.EventMemberRemove, IssuedAt: groupNow(), Subject: subject}
	if err := g.signDevice(e); err != nil {
		return err
	}
	// The removed member is told too: they are still a member as far as their
	// own copy of the state is concerned until this reaches them.
	return g.applyAndBroadcast(e)
}

func (g *groupCtx) setMeta(name, topic string) error {
	// Name and topic are one last-writer-wins record, so an unset flag means
	// "keep", not "clear" -- otherwise setting a topic would erase the name.
	r := g.gs.Resolve()
	if name == "" {
		name = r.Name
	}
	if topic == "" {
		topic = r.Topic
	}
	e := &group.Event{Type: group.EventMeta, IssuedAt: groupNow(), Name: name, Topic: topic}
	if err := g.signDevice(e); err != nil {
		return err
	}
	return g.applyAndBroadcast(e)
}

func (g *groupCtx) leave() error {
	e := &group.Event{Type: group.EventLeave, IssuedAt: groupNow(), Subject: g.state.AccountID}
	if err := g.signDevice(e); err != nil {
		return err
	}
	return g.applyAndBroadcast(e)
}

func (g *groupCtx) dissolve() error {
	e := &group.Event{Type: group.EventDissolve, IssuedAt: groupNow()}
	if err := g.signRoot(e); err != nil {
		return err
	}
	return g.applyAndBroadcast(e)
}

// applyAndBroadcast is the shape every moderation action shares: apply it
// here, persist, tell everyone, then show what it did.
func (g *groupCtx) applyAndBroadcast(e *group.Event) error {
	if err := g.applyLocal(e); err != nil {
		return err
	}
	if err := g.state.Save(g.path); err != nil {
		return err
	}
	if err := g.broadcastEvents([]*group.Event{e}); err != nil {
		return err
	}
	g.show()
	return nil
}

func (g *groupCtx) sendText(text string) error {
	if text == "" {
		return fmt.Errorf("group: -text is required")
	}
	r := g.gs.Resolve()
	if r.Dissolved {
		return fmt.Errorf("group: this group has been dissolved")
	}
	if r.RoleOf(g.state.AccountID) == group.RoleNone {
		return fmt.Errorf("group: this account is not a member")
	}

	plaintext, _, err := encodeGroupText(g.id, r.StateHash, text)
	if err != nil {
		return err
	}
	// Only members who have accepted: an invitation must not disclose the
	// invitee's address to the group before they agree to it, and until they
	// accept there is nothing to send them anyway.
	return g.fanOut(plaintext, "group text", joinedMembers(r, g.state.AccountID))
}

// syncAll pushes this client's whole fact set to every member -- the manual
// form of what a state_hash mismatch triggers automatically.
func (g *groupCtx) syncAll() error {
	r := g.gs.Resolve()
	payload, err := encodeGroupControl("snapshot", g.id, r.StateHash, g.gs.Events())
	if err != nil {
		return err
	}
	return g.fanOut(payload, "group snapshot", joinedMembers(r, g.state.AccountID))
}

func (g *groupCtx) sendSnapshotTo(m *group.Member) error {
	if m == nil {
		return fmt.Errorf("group: no such member")
	}
	r := g.gs.Resolve()
	payload, err := encodeGroupControl("snapshot", g.id, r.StateHash, g.gs.Events())
	if err != nil {
		return err
	}
	return g.fanOut(payload, "group snapshot", []group.Member{*m})
}

// broadcastEvents sends a few new facts to every member except this account
// and any listed in skip (the invitee, who just got the whole snapshot).
//
// Recipients deliberately include members who have not accepted yet: a
// membership change is exactly the kind of fact a pending invitee needs, and
// the removal of a member has to reach the member being removed.
func (g *groupCtx) broadcastEvents(events []*group.Event, skip ...string) error {
	r := g.gs.Resolve()
	payload, err := encodeGroupControl("events", g.id, r.StateHash, events)
	if err != nil {
		return err
	}

	skipped := map[string]bool{g.state.AccountID: true}
	for _, s := range skip {
		skipped[s] = true
	}
	recipients := make([]group.Member, 0, len(r.Members))
	for _, m := range r.Members {
		if !skipped[m.AccountID] {
			recipients = append(recipients, m)
		}
	}
	// A removal's subject is no longer in the member list, so add them back:
	// they are the one person who most needs to hear it.
	for _, e := range events {
		if e.Type == group.EventMemberRemove && !skipped[e.Subject] {
			if m := memberByID(r, e.Subject); m == nil {
				recipients = append(recipients, group.Member{AccountID: e.Subject, Server: g.serverFor(e.Subject)})
				skipped[e.Subject] = true
			}
		}
	}
	return g.fanOut(payload, "group events", recipients)
}

// serverFor digs a member's home server out of the fact set, for someone who
// is no longer in the resolved member list.
func (g *groupCtx) serverFor(accountID string) string {
	server := g.state.Server
	for _, e := range g.gs.Events() {
		if e.Subject == accountID && e.Server != "" {
			server = e.Server
		}
	}
	return server
}

func memberByID(r *group.Resolved, accountID string) *group.Member {
	for i := range r.Members {
		if r.Members[i].AccountID == accountID {
			return &r.Members[i]
		}
	}
	return nil
}

func joinedMembers(r *group.Resolved, except string) []group.Member {
	out := make([]group.Member, 0, len(r.Members))
	for _, m := range r.Members {
		if m.Joined && m.AccountID != except {
			out = append(out, m)
		}
	}
	return out
}

// memberIDByPrefix expands a typed prefix to a full member account id, since
// every event signs the full one.
func (g *groupCtx) memberIDByPrefix(prefix string) (string, error) {
	var matches []string
	for _, m := range g.gs.Resolve().Members {
		if strings.HasPrefix(m.AccountID, prefix) {
			matches = append(matches, m.AccountID)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("group: no member matching %q", prefix)
	default:
		return "", fmt.Errorf("group: %q matches %d members", prefix, len(matches))
	}
}

// resolveMember looks up a member's current device, caching per run.
func (g *groupCtx) resolveMember(accountIDOrPrefix, server string) (resolvedDevice, error) {
	if cached, ok := g.devices[accountIDOrPrefix]; ok {
		return cached, nil
	}
	accountID, deviceID, devicePub, err := resolvePeerDevice(server, accountIDOrPrefix)
	if err != nil {
		return resolvedDevice{}, fmt.Errorf("resolving %s: %w", shortID(accountIDOrPrefix), err)
	}
	// "" means same-server for the send path; a member's recorded server is
	// absolute, so normalize it here rather than at every call site.
	federatedServer := server
	if server == g.state.Server {
		federatedServer = ""
	}
	dev := resolvedDevice{accountID: accountID, deviceID: deviceID, devicePub: devicePub, server: federatedServer}
	g.devices[accountIDOrPrefix] = dev
	g.devices[accountID] = dev
	return dev, nil
}
