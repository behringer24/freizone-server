package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/behringer24/freizone-server/pkg/group"
)

// groupWatcher is the receiving half of groups: it drains this device's one
// message queue and dispatches each envelope to the group it names.
//
// Deliberately not scoped to a single group, because the first thing a new
// member ever receives is a snapshot for a group they have never heard of --
// requiring them to name it first would make an invitation impossible to
// accept. This is also simply what a real client does: one queue, dispatch by
// group id.
type groupWatcher struct {
	state *State
	path  string
	only  string // when set, ignore every other group

	groups map[string]*groupCtx
}

func newGroupWatcher(state *State, path, only string) *groupWatcher {
	return &groupWatcher{state: state, path: path, only: only, groups: map[string]*groupCtx{}}
}

// watch drains the queue, either once or until interrupted.
//
// The poll is deliberate rather than the SSE stream the interactive chat uses:
// this is meant to be run between other one-shot commands, and a poll makes
// what happens at each tick obvious in the output.
func (w *groupWatcher) watch(once bool) error {
	if once {
		if err := w.pollOnce(); err != nil {
			return err
		}
		w.showAll()
		return nil
	}

	label := "all groups"
	if w.only != "" {
		label = "group " + shortID(w.only)
	}
	fmt.Printf("Watching %s as %s. Ctrl+C to stop.\n", label, shortID(w.state.AccountID))
	w.showAll()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		if err := w.pollOnce(); err != nil {
			fmt.Fprintln(os.Stderr, "poll error:", err)
		}
		select {
		case <-interrupt:
			fmt.Println("\nStopped.")
			return nil
		case <-ticker.C:
		}
	}
}

func (w *groupWatcher) showAll() {
	for _, g := range w.knownGroups() {
		g.show()
	}
}

func (w *groupWatcher) knownGroups() []*groupCtx {
	var out []*groupCtx
	for id := range w.state.Groups {
		if w.only != "" && id != w.only {
			continue
		}
		out = append(out, w.ctxFor(id))
	}
	return out
}

// ctxFor returns the per-group context, creating it (and the group's local
// fact set, if this is a group we are only now hearing about) on demand.
func (w *groupWatcher) ctxFor(groupID string) *groupCtx {
	if g, ok := w.groups[groupID]; ok {
		return g
	}
	gs, ok := w.state.Groups[groupID]
	if !ok {
		gs = group.NewState()
		w.state.Groups[groupID] = gs
	}
	g := &groupCtx{
		state:   w.state,
		path:    w.path,
		id:      groupID,
		gs:      gs,
		devices: map[string]resolvedDevice{},
		batch:   map[string]*batchCapability{},
	}
	w.groups[groupID] = g
	return g
}

func (w *groupWatcher) pollOnce() error {
	resp, err := signedRequest(w.state, http.MethodGet, "/v1/messages", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("polling messages: %s: %s", resp.Status, data)
	}

	var messages []messageResponse
	if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
		return err
	}
	for _, msg := range messages {
		w.handleIncoming(msg)
	}
	return nil
}

// handleIncoming decrypts one queued envelope and routes it. Anything that is
// not a group envelope is left in the queue untouched -- the interactive chat
// owns those, and silently dropping them would lose real messages.
func (w *groupWatcher) handleIncoming(msg messageResponse) {
	decoded, err := decryptIncoming(w.state, msg)
	if err != nil {
		fmt.Printf("[%s] undecryptable: %v\n", shortID(msg.SenderAccountID), err)
		return
	}
	if decoded.kind != decodedGroupText && decoded.kind != decodedGroupControl {
		return
	}
	if w.only != "" && decoded.groupID != w.only {
		return
	}

	// A control envelope for an unknown group is how an invitation arrives:
	// the snapshot carries the genesis, so the group becomes known by being
	// told about it. A *text* for an unknown group is not -- it would be a
	// message we cannot place, so it waits for the snapshot to catch up.
	if _, known := w.state.Groups[decoded.groupID]; !known && decoded.kind != decodedGroupControl {
		fmt.Printf("[%s] message for unknown group %s -- waiting for a snapshot\n",
			shortID(msg.SenderAccountID), shortID(decoded.groupID))
		return
	}
	g := w.ctxFor(decoded.groupID)

	switch decoded.kind {
	case decodedGroupText:
		fmt.Printf("[%s in %s] %s\n", shortID(msg.SenderAccountID), shortID(decoded.groupID), decoded.text)
		g.reconcile(msg.SenderAccountID, decoded.stateHash)
	case decodedGroupControl:
		g.handleControl(msg.SenderAccountID, decoded.control)
	}

	ackMessage(w.state, msg.MessageID)
	if err := w.state.Save(w.path); err != nil {
		fmt.Fprintln(os.Stderr, "saving state:", err)
	}
}

func (g *groupCtx) handleControl(sender string, control *groupControl) {
	switch control.Kind {
	case "sync_request":
		fmt.Printf("[%s] asked for a snapshot of %s\n", shortID(sender), shortID(g.id))
		if err := g.sendSnapshotTo(memberByID(g.gs.Resolve(), sender)); err != nil {
			fmt.Fprintln(os.Stderr, "sending snapshot:", err)
		}
		return
	case "events", "snapshot":
	default:
		fmt.Printf("[%s] unknown control kind %q, ignored\n", shortID(sender), control.Kind)
		return
	}

	before := g.gs.Resolve()
	// Retry whatever an earlier envelope could not be admitted yet, together
	// with the new facts: delivery is unordered, so a membership event can
	// easily arrive before the snapshot carrying the genesis it needs.
	batch := append(g.takePending(), control.Events...)
	result := g.gs.Apply(batch)
	after := g.gs.Resolve()

	fmt.Printf("[%s] %s for %s: %d new fact(s), %d already known, %d held\n",
		shortID(sender), control.Kind, shortID(g.id),
		len(result.Applied), len(result.Known), len(result.Rejected))
	g.hold(batch, result)
	describeChange(before, after)

	// Their state hash rode along in the envelope, so answering a mismatch
	// needs no round trip to discover one.
	g.reconcile(sender, control.StateHash)
}

// maxHeldEvents bounds the buffer below. Holding is for envelopes that
// overtook the ones they depend on, which is a handful in practice -- an
// unbounded buffer would just be somewhere for a hostile peer to put things.
const maxHeldEvents = 64

// takePending empties the hold buffer for re-admission.
func (g *groupCtx) takePending() []*group.Event {
	held := g.held
	g.held = nil
	return held
}

// hold keeps the events a batch could not admit *yet*, so a later arrival can
// unblock them. An event rejected for a reason no later fact can change -- a
// bad signature, another group's id -- is dropped rather than held: retrying
// it forever would be pointless and is exactly what a hostile peer would want.
func (g *groupCtx) hold(batch []*group.Event, result group.ApplyResult) {
	for _, rejection := range result.Rejected {
		if rejection.Reason != "no genesis event yet" {
			fmt.Printf("   rejected: %s\n", rejection.Reason)
			continue
		}
		if len(g.held) >= maxHeldEvents {
			fmt.Printf("   hold buffer full, dropping an event\n")
			continue
		}
		if rejection.Index < len(batch) {
			g.held = append(g.held, batch[rejection.Index])
		}
	}
}

// reconcile compares a peer's advertised state hash against ours and, if they
// differ, sends them everything we have.
//
// Union of a grow-only fact set is idempotent and commutative, so "send them
// the lot" converges without a delta protocol or version vectors -- and a
// snapshot cannot invent anything, since every fact in it is individually
// signed.
func (g *groupCtx) reconcile(sender, peerHash string) {
	if peerHash == "" || peerHash == g.gs.StateHash() {
		return
	}
	// Nothing to offer before we have a genesis of our own -- we are the ones
	// behind, and a peer learns nothing from an empty fact set.
	if g.gs.Genesis() == nil {
		return
	}
	// Answer any given foreign hash at most once, so two peers that stay
	// divergent for a reason a snapshot cannot fix do not trade snapshots
	// forever.
	if g.answered == nil {
		g.answered = map[string]bool{}
	}
	key := sender + ":" + peerHash
	if g.answered[key] {
		return
	}
	g.answered[key] = true

	fmt.Printf("   state hash differs (theirs %s, ours %s) -- sending our snapshot\n",
		shortHash(peerHash), shortHash(g.gs.StateHash()))
	if err := g.sendSnapshotTo(memberByID(g.gs.Resolve(), sender)); err != nil {
		fmt.Fprintln(os.Stderr, "sending snapshot:", err)
	}
}

// describeChange prints what a batch of facts actually did to the membership,
// which is the part a human watching this cares about.
func describeChange(before, after *group.Resolved) {
	if before.StateHash == after.StateHash {
		return
	}
	if before.Name != after.Name || before.Topic != after.Topic {
		fmt.Printf("   meta: %q / %q\n", after.Name, after.Topic)
	}
	if !before.Dissolved && after.Dissolved {
		fmt.Println("   the group was dissolved")
	}

	beforeRoles := map[string]group.Role{}
	for _, m := range before.Members {
		beforeRoles[m.AccountID] = m.Role
	}
	for _, m := range after.Members {
		old, existed := beforeRoles[m.AccountID]
		switch {
		case !existed:
			state := "joined"
			if !m.Joined {
				state = "invited"
			}
			fmt.Printf("   %s %s (%s)\n", shortID(m.AccountID), state, m.Role)
		case old != m.Role:
			fmt.Printf("   %s is now %s (was %s)\n", shortID(m.AccountID), m.Role, old)
		}
		delete(beforeRoles, m.AccountID)
	}
	for accountID := range beforeRoles {
		fmt.Printf("   %s left or was removed\n", shortID(accountID))
	}
}

func shortHash(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}
