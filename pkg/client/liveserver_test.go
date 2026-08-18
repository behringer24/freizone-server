// The retry path against real servers, across a federation boundary.
//
// Everything else in this package is proved against fakeserver_test.go, and
// that stub has already been wrong twice in ways that hid a defect: it had no
// batch endpoint at all while the client happily posted to one, and it
// answered a missing account with a code the real server never sends. A stub
// cannot fail to be reachable either -- it fails by being told to, on a
// per-account flag, which is not the same shape of failure as a server that
// is simply not there.
//
// So this drives the one path where that difference decides the outcome: a
// group whose members sit on two servers, one of which is stopped mid-test.
// The copy for the member on the stopped server has to fail with a reason
// worth reading, the retry has to address only that member, and the member
// whose copy already arrived must not receive it twice.
//
// Skipped unless pointed at a running pair:
//
//	FREIZONE_LIVE_A=http://aff-abe:18080 \
//	FREIZONE_LIVE_B=http://aff-abe:18081 \
//	FREIZONE_LIVE_B_CONTAINER=freizone-farm-local-server2-1 \
//	go test ./pkg/client -run TestLive -v
//
// Both servers need `registration_policy: open` -- the accounts are made here
// rather than reused, so a run leaves no state anybody was relying on.
package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// liveServers reads the pair under test, or skips.
func liveServers(t *testing.T) (a, b, container string) {
	t.Helper()
	a, b = os.Getenv("FREIZONE_LIVE_A"), os.Getenv("FREIZONE_LIVE_B")
	if a == "" || b == "" {
		t.Skip("set FREIZONE_LIVE_A and FREIZONE_LIVE_B to run against real servers")
	}
	container = os.Getenv("FREIZONE_LIVE_B_CONTAINER")
	if container == "" {
		container = "freizone-farm-local-server2-1"
	}
	return a, b, container
}

// liveAccount registers a fresh account on server and returns a client holding
// it. The registration is the real POST an app makes on first run, which is
// also the cheapest proof that the server under test is the one we think.
//
// This was sixty lines of hand-rolled key generation, certificate signing and
// a raw http.Post, with the comment "the core offers nothing". It is now the
// core's own [Client.Register] (SRV-30) -- which is the honest measure of that
// gap having closed, and means every live run exercises the call an app and a
// bot actually make rather than a test's imitation of it.
func liveAccount(t *testing.T, server string) *Client {
	t.Helper()

	c, err := Open(filepath.Join(t.TempDir(), "account"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if _, err := c.Register(t.Context(), server, RegisterOptions{}); err != nil {
		t.Fatalf("registering on %s: %v", server, err)
	}
	if err := c.RotatePrekeys(t.Context()); err != nil {
		t.Fatalf("RotatePrekeys: %v", err)
	}
	if err := c.TopUpOneTimePrekeys(t.Context()); err != nil {
		t.Fatalf("TopUpOneTimePrekeys: %v", err)
	}
	return c
}

func dockerCompose(t *testing.T, action, container string) {
	t.Helper()
	out, err := exec.Command("docker", action, container).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s %s: %v: %s", action, container, err, out)
	}
	// A stopped port refuses immediately, but a started one is listening a
	// moment before the server behind it answers.
	if action == "start" {
		time.Sleep(3 * time.Second)
	}
}

func deliveryFor(t *testing.T, c *Client, groupID, messageID, accountID string) GroupDelivery {
	t.Helper()
	msgs, err := c.Messages(groupID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	for _, m := range msgs {
		if m.ID != messageID {
			continue
		}
		for _, d := range m.Deliveries {
			if d.AccountID == accountID {
				return d
			}
		}
	}
	t.Fatalf("no delivery record for %s on message %s", accountID, messageID)
	return GroupDelivery{}
}

// The whole retry story, end to end, against two real servers.
func TestLiveARetryFillsOnlyTheGapAcrossServers(t *testing.T) {
	serverA, serverB, container := liveServers(t)

	// alice and bob share a server; carol is federated, and hers is the one
	// that goes away. That split is the point: it is the only arrangement
	// where a single stopped server produces a partial failure rather than a
	// total one.
	alice := liveAccount(t, serverA)
	bob := liveAccount(t, serverA)
	carol := liveAccount(t, serverB)
	bobID := identityOf(t, bob).AccountID
	carolID := identityOf(t, carol).AccountID
	t.Logf("alice=%s bob=%s (on %s), carol=%s (on %s)",
		identityOf(t, alice).AccountID, bobID, serverA, carolID, serverB)

	groupID, err := alice.CreateGroup(t.Context(), "Retry über zwei Server")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := alice.InviteToGroup(t.Context(), groupID, bobID, ""); err != nil {
		t.Fatalf("inviting bob: %v", err)
	}
	if err := alice.InviteToGroup(t.Context(), groupID, carolID, serverB); err != nil {
		t.Fatalf("inviting carol: %v", err)
	}
	syncGroups(t, bob)
	syncGroups(t, carol)
	if err := bob.AcceptGroupInvitation(t.Context(), groupID); err != nil {
		t.Fatalf("bob accepting: %v", err)
	}
	if err := carol.AcceptGroupInvitation(t.Context(), groupID); err != nil {
		t.Fatalf("carol accepting: %v", err)
	}
	syncGroups(t, alice)
	syncGroups(t, bob)
	syncGroups(t, carol)

	membership, err := alice.GroupMembership(groupID)
	if err != nil {
		t.Fatalf("GroupMembership: %v", err)
	}
	var joined int
	for _, m := range membership.Members {
		if m.Joined {
			joined++
		}
	}
	if joined != 3 {
		t.Fatalf("want three joined members before the test starts, got %d", joined)
	}

	// Carol's server goes away. Restarted on the way out too, so a failing
	// assertion does not leave the farm in a state the next run trips over.
	dockerCompose(t, "stop", container)
	restarted := false
	defer func() {
		if !restarted {
			dockerCompose(t, "start", container)
		}
	}()

	sent, err := alice.SendGroupText(t.Context(), groupID, "einmal, mit Lücke", SendOptions{})
	if err != nil {
		t.Fatalf("SendGroupText: %v", err)
	}
	if len(sent.Message.Deliveries) != 2 {
		t.Fatalf("want one delivery record per member, got %+v", sent.Message.Deliveries)
	}

	bobsCopy := deliveryFor(t, alice, groupID, sent.Message.ID, bobID)
	if bobsCopy.State != SendSent {
		t.Errorf("bob is on the server that is still up, yet his copy is %s (%q)",
			bobsCopy.State, bobsCopy.Error)
	}
	if bobsCopy.Error != "" {
		t.Errorf("a copy that arrived carries a reason: %q", bobsCopy.Error)
	}

	carolsCopy := deliveryFor(t, alice, groupID, sent.Message.ID, carolID)
	if carolsCopy.State == SendSent {
		t.Fatalf("carol's server is stopped, yet her copy counts as delivered")
	}
	if carolsCopy.Error == "" {
		t.Error("carol's copy failed without saying why -- this is the text the bubble shows")
	}
	if carolsCopy.WireMessageID == "" {
		t.Error("no wire id was recorded, so a retry has nothing to reuse")
	}
	t.Logf("carol's copy: state=%s wire=%s reason=%q",
		carolsCopy.State, carolsCopy.WireMessageID, carolsCopy.Error)

	// Bob has it once, and this is what the retry must not disturb.
	bobLines := 0
	for _, res := range syncGroups(t, bob) {
		if res.StoredMessageID == sent.Message.ID {
			bobLines++
		}
	}
	if bobLines != 1 {
		t.Errorf("bob was told about the message %d times on the first send", bobLines)
	}

	dockerCompose(t, "start", container)
	restarted = true

	retried, err := alice.RetryGroupMessage(t.Context(), groupID, sent.Message.ID)
	if err != nil {
		t.Fatalf("RetryGroupMessage: %v", err)
	}
	for _, d := range retried.Message.Deliveries {
		if d.State != SendSent {
			t.Errorf("after the retry, %s is still %s (%q)", d.AccountID, d.State, d.Error)
		}
		if d.Error != "" {
			t.Errorf("%s arrived but kept its old reason: %q", d.AccountID, d.Error)
		}
	}

	// The wire id survived the failure, so carol's server sees the retry as
	// the same message rather than a new one, and bob's copy was never
	// re-addressed at all.
	if got := deliveryFor(t, alice, groupID, sent.Message.ID, carolID); got.WireMessageID != carolsCopy.WireMessageID {
		t.Errorf("the retry minted a new wire id for carol (%s, was %s)",
			got.WireMessageID, carolsCopy.WireMessageID)
	}
	if got := deliveryFor(t, alice, groupID, sent.Message.ID, bobID); got.WireMessageID != bobsCopy.WireMessageID {
		t.Errorf("bob's wire id changed on a retry that did not concern him (%s, was %s)",
			got.WireMessageID, bobsCopy.WireMessageID)
	}

	// Carol gets it exactly once, now that her server is back.
	carolLines := 0
	for _, res := range syncGroups(t, carol) {
		if res.StoredMessageID == sent.Message.ID {
			carolLines++
		}
	}
	if carolLines != 1 {
		t.Errorf("carol was told about the message %d times, want once", carolLines)
	}
	if got := transcriptCopies(t, carol, groupID, "einmal, mit Lücke"); got != 1 {
		t.Errorf("carol's transcript holds the message %d times", got)
	}

	// And bob, who already had it, gets nothing further -- the failure the
	// notification flood came from.
	for _, res := range syncGroups(t, bob) {
		if res.StoredMessageID == sent.Message.ID {
			t.Error("the retry delivered bob a second copy of a message he already had")
		}
	}
	if got := transcriptCopies(t, bob, groupID, "einmal, mit Lücke"); got != 1 {
		t.Errorf("bob's transcript holds the message %d times", got)
	}
}

func transcriptCopies(t *testing.T, c *Client, groupID, text string) int {
	t.Helper()
	msgs, err := c.Messages(groupID)
	if err != nil {
		t.Fatalf("Messages: %v", err)
	}
	var n int
	for _, m := range msgs {
		if strings.Contains(m.Text, text) {
			n++
		}
	}
	return n
}
