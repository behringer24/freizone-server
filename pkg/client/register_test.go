package client

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/behringer24/freizone-server/pkg/address"
)

// freshClient is an account directory with nothing in it -- what a bot or an
// app has on its very first run, before any server has heard of it.
func freshClient(t *testing.T) *Client {
	t.Helper()
	c, err := Open(filepath.Join(t.TempDir(), "account"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// The whole point: a caller with nothing gets a working account, and the
// identity is on disk afterwards rather than only in the return value.
func TestRegisterCreatesAnAccountAndStoresIt(t *testing.T) {
	srv := newFakeServer(t)
	c := freshClient(t)

	id, err := c.Register(t.Context(), srv.url, RegisterOptions{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if id.AccountID == "" || id.DeviceID == "" {
		t.Fatalf("registration returned an incomplete identity: %+v", id)
	}

	// The account id is a derivation of the root key, not something the server
	// assigned -- so it has to verify against the key we kept.
	ok, err := address.Verify(id.AccountID, id.RootPub)
	if err != nil || !ok {
		t.Errorf("the account id does not derive from its own root key (err %v)", err)
	}

	stored, err := c.Identity()
	if err != nil {
		t.Fatalf("Identity after registering: %v", err)
	}
	if stored.AccountID != id.AccountID || stored.Server != srv.url {
		t.Errorf("stored identity does not match what was registered: %+v", stored)
	}

	// And the server really has it: resolving is the same lookup a peer does.
	if _, err := c.ResolvePeer(t.Context(), id.AccountID, srv.url); err != nil {
		t.Errorf("the registered account cannot be resolved: %v", err)
	}
}

// Registering into a directory that already holds a finished identity would
// abandon the account it has. That is a caller mistake, and it says so.
func TestRegisteringTwiceIsRefused(t *testing.T) {
	srv := newFakeServer(t)
	c := freshClient(t)

	if _, err := c.Register(t.Context(), srv.url, RegisterOptions{}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, err := c.Register(t.Context(), srv.url, RegisterOptions{})
	if !errors.Is(err, ErrAlreadyRegistered) {
		t.Fatalf("want ErrAlreadyRegistered, got %v", err)
	}
	if srv.registrationCount() != 1 {
		t.Errorf("a refused second attempt must not have reached the server: %d registrations", srv.registrationCount())
	}
}

// The failure this whole design exists for. The server creates the account
// when it answers; the caller learns of it when it reads that answer. Lose the
// answer -- crash, dropped connection, killed container -- and a naive retry
// registers a *second* account under a *different* address, having spent a
// second invite code on it.
func TestAnInterruptedRegistrationIsResumedNotRepeated(t *testing.T) {
	srv := newFakeServer(t)
	c := freshClient(t)

	// The first attempt reaches the server and creates the account, then the
	// answer is lost: the fake server returns 500 *after* doing the work,
	// which is exactly the shape of a connection dropped on the way back.
	srv.set(func(s *fakeServer) { s.loseRegistrationAnswer = true })
	if _, err := c.Register(t.Context(), srv.url, RegisterOptions{}); err == nil {
		t.Fatal("the interrupted attempt has to report a failure")
	}
	if srv.registrationCount() != 1 {
		t.Fatalf("the account should exist on the server: %d registrations", srv.registrationCount())
	}

	// What a restart does. The account id must come back the same, and nothing
	// new may be created.
	srv.set(func(s *fakeServer) { s.loseRegistrationAnswer = false })
	id, err := c.Register(t.Context(), srv.url, RegisterOptions{})
	if err != nil {
		t.Fatalf("resuming: %v", err)
	}
	if srv.registrationCount() != 1 {
		t.Errorf("resuming must not create a second account: %d registrations", srv.registrationCount())
	}

	// The address is the thing that must not move: an operator has already
	// been told it, and may already have invited it to a group.
	stored, err := c.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if stored.AccountID != id.AccountID {
		t.Errorf("the address moved across the resume: %s then %s", id.AccountID, stored.AccountID)
	}

	// Once settled, it behaves like any finished registration.
	if _, err := c.Register(t.Context(), srv.url, RegisterOptions{}); !errors.Is(err, ErrAlreadyRegistered) {
		t.Errorf("after resuming, a further attempt must be refused: %v", err)
	}
}

// A resumed attempt that finds the account genuinely absent has to finish the
// job -- with the same keys, so the address still does not move.
func TestAResumedRegistrationRetriesWhenTheAccountIsNotThere(t *testing.T) {
	srv := newFakeServer(t)
	c := freshClient(t)

	// This time the request never lands: the server refuses before creating
	// anything, so the marker is set but there is no account behind it.
	srv.set(func(s *fakeServer) { s.registrationClosed = true })
	if _, err := c.Register(t.Context(), srv.url, RegisterOptions{}); err == nil {
		t.Fatal("a closed server must refuse")
	}
	if srv.registrationCount() != 0 {
		t.Fatalf("nothing should have been created: %d registrations", srv.registrationCount())
	}
	before, err := c.Identity()
	if err != nil {
		t.Fatalf("the keys must already be on disk after a failed attempt: %v", err)
	}

	srv.set(func(s *fakeServer) { s.registrationClosed = false })
	id, err := c.Register(t.Context(), srv.url, RegisterOptions{})
	if err != nil {
		t.Fatalf("retrying: %v", err)
	}
	if srv.registrationCount() != 1 {
		t.Errorf("the retry should have created exactly one account: %d", srv.registrationCount())
	}
	if id.AccountID != before.AccountID {
		t.Errorf("a retry must reuse the keys it already wrote: %s then %s", before.AccountID, id.AccountID)
	}
}

// An invite-only server refuses without a code and accepts with one. Worth a
// test because the code is optional in the wire body, so omitting it is a
// perfectly valid request that simply gets a different answer.
func TestAnInviteOnlyServerNeedsTheCode(t *testing.T) {
	srv := newFakeServer(t)
	srv.set(func(s *fakeServer) { s.inviteRequired = true })

	without := freshClient(t)
	_, err := without.Register(t.Context(), srv.url, RegisterOptions{})
	if err == nil {
		t.Fatal("an invite-only server must refuse a registration with no code")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "invite_required" {
		t.Errorf("the refusal should say what is missing, got %v", err)
	}

	with := freshClient(t)
	if _, err := with.Register(t.Context(), srv.url, RegisterOptions{InviteCode: "ABCD-EFGH-JKMN"}); err != nil {
		t.Fatalf("registering with a code: %v", err)
	}
}

// Claiming a server is a different operation from registering on one, and the
// setup token is what separates them.
func TestClaimServerNeedsTheSetupToken(t *testing.T) {
	srv := newFakeServer(t)
	srv.set(func(s *fakeServer) { s.setupToken = "the-real-token" })

	wrong := freshClient(t)
	if _, err := wrong.ClaimServer(t.Context(), srv.url, "not-the-token"); err == nil {
		t.Fatal("a wrong setup token must be refused")
	}

	right := freshClient(t)
	if _, err := right.ClaimServer(t.Context(), srv.url, "the-real-token"); err != nil {
		t.Fatalf("ClaimServer: %v", err)
	}

	empty := freshClient(t)
	if _, err := empty.ClaimServer(t.Context(), srv.url, ""); err == nil {
		t.Error("claiming with no token at all should be refused before any request goes out")
	}
}

// NewIdentity is exported so a caller can know its own address before any
// server has heard of it -- an account id is derived, not assigned.
func TestNewIdentityDerivesItsOwnAddress(t *testing.T) {
	id, err := NewIdentity("chat.example.org")
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	ok, err := address.Verify(id.AccountID, id.RootPub)
	if err != nil || !ok {
		t.Fatalf("the id does not derive from the key (err %v)", err)
	}
	if id.Server != "chat.example.org" {
		t.Errorf("server: got %q", id.Server)
	}
	second, err := NewIdentity("chat.example.org")
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	if second.AccountID == id.AccountID {
		t.Error("two identities must not collide")
	}
}

func TestRegisterNeedsAServer(t *testing.T) {
	c := freshClient(t)
	if _, err := c.Register(t.Context(), "", RegisterOptions{}); err == nil {
		t.Error("registering with no server address must be refused")
	}
}
