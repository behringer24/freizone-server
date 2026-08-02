package group

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/devicecert"
)

var baseTime = time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)

// at returns a timestamp offset by n seconds -- second granularity, matching
// what the signing bytes actually carry.
func at(n int) time.Time { return baseTime.Add(time.Duration(n) * time.Second) }

// testAccount is a full identity: root key, account id, and a device
// certificate chained to it, i.e. everything a signer block needs.
type testAccount struct {
	seed       []byte
	rootPriv   ed25519.PrivateKey
	accountID  string
	devicePriv ed25519.PrivateKey
	signer     *Signer
	server     string
}

func newAccount(t *testing.T, server string) *testAccount {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("generating seed: %v", err)
	}
	rootPriv := ed25519.NewKeyFromSeed(seed)
	rootPub := rootPriv.Public().(ed25519.PublicKey)

	accountID, err := address.DeriveID(rootPub)
	if err != nil {
		t.Fatalf("deriving account id: %v", err)
	}

	devicePub, devicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating device key: %v", err)
	}
	deviceID, err := devicecert.NewDeviceID()
	if err != nil {
		t.Fatalf("generating device id: %v", err)
	}
	cert, err := devicecert.SignDeviceCertificate(accountID, deviceID, devicePub, baseTime, rootPriv)
	if err != nil {
		t.Fatalf("signing device certificate: %v", err)
	}

	return &testAccount{
		seed:       seed,
		rootPriv:   rootPriv,
		accountID:  accountID,
		devicePriv: devicePriv,
		server:     server,
		signer: &Signer{
			AccountID:  accountID,
			RootPubKey: rootPub,
			DeviceCert: *cert,
		},
	}
}

// testGroup is a founded group plus the founder's keys.
type testGroup struct {
	id       string
	rootPriv ed25519.PrivateKey
	nonce    []byte
	founder  *testAccount
	genesis  *Event
}

func newGroup(t *testing.T, founder *testAccount) *testGroup {
	t.Helper()

	nonce, err := NewNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	rootPriv, err := DeriveRootKey(founder.seed, nonce)
	if err != nil {
		t.Fatalf("deriving group root key: %v", err)
	}
	id, err := DeriveID(rootPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("deriving group id: %v", err)
	}

	genesis := &Event{
		Type:       EventGenesis,
		GroupID:    id,
		IssuedAt:   at(0),
		RootPubKey: rootPriv.Public().(ed25519.PublicKey),
		Nonce:      nonce,
		Subject:    founder.accountID,
		Server:     founder.server,
	}
	if err := SignRoot(genesis, rootPriv); err != nil {
		t.Fatalf("signing genesis: %v", err)
	}

	return &testGroup{id: id, rootPriv: rootPriv, nonce: nonce, founder: founder, genesis: genesis}
}

func (g *testGroup) root(t *testing.T, e *Event) *Event {
	t.Helper()
	e.GroupID = g.id
	if err := SignRoot(e, g.rootPriv); err != nil {
		t.Fatalf("signing %s: %v", e.Type, err)
	}
	return e
}

func (g *testGroup) by(t *testing.T, acct *testAccount, e *Event) *Event {
	t.Helper()
	e.GroupID = g.id
	if err := SignDevice(e, acct.signer, acct.devicePriv); err != nil {
		t.Fatalf("signing %s: %v", e.Type, err)
	}
	return e
}

// apply admits events and fails the test on any rejection -- for the many
// cases where admission is expected to be uneventful and the interesting part
// is what the fold makes of them.
func apply(t *testing.T, s *State, events ...*Event) {
	t.Helper()
	result := s.Apply(events)
	if len(result.Rejected) > 0 {
		t.Fatalf("unexpected rejection: %+v", result.Rejected)
	}
}

func TestGroupIDIsDistinctFromAccountID(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	groupID, err := DeriveID(pub)
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := address.DeriveID(pub)
	if err != nil {
		t.Fatal(err)
	}

	if groupID == accountID {
		t.Fatal("group id and account id must differ for the same key")
	}
	version, err := address.VersionOf(groupID)
	if err != nil {
		t.Fatalf("group id does not normalize: %v", err)
	}
	if version != address.VersionGroup {
		t.Fatalf("group id version marker = %d, want %d", version, address.VersionGroup)
	}

	ok, err := VerifyID(groupID, pub)
	if err != nil || !ok {
		t.Fatalf("VerifyID(own key) = %v, %v; want true, nil", ok, err)
	}
	// An account id for the same key must not pass as a group id: the marker
	// is the only thing separating them, so this is the check that matters.
	if ok, _ := VerifyID(accountID, pub); ok {
		t.Fatal("an account id must not verify as a group id")
	}
}

func TestDeriveRootKeyIsReproducibleFromSeedAndNonce(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	first, err := DeriveRootKey(founder.seed, nonce)
	if err != nil {
		t.Fatal(err)
	}
	// The whole point: the founder loses every device, restores the account
	// root key from the seed phrase, reads the nonce out of a member's copy of
	// the genesis event, and is the founder again.
	again, err := DeriveRootKey(founder.seed, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, again) {
		t.Fatal("same seed and nonce must derive the same group root key")
	}

	otherNonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	other, err := DeriveRootKey(founder.seed, otherNonce)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, other) {
		t.Fatal("a second group founded by the same account must get its own key")
	}

	if _, err := DeriveRootKey(founder.seed[:16], nonce); err == nil {
		t.Fatal("a short seed must be rejected")
	}
	if _, err := DeriveRootKey(founder.seed, nonce[:8]); err == nil {
		t.Fatal("a short nonce must be rejected")
	}
}

func TestEventSignatureRoundTripAndTampering(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	invitee := newAccount(t, "b.example.org")
	g := newGroup(t, founder)

	add := g.by(t, founder, &Event{
		Type:     EventMemberAdd,
		IssuedAt: at(1),
		Subject:  invitee.accountID,
		Server:   invitee.server,
	})
	if err := add.Verify(g.rootPriv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("freshly signed event must verify: %v", err)
	}

	// Every field in the signing bytes must be covered by the signature.
	for name, mutate := range map[string]func(e *Event){
		"subject":   func(e *Event) { e.Subject = founder.accountID },
		"server":    func(e *Event) { e.Server = "evil.example.org" },
		"timestamp": func(e *Event) { e.IssuedAt = at(99) },
		"type":      func(e *Event) { e.Type = EventMemberRemove },
	} {
		tampered := *add
		mutate(&tampered)
		if err := tampered.Verify(g.rootPriv.Public().(ed25519.PublicKey)); err == nil {
			t.Fatalf("tampering with %s must invalidate the signature", name)
		}
	}
}

func TestValidateRejectsFieldsOutsideTheSignature(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	other := newAccount(t, "b.example.org")
	g := newGroup(t, founder)

	cases := map[string]*Event{
		"role on a member_remove": {
			Type: EventMemberRemove, GroupID: g.id, IssuedAt: at(1),
			Subject: other.accountID, Role: RoleAdmin,
		},
		"server on a member_remove": {
			Type: EventMemberRemove, GroupID: g.id, IssuedAt: at(1),
			Subject: other.accountID, Server: "b.example.org",
		},
		"topic on a member_add": {
			Type: EventMemberAdd, GroupID: g.id, IssuedAt: at(1),
			Subject: other.accountID, Server: other.server, Topic: "sneaky",
		},
		"subject on a meta": {
			Type: EventMeta, GroupID: g.id, IssuedAt: at(1),
			Subject: other.accountID, Name: "Group",
		},
		"granting membership": {
			Type: EventRoleGrant, GroupID: g.id, IssuedAt: at(1),
			Subject: other.accountID, Role: RoleMember,
		},
		"granting foundership": {
			Type: EventRoleGrant, GroupID: g.id, IssuedAt: at(1),
			Subject: other.accountID, Role: RoleFounder,
		},
		"sub-second timestamp": {
			Type: EventMemberAdd, GroupID: g.id, IssuedAt: at(1).Add(500 * time.Millisecond),
			Subject: other.accountID, Server: other.server,
		},
	}

	for name, e := range cases {
		if err := SignDevice(e, founder.signer, founder.devicePriv); err == nil {
			t.Fatalf("%s: signing must fail validation", name)
		}
	}
}

func TestSelfSignedEventsMustBeAboutTheirSigner(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	member := newAccount(t, "b.example.org")
	g := newGroup(t, founder)

	// A "join accept" on someone else's behalf would let an inviter waive the
	// consent the accept exists to obtain.
	forged := &Event{
		Type: EventJoinAccept, GroupID: g.id, IssuedAt: at(2), Subject: member.accountID,
	}
	if err := SignDevice(forged, founder.signer, founder.devicePriv); err == nil {
		t.Fatal("join_accept signed by someone other than its subject must be rejected")
	}

	forgedLeave := &Event{
		Type: EventLeave, GroupID: g.id, IssuedAt: at(2), Subject: member.accountID,
	}
	if err := SignDevice(forgedLeave, founder.signer, founder.devicePriv); err == nil {
		t.Fatal("leave signed by someone other than its subject must be rejected")
	}
}

func TestRootSignedEventsCannotBeDeviceSigned(t *testing.T) {
	founder := newAccount(t, "a.example.org")
	g := newGroup(t, founder)

	dissolve := &Event{Type: EventDissolve, GroupID: g.id, IssuedAt: at(5)}
	if err := SignDevice(dissolve, founder.signer, founder.devicePriv); err == nil {
		t.Fatal("dissolve must not be signable with a device key")
	}

	// And the reverse: an ordinary event signed by the group root key has no
	// signer block and must not be accepted as if it had one.
	add := &Event{Type: EventMemberAdd, GroupID: g.id, IssuedAt: at(1), Subject: founder.accountID, Server: "x"}
	if err := SignRoot(add, g.rootPriv); err == nil {
		t.Fatal("member_add must not be signable with the group root key")
	}
}
