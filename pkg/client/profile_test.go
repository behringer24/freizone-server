package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/pkg/profileclaim"
)

// knownDevice gives the fixture's peer a device the client has cached, which
// is the precondition for verifying anything they assert about themselves.
func knownDevice(t *testing.T, c *Client, peer string) (string, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("device id: %v", err)
	}
	deviceID := hex.EncodeToString(raw)

	if err := c.putPeerDevice(PeerEndpoint{
		AccountID: peer, DeviceID: deviceID, DevicePub: pub,
	}); err != nil {
		t.Fatalf("putPeerDevice: %v", err)
	}
	return deviceID, priv
}

func claimPayload(t *testing.T, id, text string, claim *profileclaim.Claim) []byte {
	t.Helper()
	m := map[string]any{"v": 1, "id": id, "text": text}
	if claim != nil {
		m["profile"] = claim
	}
	return mustJSON(t, m)
}

func TestProfileClaimArrivesWithAMessage(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	deviceID, priv := knownDevice(t, c, "them")

	claim, err := profileclaim.Sign("them", deviceID, "Anna", time.Now(), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	res := mustHandle(t, c, p.msg("m1", p.send(claimPayload(t, "id-1", "hello", claim))), ReceiveOptions{})
	if !res.ProfileRenamed {
		t.Error("a first claim must report the name as changed, or nothing tells the transcript to say so")
	}
	if res.StoredMessageID != "id-1" {
		t.Errorf("the message itself must still be stored, got %q", res.StoredMessageID)
	}

	profile, err := c.PeerProfile("them")
	if err != nil {
		t.Fatalf("PeerProfile: %v", err)
	}
	if profile.Name() != "Anna" {
		t.Errorf("stored name: want %q, got %q", "Anna", profile.Name())
	}
}

// The message is what must survive a bad claim. Everything else about this
// feature is optional; losing a message over a name would not be.
func TestForgedProfileClaimIsDroppedAndTheMessageArrives(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	deviceID, _ := knownDevice(t, c, "them")

	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	forged, err := profileclaim.Sign("them", deviceID, "Bank Support", time.Now(), otherPriv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	res := mustHandle(t, c, p.msg("m1", p.send(claimPayload(t, "id-1", "hello", forged))), ReceiveOptions{})
	if res.ProfileRenamed {
		t.Error("a claim signed by the wrong key was adopted")
	}
	if res.StoredMessageID != "id-1" {
		t.Error("the message was lost along with the claim it carried")
	}
	profile, err := c.PeerProfile("them")
	if err != nil {
		t.Fatalf("PeerProfile: %v", err)
	}
	if profile.Name() != "" {
		t.Errorf("a forged name was stored: %q", profile.Name())
	}
}

// A claim naming a device we hold no key for cannot be checked, and an
// unchecked name is worth less than no name.
func TestProfileClaimFromAnUnknownDeviceIsIgnored(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	knownDevice(t, c, "them")

	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	claim, err := profileclaim.Sign("them", "aabbccddeeff0011", "Anna", time.Now(), otherPriv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	res := mustHandle(t, c, p.msg("m1", p.send(claimPayload(t, "id-1", "hello", claim))), ReceiveOptions{})
	if res.ProfileRenamed {
		t.Error("a claim from a device this client has no key for was adopted")
	}
}

func TestNewerProfileClaimWinsAndOlderIsIgnored(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	deviceID, priv := knownDevice(t, c, "them")

	base := time.Now().UTC()
	first, err := profileclaim.Sign("them", deviceID, "Anna", base, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	newer, err := profileclaim.Sign("them", deviceID, "Anna B.", base.Add(time.Minute), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	mustHandle(t, c, p.msg("m1", p.send(claimPayload(t, "id-1", "one", first))), ReceiveOptions{})
	p.settled()
	res := mustHandle(t, c, p.msg("m2", p.send(claimPayload(t, "id-2", "two", newer))), ReceiveOptions{})
	if !res.ProfileRenamed {
		t.Error("a newer claim did not report the rename")
	}
	p.settled()
	// The old one again, as a replay would deliver it.
	stale := mustHandle(t, c, p.msg("m3", p.send(claimPayload(t, "id-3", "three", first))), ReceiveOptions{})
	if stale.ProfileRenamed {
		t.Error("an older claim displaced a newer one")
	}

	profile, err := c.PeerProfile("them")
	if err != nil {
		t.Fatalf("PeerProfile: %v", err)
	}
	if profile.Name() != "Anna B." {
		t.Errorf("current name: want %q, got %q", "Anna B.", profile.Name())
	}
	if len(profile.Claims) != 2 {
		t.Errorf("history: want the two distinct claims, got %d", len(profile.Claims))
	}
}

// Re-stating the same name must not report a rename: the transcript line is
// for a change somebody made, and one per message would be noise.
func TestRepeatedIdenticalClaimIsNotARename(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	deviceID, priv := knownDevice(t, c, "them")

	claim, err := profileclaim.Sign("them", deviceID, "Anna", time.Now(), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	mustHandle(t, c, p.msg("m1", p.send(claimPayload(t, "id-1", "one", claim))), ReceiveOptions{})
	p.settled()
	again := mustHandle(t, c, p.msg("m2", p.send(claimPayload(t, "id-2", "two", claim))), ReceiveOptions{})
	if again.ProfileRenamed {
		t.Error("the same claim twice was reported as a rename")
	}
}

func TestWithdrawnClaimClearsTheName(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	deviceID, priv := knownDevice(t, c, "them")

	base := time.Now().UTC()
	named, err := profileclaim.Sign("them", deviceID, "Anna", base, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	withdrawn, err := profileclaim.Sign("them", deviceID, "", base.Add(time.Minute), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	mustHandle(t, c, p.msg("m1", p.send(claimPayload(t, "id-1", "one", named))), ReceiveOptions{})
	p.settled()
	res := mustHandle(t, c, p.msg("m2", p.send(claimPayload(t, "id-2", "two", withdrawn))), ReceiveOptions{})
	if !res.ProfileRenamed {
		t.Error("a withdrawal is a change and must be reported as one")
	}

	profile, err := c.PeerProfile("them")
	if err != nil {
		t.Fatalf("PeerProfile: %v", err)
	}
	if profile.Name() != "" {
		t.Errorf("a withdrawn name still reads as %q", profile.Name())
	}
	if len(profile.Claims) != 2 {
		t.Error("the withdrawal must not erase the history it retracts -- a report needs both")
	}
}

// A receipt is the carrier that reaches somebody this account only reads from.
func TestProfileClaimRidesOnAReceipt(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	deviceID, priv := knownDevice(t, c, "them")

	claim, err := profileclaim.Sign("them", deviceID, "Anna", time.Now(), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	receipt := mustJSON(t, map[string]any{
		"v": 2, "kind": "receipt", "status": "delivered",
		"up_to_sent_at": time.Now().UTC().Format(receiptTimeLayout),
		"profile":       claim,
	})

	res := mustHandle(t, c, p.msg("m1", p.send(receipt)), ReceiveOptions{})
	if !res.ProfileRenamed {
		t.Error("a claim on a receipt was not adopted")
	}
	if res.Content.Kind != ContentReceipt {
		t.Errorf("the receipt stopped being a receipt: %v", res.Content.Kind)
	}
}

// The history is bounded, or a peer renaming itself in a loop grows a file
// without limit.
func TestProfileHistoryIsBounded(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)
	deviceID, priv := knownDevice(t, c, "them")

	base := time.Now().UTC()
	for i := 0; i < maxProfileClaims+5; i++ {
		claim, err := profileclaim.Sign("them", deviceID, "name"+string(rune('a'+i)), base.Add(time.Duration(i)*time.Minute), priv)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		mustHandle(t, c, p.msg("m"+string(rune('a'+i)), p.send(claimPayload(t, "id-"+string(rune('a'+i)), "x", claim))), ReceiveOptions{})
		p.settled()
	}

	profile, err := c.PeerProfile("them")
	if err != nil {
		t.Fatalf("PeerProfile: %v", err)
	}
	if len(profile.Claims) != maxProfileClaims {
		t.Errorf("history: want it capped at %d, got %d", maxProfileClaims, len(profile.Claims))
	}
	if profile.Name() != "name"+string(rune('a'+maxProfileClaims+4)) {
		t.Errorf("the newest claim is not first: %q", profile.Name())
	}
}

// A stranger's opening message arrives before their device has ever been
// resolved -- and that is exactly the message whose sender cannot be placed.
// The claim is held, and adopted the moment their key is learned.
func TestClaimFromAFirstMessageIsHeldUntilTheKeyArrives(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("device id: %v", err)
	}
	deviceID := hex.EncodeToString(raw)

	claim, err := profileclaim.Sign("them", deviceID, "Anna", time.Now(), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// No putPeerDevice yet: this is a first message from somebody unknown.
	res := mustHandle(t, c, p.msg("m1", p.send(claimPayload(t, "id-1", "hello", claim))), ReceiveOptions{})
	if res.ProfileRenamed {
		t.Error("an unverified claim was reported as a rename")
	}
	if name := nameOf(t, c, "them"); name != "" {
		t.Errorf("an unverified claim is showing as %q", name)
	}

	// Resolving them -- which a reply, or opening the request, does -- is what
	// the held claim was waiting on.
	if err := c.putPeerDevice(PeerEndpoint{AccountID: "them", DeviceID: deviceID, DevicePub: pub}); err != nil {
		t.Fatalf("putPeerDevice: %v", err)
	}
	if name := nameOf(t, c, "them"); name != "Anna" {
		t.Errorf("after learning their key the name is %q, want %q", name, "Anna")
	}
}

// A held claim that turns out not to be theirs is discarded when the key
// arrives, not kept for another try: the key was the answer it waited on.
func TestHeldClaimSignedByAStrangerIsDiscarded(t *testing.T) {
	c, p := newFixture(t, "me", "them", nil)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("device id: %v", err)
	}
	deviceID := hex.EncodeToString(raw)

	forged, err := profileclaim.Sign("them", deviceID, "Bank Support", time.Now(), otherPriv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	mustHandle(t, c, p.msg("m1", p.send(claimPayload(t, "id-1", "hello", forged))), ReceiveOptions{})

	if err := c.putPeerDevice(PeerEndpoint{AccountID: "them", DeviceID: deviceID, DevicePub: pub}); err != nil {
		t.Fatalf("putPeerDevice: %v", err)
	}
	if name := nameOf(t, c, "them"); name != "" {
		t.Errorf("a forged held claim was promoted as %q", name)
	}
	file, _, err := c.readProfileLocked("them")
	if err != nil {
		t.Fatalf("readProfileLocked: %v", err)
	}
	if len(file.Pending) != 0 {
		t.Error("the held claim was kept after the key had already answered it")
	}
}

func nameOf(t *testing.T, c *Client, peer string) string {
	t.Helper()
	profile, err := c.PeerProfile(peer)
	if err != nil {
		t.Fatalf("PeerProfile: %v", err)
	}
	return profile.Name()
}
