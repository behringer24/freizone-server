package profileclaim

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

const (
	testAccountID = "k5x9p2qan7f3xyzqeh8m1"
	testDeviceID  = "0011223344556677"
)

func testKey(t *testing.T, seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := testKey(t, 1)
	issued := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	c, err := Sign(testAccountID, testDeviceID, "Anna", issued, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := c.Verify(testAccountID, pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// A claim lifted out of one account's message must not verify under another
// identity. This is the entire reason the account id is in the signing bytes
// while being absent from the wire.
func TestVerifyRejectsReplayUnderAnotherAccount(t *testing.T) {
	pub, priv := testKey(t, 1)
	c, err := Sign(testAccountID, testDeviceID, "Anna", time.Now(), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := c.Verify("qqqqqqqqqqqqqqqqqqqqq", pub); err == nil {
		t.Fatal("a claim verified under an account id it was not signed for")
	}
}

func TestVerifyRejectsWrongDeviceKey(t *testing.T) {
	_, priv := testKey(t, 1)
	otherPub, _ := testKey(t, 2)
	c, err := Sign(testAccountID, testDeviceID, "Anna", time.Now(), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := c.Verify(testAccountID, otherPub); err == nil {
		t.Fatal("a claim verified under a key that did not sign it")
	}
}

func TestVerifyRejectsTamperedFields(t *testing.T) {
	pub, priv := testKey(t, 1)
	issued := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name   string
		break_ func(*Claim)
	}{
		{"name", func(c *Claim) { c.Name = "Bank Support" }},
		{"device id", func(c *Claim) { c.DeviceID = "7766554433221100" }},
		{"issued at", func(c *Claim) { c.IssuedAt = issued.Add(time.Hour) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Sign(testAccountID, testDeviceID, "Anna", issued, priv)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			tc.break_(c)
			if err := c.Verify(testAccountID, pub); err == nil {
				t.Fatalf("a claim verified after its %s was changed", tc.name)
			}
		})
	}
}

// An empty name is a withdrawal, not an invalid claim: it has to be signable
// and verifiable, or there is no way back out of having stated a name.
func TestWithdrawalIsSignedAndVerified(t *testing.T) {
	pub, priv := testKey(t, 1)
	c, err := Sign(testAccountID, testDeviceID, "", time.Now(), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !c.IsWithdrawal() {
		t.Fatal("an empty name is not reported as a withdrawal")
	}
	if err := c.Verify(testAccountID, pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestValidateName(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"plain", "Anna", false},
		{"empty is the withdrawal", "", false},
		{"spaces inside", "Andreas Behringer (Kassenwart)", false},
		{"zero-width joiner is allowed", "Anna" + string(rune(0x200D)) + "B", false},
		{"at the byte limit", strings.Repeat("a", MaxNameBytes), false},
		{"over the byte limit", strings.Repeat("a", MaxNameBytes+1), true},
		{"multibyte over the byte limit", strings.Repeat("ä", MaxNameBytes/2+1), true},
		{"leading space", " Anna", true},
		{"trailing space", "Anna ", true},
		{"newline", "Anna\nSupport", true},
		{"tab", "Anna\tSupport", true},
		{"control character", "Anna\x00", true},
		{"right-to-left override", "Anna" + string(rune(0x202E)) + "Support", true},
		{"left-to-right mark", "Anna" + string(rune(0x200E)) + "Support", true},
		{"first strong isolate", "Anna" + string(rune(0x2066)) + "Support", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateName(tc.input)
			if tc.wantErr != (err != nil) {
				t.Fatalf("ValidateName(%q) = %v, want error: %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

// A correctly signed claim whose name breaks the rules is still refused --
// otherwise a hostile client signs its way past every display rule.
func TestVerifyRejectsSignedButInvalidName(t *testing.T) {
	pub, priv := testKey(t, 1)
	c := &Claim{Name: "Anna" + string(rune(0x202E)) + "Support", DeviceID: testDeviceID, IssuedAt: time.Now().UTC()}
	buf, err := c.signingBytes(testAccountID)
	if err != nil {
		t.Fatalf("signingBytes: %v", err)
	}
	c.Signature = ed25519.Sign(priv, buf)

	if err := c.Verify(testAccountID, pub); err == nil {
		t.Fatal("a signed claim with a bidi override in its name was accepted")
	}
}

func TestSupersedesTime(t *testing.T) {
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	c := &Claim{IssuedAt: base}

	if !c.SupersedesTime(base.Add(-time.Second)) {
		t.Error("a newer claim does not supersede an older one")
	}
	if c.SupersedesTime(base) {
		t.Error("an equally old claim supersedes, so a replay could displace what is stored")
	}
	if c.SupersedesTime(base.Add(time.Second)) {
		t.Error("an older claim supersedes a newer one")
	}
}

// The cross-repo contract: freizone-app produces these same bytes, so a fixed
// vector is what stops the two implementations drifting apart silently. Change
// it only when PROTOCOL §6 changes, and then in both repos at once.
func TestSigningBytesVector(t *testing.T) {
	c := &Claim{
		Name:     "Anna",
		DeviceID: testDeviceID,
		IssuedAt: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
	}
	got, err := c.signingBytes(testAccountID)
	if err != nil {
		t.Fatalf("signingBytes: %v", err)
	}

	const want = "0015" + // uint16BE(21)
		"6b357839703271616e37663378797a716568386d31" + // account id
		"0011223344556677" + // device id, raw
		"0004" + "416e6e61" + // uint16BE(4), "Anna"
		"0014" + "323032362d30392d30315431303a30303a30305a" // uint16BE(20), RFC 3339

	if hex.EncodeToString(got) != want {
		t.Fatalf("signing bytes drifted\n got: %s\nwant: %s", hex.EncodeToString(got), want)
	}
}

func TestSignRejectsBadDeviceID(t *testing.T) {
	_, priv := testKey(t, 1)
	if _, err := Sign(testAccountID, "nothex", "Anna", time.Now(), priv); err == nil {
		t.Fatal("a non-hex device id was accepted")
	}
	if _, err := Sign(testAccountID, "00112233", "Anna", time.Now(), priv); err == nil {
		t.Fatal("a device id of the wrong length was accepted")
	}
}

func TestSignTrimsAndRejects(t *testing.T) {
	_, priv := testKey(t, 1)

	c, err := Sign(testAccountID, testDeviceID, "  Anna  ", time.Now(), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if c.Name != "Anna" {
		t.Fatalf("Sign did not trim the name: %q", c.Name)
	}
	if _, err := Sign(testAccountID, testDeviceID, "Anna\nSupport", time.Now(), priv); err == nil {
		t.Fatal("a name with a line break was signed")
	}
}
