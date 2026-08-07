package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
)

// SRV-04. A prekey bundle is public key material and stays readable by anyone,
// but the one-time prekey inside it is a consumable: an anonymous caller could
// drain a device's whole pool by asking repeatedly, costing that device forward
// secrecy on the first message of every session until it topped up again.

// federatedClaimBody builds the optional request body a claimant from another
// server sends: its own self-certifying identity chain, same shape federated
// message delivery uses.
func federatedClaimBody(t *testing.T, sender identityKeys, certSigner identityKeys) []byte {
	t.Helper()
	body, err := json.Marshal(claimPrekeyBundleRequest{
		SenderAccountID:  sender.accountID,
		SenderRootPubKey: b64(sender.rootPub),
		SenderDeviceCert: federationDeviceCertDTO{
			DeviceID:     sender.deviceID,
			DevicePubKey: b64(sender.devicePub),
			IssuedAt:     sender.issuedAt.UTC().Format(time.RFC3339),
			Signature:    b64(certSigner.certSignature(t)),
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return body
}

// The compatibility guarantee: an unauthenticated claim still succeeds and still
// carries everything needed to start a session -- it just doesn't consume a
// one-time prekey. That is the shape an empty pool already produces, so every
// existing client handles it, which is what makes closing this hole a
// non-breaking change.
func TestClaimPrekeyBundleAnonymousGetsBundleWithoutOneTimePrekey(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	uploadPrekeysT(t, a.Router(), k, 5)

	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+k.deviceID+"/prekey-bundle", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp prekeyBundleResponse
	decodeJSON(t, rec, &resp)

	if resp.OneTimePrekey != nil {
		t.Error("an anonymous claim must not consume a one-time prekey")
	}
	if resp.OneTimePrekeyOmitted != oneTimePrekeyOmittedUnauthenticated {
		t.Errorf("one_time_prekey_omitted = %q, want %q", resp.OneTimePrekeyOmitted, oneTimePrekeyOmittedUnauthenticated)
	}
	// Still a usable bundle: the signed prekey and its certificates are what a
	// session actually needs; the one-time key only strengthens the first
	// message.
	if resp.SignedPrekey.PubKey == "" || resp.DHIdentityPubKey == "" {
		t.Error("the bundle must still carry the signed prekey and dh identity")
	}
}

// The point of the whole change: however often an anonymous caller asks, the
// pool is untouched.
func TestClaimPrekeyBundleAnonymousCannotDrainThePool(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	uploadPrekeysT(t, a.Router(), k, 5)

	for i := 0; i < 20; i++ {
		rec := doRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+k.deviceID+"/prekey-bundle", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("claim %d status = %d, want 200", i, rec.Code)
		}
	}

	remaining, err := store.CountOneTimePrekeys(db, k.deviceID)
	if err != nil {
		t.Fatalf("CountOneTimePrekeys() error = %v", err)
	}
	if remaining != 5 {
		t.Errorf("remaining one-time prekeys = %d, want 5 -- an anonymous caller drained the pool", remaining)
	}
}

// An identified claimant facing a genuinely empty pool must be distinguishable
// from one that was refused a key, or a client cannot tell a drained peer from
// its own broken credentials.
func TestClaimPrekeyBundleReportsWhyTheKeyIsMissing(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	initiator := registerAccount(t, a)
	uploadPrekeysT(t, a.Router(), k, 1)

	var resp prekeyBundleResponse
	decodeJSON(t, claimBundleT(t, a.Router(), k.deviceID, initiator), &resp)
	if resp.OneTimePrekey == nil {
		t.Fatal("an authenticated claim should get a one-time prekey")
	}
	if resp.OneTimePrekeyOmitted != "" {
		t.Errorf("one_time_prekey_omitted = %q, want empty when a key was handed out", resp.OneTimePrekeyOmitted)
	}

	decodeJSON(t, claimBundleT(t, a.Router(), k.deviceID, initiator), &resp)
	if resp.OneTimePrekeyOmitted != oneTimePrekeyOmittedPoolEmpty {
		t.Errorf("one_time_prekey_omitted = %q, want %q", resp.OneTimePrekeyOmitted, oneTimePrekeyOmittedPoolEmpty)
	}
}

// Credentials that are present but wrong must be refused outright. Quietly
// degrading them to "anonymous" would turn a client bug or a skewed clock into a
// silent, months-long loss of forward secrecy that nothing would report.
func TestClaimPrekeyBundleRejectsBadCredentialsRatherThanDowngrading(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	initiator := registerAccount(t, a)
	uploadPrekeysT(t, a.Router(), k, 2)

	// A real device id, signed with somebody else's key.
	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+k.deviceID+"/prekey-bundle",
		nil, initiator.deviceID, k.devicePriv)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}
}

// A sender whose account lives on another server has no local row to
// authenticate against, so it presents its own self-certifying chain inline --
// the same form federated message delivery uses. Without this, closing the hole
// would have broken federated first contact entirely.
func TestClaimPrekeyBundleAcceptsFederatedSender(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	uploadPrekeysT(t, a.Router(), k, 2)

	foreign := newIdentityKeys(t) // deliberately never registered here

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/devices/"+k.deviceID+"/prekey-bundle",
		federatedClaimBody(t, foreign, foreign), foreign)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp prekeyBundleResponse
	decodeJSON(t, rec, &resp)
	if resp.OneTimePrekey == nil {
		t.Error("a verified federated sender should get a one-time prekey")
	}
}

func TestClaimPrekeyBundleRejectsFederatedSenderWithABadCertificate(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	uploadPrekeysT(t, a.Router(), k, 2)

	foreign := newIdentityKeys(t)
	mallory := newIdentityKeys(t)

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/devices/"+k.deviceID+"/prekey-bundle",
		federatedClaimBody(t, foreign, mallory), foreign)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

// The federation switch governs the foreign form too. Accepting the credentials
// of a server this one refuses to exchange messages with would be an odd
// exception -- and that sender could not have delivered the message the bundle
// is for anyway.
func TestClaimPrekeyBundleRefusesFederatedSenderWhenFederationIsOff(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	uploadPrekeysT(t, a.Router(), k, 2)
	if err := store.SetFederationEnabled(db, false); err != nil {
		t.Fatalf("SetFederationEnabled() error = %v", err)
	}

	foreign := newIdentityKeys(t)
	rec := doFederatedSignedRequest(t, a.Router(), "/v1/devices/"+k.deviceID+"/prekey-bundle",
		federatedClaimBody(t, foreign, foreign), foreign)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
	// Same status as a dead device id, different code -- a sender must not
	// react to a switched-off federation by discarding its cached device.
	if code := errorCodeT(t, rec); code != "federation_disabled" {
		t.Errorf("error code = %q, want federation_disabled", code)
	}

	// A local claimant is unaffected -- switching federation off must not stop
	// this server's own users starting conversations with each other.
	initiator := registerAccount(t, a)
	var resp prekeyBundleResponse
	decodeJSON(t, claimBundleT(t, a.Router(), k.deviceID, initiator), &resp)
	if resp.OneTimePrekey == nil {
		t.Error("a local claim must still get a one-time prekey with federation off")
	}
}

// A federated sender on the blocklist is refused, so blocking someone also stops
// them consuming prekeys -- inherited from verifyFederatedSender, and worth
// pinning, since reusing that check is the whole reason this endpoint accepts an
// inline claim at all.
func TestClaimPrekeyBundleRefusesBlockedFederatedSender(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)
	uploadPrekeysT(t, a.Router(), k, 2)

	foreign := newIdentityKeys(t)
	if err := store.BlockFederationSender(db, foreign.accountID, "admin", nil, time.Now()); err != nil {
		t.Fatalf("BlockFederationSender() error = %v", err)
	}

	rec := doFederatedSignedRequest(t, a.Router(), "/v1/devices/"+k.deviceID+"/prekey-bundle",
		federatedClaimBody(t, foreign, foreign), foreign)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}
