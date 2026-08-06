package api

import (
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/attest"
)

// withTestIssuer temporarily replaces attest.TrustedIssuers, mirroring
// cmd/server/attestation_test.go's helper of the same name -- both need to
// control the package-level trusted set rather than depend on whichever
// real keys happen to be compiled in.
func withTestIssuer(t *testing.T, pub ed25519.PublicKey) {
	t.Helper()
	original := attest.TrustedIssuers
	attest.TrustedIssuers = []ed25519.PublicKey{pub}
	t.Cleanup(func() { attest.TrustedIssuers = original })
}

func mustSignToken(t *testing.T, priv ed25519.PrivateKey, domain, tier string, seats uint32, issuedAt, expiresAt time.Time) string {
	t.Helper()
	a, err := attest.Sign(domain, tier, "Example GmbH", seats, issuedAt, expiresAt, priv)
	if err != nil {
		t.Fatalf("attest.Sign() error = %v", err)
	}
	token, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	return token
}

func TestHandleGetLicenseStatusRequiresAdmin(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/license", nil, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleGetLicenseStatusNoAttestation(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	newAccountWithRole(t, db, store.RoleUser)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/license", nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp licenseStatusResponse
	decodeJSON(t, rec, &resp)
	if resp.Attested {
		t.Error("Attested = true, want false when no attestation is configured")
	}
	if resp.OverLimit {
		t.Error("OverLimit = true, want false when there is no ceiling to compare against")
	}
	if resp.ActiveAccounts != 2 {
		t.Errorf("ActiveAccounts = %d, want 2 (the admin plus the one member created)", resp.ActiveAccounts)
	}
}

func TestHandleGetLicenseStatusOverLimit(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	pub, priv, err := attest.GenerateIssuerKey()
	if err != nil {
		t.Fatalf("GenerateIssuerKey() error = %v", err)
	}
	withTestIssuer(t, pub)

	a.Config.Domain = "chat.example.org"
	now := time.Now()
	a.Config.Attestation = mustSignToken(t, priv, "chat.example.org", attest.TierCommercial, 1, now, now.Add(24*time.Hour))

	// Seats=1, but the admin account created above plus one more member
	// pushes active accounts to 2 -- over the ceiling.
	newAccountWithRole(t, db, store.RoleUser)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/license", nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp licenseStatusResponse
	decodeJSON(t, rec, &resp)
	if !resp.Attested {
		t.Fatal("Attested = false, want true for a genuine, current attestation")
	}
	if resp.Seats != 1 {
		t.Errorf("Seats = %d, want 1", resp.Seats)
	}
	if resp.ActiveAccounts != 2 {
		t.Errorf("ActiveAccounts = %d, want 2", resp.ActiveAccounts)
	}
	if !resp.OverLimit {
		t.Error("OverLimit = false, want true when active accounts exceed Seats")
	}
}

func TestHandleGetLicenseStatusUnspecifiedSeatsNeverOverLimit(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	pub, priv, err := attest.GenerateIssuerKey()
	if err != nil {
		t.Fatalf("GenerateIssuerKey() error = %v", err)
	}
	withTestIssuer(t, pub)

	a.Config.Domain = "chat.example.org"
	now := time.Now()
	a.Config.Attestation = mustSignToken(t, priv, "chat.example.org", attest.TierCommunity, 0, now, now.Add(24*time.Hour))
	newAccountWithRole(t, db, store.RoleUser)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/license", nil, admin.deviceID, admin.devicePriv)
	var resp licenseStatusResponse
	decodeJSON(t, rec, &resp)
	if !resp.Attested {
		t.Fatal("Attested = false, want true")
	}
	if resp.Seats != 0 {
		t.Errorf("Seats = %d, want 0 (unspecified)", resp.Seats)
	}
	if resp.OverLimit {
		t.Error("OverLimit = true, want false when Seats is unspecified regardless of account count")
	}
}

// TestHandleGetLicenseStatusUnsetDomainStillAttests mirrors
// cmd/server/attestation_test.go's TestCheckAttestationUnsetDomainDoesNotWarn
// -- a server behind an external reverse proxy legitimately never sets
// FREIZONE_DOMAIN, and that must not read as "not attested" here either.
func TestHandleGetLicenseStatusUnsetDomainStillAttests(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	pub, priv, err := attest.GenerateIssuerKey()
	if err != nil {
		t.Fatalf("GenerateIssuerKey() error = %v", err)
	}
	withTestIssuer(t, pub)

	// Domain deliberately left unset.
	now := time.Now()
	a.Config.Attestation = mustSignToken(t, priv, "chat.example.org", attest.TierCommunity, 5, now, now.Add(24*time.Hour))

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/license", nil, admin.deviceID, admin.devicePriv)
	var resp licenseStatusResponse
	decodeJSON(t, rec, &resp)
	if !resp.Attested {
		t.Error("Attested = false, want true when FREIZONE_DOMAIN is unset but the signature is genuine")
	}
	if resp.Seats != 5 {
		t.Errorf("Seats = %d, want 5", resp.Seats)
	}
}
