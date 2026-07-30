package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
)

func TestHandleCreateInviteRequiresAdmin(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a) // non-admin

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/invites", []byte(`{}`), k.deviceID, k.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCreateInviteAsAdmin(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyInvite)

	admin := newIdentityKeys(t)
	if err := store.CreateAccount(db, store.Account{ID: admin.accountID, RootPubKey: admin.rootPub, Role: store.RoleAdmin, Status: store.AccountStatusActive, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	if err := store.CreateDevice(db, store.Device{
		DeviceID: admin.deviceID, AccountID: admin.accountID, DevicePubKey: admin.devicePub,
		CertIssuedAt: admin.issuedAt, CertSignature: admin.certSignature(t), Status: store.DeviceStatusActive, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/invites", []byte(`{}`), admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}

	var resp createInviteResponse
	decodeJSON(t, rec, &resp)
	if resp.Code == "" {
		t.Error("expected a non-empty invite code")
	}

	inv, err := store.GetInviteCode(db, resp.Code)
	if err != nil {
		t.Fatalf("GetInviteCode() error = %v", err)
	}
	if inv.CreatedByAccountID != admin.accountID {
		t.Errorf("CreatedByAccountID = %q, want %q", inv.CreatedByAccountID, admin.accountID)
	}
}

func TestHandleCreateInviteWithExpiry(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyInvite)

	admin := newIdentityKeys(t)
	if err := store.CreateAccount(db, store.Account{ID: admin.accountID, RootPubKey: admin.rootPub, Role: store.RoleAdmin, Status: store.AccountStatusActive, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	if err := store.CreateDevice(db, store.Device{
		DeviceID: admin.deviceID, AccountID: admin.accountID, DevicePubKey: admin.devicePub,
		CertIssuedAt: admin.issuedAt, CertSignature: admin.certSignature(t), Status: store.DeviceStatusActive, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}

	expiresAt := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	body, _ := json.Marshal(createInviteRequest{ExpiresAt: &expiresAt})

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/invites", body, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}

	var resp createInviteResponse
	decodeJSON(t, rec, &resp)
	if resp.ExpiresAt == nil {
		t.Error("expected expires_at to be set in the response")
	}
}

// mustCreateAdmin registers an active admin account+device directly in the
// store, for the signed admin endpoints.
func mustCreateAdmin(t *testing.T, db *sql.DB) identityKeys {
	t.Helper()
	admin := newIdentityKeys(t)
	if err := store.CreateAccount(db, store.Account{
		ID: admin.accountID, RootPubKey: admin.rootPub, Role: store.RoleAdmin,
		Status: store.AccountStatusActive, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	if err := store.CreateDevice(db, store.Device{
		DeviceID: admin.deviceID, AccountID: admin.accountID, DevicePubKey: admin.devicePub,
		CertIssuedAt: admin.issuedAt, CertSignature: admin.certSignature(t),
		Status: store.DeviceStatusActive, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	return admin
}

func TestHandleCreateInviteReturnsAShortGroupedCode(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyInvite)
	admin := mustCreateAdmin(t, db)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/invites", []byte(`{}`), admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
	var resp createInviteResponse
	decodeJSON(t, rec, &resp)

	// "ABCD-EFGH-JKMN" -- the whole point is that this can be read aloud.
	if want := "ABCD-EFGH-JKMN"; len(resp.Code) != len(want) {
		t.Errorf("code %q is %d chars, want %d (as in %q)", resp.Code, len(resp.Code), len(want), want)
	}
	if strings.Count(resp.Code, "-") != 2 {
		t.Errorf("code %q should be grouped in fours by two hyphens", resp.Code)
	}
}

func TestHandleCreateInviteAppliesTheDefaultExpiry(t *testing.T) {
	// An invite that never expires is what would make guessing one worth
	// attempting, so omitting expires_at must NOT mean "forever".
	a, db := newTestAPI(t, config.PolicyInvite)
	admin := mustCreateAdmin(t, db)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/invites", []byte(`{}`), admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
	var resp createInviteResponse
	decodeJSON(t, rec, &resp)

	if resp.ExpiresAt == nil {
		t.Fatal("expires_at is absent, want the configured default to have been applied")
	}
	expires, err := time.Parse(time.RFC3339, *resp.ExpiresAt)
	if err != nil {
		t.Fatalf("parsing expires_at %q: %v", *resp.ExpiresAt, err)
	}
	// 14 days out per newTestAPI's config; allow a day of slack rather than
	// pinning the clock.
	wantAround := time.Now().AddDate(0, 0, 14)
	if expires.Before(wantAround.Add(-24*time.Hour)) || expires.After(wantAround.Add(24*time.Hour)) {
		t.Errorf("expires_at = %v, want roughly %v", expires, wantAround)
	}
}

func TestInviteCodeRedeemsHoweverItWasTyped(t *testing.T) {
	// End-to-end over HTTP: issue a code through the admin endpoint, then
	// register with it the way a person might actually have retyped it.
	variants := map[string]func(string) string{
		"as issued":         func(c string) string { return c },
		"lowercased":        strings.ToLower,
		"without hyphens":   func(c string) string { return strings.ReplaceAll(c, "-", "") },
		"lowercase compact": func(c string) string { return strings.ToLower(strings.ReplaceAll(c, "-", "")) },
		"O typed for zero":  func(c string) string { return strings.ReplaceAll(c, "0", "O") },
		"l typed for one":   func(c string) string { return strings.ReplaceAll(c, "1", "l") },
	}

	for name, mangle := range variants {
		t.Run(name, func(t *testing.T) {
			a, db := newTestAPI(t, config.PolicyInvite)
			admin := mustCreateAdmin(t, db)

			rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/invites", []byte(`{}`), admin.deviceID, admin.devicePriv)
			if rec.Code != http.StatusCreated {
				t.Fatalf("create invite status = %d, body = %s", rec.Code, rec.Body.String())
			}
			var resp createInviteResponse
			decodeJSON(t, rec, &resp)

			typed := mangle(resp.Code)
			k := newIdentityKeys(t)
			reg := doRequest(t, a.Router(), http.MethodPost, "/v1/accounts", registerBodyT(t, k, &typed))
			if reg.Code != http.StatusCreated {
				t.Errorf("register with %q: status = %d, want 201, body = %s", typed, reg.Code, reg.Body.String())
			}
		})
	}
}

func TestInviteCodeStillRejectsAWrongCodeOverHTTP(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyInvite)
	mustCreateAdmin(t, db)

	wrong := "ZZZZ-ZZZZ-ZZZZ"
	k := newIdentityKeys(t)
	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/accounts", registerBodyT(t, k, &wrong))
	if rec.Code == http.StatusCreated {
		t.Error("registration with a bogus invite code succeeded, want it refused")
	}
}
