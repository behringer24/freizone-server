package api

import (
	"encoding/json"
	"net/http"
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
