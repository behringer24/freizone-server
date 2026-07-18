package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
)

func registerBodyT(t *testing.T, k identityKeys, inviteCode *string) []byte {
	t.Helper()
	req := registerAccountRequest{
		RootPubKey:          b64(k.rootPub),
		DeviceID:            k.deviceID,
		DevicePubKey:        b64(k.devicePub),
		DeviceCertIssuedAt:  k.issuedAt.UTC().Format(time.RFC3339),
		DeviceCertSignature: b64(k.certSignature(t)),
		InviteCode:          inviteCode,
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return body
}

func TestHandleRegisterAccountOpenPolicy(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := newIdentityKeys(t)

	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/accounts", registerBodyT(t, k, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}

	var resp accountResponse
	decodeJSON(t, rec, &resp)
	if resp.ID != k.accountID {
		t.Errorf("account id = %q, want %q", resp.ID, k.accountID)
	}

	acc, err := store.GetAccount(db, k.accountID)
	if err != nil {
		t.Fatalf("GetAccount() error = %v", err)
	}
	if acc.Role == store.RoleAdmin {
		t.Error("self-registered account should not be admin")
	}
}

func TestHandleRegisterAccountClosedPolicy(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyClosed)
	k := newIdentityKeys(t)

	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/accounts", registerBodyT(t, k, nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRegisterAccountDuplicate(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := newIdentityKeys(t)

	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/accounts", registerBodyT(t, k, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("first register status = %d, want 201", rec.Code)
	}

	rec2 := doRequest(t, a.Router(), http.MethodPost, "/v1/accounts", registerBodyT(t, k, nil))
	if rec2.Code != http.StatusConflict {
		t.Errorf("duplicate register status = %d, want 409", rec2.Code)
	}
}

func TestHandleRegisterAccountInvitePolicy(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyInvite)

	admin := newIdentityKeys(t)
	if err := store.CreateAccount(db, store.Account{ID: admin.accountID, RootPubKey: admin.rootPub, Role: store.RoleAdmin, Status: store.AccountStatusActive, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}

	k := newIdentityKeys(t)

	// Without an invite code: forbidden.
	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/accounts", registerBodyT(t, k, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no-invite-code status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}

	code, err := store.CreateInviteCode(db, admin.accountID, nil, time.Now())
	if err != nil {
		t.Fatalf("CreateInviteCode() error = %v", err)
	}

	rec2 := doRequest(t, a.Router(), http.MethodPost, "/v1/accounts", registerBodyT(t, k, &code))
	if rec2.Code != http.StatusCreated {
		t.Fatalf("with-invite-code status = %d, want 201, body = %s", rec2.Code, rec2.Body.String())
	}

	// Reusing the same code for a second registration must fail.
	k2 := newIdentityKeys(t)
	rec3 := doRequest(t, a.Router(), http.MethodPost, "/v1/accounts", registerBodyT(t, k2, &code))
	if rec3.Code != http.StatusGone {
		t.Errorf("reused-invite-code status = %d, want 410, body = %s", rec3.Code, rec3.Body.String())
	}
}

func TestHandleGetAccount(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := newIdentityKeys(t)

	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/accounts", registerBodyT(t, k, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201", rec.Code)
	}

	getRec := doRequest(t, a.Router(), http.MethodGet, "/v1/accounts/"+k.accountID, nil)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200, body = %s", getRec.Code, getRec.Body.String())
	}

	var resp accountResponse
	decodeJSON(t, getRec, &resp)
	if resp.ID != k.accountID || resp.RootPubKey != b64(k.rootPub) {
		t.Errorf("unexpected account response: %+v", resp)
	}
	if len(resp.Devices) != 1 {
		t.Errorf("len(devices) = %d, want 1", len(resp.Devices))
	}
}

func TestHandleGetAccountNotFound(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := newIdentityKeys(t)

	rec := doRequest(t, a.Router(), http.MethodGet, "/v1/accounts/"+k.accountID, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleGetVAPIDPublicKey(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)

	rec := doRequest(t, a.Router(), http.MethodGet, "/v1/vapid-public-key", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	decodeJSON(t, rec, &resp)
	if resp["key"] == "" || resp["key"] != a.VAPIDPublicKey {
		t.Errorf("key = %q, want %q", resp["key"], a.VAPIDPublicKey)
	}
}
