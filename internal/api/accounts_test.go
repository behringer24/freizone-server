package api

import (
	"encoding/json"
	"net/http"
	"strings"
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

func TestHandleRegisterAccountIDPrefixConflict(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := newIdentityKeys(t)

	// A different account that happens to share k's first 5 id characters
	// -- store.CreateAccount doesn't validate id format, so this is a
	// cheap way to force the collision without brute-forcing a real key.
	colliding := k.accountID[:5] + "-a-different-account-entirely"
	if err := store.CreateAccount(db, store.Account{
		ID: colliding, RootPubKey: k.rootPub, Role: store.RoleUser, Status: store.AccountStatusActive, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seeding colliding account error = %v", err)
	}

	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/accounts", registerBodyT(t, k, nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "id_prefix_taken") {
		t.Errorf("body = %s, want it to mention id_prefix_taken", rec.Body.String())
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

func TestHandleGetAccountByPrefix(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := newIdentityKeys(t)

	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/accounts", registerBodyT(t, k, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201", rec.Code)
	}

	// Looking up just the first 5 characters (with a trailing dash, as
	// FormatForDisplay would show it) must resolve to the same account as
	// the full id, and the response's own "id" is always the true full id.
	prefix := k.accountID[:5] + "-"
	getRec := doRequest(t, a.Router(), http.MethodGet, "/v1/accounts/"+prefix, nil)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get by prefix status = %d, want 200, body = %s", getRec.Code, getRec.Body.String())
	}

	var resp accountResponse
	decodeJSON(t, getRec, &resp)
	if resp.ID != k.accountID {
		t.Errorf("account id = %q, want %q", resp.ID, k.accountID)
	}
}

func TestHandleGetAccountByPrefixNotFound(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)

	rec := doRequest(t, a.Router(), http.MethodGet, "/v1/accounts/zzzzz", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
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

func TestHandleDeleteOwnAccount(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/accounts/"+k.accountID, nil, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	if _, err := store.GetAccount(db, k.accountID); err == nil {
		t.Error("expected account to be gone after self-delete")
	}
}

// TestHandleDeleteOwnAccountRejectsOtherAccount confirms the target is
// never taken from the path in isolation: a validly-signed request from
// k1's own device, naming k2's account in the path, must be rejected --
// deleting a different account is impossible, not just policy-forbidden.
func TestHandleDeleteOwnAccountRejectsOtherAccount(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	k1 := registerAccount(t, a)
	k2 := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/accounts/"+k2.accountID, nil, k1.deviceID, k1.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}

	if _, err := store.GetAccount(db, k2.accountID); err != nil {
		t.Errorf("GetAccount(k2) error = %v, want k2 to still exist", err)
	}
}

func TestHandleDeleteOwnAccountLastAdminGuard(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)

	rec := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/accounts/"+admin.accountID, nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}

	if _, err := store.GetAccount(db, admin.accountID); err != nil {
		t.Errorf("GetAccount() error = %v, want the sole admin to still exist", err)
	}
}

func TestHandleDeleteOwnAccountRequiresAuthentication(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	rec := doRequest(t, a.Router(), http.MethodDelete, "/v1/accounts/"+k.accountID, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401, body = %s", rec.Code, rec.Body.String())
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
