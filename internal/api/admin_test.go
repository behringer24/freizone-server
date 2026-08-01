package api

import (
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
)

// newAccountWithRole creates an account+device directly (bypassing
// registration) with the given role, for setting up admin/moderator
// identities in tests.
func newAccountWithRole(t *testing.T, db *sql.DB, role store.Role) identityKeys {
	t.Helper()
	k := newIdentityKeys(t)
	if err := store.CreateAccount(db, store.Account{
		ID: k.accountID, RootPubKey: k.rootPub, Role: role, Status: store.AccountStatusActive, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	if err := store.CreateDevice(db, store.Device{
		DeviceID: k.deviceID, AccountID: k.accountID, DevicePubKey: k.devicePub,
		CertIssuedAt: k.issuedAt, CertSignature: k.certSignature(t), Status: store.DeviceStatusActive, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateDevice() error = %v", err)
	}
	return k
}

func TestHandleListAccountsRequiresAdminOrModerator(t *testing.T) {
	a, _ := newTestAPI(t, config.PolicyOpen)
	k := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/accounts", nil, k.deviceID, k.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleListAccountsAsAdminAndModerator(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	moderator := newAccountWithRole(t, db, store.RoleModerator)
	user := registerAccount(t, a)

	for _, caller := range []identityKeys{admin, moderator} {
		rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/accounts", nil, caller.deviceID, caller.devicePriv)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var resp []adminAccountResponse
		decodeJSON(t, rec, &resp)
		if len(resp) != 3 {
			t.Fatalf("got %d accounts, want 3", len(resp))
		}
		var sawUser bool
		for _, acc := range resp {
			if acc.ID == user.accountID {
				sawUser = true
				if acc.Role != string(store.RoleUser) {
					t.Errorf("user role = %q, want %q", acc.Role, store.RoleUser)
				}
			}
		}
		if !sawUser {
			t.Error("registered user not present in account list")
		}
	}
}

// SRV-09: the list is what an operator uses to tell a live account from an
// abandoned one, so the activity figures have to survive the trip to the wire
// -- and be there, as zeroes, for an account with nothing going on. A missing
// field would be indistinguishable from an older server.
func TestHandleListAccountsCarriesActivitySignals(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	alice := registerAccount(t, a)
	bob := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/messages",
		sendMessageBody(t, "msg1", bob.deviceID, `{"ciphertext":"abc"}`), alice.deviceID, alice.devicePriv)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202, body = %s", rec.Code, rec.Body.String())
	}

	rec = doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/accounts", nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp []adminAccountResponse
	decodeJSON(t, rec, &resp)

	byID := make(map[string]adminAccountResponse, len(resp))
	for _, acc := range resp {
		byID[acc.ID] = acc
	}

	recipient := byID[bob.accountID]
	if recipient.PendingMessages != 1 {
		t.Errorf("recipient pending = %d, want 1", recipient.PendingMessages)
	}
	if recipient.OldestPendingAt == nil {
		t.Error("recipient oldest_pending_at is absent, want the queued message's sent_at")
	}
	// The quota the usage is shown against is the per-device limit times the
	// account's devices -- that is where it is actually enforced.
	if want := a.Config.MaxBlobBytesPerDevice; recipient.BlobBytesLimit != want {
		t.Errorf("recipient blob limit = %d, want %d for one device", recipient.BlobBytesLimit, want)
	}
	if recipient.DeviceCount != 1 {
		t.Errorf("recipient device count = %d, want 1", recipient.DeviceCount)
	}

	// The sender's own queue is empty: present and zero, not omitted.
	sender := byID[alice.accountID]
	if sender.PendingMessages != 0 {
		t.Errorf("sender pending = %d, want 0", sender.PendingMessages)
	}
	if sender.OldestPendingAt != nil {
		t.Errorf("sender oldest_pending_at = %q, want absent for an empty queue", *sender.OldestPendingAt)
	}
	if sender.BlobBytes != 0 || sender.BlobCount != 0 {
		t.Errorf("sender blobs = (%d, %d), want (0, 0)", sender.BlobCount, sender.BlobBytes)
	}
}

// SRV-14: who invited whom is the one account-to-account link this server
// keeps, so it goes to admins and stops there -- a moderator gets the activity
// figures without the social thread between accounts.
func TestHandleListAccountsInviterIsAdminOnly(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyInvite)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	moderator := newAccountWithRole(t, db, store.RoleModerator)

	code, err := store.CreateInviteCode(db, admin.accountID, nil, time.Now())
	if err != nil {
		t.Fatalf("CreateInviteCode() error = %v", err)
	}
	invitee := newIdentityKeys(t)
	rec := doRequest(t, a.Router(), http.MethodPost, "/v1/accounts", registerBodyT(t, invitee, &code))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}

	listAs := func(caller identityKeys) map[string]adminAccountResponse {
		t.Helper()
		rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/accounts", nil, caller.deviceID, caller.devicePriv)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var resp []adminAccountResponse
		decodeJSON(t, rec, &resp)
		byID := make(map[string]adminAccountResponse, len(resp))
		for _, acc := range resp {
			byID[acc.ID] = acc
		}
		return byID
	}

	asAdmin := listAs(admin)[invitee.accountID]
	if asAdmin.InvitedBy == nil {
		t.Fatal("admin sees no invited_by, want the inviting account")
	}
	if *asAdmin.InvitedBy != admin.accountID {
		t.Errorf("invited_by = %q, want %q", *asAdmin.InvitedBy, admin.accountID)
	}

	if got := listAs(moderator)[invitee.accountID]; got.InvitedBy != nil {
		t.Errorf("moderator sees invited_by = %q, want it withheld", *got.InvitedBy)
	}
	// Withholding it must not have withheld the rest.
	if got := listAs(moderator)[invitee.accountID]; got.ID != invitee.accountID || got.DeviceCount != 1 {
		t.Errorf("moderator's entry = %+v, want the account with its device count intact", got)
	}
}

// Absent is "not known here", never "registered openly" -- the same field is
// empty for an account that needed no invite and for one whose inviter has
// since been deleted (the invite row cascades with them).
func TestHandleListAccountsOmitsInviterWhenThereIsNone(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	openJoiner := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/accounts", nil, admin.deviceID, admin.devicePriv)
	var resp []adminAccountResponse
	decodeJSON(t, rec, &resp)
	for _, acc := range resp {
		if acc.ID == openJoiner.accountID && acc.InvitedBy != nil {
			t.Errorf("invited_by = %q for an account that registered openly, want absent", *acc.InvitedBy)
		}
	}
}

func TestHandleSetAccountRolePromotesAndDemotes(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	user := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/accounts/"+user.accountID+"/role",
		[]byte(`{"role":"moderator"}`), admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("promote status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	acc, err := store.GetAccount(db, user.accountID)
	if err != nil {
		t.Fatalf("GetAccount() error = %v", err)
	}
	if acc.Role != store.RoleModerator {
		t.Errorf("role = %q, want %q", acc.Role, store.RoleModerator)
	}

	rec = doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/accounts/"+user.accountID+"/role",
		[]byte(`{"role":"user"}`), admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("demote status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	acc, err = store.GetAccount(db, user.accountID)
	if err != nil {
		t.Fatalf("GetAccount() error = %v", err)
	}
	if acc.Role != store.RoleUser {
		t.Errorf("role = %q, want %q", acc.Role, store.RoleUser)
	}
}

func TestHandleSetAccountRoleRequiresAdmin(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	moderator := newAccountWithRole(t, db, store.RoleModerator)
	user := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/accounts/"+user.accountID+"/role",
		[]byte(`{"role":"admin"}`), moderator.deviceID, moderator.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSetAccountRoleRejectsInvalidRole(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	user := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/accounts/"+user.accountID+"/role",
		[]byte(`{"role":"superadmin"}`), admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSetAccountRoleUnknownAccount(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/accounts/does-not-exist/role",
		[]byte(`{"role":"moderator"}`), admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleSetAccountRoleLastAdminGuard(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/accounts/"+admin.accountID+"/role",
		[]byte(`{"role":"user"}`), admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleBlockAccountPreventsAuthenticationThenUnblockRestoresIt(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	user := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/accounts/"+user.accountID+"/block",
		nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("block status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	// The blocked user's own signed requests must now be rejected --
	// this is the dormant-bug fix: account status was never enforced
	// before.
	rec = doSignedRequest(t, a.Router(), http.MethodPost, "/v1/devices/"+user.deviceID+"/revoke", []byte(`{}`), user.deviceID, user.devicePriv)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("blocked user request status = %d, want 401, body = %s", rec.Code, rec.Body.String())
	}

	rec = doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/accounts/"+user.accountID+"/unblock",
		nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("unblock status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	acc, err := store.GetAccount(db, user.accountID)
	if err != nil {
		t.Fatalf("GetAccount() error = %v", err)
	}
	if acc.Status != store.AccountStatusActive {
		t.Errorf("status after unblock = %q, want %q", acc.Status, store.AccountStatusActive)
	}
}

// SRV-08: the global block is the one account-changing action a moderator
// gets, so that moderating a server doesn't require handing out admin.
func TestHandleBlockAccountAsModerator(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	newAccountWithRole(t, db, store.RoleAdmin) // so the last-admin guard is never what answers
	moderator := newAccountWithRole(t, db, store.RoleModerator)
	user := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/accounts/"+user.accountID+"/block",
		nil, moderator.deviceID, moderator.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("block status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	acc, err := store.GetAccount(db, user.accountID)
	if err != nil {
		t.Fatalf("GetAccount() error = %v", err)
	}
	if acc.Status != store.AccountStatusDisabled {
		t.Errorf("status = %q, want %q", acc.Status, store.AccountStatusDisabled)
	}

	rec = doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/accounts/"+user.accountID+"/unblock",
		nil, moderator.deviceID, moderator.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("unblock status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
}

// The guard that keeps SRV-08 from becoming a privilege escalation: a
// disabled account cannot make a single authenticated request, so a moderator
// who could block staff would hold removal power over them. Two admins exist
// deliberately -- the last-admin guard would otherwise mask the real rule with
// a 409.
func TestHandleBlockAccountModeratorCannotTouchStaff(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	newAccountWithRole(t, db, store.RoleAdmin)
	moderator := newAccountWithRole(t, db, store.RoleModerator)
	otherModerator := newAccountWithRole(t, db, store.RoleModerator)

	for _, tc := range []struct {
		name   string
		target identityKeys
	}{
		{"an admin", admin},
		{"another moderator", otherModerator},
		{"themselves", moderator},
	} {
		for _, action := range []string{"block", "unblock"} {
			rec := doSignedRequest(t, a.Router(), http.MethodPost,
				"/v1/admin/accounts/"+tc.target.accountID+"/"+action,
				nil, moderator.deviceID, moderator.devicePriv)
			if rec.Code != http.StatusForbidden {
				t.Errorf("moderator %s %s: status = %d, want 403, body = %s",
					action, tc.name, rec.Code, rec.Body.String())
			}
		}
	}

	// The admin's own power is untouched by the new rule.
	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/accounts/"+moderator.accountID+"/block",
		nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Errorf("admin blocking a moderator: status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
}

// Widening block/unblock must not have widened anything else.
func TestModeratorStillCannotSetRolesOrDelete(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	newAccountWithRole(t, db, store.RoleAdmin)
	moderator := newAccountWithRole(t, db, store.RoleModerator)
	user := registerAccount(t, a)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/accounts/"+user.accountID+"/role",
		[]byte(`{"role":"admin"}`), moderator.deviceID, moderator.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("moderator set-role status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}

	rec = doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/admin/accounts/"+user.accountID,
		nil, moderator.deviceID, moderator.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("moderator delete status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleBlockAccountLastAdminGuard(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/accounts/"+admin.accountID+"/block",
		nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandleDeleteAccountLastAdminGuard(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)

	rec := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/admin/accounts/"+admin.accountID, nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
}

// TestHandleDeleteAccountCascadesAsInviteCreator confirms that deleting an
// account that created an invite code no longer fails with a foreign-key
// error (migrations/0005) -- the invite is deleted along with its creator.
func TestHandleDeleteAccountCascadesAsInviteCreator(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin1 := newAccountWithRole(t, db, store.RoleAdmin)
	admin2 := newAccountWithRole(t, db, store.RoleAdmin) // second admin so the guard doesn't block deleting admin1

	code, err := store.CreateInviteCode(db, admin1.accountID, nil, time.Now())
	if err != nil {
		t.Fatalf("CreateInviteCode() error = %v", err)
	}

	rec := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/admin/accounts/"+admin1.accountID, nil, admin2.deviceID, admin2.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	if _, err := store.GetAccount(db, admin1.accountID); err == nil {
		t.Error("expected admin1 to be gone after delete")
	}
	if _, err := store.GetInviteCode(db, code); err == nil {
		t.Error("expected the invite created by the deleted account to be gone too (CASCADE)")
	}
}

// TestHandleDeleteAccountCascadesAsInviteUser confirms deleting a user who
// consumed someone else's invite code just clears used_by_account_id
// (SET NULL) rather than failing or deleting the invite record.
func TestHandleDeleteAccountCascadesAsInviteUser(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	user := registerAccount(t, a)

	code, err := store.CreateInviteCode(db, admin.accountID, nil, time.Now())
	if err != nil {
		t.Fatalf("CreateInviteCode() error = %v", err)
	}
	if err := store.ConsumeInviteCode(db, code, user.accountID, time.Now()); err != nil {
		t.Fatalf("ConsumeInviteCode() error = %v", err)
	}

	rec := doSignedRequest(t, a.Router(), http.MethodDelete, "/v1/admin/accounts/"+user.accountID, nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	inv, err := store.GetInviteCode(db, code)
	if err != nil {
		t.Fatalf("GetInviteCode() error = %v, want the invite to still exist", err)
	}
	if inv.UsedByAccountID != nil {
		t.Errorf("UsedByAccountID = %v, want nil after the using account was deleted", *inv.UsedByAccountID)
	}
}

func TestHandleRegistrationPolicyGetAndPut(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyClosed)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	moderator := newAccountWithRole(t, db, store.RoleModerator)

	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/registration-policy", nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp registrationPolicyResponse
	decodeJSON(t, rec, &resp)
	if resp.Policy != string(config.PolicyClosed) {
		t.Errorf("policy = %q, want %q", resp.Policy, config.PolicyClosed)
	}

	// Moderator can read but not write.
	rec = doSignedRequest(t, a.Router(), http.MethodPut, "/v1/admin/registration-policy", []byte(`{"policy":"open"}`), moderator.deviceID, moderator.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("moderator put status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}

	rec = doSignedRequest(t, a.Router(), http.MethodPut, "/v1/admin/registration-policy", []byte(`{"policy":"invalid"}`), admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid policy status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}

	rec = doSignedRequest(t, a.Router(), http.MethodPut, "/v1/admin/registration-policy", []byte(`{"policy":"open"}`), admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin put status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	policy, err := store.GetRegistrationPolicy(db)
	if err != nil {
		t.Fatalf("GetRegistrationPolicy() error = %v", err)
	}
	if policy != string(config.PolicyOpen) {
		t.Errorf("persisted policy = %q, want %q", policy, config.PolicyOpen)
	}
}

func TestHandleFederationEnabledGetAndPut(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyOpen)
	admin := newAccountWithRole(t, db, store.RoleAdmin)
	moderator := newAccountWithRole(t, db, store.RoleModerator)

	// Default (unseeded) reads as enabled.
	rec := doSignedRequest(t, a.Router(), http.MethodGet, "/v1/admin/federation", nil, admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp federationEnabledResponse
	decodeJSON(t, rec, &resp)
	if !resp.Enabled {
		t.Errorf("enabled = %v, want true by default", resp.Enabled)
	}

	// Moderator can read but not write (same protection as registration policy).
	rec = doSignedRequest(t, a.Router(), http.MethodPut, "/v1/admin/federation", []byte(`{"enabled":false}`), moderator.deviceID, moderator.devicePriv)
	if rec.Code != http.StatusForbidden {
		t.Errorf("moderator put status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}

	// Admin can turn it off; the change persists.
	rec = doSignedRequest(t, a.Router(), http.MethodPut, "/v1/admin/federation", []byte(`{"enabled":false}`), admin.deviceID, admin.devicePriv)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin put status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	enabled, err := store.GetFederationEnabled(db)
	if err != nil {
		t.Fatalf("GetFederationEnabled() error = %v", err)
	}
	if enabled {
		t.Errorf("persisted enabled = %v, want false", enabled)
	}
}

func TestHandleCreateInviteAsModerator(t *testing.T) {
	a, db := newTestAPI(t, config.PolicyInvite)
	moderator := newAccountWithRole(t, db, store.RoleModerator)

	rec := doSignedRequest(t, a.Router(), http.MethodPost, "/v1/admin/invites", []byte(`{}`), moderator.deviceID, moderator.devicePriv)
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
}
