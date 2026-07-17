// Server admin surface: the user list, role management, block/unblock,
// account deletion, and the runtime-mutable registration policy. See
// docs/PROTOCOL.md for the full permission matrix (admin vs. moderator).
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
)

// requireAdminOrModerator is the shared gate for endpoints moderators may
// also use (the user list, viewing the registration policy, invites).
func requireAdminOrModerator(w http.ResponseWriter, r *http.Request) (auth.Identity, bool) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok || (identity.Role != store.RoleAdmin && identity.Role != store.RoleModerator) {
		writeError(w, http.StatusForbidden, "forbidden", "admin or moderator privileges required")
		return auth.Identity{}, false
	}
	return identity, true
}

// requireAdmin is the shared gate for admin-only endpoints: granting
// roles, blocking/unblocking, deleting accounts, and changing the
// registration policy. Deliberately stricter than invite creation, so
// privilege escalation and account removal can never come from a
// moderator.
func requireAdmin(w http.ResponseWriter, r *http.Request) (auth.Identity, bool) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok || identity.Role != store.RoleAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "admin privileges required")
		return auth.Identity{}, false
	}
	return identity, true
}

// wouldRemoveLastActiveAdmin reports whether changing target away from
// being an active admin (demoting, blocking, or deleting it) would leave
// the server with zero usable admins. Accounts that aren't currently a
// counted active admin never trigger this.
func (a *API) wouldRemoveLastActiveAdmin(target *store.Account) (bool, error) {
	if target.Role != store.RoleAdmin || target.Status != store.AccountStatusActive {
		return false, nil
	}
	count, err := store.CountActiveAdmins(a.DB)
	if err != nil {
		return false, err
	}
	return count <= 1, nil
}

// handleListAccounts returns every registered account. Available to
// admins and moderators alike; the app also uses this to discover its own
// role (a 403 here means "hide the admin area entirely").
func (a *API) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdminOrModerator(w, r); !ok {
		return
	}

	accounts, err := store.ListAccounts(a.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	resp := make([]adminAccountResponse, 0, len(accounts))
	for _, acc := range accounts {
		resp = append(resp, adminAccountResponseFrom(acc))
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSetAccountRole grants or revokes admin/moderator status. Admin
// only, per the confirmed permission model: moderators can never touch
// roles, so privilege escalation stays admin-only.
func (a *API) handleSetAccountRole(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdmin(w, r); !ok {
		return
	}
	id := r.PathValue("id")

	var req setAccountRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	role, ok := store.ParseRole(req.Role)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_role", "role must be one of user, moderator, admin")
		return
	}

	target, err := store.GetAccount(a.DB, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown account")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	if role != store.RoleAdmin {
		blocked, err := a.wouldRemoveLastActiveAdmin(target)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		if blocked {
			writeError(w, http.StatusConflict, "last_admin", "cannot demote the server's only remaining admin")
			return
		}
	}

	if err := store.SetAccountRole(a.DB, id, role); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

// handleBlockAccount temporarily disables an account -- internal/auth's
// Middleware rejects every request from a disabled account. Admin only.
func (a *API) handleBlockAccount(w http.ResponseWriter, r *http.Request) {
	a.setAccountStatus(w, r, store.AccountStatusDisabled)
}

// handleUnblockAccount restores a previously blocked account. Admin only.
func (a *API) handleUnblockAccount(w http.ResponseWriter, r *http.Request) {
	a.setAccountStatus(w, r, store.AccountStatusActive)
}

func (a *API) setAccountStatus(w http.ResponseWriter, r *http.Request, status string) {
	if _, ok := requireAdmin(w, r); !ok {
		return
	}
	id := r.PathValue("id")

	target, err := store.GetAccount(a.DB, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown account")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	if status != store.AccountStatusActive {
		blocked, err := a.wouldRemoveLastActiveAdmin(target)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		if blocked {
			writeError(w, http.StatusConflict, "last_admin", "cannot block the server's only remaining admin")
			return
		}
	}

	if err := store.SetAccountStatus(a.DB, id, status); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

// handleDeleteAccount permanently removes an account (cascading through
// its devices to their prekeys/queued messages, and through invite_codes
// per migrations/0005). Admin only.
func (a *API) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdmin(w, r); !ok {
		return
	}
	id := r.PathValue("id")

	target, err := store.GetAccount(a.DB, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown account")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	blocked, err := a.wouldRemoveLastActiveAdmin(target)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if blocked {
		writeError(w, http.StatusConflict, "last_admin", "cannot delete the server's only remaining admin")
		return
	}

	if err := store.DeleteAccount(a.DB, id); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

// handleGetRegistrationPolicy returns the current registration policy.
// Available to admins and moderators (read-only for the latter).
func (a *API) handleGetRegistrationPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdminOrModerator(w, r); !ok {
		return
	}
	policy, err := store.GetRegistrationPolicy(a.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, registrationPolicyResponse{Policy: policy})
}

// handleSetRegistrationPolicy changes the registration policy at runtime
// (persisted -- survives a restart). Admin only.
func (a *API) handleSetRegistrationPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdmin(w, r); !ok {
		return
	}

	var req setRegistrationPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	switch config.RegistrationPolicy(req.Policy) {
	case config.PolicyOpen, config.PolicyInvite, config.PolicyClosed:
	default:
		writeError(w, http.StatusBadRequest, "invalid_policy", "policy must be one of open, invite, closed")
		return
	}

	if err := store.SetRegistrationPolicy(a.DB, req.Policy); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, registrationPolicyResponse{Policy: req.Policy})
}
