// Admin surface for the federation blocklist -- see federation.go and
// docs/PROTOCOL.md's federation section. Same permission shape as the
// existing account block/unblock endpoints in admin.go: viewing is
// available to admins and moderators, changing it is admin-only.
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/behringer24/freizone-server/internal/store"
)

// handleListFederationBlocklist returns every account currently blocked
// from federating in. Admins and moderators alike.
func (a *API) handleListFederationBlocklist(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdminOrModerator(w, r); !ok {
		return
	}

	entries, err := store.ListFederationBlocklist(a.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	resp := make([]federationBlockEntryResponse, 0, len(entries))
	for _, e := range entries {
		resp = append(resp, federationBlockEntryResponseFrom(e))
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleBlockFederationSender blocks a remote account id from delivering
// federated messages here. Admin only.
func (a *API) handleBlockFederationSender(w http.ResponseWriter, r *http.Request) {
	identity, ok := requireAdmin(w, r)
	if !ok {
		return
	}

	var req blockFederationSenderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if req.AccountID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "account_id is required")
		return
	}

	if err := store.BlockFederationSender(a.DB, req.AccountID, identity.AccountID, req.Reason, a.Now()); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

// handleUnblockFederationSender removes a previously blocked account id
// from the federation blocklist. Admin only.
func (a *API) handleUnblockFederationSender(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireAdmin(w, r); !ok {
		return
	}
	accountID := r.PathValue("account_id")

	if err := store.UnblockFederationSender(a.DB, accountID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "account is not blocked")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}
