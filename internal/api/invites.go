package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/store"
)

// handleCreateInvite issues a single-use invite code, for an admin or
// moderator to hand out (e.g. rendered as a QR code by the app) when the
// registration policy is "invite".
func (a *API) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok || (identity.Role != store.RoleAdmin && identity.Role != store.RoleModerator) {
		writeError(w, http.StatusForbidden, "forbidden", "admin or moderator privileges required")
		return
	}

	var req createInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}

	now := a.Now()

	// An explicit expires_at wins; otherwise the operator's configured
	// default applies. Leaving a code valid forever is what would make
	// guessing one worth attempting, so "no expiry" is only reachable by
	// setting FREIZONE_INVITE_EXPIRY_DAYS=0 deliberately.
	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid expires_at")
			return
		}
		expiresAt = &t
	} else if a.Config.InviteExpiryDays > 0 {
		t := now.AddDate(0, 0, a.Config.InviteExpiryDays)
		expiresAt = &t
	}

	code, err := store.CreateInviteCode(a.DB, identity.AccountID, expiresAt, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	resp := createInviteResponse{Code: code}
	if expiresAt != nil {
		s := expiresAt.UTC().Format(time.RFC3339)
		resp.ExpiresAt = &s
	}
	writeJSON(w, http.StatusCreated, resp)
}
