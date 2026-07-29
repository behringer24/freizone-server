package api

import (
	"net/http"

	"github.com/behringer24/freizone-server/internal/store"
)

// handleGetServerStatus is a public discovery endpoint a client can call
// with only a server address, before it has any identity or credentials,
// to decide which setup path applies: bootstrap (no admin claimed yet),
// self-register (open policy), invite-code registration, or "registration
// is closed, ask the admin for an invite". Neither field is sensitive --
// claimed just means "an admin exists", and the registration policy has
// to be knowable before someone can register at all.
func (a *API) handleGetServerStatus(w http.ResponseWriter, r *http.Request) {
	claimed, err := store.SetupTokenClaimed(a.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	policy, err := store.GetRegistrationPolicy(a.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	federationEnabled, err := store.GetFederationEnabled(a.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	// Advertised so a sender can size (or recompress) an attachment before
	// uploading, instead of discovering a foreign server's limit by getting
	// a 413 after pushing the whole thing -- the recipient's server is the
	// one that stores blobs, and its limits are not the sender's to guess.
	writeJSON(w, http.StatusOK, serverStatusResponse{
		Claimed:            claimed,
		RegistrationPolicy: policy,
		FederationEnabled:  federationEnabled,
		BlobsEnabled:       a.Config.BlobsEnabled,
		MaxBlobBytes:       a.Config.MaxBlobBytes,
	})
}
