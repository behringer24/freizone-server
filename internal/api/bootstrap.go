package api

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/devicecert"
)

// handleBootstrapClaim claims the first admin account using the one-time
// setup token printed to the server log on first boot.
func (a *API) handleBootstrapClaim(w http.ResponseWriter, r *http.Request) {
	var req bootstrapClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}

	rootPub, err := decodeBase64Key(req.RootPubKey, ed25519.PublicKeySize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid root_pubkey: "+err.Error())
		return
	}
	devicePub, err := decodeBase64Key(req.DevicePubKey, ed25519.PublicKeySize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid device_pubkey: "+err.Error())
		return
	}
	issuedAt, err := time.Parse(time.RFC3339, req.DeviceCertIssuedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid device_cert_issued_at")
		return
	}
	sig, err := decodeBase64Key(req.DeviceCertSignature, ed25519.SignatureSize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid device_cert_signature")
		return
	}

	accountID, err := address.DeriveID(rootPub)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid root_pubkey")
		return
	}

	cert := &devicecert.DeviceCertificate{
		AccountID:    accountID,
		DeviceID:     req.DeviceID,
		DevicePubKey: devicePub,
		IssuedAt:     issuedAt,
		Signature:    sig,
	}
	if err := cert.Verify(rootPub); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_certificate", "device certificate signature is invalid")
		return
	}

	tx, err := a.DB.Begin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	// No "an admin already exists" pre-check here: ClaimSetupToken's own
	// used_at IS NULL reuse-protection already blocks re-claiming with a
	// spent token, and a fresh token (via --reset-admin/--reset-setup-token)
	// is deliberately allowed to claim an additional or replacement admin
	// -- that's the recovery path for a lost admin device/key.
	now := a.Now()
	if err := store.CreateAccount(tx, store.Account{
		ID:            accountID,
		RootPubKey:    rootPub,
		VersionMarker: address.CurrentVersion,
		Status:        store.AccountStatusActive,
		Role:          store.RoleAdmin,
		CreatedAt:     now,
	}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "account_exists", "account already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	device := store.Device{
		DeviceID:      req.DeviceID,
		AccountID:     accountID,
		DevicePubKey:  devicePub,
		CertIssuedAt:  issuedAt,
		CertSignature: sig,
		Status:        store.DeviceStatusActive,
		CreatedAt:     now,
	}
	if err := store.CreateDevice(tx, device); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "device_exists", "device already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	if err := store.ClaimSetupToken(tx, req.SetupToken, accountID, now); err != nil {
		if errors.Is(err, store.ErrInvalidToken) {
			// tx must be rolled back -- and released -- before recording
			// against a.DB below: both hold a write lock on the same
			// SQLite database, so recording while tx is still open would
			// just block until busy_timeout, then fail silently. Rolling
			// back here (rather than relying on the deferred Rollback,
			// which becomes a safe no-op after this) is what makes the
			// failed-attempt count survive tx's rollback instead of
			// racing it -- that count is what keeps a short token safe
			// against online guessing on this rate-limit-free endpoint.
			if rbErr := tx.Rollback(); rbErr != nil && a.Logger != nil {
				a.Logger.Error("rolling back failed bootstrap claim", "error", rbErr)
			}
			if recErr := store.RecordFailedSetupTokenAttempt(a.DB); recErr != nil && a.Logger != nil {
				a.Logger.Error("recording failed setup token attempt", "error", recErr)
			}
			if a.Logger != nil {
				a.Logger.Warn("bootstrap claim rejected: invalid, already-used, or locked-out setup token")
			}
			writeError(w, http.StatusUnauthorized, "invalid_token", "invalid or already-used setup token")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	acc := &store.Account{ID: accountID, RootPubKey: rootPub, Role: store.RoleAdmin, CreatedAt: now}
	writeJSON(w, http.StatusCreated, accountResponseFrom(acc, []store.Device{device}))
}
