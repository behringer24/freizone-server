package api

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/address"
	"github.com/behringer24/freizone-server/internal/devicecert"
	"github.com/behringer24/freizone-server/internal/store"
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

	exists, err := store.AnyAdminExists(tx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if exists {
		writeError(w, http.StatusConflict, "admin_exists", "an admin account already exists")
		return
	}

	now := a.Now()
	if err := store.CreateAccount(tx, store.Account{
		ID:            accountID,
		RootPubKey:    rootPub,
		VersionMarker: address.CurrentVersion,
		Status:        store.AccountStatusActive,
		IsAdmin:       true,
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

	acc := &store.Account{ID: accountID, RootPubKey: rootPub, IsAdmin: true, CreatedAt: now}
	writeJSON(w, http.StatusCreated, accountResponseFrom(acc, []store.Device{device}))
}
