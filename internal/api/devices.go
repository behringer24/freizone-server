package api

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/devicecert"
)

// handleAddDevice adds a new device certificate to an account. The request
// must be signed by a device already active on that account; the body
// carries a new device certificate pre-signed by the account's root key.
func (a *API) handleAddDevice(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	var req addDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}

	if req.AccountID != identity.AccountID {
		writeError(w, http.StatusForbidden, "forbidden", "signing device does not belong to this account")
		return
	}

	devicePub, err := decodeBase64Key(req.DevicePubKey, ed25519.PublicKeySize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid device_pubkey: "+err.Error())
		return
	}
	issuedAt, err := time.Parse(time.RFC3339, req.IssuedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid issued_at")
		return
	}
	sig, err := decodeBase64Key(req.Signature, ed25519.SignatureSize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid signature")
		return
	}

	account, err := store.GetAccount(a.DB, req.AccountID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown account")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	cert := &devicecert.DeviceCertificate{
		AccountID:    req.AccountID,
		DeviceID:     req.DeviceID,
		DevicePubKey: devicePub,
		IssuedAt:     issuedAt,
		Signature:    sig,
	}
	if err := cert.Verify(account.RootPubKey); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_certificate", "device certificate signature is invalid")
		return
	}

	now := a.Now()
	device := store.Device{
		DeviceID:      req.DeviceID,
		AccountID:     req.AccountID,
		DevicePubKey:  devicePub,
		CertIssuedAt:  issuedAt,
		CertSignature: sig,
		Status:        store.DeviceStatusActive,
		CreatedAt:     now,
	}
	if err := store.CreateDevice(a.DB, device); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "device_exists", "device already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	writeJSON(w, http.StatusCreated, deviceResponseFrom(device))
}

// handleRevokeDevice revokes an existing device. The request must be signed
// by a device already active on the account; the body carries a
// root-key-signed revocation record.
func (a *API) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	pathDeviceID := r.PathValue("device_id")

	var req revokeDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}

	if req.DeviceID != pathDeviceID {
		writeError(w, http.StatusBadRequest, "invalid_request", "device_id in body does not match path")
		return
	}
	if req.AccountID != identity.AccountID {
		writeError(w, http.StatusForbidden, "forbidden", "signing device does not belong to this account")
		return
	}

	revokedAt, err := time.Parse(time.RFC3339, req.RevokedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid revoked_at")
		return
	}
	sig, err := decodeBase64Key(req.Signature, ed25519.SignatureSize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid signature")
		return
	}

	account, err := store.GetAccount(a.DB, req.AccountID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown account")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	rev := &devicecert.DeviceRevocation{
		AccountID: req.AccountID,
		DeviceID:  req.DeviceID,
		RevokedAt: revokedAt,
		Signature: sig,
	}
	if err := rev.Verify(account.RootPubKey); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_revocation", "revocation signature is invalid")
		return
	}

	if err := store.RevokeDevice(a.DB, req.DeviceID, revokedAt); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown or already-revoked device")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
