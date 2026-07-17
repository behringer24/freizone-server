package api

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/address"
	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/devicecert"
	"github.com/behringer24/freizone-server/internal/store"
)

// handleRegisterAccount creates a new (non-admin) account, subject to the
// server's registration policy.
func (a *API) handleRegisterAccount(w http.ResponseWriter, r *http.Request) {
	var req registerAccountRequest
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

	switch a.Config.RegistrationPolicy {
	case config.PolicyClosed:
		writeError(w, http.StatusForbidden, "registration_closed", "registration is closed on this server")
		return
	case config.PolicyInvite:
		if req.InviteCode == nil || *req.InviteCode == "" {
			writeError(w, http.StatusForbidden, "invite_required", "an invite code is required to register")
			return
		}
	}

	now := a.Now()
	tx, err := a.DB.Begin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	if err := store.CreateAccount(tx, store.Account{
		ID:            accountID,
		RootPubKey:    rootPub,
		VersionMarker: address.CurrentVersion,
		Status:        store.AccountStatusActive,
		IsAdmin:       false,
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

	if a.Config.RegistrationPolicy == config.PolicyInvite {
		if err := store.ConsumeInviteCode(tx, *req.InviteCode, accountID, now); err != nil {
			switch {
			case errors.Is(err, store.ErrNotFound):
				writeError(w, http.StatusNotFound, "invite_not_found", "unknown invite code")
			case errors.Is(err, store.ErrInviteExpired):
				writeError(w, http.StatusGone, "invite_expired", "invite code has expired")
			case errors.Is(err, store.ErrInviteAlreadyUsed):
				writeError(w, http.StatusGone, "invite_used", "invite code has already been used")
			default:
				writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			}
			return
		}
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	acc := &store.Account{ID: accountID, RootPubKey: rootPub, CreatedAt: now}
	writeJSON(w, http.StatusCreated, accountResponseFrom(acc, []store.Device{device}))
}

// handleGetAccount is the public key directory: anyone can look up an
// account's root public key and device certificates, to independently
// verify them (self-certifying address, per docs/PROTOCOL.md).
func (a *API) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	id, err := address.Normalize(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed account id")
		return
	}

	acc, err := store.GetAccount(a.DB, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown account")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	devices, err := store.ListDevicesByAccount(a.DB, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, accountResponseFrom(acc, devices))
}
