package api

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/config"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/devicecert"
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

	policy, err := store.GetRegistrationPolicy(a.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	switch config.RegistrationPolicy(policy) {
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
		Role:          store.RoleUser,
		CreatedAt:     now,
	}); err != nil {
		if errors.Is(err, store.ErrIDPrefixConflict) {
			writeError(w, http.StatusConflict, "id_prefix_taken",
				"this server already has an account whose id starts the same way -- generate a new identity and try again")
			return
		}
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

	if config.RegistrationPolicy(policy) == config.PolicyInvite {
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
// verify them (self-certifying address, per docs/PROTOCOL.md). Also
// accepts the shorter, unchecksummed PrefixLength form (docs/PROTOCOL.md's
// id-prefix uniqueness note) as an alias for the full id -- either way,
// the response's own "id" field is always the true full id, which is what
// the caller must actually use and verify against the returned root key.
func (a *API) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	stripped := address.StripSeparators(r.PathValue("id"))

	var acc *store.Account
	var err error
	switch len(stripped) {
	case address.PrefixLength:
		if !address.ValidCharset(stripped) {
			writeError(w, http.StatusBadRequest, "invalid_request", "malformed account id")
			return
		}
		acc, err = store.GetAccountByPrefix(a.DB, stripped)
	default:
		var normalized string
		normalized, err = address.Normalize(r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "malformed account id")
			return
		}
		acc, err = store.GetAccount(a.DB, normalized)
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown account")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	devices, err := store.ListDevicesByAccount(a.DB, acc.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, accountResponseFrom(acc, devices))
}

// handleDeleteOwnAccount permanently deletes the caller's own account --
// the self-service counterpart to handleDeleteAccount (admin.go), which
// targets a *different* account and requires admin privileges. The
// target here is never taken from the path/body verbatim: it's always
// identity.AccountID, already cryptographically established by
// internal/auth.Middleware from the request's signature -- the path id
// is checked against it (mirroring handleAddDevice/handleRevokeDevice's
// "signing device does not belong to this account" pattern) purely as
// defense in depth, not as the actual authorization source. This makes
// deleting a different account structurally impossible, not just
// policy-forbidden.
func (a *API) handleDeleteOwnAccount(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	id := r.PathValue("id")
	if id != identity.AccountID {
		writeError(w, http.StatusForbidden, "forbidden", "signing device does not belong to this account")
		return
	}

	target, err := store.GetAccount(a.DB, identity.AccountID)
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

	if err := store.DeleteAccount(a.DB, identity.AccountID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}
