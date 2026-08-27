package api

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
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

	// Scope the revocation to the caller's own account (== req.AccountID,
	// checked above). Device ids are public, so a device-id-only revocation
	// would let any account revoke another account's devices; binding it to
	// the authenticated identity is what keeps "a request signed by account A
	// can never act on account B" true here too.
	if err := store.RevokeDevice(a.DB, identity.AccountID, req.DeviceID, revokedAt); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown or already-revoked device")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// handleSetPushEndpoint registers (or, with all fields nil/omitted,
// clears) the calling device's push subscription -- see docs/PROTOCOL.md's
// push section. Only a device can manage its own subscription.
//
// The server later makes outbound requests to whatever endpoint URL is
// registered here, which is an SSRF surface (a malicious device could
// point it at an internal address). Two layers guard it: this handler
// requires an https URL, and the client that actually sends the wake
// (newUnifiedPushClient, see pushclient.go) refuses redirects and refuses
// to connect to any resolved loopback/link-local/private/ULA/unspecified/
// multicast address -- so neither a direct internal endpoint nor a public
// endpoint that 302-redirects to one gets through (security audit M1).
func (a *API) handleSetPushEndpoint(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	deviceID := r.PathValue("device_id")
	if identity.DeviceID != deviceID {
		writeError(w, http.StatusForbidden, "forbidden", "can only set the push subscription for your own device")
		return
	}

	var req setPushEndpointRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}

	allNil := req.Endpoint == nil && req.P256dh == nil && req.Auth == nil
	allSet := req.Endpoint != nil && req.P256dh != nil && req.Auth != nil
	if !allNil && !allSet {
		writeError(w, http.StatusBadRequest, "invalid_request", "endpoint, p256dh, and auth must be given together or not at all")
		return
	}

	var sub *store.PushSubscription
	if allSet {
		parsed, err := url.Parse(*req.Endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "endpoint must be an https:// URL")
			return
		}
		if *req.P256dh == "" || *req.Auth == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "p256dh and auth must not be empty")
			return
		}
		sub = &store.PushSubscription{Endpoint: *req.Endpoint, P256dh: *req.P256dh, Auth: *req.Auth}
	}

	if err := store.SetDevicePushSubscription(a.DB, deviceID, sub); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown device")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleSetPushTarget registers (or, with both fields nil/omitted,
// clears) the calling device's FCM/APNs push target -- the counterpart
// to handleSetPushEndpoint for devices delivered through a
// freizone-gateway instead of UnifiedPush. Only a device can manage its
// own target. Setting one clears the other (see
// store.SetDevicePushTarget) -- a device uses exactly one wake mechanism
// at a time.
func (a *API) handleSetPushTarget(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	deviceID := r.PathValue("device_id")
	if identity.DeviceID != deviceID {
		writeError(w, http.StatusForbidden, "forbidden", "can only set the push target for your own device")
		return
	}

	var req setPushTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}

	allNil := req.Platform == nil && req.Token == nil
	allSet := req.Platform != nil && req.Token != nil
	if !allNil && !allSet {
		writeError(w, http.StatusBadRequest, "invalid_request", "platform and token must be given together or not at all")
		return
	}

	var target *store.PushTarget
	if allSet {
		if *req.Platform != store.PushPlatformFCM && *req.Platform != store.PushPlatformAPNS {
			writeError(w, http.StatusBadRequest, "invalid_request", "platform must be one of: fcm, apns")
			return
		}
		if *req.Token == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "token must not be empty")
			return
		}
		target = &store.PushTarget{Platform: *req.Platform, Token: *req.Token}
	}

	if err := store.SetDevicePushTarget(a.DB, deviceID, target); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown device")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
