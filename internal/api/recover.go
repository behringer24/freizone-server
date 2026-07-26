// Account recovery: attaching a fresh device to an EXISTING account after
// total device loss, authenticated by the account's root key. See SRV-06 in
// docs/ROADMAP.md and its client companion APP-01 (recovery seed phrase).
package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// handleRecoverAccount attaches a new device to an existing account and, in
// the same step, revokes every previously-active device. It exists because
// neither of the normal paths works after losing every device: POST
// /v1/devices needs an already-active device's signature, and POST
// /v1/accounts rejects an existing account (409 account_exists). Since
// account_id == hash(root_pubkey), restoring the root key from a seed phrase
// (APP-01) restores the same account, and this endpoint lets that restored
// key mint a fresh device without any surviving device.
//
// Registered as a public route (see router.go) because, like
// handleReceiveFederatedMessage, it performs its own inline authentication
// rather than internal/auth.Middleware's local-device lookup -- here the
// request is signed by the account's ROOT key (the account's ultimate
// authority, which already signs every device cert and revocation), not by a
// device key. Signature-Key-Id must be the base64 root public key, the same
// self-describing-key convention federation uses; the whole request body
// (the new device cert) is covered by that root signature, and a fresh
// timestamp+nonce make it replay-proof.
func (a *API) handleRecoverAccount(w http.ResponseWriter, r *http.Request) {
	id, err := address.Normalize(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed account id")
		return
	}
	account, err := store.GetAccount(a.DB, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Account existence is already public via GET /v1/accounts/{id},
			// so a 404 here leaks nothing new -- and we need the account's
			// root key to verify the signature at all.
			writeError(w, http.StatusNotFound, "not_found", "unknown account")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req recoverAccountRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if req.DeviceID == "" || req.DevicePubKey == "" || req.DeviceCertIssuedAt == "" || req.DeviceCertSignature == "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"device_id, device_pubkey, device_cert_issued_at, and device_cert_signature are required")
		return
	}

	// --- Authenticate the request with the account's ROOT key ---------------
	if !a.verifyRootSignature(r, body, account) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return
	}

	// Status is checked only AFTER authentication, so an unauthenticated
	// caller can't use this endpoint as an oracle for whether an account is
	// active vs. blocked (only the account's own root-key holder gets here).
	// Recovery must not resurrect a blocked or otherwise inactive account.
	if account.Status != store.AccountStatusActive {
		writeError(w, http.StatusForbidden, "forbidden", "account is not active")
		return
	}

	// --- Verify the new device certificate under the root key ---------------
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
	certSig, err := decodeBase64Key(req.DeviceCertSignature, ed25519.SignatureSize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid device_cert_signature")
		return
	}
	cert := &devicecert.DeviceCertificate{
		AccountID:    account.ID,
		DeviceID:     req.DeviceID,
		DevicePubKey: devicePub,
		IssuedAt:     issuedAt,
		Signature:    certSig,
	}
	if err := cert.Verify(account.RootPubKey); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_certificate", "device certificate signature is invalid")
		return
	}

	// --- Add the new device and revoke every previously-active one ----------
	now := a.Now()
	tx, err := a.DB.Begin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	existing, err := store.ListDevicesByAccount(tx, account.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	newDevice := store.Device{
		DeviceID:      req.DeviceID,
		AccountID:     account.ID,
		DevicePubKey:  devicePub,
		CertIssuedAt:  issuedAt,
		CertSignature: certSig,
		Status:        store.DeviceStatusActive,
		CreatedAt:     now,
	}
	if err := store.CreateDevice(tx, newDevice); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "device_exists",
				"device already exists -- a repeat recovery must use a fresh device id")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	// Revoke-all-others: total device loss is the premise, so the old devices
	// are gone or compromised. Cutting them off in the same root-authenticated
	// step is what makes recovery safe (see SRV-06).
	for _, d := range existing {
		if d.DeviceID == req.DeviceID || d.Status != store.DeviceStatusActive {
			continue
		}
		if err := store.RevokeDevice(tx, d.DeviceID, now); err != nil && !errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	devices, err := store.ListDevicesByAccount(a.DB, account.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(w, http.StatusCreated, accountResponseFrom(account, devices))
}

// verifyRootSignature checks that r carries a valid per-request signature made
// by account's root key, with a fresh (in-skew, non-replayed) timestamp+nonce.
// Mirrors handleReceiveFederatedMessage's inline verification, but against the
// stored root public key instead of a sender-supplied device key. body is the
// already-read request body (see readBody). It reports only ok/not-ok; the
// caller emits the generic 401 so failures give no oracle.
func (a *API) verifyRootSignature(r *http.Request, body []byte, account *store.Account) bool {
	headers, err := httpsig.ParseRequestHeaders(r)
	if err != nil {
		return false
	}
	// Bind the signature to the account's actual root key: Signature-Key-Id
	// must literally be that key (self-describing-key convention).
	if headers.KeyID != base64.StdEncoding.EncodeToString(account.RootPubKey) {
		return false
	}
	ts, err := httpsig.ParseTimestamp(headers.Timestamp)
	if err != nil {
		return false
	}
	if !httpsig.WithinSkew(ts, a.Now(), auth.MaxClockSkew) {
		return false
	}
	canonical := httpsig.CanonicalStringFromRequest(r, headers, body)
	if err := httpsig.Verify(canonical, headers.Signature, account.RootPubKey); err != nil {
		return false
	}
	// expires_at = ts + MaxClockSkew, same reasoning as internal/auth's nonce
	// bookkeeping: past that point the skew check alone already rejects a
	// replay of this timestamp, so the record is safe to purge.
	nonceOK, err := store.RecordNonce(a.DB, headers.KeyID, headers.Nonce, ts, ts.Add(auth.MaxClockSkew))
	if err != nil || !nonceOK {
		return false
	}
	return true
}
