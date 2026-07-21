package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/devicecert"
)

// x25519PubKeySize is the byte length of an X25519 public key.
const x25519PubKeySize = 32

// handleUploadPrekeys uploads/replaces a device's X3DH key material: its
// long-term DH identity key (on first upload, or to rotate), its current
// signed prekey, and a batch of one-time prekeys to append to its pool.
func (a *API) handleUploadPrekeys(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	deviceID := r.PathValue("device_id")
	if identity.DeviceID != deviceID {
		writeError(w, http.StatusForbidden, "forbidden", "can only upload prekeys for your own device")
		return
	}

	var req uploadPrekeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}

	device, err := store.GetDevice(a.DB, deviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown device")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	now := a.Now()
	dhIdentityPubKey := device.DHIdentityPubKey

	if req.DHIdentityCert != nil {
		dhPub, err := decodeBase64Key(req.DHIdentityCert.DHPubKey, x25519PubKeySize)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid dh_pubkey: "+err.Error())
			return
		}
		issuedAt, err := time.Parse(time.RFC3339, req.DHIdentityCert.IssuedAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid dh_identity_cert.issued_at")
			return
		}
		sig, err := decodeBase64Key(req.DHIdentityCert.Signature, ed25519.SignatureSize)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid dh_identity_cert.signature")
			return
		}

		cert := &devicecert.DHIdentityCertificate{
			AccountID: identity.AccountID,
			DeviceID:  deviceID,
			DHPubKey:  dhPub,
			IssuedAt:  issuedAt,
			Signature: sig,
		}
		if err := cert.Verify(device.DevicePubKey); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_certificate", "dh identity certificate signature is invalid")
			return
		}

		if err := store.UpsertDHIdentity(a.DB, deviceID, dhPub, sig, issuedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		dhIdentityPubKey = dhPub
	}

	if dhIdentityPubKey == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "no dh identity key on file; include dh_identity_cert on first upload")
		return
	}

	spkPub, err := decodeBase64Key(req.SignedPrekey.PubKey, x25519PubKeySize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid signed_prekey.pubkey: "+err.Error())
		return
	}
	spkDHIdentityPub, err := decodeBase64Key(req.SignedPrekey.DHIdentityPubKey, x25519PubKeySize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid signed_prekey.dh_identity_pubkey: "+err.Error())
		return
	}
	if !bytes.Equal(spkDHIdentityPub, dhIdentityPubKey) {
		writeError(w, http.StatusBadRequest, "invalid_request", "signed_prekey.dh_identity_pubkey does not match this device's dh identity key")
		return
	}
	spkIssuedAt, err := time.Parse(time.RFC3339, req.SignedPrekey.IssuedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid signed_prekey.issued_at")
		return
	}
	spkSig, err := decodeBase64Key(req.SignedPrekey.Signature, ed25519.SignatureSize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid signed_prekey.signature")
		return
	}

	spkCert := &devicecert.SignedPrekeyCertificate{
		AccountID:        identity.AccountID,
		DeviceID:         deviceID,
		KeyID:            req.SignedPrekey.KeyID,
		DHIdentityPubKey: spkDHIdentityPub,
		PrekeyPubKey:     spkPub,
		IssuedAt:         spkIssuedAt,
		Signature:        spkSig,
	}
	if err := spkCert.Verify(device.DevicePubKey); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_certificate", "signed prekey certificate signature is invalid")
		return
	}

	if err := store.UpsertSignedPrekey(a.DB, store.SignedPrekey{
		DeviceID:  deviceID,
		KeyID:     req.SignedPrekey.KeyID,
		PubKey:    spkPub,
		Signature: spkSig,
		IssuedAt:  spkIssuedAt,
		CreatedAt: now,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	if len(req.OneTimePrekeys) > 0 {
		inputs := make([]store.OneTimePrekeyInput, 0, len(req.OneTimePrekeys))
		for _, k := range req.OneTimePrekeys {
			pub, err := decodeBase64Key(k.PubKey, x25519PubKeySize)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_request", "invalid one_time_prekeys entry: "+err.Error())
				return
			}
			inputs = append(inputs, store.OneTimePrekeyInput{KeyID: k.KeyID, PubKey: pub})
		}
		if err := store.AddOneTimePrekeys(a.DB, deviceID, inputs, now); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleGetPrekeyStatus reports how many unclaimed one-time prekeys a
// device has left, so it can decide whether to top up -- a non-destructive
// counterpart to handleClaimPrekeyBundle, which consumes one.
func (a *API) handleGetPrekeyStatus(w http.ResponseWriter, r *http.Request) {
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	deviceID := r.PathValue("device_id")
	if identity.DeviceID != deviceID {
		writeError(w, http.StatusForbidden, "forbidden", "can only check your own device's prekey status")
		return
	}

	remaining, err := store.CountOneTimePrekeys(a.DB, deviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, prekeyStatusResponse{OneTimePrekeysRemaining: remaining})
}

// lowOneTimePrekeyThreshold is the remaining-pool size below which
// handleClaimPrekeyBundle proactively wakes the device (see there) --
// chosen well below the client's default upload batch of 10
// (app_session.dart's _oneTimePrekeyBatch) so a wake fires with enough
// runway left to actually replenish before the pool hits zero.
const lowOneTimePrekeyThreshold = 3

// handleClaimPrekeyBundle atomically hands out a device's current X3DH
// bundle -- including one one-time prekey, if the pool isn't empty -- for
// an initiator to start a session. Public, like the account directory: no
// trust in the server is required, only in the signature chain the caller
// verifies independently (device_pubkey from GET /v1/accounts/{id}).
func (a *API) handleClaimPrekeyBundle(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("device_id")

	device, err := store.GetDevice(a.DB, deviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "unknown device")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if device.Status != store.DeviceStatusActive || device.DHIdentityPubKey == nil {
		writeError(w, http.StatusNotFound, "not_found", "device has no prekey bundle available")
		return
	}

	spk, err := store.GetSignedPrekey(a.DB, deviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "device has no prekey bundle available")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	claimed, err := store.ClaimOneTimePrekey(a.DB, deviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	// A device with a live SSE connection re-checks its own pool on every
	// reconnect anyway (see AppSession's SSE onConnected hook), so only a
	// device with no open connection right now needs an active nudge --
	// otherwise it might not open the app again for a long time. Only
	// wake if a key was actually claimed just now: an already-empty pool
	// has nothing new to warn about, so this can't fire on every repeat
	// call once drained.
	if claimed != nil && !a.broker.hasSubscribers(deviceID) {
		if remaining, err := store.CountOneTimePrekeys(a.DB, deviceID); err == nil && remaining < lowOneTimePrekeyThreshold {
			a.wakeDevice(device)
		}
	}

	resp := prekeyBundleResponse{
		DeviceID:         deviceID,
		DHIdentityPubKey: base64.StdEncoding.EncodeToString(device.DHIdentityPubKey),
		DHIdentityCert: dhIdentityCertDTO{
			DHPubKey:  base64.StdEncoding.EncodeToString(device.DHIdentityPubKey),
			IssuedAt:  device.DHIdentityIssuedAt.UTC().Format(time.RFC3339),
			Signature: base64.StdEncoding.EncodeToString(device.DHIdentitySignature),
		},
		SignedPrekey: signedPrekeyDTO{
			KeyID:            spk.KeyID,
			DHIdentityPubKey: base64.StdEncoding.EncodeToString(device.DHIdentityPubKey),
			PubKey:           base64.StdEncoding.EncodeToString(spk.PubKey),
			IssuedAt:         spk.IssuedAt.UTC().Format(time.RFC3339),
			Signature:        base64.StdEncoding.EncodeToString(spk.Signature),
		},
	}
	if claimed != nil {
		resp.OneTimePrekey = &oneTimePrekeyDTO{
			KeyID:  claimed.KeyID,
			PubKey: base64.StdEncoding.EncodeToString(claimed.PubKey),
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
