package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
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
// signed prekey, and a batch of one-time prekeys -- appended to its pool by
// default, or replacing it outright when ReplaceOneTimePrekeys asks for that
// (see uploadPrekeysRequest).
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

	if req.ReplaceOneTimePrekeys {
		if err := store.DeleteOneTimePrekeys(a.DB, deviceID); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
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

// bundleClaimant is who asked for a prekey bundle, as far as this server could
// establish it. Only [bundleClaimant.Identified] gates anything: the claim
// itself is answered for anyone, since a bundle is public key material by
// design, but a one-time prekey is a consumable and goes only to a caller that
// can be held responsible for consuming it (SRV-04).
type bundleClaimant struct {
	// AccountID is empty for an anonymous claimant. Not used for any decision
	// today -- kept because it is what a per-claimant rate limit would need,
	// and because logging "who drained this pool" is the first thing anyone
	// will want if it ever happens again.
	AccountID  string
	Identified bool
}

// authenticateBundleClaimant establishes who is claiming a prekey bundle,
// accepting either form of credential the protocol has and treating their
// absence as a legitimate anonymous request.
//
//   - A body carrying a federated sender claim: verified inline against the
//     caller's own root key (§9's self-describing-key form, exactly as the
//     federated message and blob routes do). This is the only form available to
//     a sender whose account lives on another server, and it is refused
//     outright when this server has federation switched off -- accepting the
//     credentials of a server we won't talk to would be an odd exception.
//   - Signature headers with no such body: an ordinary §3 device signature from
//     a device registered here.
//   - Neither: anonymous, ok=true, Identified=false.
//
// Credentials that are present but do not verify are always refused -- never
// downgraded to anonymous, which would turn a client bug or a clock skew into a
// silent loss of forward secrecy that nobody would notice for months. Writes
// the error response and returns ok=false in that case.
func (a *API) authenticateBundleClaimant(w http.ResponseWriter, r *http.Request) (bundleClaimant, bool) {
	body, ok := readBody(w, r)
	if !ok {
		return bundleClaimant{}, false
	}
	// Restored for auth.TryAuthenticate below, which reads the body to rebuild
	// the canonical string.
	r.Body = io.NopCloser(bytes.NewReader(body))

	if len(bytes.TrimSpace(body)) > 0 {
		var req claimPrekeyBundleRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
			return bundleClaimant{}, false
		}
		if req.SenderAccountID != "" || req.SenderRootPubKey != "" || req.SenderDeviceCert.DeviceID != "" {
			enabled, err := store.GetFederationEnabled(a.DB)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "internal", "internal server error")
				return bundleClaimant{}, false
			}
			if !enabled {
				writeError(w, http.StatusNotFound, "federation_disabled", "federation is disabled on this server")
				return bundleClaimant{}, false
			}
			sender, ok := a.verifyFederatedSender(w, r, federatedSenderClaim{
				AccountID:   req.SenderAccountID,
				RootPubKey:  req.SenderRootPubKey,
				DeviceCert:  req.SenderDeviceCert,
				RequestBody: body,
			})
			if !ok {
				return bundleClaimant{}, false
			}
			return bundleClaimant{AccountID: sender.AccountID, Identified: true}, true
		}
	}

	if !auth.HasSignatureHeaders(r) {
		return bundleClaimant{}, true // anonymous, and allowed to be
	}
	identity, err := a.Auth.TryAuthenticate(r)
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("prekey bundle claim authentication failed", "error", err, "path", r.URL.Path)
		}
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return bundleClaimant{}, false
	}
	return bundleClaimant{AccountID: identity.AccountID, Identified: true}, true
}

// handleClaimPrekeyBundle atomically hands out a device's current X3DH
// bundle for an initiator to start a session. The public key material is
// served to anyone -- no trust in the server is required, only in the
// signature chain the caller verifies independently (device_pubkey from
// GET /v1/accounts/{id}) -- but the one-time prekey it would normally include
// goes only to a claimant this server could identify (SRV-04, see
// authenticateBundleClaimant).
func (a *API) handleClaimPrekeyBundle(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("device_id")

	claimant, ok := a.authenticateBundleClaimant(w, r)
	if !ok {
		return
	}

	// The three 404s carry distinct codes on purpose: a claimant holding a
	// cached device id needs to tell "this id is dead, re-resolve the peer's
	// device list" (unknown_device / no_prekey_bundle) apart from "this whole
	// server won't talk to me" (federation_disabled, above) — see
	// docs/PROTOCOL.md §4's stale-device rule.
	device, err := store.GetDevice(a.DB, deviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "unknown_device", "unknown device")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	if device.Status != store.DeviceStatusActive || device.DHIdentityPubKey == nil {
		writeError(w, http.StatusNotFound, "no_prekey_bundle", "device has no prekey bundle available")
		return
	}

	spk, err := store.GetSignedPrekey(a.DB, deviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no_prekey_bundle", "device has no prekey bundle available")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}

	// The heart of SRV-04. A one-time prekey is a consumable, and an anonymous
	// caller could drain a device's whole pool by asking repeatedly -- costing
	// that device forward secrecy on the first message of every session until
	// it next tops up. So the pool is only opened to a caller this server could
	// identify; everyone else gets the bundle without one, which is a shape
	// every client already handles (an empty pool produces it too, see
	// docs/PROTOCOL.md §5). Nothing about confidentiality changes either way.
	var claimed *store.ClaimedOneTimePrekey
	if claimant.Identified {
		claimed, err = store.ClaimOneTimePrekey(a.DB, deviceID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
	}

	// A device with a live SSE connection re-checks its own pool on every
	// reconnect anyway (see AppSession's SSE onConnected hook), so only a
	// device with no open connection right now needs an active nudge --
	// otherwise it might not open the app again for a long time. Only
	// wake if a key was actually claimed just now: an already-empty pool
	// has nothing new to warn about, so this can't fire on every repeat
	// call once drained. Since an anonymous claimant never claims a key
	// (above), this also stops being a way for anyone to make this server
	// send push wakes to an arbitrary device on demand.
	if claimed != nil && !a.broker.hasResponsiveSubscriber(deviceID) {
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
	} else {
		// Says *why* there is no one-time prekey. Without this the two reasons
		// are indistinguishable, and "your request wasn't authenticated" is
		// something a client should be able to notice and log rather than
		// silently accept as a drained pool.
		if claimant.Identified {
			resp.OneTimePrekeyOmitted = oneTimePrekeyOmittedPoolEmpty
		} else {
			resp.OneTimePrekeyOmitted = oneTimePrekeyOmittedUnauthenticated
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
