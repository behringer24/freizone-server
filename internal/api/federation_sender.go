package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/address"
	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// federatedSenderClaim is the identity a cross-server caller asserts about
// itself, plus what is needed to authenticate the request carrying it.
//
// Exactly one of RequestBody / BodyDigest is used: a JSON endpoint passes
// the bytes it already read, while the blob upload -- which must not buffer
// a multi-megabyte body to authenticate it -- passes the hex digest the
// client stated in the Blob-Digest header instead. Either way the same
// canonical string gets verified.
type federatedSenderClaim struct {
	AccountID   string
	RootPubKey  string
	DeviceCert  federationDeviceCertDTO
	RequestBody []byte
	BodyDigest  string
}

// federatedSender is a caller whose self-certifying identity chain checked
// out: the account id really is the hash of the root key, the device
// certificate really is signed by that root key, and the request really is
// signed by that certified device key.
type federatedSender struct {
	AccountID    string
	DeviceID     string
	DevicePubKey ed25519.PublicKey
}

// verifyFederatedSender authenticates a caller from ANY server, writing the
// error response and returning ok=false on any failure.
//
// Unlike internal/auth.Middleware -- which resolves Signature-Key-Id against
// a locally registered device -- a foreign sender has no local row to look
// up, so its whole identity chain is verified inline from material carried
// in the request: account_id == hash(root_pubkey) (pkg/address), the device
// certificate's signature under that root key (pkg/devicecert, the same
// check handleAddDevice makes once at registration), and the request
// signature against that certified device key. Shared by the federated
// message and blob endpoints so both enforce identical rules.
func (a *API) verifyFederatedSender(w http.ResponseWriter, r *http.Request, claim federatedSenderClaim) (federatedSender, bool) {
	senderRootPub, err := decodeBase64Key(claim.RootPubKey, ed25519.PublicKeySize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid sender_root_pub_key: "+err.Error())
		return federatedSender{}, false
	}
	if valid, err := address.Verify(claim.AccountID, senderRootPub); err != nil || !valid {
		writeError(w, http.StatusBadRequest, "invalid_request", "sender_account_id does not match sender_root_pub_key")
		return federatedSender{}, false
	}

	senderDevicePub, err := decodeBase64Key(claim.DeviceCert.DevicePubKey, ed25519.PublicKeySize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid sender_device_cert.device_pub_key: "+err.Error())
		return federatedSender{}, false
	}
	certIssuedAt, err := time.Parse(time.RFC3339, claim.DeviceCert.IssuedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid sender_device_cert.issued_at")
		return federatedSender{}, false
	}
	certSig, err := decodeBase64Key(claim.DeviceCert.Signature, ed25519.SignatureSize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid sender_device_cert.signature")
		return federatedSender{}, false
	}
	cert := &devicecert.DeviceCertificate{
		AccountID:    claim.AccountID,
		DeviceID:     claim.DeviceCert.DeviceID,
		DevicePubKey: senderDevicePub,
		IssuedAt:     certIssuedAt,
		Signature:    certSig,
	}
	if err := cert.Verify(senderRootPub); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_certificate", "sender device certificate signature is invalid")
		return federatedSender{}, false
	}

	blocked, err := store.IsFederationBlocked(a.DB, claim.AccountID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return federatedSender{}, false
	}
	if blocked {
		writeError(w, http.StatusForbidden, "forbidden", "sender is blocked on this server")
		return federatedSender{}, false
	}

	headers, err := httpsig.ParseRequestHeaders(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return federatedSender{}, false
	}
	// Binds the two independently-supplied facts together: the signature
	// proves possession of the key named in Signature-Key-Id, and the
	// certificate proves that same key is certified under the claimed
	// account -- so Signature-Key-Id must literally be that key, the same
	// self-describing-key convention freizone-gateway already uses.
	if headers.KeyID != base64.StdEncoding.EncodeToString(senderDevicePub) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return federatedSender{}, false
	}
	ts, err := httpsig.ParseTimestamp(headers.Timestamp)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return federatedSender{}, false
	}
	if !httpsig.WithinSkew(ts, a.Now(), auth.MaxClockSkew) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return federatedSender{}, false
	}

	var canonical string
	if claim.BodyDigest != "" {
		canonical = httpsig.CanonicalStringWithBodyDigest(
			r.Method, r.URL.Path, r.URL.RawQuery, headers.Timestamp, headers.Nonce, headers.KeyID, claim.BodyDigest)
	} else {
		canonical = httpsig.CanonicalStringFromRequest(r, headers, claim.RequestBody)
	}
	if err := httpsig.Verify(canonical, headers.Signature, senderDevicePub); err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return federatedSender{}, false
	}

	// expires_at = ts + MaxClockSkew, same reasoning as internal/auth's own
	// nonce bookkeeping: once real time has moved this far past ts, a
	// replay of this exact timestamp is already rejected by the skew check
	// above, making the record safe to purge.
	nonceOK, err := store.RecordNonce(a.DB, headers.KeyID, headers.Nonce, ts, ts.Add(auth.MaxClockSkew))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "internal server error")
		return federatedSender{}, false
	}
	if !nonceOK {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication failed")
		return federatedSender{}, false
	}

	return federatedSender{
		AccountID:    claim.AccountID,
		DeviceID:     claim.DeviceCert.DeviceID,
		DevicePubKey: senderDevicePub,
	}, true
}
