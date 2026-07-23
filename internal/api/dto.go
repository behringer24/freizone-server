package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/behringer24/freizone-server/internal/store"
)

type bootstrapClaimRequest struct {
	SetupToken          string `json:"setup_token"`
	RootPubKey          string `json:"root_pubkey"`
	DeviceID            string `json:"device_id"`
	DevicePubKey        string `json:"device_pubkey"`
	DeviceCertIssuedAt  string `json:"device_cert_issued_at"`
	DeviceCertSignature string `json:"device_cert_signature"`
}

type registerAccountRequest struct {
	RootPubKey          string  `json:"root_pubkey"`
	DeviceID            string  `json:"device_id"`
	DevicePubKey        string  `json:"device_pubkey"`
	DeviceCertIssuedAt  string  `json:"device_cert_issued_at"`
	DeviceCertSignature string  `json:"device_cert_signature"`
	InviteCode          *string `json:"invite_code,omitempty"`
}

type addDeviceRequest struct {
	AccountID    string `json:"account_id"`
	DeviceID     string `json:"device_id"`
	DevicePubKey string `json:"device_pubkey"`
	IssuedAt     string `json:"issued_at"`
	Signature    string `json:"signature"`
}

type revokeDeviceRequest struct {
	AccountID string `json:"account_id"`
	DeviceID  string `json:"device_id"`
	RevokedAt string `json:"revoked_at"`
	Signature string `json:"signature"`
}

// setPushEndpointRequest registers or clears (all fields nil/omitted) a
// device's push subscription. Endpoint, P256dh, and Auth must be given
// together or not at all -- see handleSetPushEndpoint.
type setPushEndpointRequest struct {
	Endpoint *string `json:"endpoint"`
	P256dh   *string `json:"p256dh"`
	Auth     *string `json:"auth"`
}

// setPushTargetRequest registers or clears (both fields nil/omitted) a
// device's FCM/APNs push target. Platform and Token must be given
// together or not at all -- see handleSetPushTarget.
type setPushTargetRequest struct {
	Platform *string `json:"platform"`
	Token    *string `json:"token"`
}

type createInviteRequest struct {
	ExpiresAt *string `json:"expires_at,omitempty"`
}

type createInviteResponse struct {
	Code      string  `json:"code"`
	ExpiresAt *string `json:"expires_at,omitempty"`
}

type adminAccountResponse struct {
	ID        string `json:"id"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

func adminAccountResponseFrom(acc store.Account) adminAccountResponse {
	return adminAccountResponse{
		ID:        acc.ID,
		Role:      string(acc.Role),
		Status:    acc.Status,
		CreatedAt: acc.CreatedAt.UTC().Format(time.RFC3339),
	}
}

type setAccountRoleRequest struct {
	Role string `json:"role"`
}

// blockFederationSenderRequest blocks a remote account id from delivering
// federated messages here -- see docs/PROTOCOL.md's federation section on
// why this is per-account, not per-origin-server.
type blockFederationSenderRequest struct {
	AccountID string  `json:"account_id"`
	Reason    *string `json:"reason,omitempty"`
}

type federationBlockEntryResponse struct {
	AccountID string  `json:"account_id"`
	BlockedAt string  `json:"blocked_at"`
	BlockedBy string  `json:"blocked_by"`
	Reason    *string `json:"reason,omitempty"`
}

func federationBlockEntryResponseFrom(e store.FederationBlockEntry) federationBlockEntryResponse {
	return federationBlockEntryResponse{
		AccountID: e.AccountID,
		BlockedAt: e.BlockedAt.UTC().Format(time.RFC3339),
		BlockedBy: e.BlockedBy,
		Reason:    e.Reason,
	}
}

type statusResponse struct {
	Status string `json:"status"`
}

type registrationPolicyResponse struct {
	Policy string `json:"policy"`
}

type setRegistrationPolicyRequest struct {
	Policy string `json:"policy"`
}

// serverStatusResponse is the public GET /v1/server-status payload -- see
// internal/api/server_status.go.
type serverStatusResponse struct {
	Claimed            bool   `json:"claimed"`
	RegistrationPolicy string `json:"registration_policy"`
	FederationEnabled  bool   `json:"federation_enabled"`
}

type federationEnabledResponse struct {
	Enabled bool `json:"enabled"`
}

type setFederationEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

type accountResponse struct {
	ID         string           `json:"id"`
	RootPubKey string           `json:"root_pubkey"`
	Devices    []deviceResponse `json:"devices"`
}

type deviceResponse struct {
	DeviceID     string `json:"device_id"`
	DevicePubKey string `json:"device_pubkey"`
	IssuedAt     string `json:"issued_at"`
	// Signature is the device certificate's signature (by the account's
	// root key) -- required so a client can verify the full self-certifying
	// chain (root_pubkey -> this signature -> device_pubkey) itself,
	// without trusting the server's word for it.
	Signature string  `json:"signature"`
	Status    string  `json:"status"`
	RevokedAt *string `json:"revoked_at,omitempty"`
}

type dhIdentityCertDTO struct {
	DHPubKey  string `json:"dh_pubkey"`
	IssuedAt  string `json:"issued_at"`
	Signature string `json:"signature"`
}

type signedPrekeyDTO struct {
	KeyID            uint32 `json:"key_id"`
	DHIdentityPubKey string `json:"dh_identity_pubkey"`
	PubKey           string `json:"pubkey"`
	IssuedAt         string `json:"issued_at"`
	Signature        string `json:"signature"`
}

type oneTimePrekeyDTO struct {
	KeyID  uint32 `json:"key_id"`
	PubKey string `json:"pubkey"`
}

type uploadPrekeysRequest struct {
	DHIdentityCert *dhIdentityCertDTO `json:"dh_identity_cert,omitempty"`
	SignedPrekey   signedPrekeyDTO    `json:"signed_prekey"`
	OneTimePrekeys []oneTimePrekeyDTO `json:"one_time_prekeys,omitempty"`
}

type prekeyBundleResponse struct {
	DeviceID         string            `json:"device_id"`
	DHIdentityPubKey string            `json:"dh_identity_pubkey"`
	DHIdentityCert   dhIdentityCertDTO `json:"dh_identity_cert"`
	SignedPrekey     signedPrekeyDTO   `json:"signed_prekey"`
	OneTimePrekey    *oneTimePrekeyDTO `json:"one_time_prekey,omitempty"`
}

// prekeyStatusResponse is the GET /v1/devices/{id}/prekey-status payload --
// lets a device check its own one-time-prekey pool without consuming one
// (unlike POST .../prekey-bundle, which claims and removes a key).
type prekeyStatusResponse struct {
	OneTimePrekeysRemaining int `json:"one_time_prekeys_remaining"`
}

type sendMessageRequest struct {
	MessageID          string          `json:"message_id"`
	RecipientAccountID string          `json:"recipient_account_id"`
	RecipientDeviceID  string          `json:"recipient_device_id"`
	Payload            json.RawMessage `json:"payload"`
}

type messageResponse struct {
	MessageID       string          `json:"message_id"`
	SenderAccountID string          `json:"sender_account_id"`
	SenderDeviceID  string          `json:"sender_device_id"`
	SentAt          string          `json:"sent_at"`
	Payload         json.RawMessage `json:"payload"`
}

func messageResponseFrom(m store.Message) messageResponse {
	return messageResponse{
		MessageID:       m.MessageID,
		SenderAccountID: m.SenderAccountID,
		SenderDeviceID:  m.SenderDeviceID,
		SentAt:          m.SentAt.UTC().Format(time.RFC3339),
		Payload:         json.RawMessage(m.Payload),
	}
}

// federationDeviceCertDTO is the sending device's own certificate,
// carried inline since the recipient server has no local row to look one
// up from (see handleReceiveFederatedMessage).
type federationDeviceCertDTO struct {
	DeviceID     string `json:"device_id"`
	DevicePubKey string `json:"device_pub_key"`
	IssuedAt     string `json:"issued_at"`
	Signature    string `json:"signature"`
}

// federationMessageRequest is a cross-server message delivery: unlike
// sendMessageRequest (which relies on the caller already being a known,
// registered local device), this carries everything needed to verify the
// sender purely cryptographically -- no prior registration with this
// server required. See docs/PROTOCOL.md's federation section.
type federationMessageRequest struct {
	SenderAccountID    string                  `json:"sender_account_id"`
	SenderRootPubKey   string                  `json:"sender_root_pub_key"`
	SenderDeviceCert   federationDeviceCertDTO `json:"sender_device_cert"`
	RecipientAccountID string                  `json:"recipient_account_id"`
	RecipientDeviceID  string                  `json:"recipient_device_id"`
	MessageID          string                  `json:"message_id"`
	Payload            json.RawMessage         `json:"payload"`
}

func decodeBase64Key(s string, expectedLen int) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding: %w", err)
	}
	if len(raw) != expectedLen {
		return nil, fmt.Errorf("expected %d bytes, got %d", expectedLen, len(raw))
	}
	return raw, nil
}

func deviceResponseFrom(d store.Device) deviceResponse {
	resp := deviceResponse{
		DeviceID:     d.DeviceID,
		DevicePubKey: base64.StdEncoding.EncodeToString(d.DevicePubKey),
		IssuedAt:     d.CertIssuedAt.UTC().Format(time.RFC3339),
		Signature:    base64.StdEncoding.EncodeToString(d.CertSignature),
		Status:       d.Status,
	}
	if d.RevokedAt != nil {
		s := d.RevokedAt.UTC().Format(time.RFC3339)
		resp.RevokedAt = &s
	}
	return resp
}

func accountResponseFrom(acc *store.Account, devices []store.Device) accountResponse {
	resp := accountResponse{
		ID:         acc.ID,
		RootPubKey: base64.StdEncoding.EncodeToString(acc.RootPubKey),
		Devices:    make([]deviceResponse, 0, len(devices)),
	}
	for _, d := range devices {
		resp.Devices = append(resp.Devices, deviceResponseFrom(d))
	}
	return resp
}
