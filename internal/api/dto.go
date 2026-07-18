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

type statusResponse struct {
	Status string `json:"status"`
}

type registrationPolicyResponse struct {
	Policy string `json:"policy"`
}

type setRegistrationPolicyRequest struct {
	Policy string `json:"policy"`
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
