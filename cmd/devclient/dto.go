package main

import "encoding/json"

// These mirror the server's wire DTOs (internal/api/dto.go) exactly, per
// docs/PROTOCOL.md. devclient is a separate client, same as any future
// mobile app would be, so it defines its own copies rather than importing
// the server's internal (package-private) types.

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
	RecipientAccountID string          `json:"recipient_account_id,omitempty"`
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

type accountResponse struct {
	ID         string           `json:"id"`
	RootPubKey string           `json:"root_pubkey"`
	Devices    []deviceResponse `json:"devices"`
}

type deviceResponse struct {
	DeviceID     string  `json:"device_id"`
	DevicePubKey string  `json:"device_pubkey"`
	IssuedAt     string  `json:"issued_at"`
	Signature    string  `json:"signature"`
	Status       string  `json:"status"`
	RevokedAt    *string `json:"revoked_at,omitempty"`
}
