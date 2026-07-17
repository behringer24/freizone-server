package api

import (
	"encoding/base64"
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

type createInviteRequest struct {
	ExpiresAt *string `json:"expires_at,omitempty"`
}

type createInviteResponse struct {
	Code      string  `json:"code"`
	ExpiresAt *string `json:"expires_at,omitempty"`
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
	Status       string  `json:"status"`
	RevokedAt    *string `json:"revoked_at,omitempty"`
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
