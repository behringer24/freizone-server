package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/address"
	"github.com/behringer24/freizone-server/internal/devicecert"
	"github.com/behringer24/freizone-server/internal/ratchet"
)

// newIdentity generates a fresh root key, device key, and derived account
// id -- everything needed before claiming an account on server.
func newIdentity(server string) (*State, error) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating root key: %w", err)
	}
	devicePub, devicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating device key: %w", err)
	}
	deviceID, err := devicecert.NewDeviceID()
	if err != nil {
		return nil, err
	}
	accountID, err := address.DeriveID(rootPub)
	if err != nil {
		return nil, fmt.Errorf("deriving account id: %w", err)
	}

	return &State{
		Server:         server,
		AccountID:      accountID,
		RootPub:        rootPub,
		RootPriv:       rootPriv,
		DeviceID:       deviceID,
		DevicePub:      devicePub,
		DevicePriv:     devicePriv,
		OneTimePrekeys: make(map[uint32]OTPKState),
		Sessions:       make(map[string]*ratchet.Session),
	}, nil
}

// claimAccount claims an account (bootstrap or self-registration) at path,
// signing a fresh device certificate with the account's root key.
func claimAccount(state *State, path, setupToken string, inviteCode *string) error {
	issuedAt := time.Now().UTC()
	cert, err := devicecert.SignDeviceCertificate(state.AccountID, state.DeviceID, ed25519.PublicKey(state.DevicePub), issuedAt, ed25519.PrivateKey(state.RootPriv))
	if err != nil {
		return fmt.Errorf("signing device certificate: %w", err)
	}

	var body []byte
	if setupToken != "" {
		body, err = json.Marshal(bootstrapClaimRequest{
			SetupToken:          setupToken,
			RootPubKey:          base64.StdEncoding.EncodeToString(state.RootPub),
			DeviceID:            state.DeviceID,
			DevicePubKey:        base64.StdEncoding.EncodeToString(state.DevicePub),
			DeviceCertIssuedAt:  issuedAt.Format(time.RFC3339),
			DeviceCertSignature: base64.StdEncoding.EncodeToString(cert.Signature),
		})
	} else {
		body, err = json.Marshal(registerAccountRequest{
			RootPubKey:          base64.StdEncoding.EncodeToString(state.RootPub),
			DeviceID:            state.DeviceID,
			DevicePubKey:        base64.StdEncoding.EncodeToString(state.DevicePub),
			DeviceCertIssuedAt:  issuedAt.Format(time.RFC3339),
			DeviceCertSignature: base64.StdEncoding.EncodeToString(cert.Signature),
			InviteCode:          inviteCode,
		})
	}
	if err != nil {
		return fmt.Errorf("building request body: %w", err)
	}

	resp, err := jsonRequest(state.Server, http.MethodPost, path, body)
	if err != nil {
		return fmt.Errorf("calling %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s failed: %s: %s", path, resp.Status, data)
	}
	return nil
}

// getAccount fetches an account's public directory entry.
func getAccount(server, accountID string) (*accountResponse, error) {
	resp, err := jsonRequest(server, http.MethodGet, "/v1/accounts/"+accountID, nil)
	if err != nil {
		return nil, fmt.Errorf("fetching account %s: %w", accountID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("fetching account %s failed: %s: %s", accountID, resp.Status, data)
	}
	var acc accountResponse
	if err := json.NewDecoder(resp.Body).Decode(&acc); err != nil {
		return nil, fmt.Errorf("decoding account response: %w", err)
	}
	return &acc, nil
}

// resolvePeerDevice fetches accountID's directory entry and returns the
// first active device whose certificate independently verifies against the
// account's root key -- no trust in the server is required, only in this
// signature chain (see docs/PROTOCOL.md).
func resolvePeerDevice(server, accountID string) (deviceID string, devicePubKey ed25519.PublicKey, err error) {
	acc, err := getAccount(server, accountID)
	if err != nil {
		return "", nil, err
	}

	rootPub, err := base64.StdEncoding.DecodeString(acc.RootPubKey)
	if err != nil {
		return "", nil, fmt.Errorf("decoding root pubkey: %w", err)
	}

	ok, err := address.Verify(acc.ID, ed25519.PublicKey(rootPub))
	if err != nil {
		return "", nil, fmt.Errorf("verifying account id: %w", err)
	}
	if !ok {
		return "", nil, fmt.Errorf("account id %s does not match its root pubkey", acc.ID)
	}

	for _, d := range acc.Devices {
		if d.Status != "active" {
			continue
		}
		devicePub, err := base64.StdEncoding.DecodeString(d.DevicePubKey)
		if err != nil {
			continue
		}
		issuedAt, err := time.Parse(time.RFC3339, d.IssuedAt)
		if err != nil {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(d.Signature)
		if err != nil {
			continue
		}

		cert := &devicecert.DeviceCertificate{
			AccountID:    acc.ID,
			DeviceID:     d.DeviceID,
			DevicePubKey: ed25519.PublicKey(devicePub),
			IssuedAt:     issuedAt,
			Signature:    sig,
		}
		if err := cert.Verify(ed25519.PublicKey(rootPub)); err != nil {
			continue
		}
		return d.DeviceID, ed25519.PublicKey(devicePub), nil
	}

	return "", nil, fmt.Errorf("no verifiable active device found for account %s", accountID)
}
