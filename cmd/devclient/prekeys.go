package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/pkg/devicecert"
	"github.com/behringer24/freizone-server/pkg/ratchet"
)

// defaultOneTimePrekeyBatch is how many one-time prekeys to generate and
// upload at once.
const defaultOneTimePrekeyBatch = 10

// uploadPrekeys generates (if not already present) a DH identity key, a
// fresh signed prekey, and otpkCount one-time prekeys, and uploads them.
// state is mutated with the new key material on success.
func uploadPrekeys(state *State, otpkCount int) error {
	curve := ecdh.X25519()
	now := time.Now().UTC()

	var dhPriv *ecdh.PrivateKey
	var dhCertDTO *dhIdentityCertDTO

	if len(state.DHIdentityPriv) == 0 {
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generating dh identity key: %w", err)
		}
		cert, err := devicecert.SignDHIdentityCertificate(state.AccountID, state.DeviceID, priv.PublicKey().Bytes(), now, ed25519.PrivateKey(state.DevicePriv))
		if err != nil {
			return fmt.Errorf("signing dh identity certificate: %w", err)
		}
		state.DHIdentityPub = priv.PublicKey().Bytes()
		state.DHIdentityPriv = priv.Bytes()
		dhPriv = priv
		dhCertDTO = &dhIdentityCertDTO{
			DHPubKey:  base64.StdEncoding.EncodeToString(cert.DHPubKey),
			IssuedAt:  cert.IssuedAt.Format(time.RFC3339),
			Signature: base64.StdEncoding.EncodeToString(cert.Signature),
		}
	} else {
		priv, err := curve.NewPrivateKey(state.DHIdentityPriv)
		if err != nil {
			return fmt.Errorf("loading dh identity key: %w", err)
		}
		dhPriv = priv
	}

	spkPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating signed prekey: %w", err)
	}
	spkKeyID := state.NextSignedPrekeyID
	state.NextSignedPrekeyID++

	spkCert, err := devicecert.SignSignedPrekeyCertificate(state.AccountID, state.DeviceID, spkKeyID, dhPriv.PublicKey().Bytes(), spkPriv.PublicKey().Bytes(), now, ed25519.PrivateKey(state.DevicePriv))
	if err != nil {
		return fmt.Errorf("signing signed prekey certificate: %w", err)
	}
	state.SignedPrekeyID = spkKeyID
	state.SignedPrekeyPub = spkPriv.PublicKey().Bytes()
	state.SignedPrekeyPriv = spkPriv.Bytes()

	if state.OneTimePrekeys == nil {
		state.OneTimePrekeys = make(map[uint32]OTPKState)
	}
	otpkDTOs := make([]oneTimePrekeyDTO, 0, otpkCount)
	for i := 0; i < otpkCount; i++ {
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generating one-time prekey: %w", err)
		}
		keyID := state.NextOTPKKeyID
		state.NextOTPKKeyID++
		state.OneTimePrekeys[keyID] = OTPKState{Pub: priv.PublicKey().Bytes(), Priv: priv.Bytes()}
		otpkDTOs = append(otpkDTOs, oneTimePrekeyDTO{KeyID: keyID, PubKey: base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())})
	}

	req := uploadPrekeysRequest{
		DHIdentityCert: dhCertDTO,
		SignedPrekey: signedPrekeyDTO{
			KeyID:            spkCert.KeyID,
			DHIdentityPubKey: base64.StdEncoding.EncodeToString(spkCert.DHIdentityPubKey),
			PubKey:           base64.StdEncoding.EncodeToString(spkCert.PrekeyPubKey),
			IssuedAt:         spkCert.IssuedAt.Format(time.RFC3339),
			Signature:        base64.StdEncoding.EncodeToString(spkCert.Signature),
		},
		OneTimePrekeys: otpkDTOs,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("building upload prekeys request: %w", err)
	}

	resp, err := signedRequest(state, http.MethodPost, "/v1/devices/"+state.DeviceID+"/prekeys", body)
	if err != nil {
		return fmt.Errorf("uploading prekeys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload prekeys failed: %s: %s", resp.Status, data)
	}
	return nil
}

// claimPrekeyBundle claims a prekey bundle for deviceID.
func claimPrekeyBundle(server, deviceID string) (*prekeyBundleResponse, error) {
	resp, err := jsonRequest(server, http.MethodPost, "/v1/devices/"+deviceID+"/prekey-bundle", nil)
	if err != nil {
		return nil, fmt.Errorf("claiming prekey bundle: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("claiming prekey bundle failed: %s: %s", resp.Status, data)
	}
	var bundle prekeyBundleResponse
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("decoding prekey bundle: %w", err)
	}
	return &bundle, nil
}

// bundleToRemoteBundle verifies a claimed bundle's certificates against the
// peer device's Ed25519 signing key, and converts it to a
// ratchet.RemoteBundle ready for InitiateSession.
func bundleToRemoteBundle(b *prekeyBundleResponse, accountID, deviceID string, devicePubKey ed25519.PublicKey) (ratchet.RemoteBundle, error) {
	curve := ecdh.X25519()

	dhPubRaw, err := base64.StdEncoding.DecodeString(b.DHIdentityPubKey)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("decoding dh identity pubkey: %w", err)
	}
	dhIssuedAt, err := time.Parse(time.RFC3339, b.DHIdentityCert.IssuedAt)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("parsing dh identity cert issued_at: %w", err)
	}
	dhSig, err := base64.StdEncoding.DecodeString(b.DHIdentityCert.Signature)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("decoding dh identity cert signature: %w", err)
	}
	dhCert := &devicecert.DHIdentityCertificate{AccountID: accountID, DeviceID: deviceID, DHPubKey: dhPubRaw, IssuedAt: dhIssuedAt, Signature: dhSig}
	if err := dhCert.Verify(devicePubKey); err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("dh identity certificate is invalid: %w", err)
	}

	spkPubRaw, err := base64.StdEncoding.DecodeString(b.SignedPrekey.PubKey)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("decoding signed prekey pubkey: %w", err)
	}
	spkDHPubRaw, err := base64.StdEncoding.DecodeString(b.SignedPrekey.DHIdentityPubKey)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("decoding signed prekey dh identity pubkey: %w", err)
	}
	spkIssuedAt, err := time.Parse(time.RFC3339, b.SignedPrekey.IssuedAt)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("parsing signed prekey issued_at: %w", err)
	}
	spkSig, err := base64.StdEncoding.DecodeString(b.SignedPrekey.Signature)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("decoding signed prekey signature: %w", err)
	}
	spkCert := &devicecert.SignedPrekeyCertificate{
		AccountID: accountID, DeviceID: deviceID, KeyID: b.SignedPrekey.KeyID,
		DHIdentityPubKey: spkDHPubRaw, PrekeyPubKey: spkPubRaw, IssuedAt: spkIssuedAt, Signature: spkSig,
	}
	if err := spkCert.Verify(devicePubKey); err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("signed prekey certificate is invalid: %w", err)
	}
	if !bytes.Equal(spkDHPubRaw, dhPubRaw) {
		return ratchet.RemoteBundle{}, errors.New("signed prekey is not bound to the claimed dh identity key")
	}

	dhPub, err := curve.NewPublicKey(dhPubRaw)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("parsing dh identity pubkey: %w", err)
	}
	spkPub, err := curve.NewPublicKey(spkPubRaw)
	if err != nil {
		return ratchet.RemoteBundle{}, fmt.Errorf("parsing signed prekey pubkey: %w", err)
	}

	remote := ratchet.RemoteBundle{
		DHIdentityPubKey: dhPub,
		SignedPrekeyID:   b.SignedPrekey.KeyID,
		SignedPrekeyPub:  spkPub,
	}
	if b.OneTimePrekey != nil {
		otpkPubRaw, err := base64.StdEncoding.DecodeString(b.OneTimePrekey.PubKey)
		if err != nil {
			return ratchet.RemoteBundle{}, fmt.Errorf("decoding one-time prekey pubkey: %w", err)
		}
		otpkPub, err := curve.NewPublicKey(otpkPubRaw)
		if err != nil {
			return ratchet.RemoteBundle{}, fmt.Errorf("parsing one-time prekey pubkey: %w", err)
		}
		keyID := b.OneTimePrekey.KeyID
		remote.OneTimePrekeyID = &keyID
		remote.OneTimePrekeyPub = otpkPub
	}
	return remote, nil
}
