package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// randomNonce generates a client-random nonce for a signed request.
func randomNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// randomMessageID generates a client-random message id.
func randomMessageID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating message id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// jsonRequest performs an unauthenticated JSON request (bootstrap,
// register, account lookup, prekey bundle claim -- all public endpoints).
func jsonRequest(server, method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, server+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return http.DefaultClient.Do(req)
}

// signedRequest performs a request signed with state's device key, per
// docs/PROTOCOL.md's per-request signature scheme.
func signedRequest(state *State, method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, state.Server+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	ts := time.Now()
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	sig := httpsig.Sign(method, path, "", body, state.DeviceID, ts, nonce, ed25519.PrivateKey(state.DevicePriv))

	req.Header.Set(httpsig.HeaderKeyID, state.DeviceID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	return http.DefaultClient.Do(req)
}

// federatedSignedRequest sends a request to a DIFFERENT server than
// state.Server, signed with state's own device key using the
// self-describing-key convention federation uses in place of a
// registered device id: Signature-Key-Id is the base64-encoded device
// public key itself, since the target server has no local row for this
// device to look a device id up in. See docs/PROTOCOL.md §9.
func federatedSignedRequest(state *State, targetServer, method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, targetServer+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	keyID := base64.StdEncoding.EncodeToString(state.DevicePub)
	ts := time.Now()
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	sig := httpsig.Sign(method, path, "", body, keyID, ts, nonce, ed25519.PrivateKey(state.DevicePriv))

	req.Header.Set(httpsig.HeaderKeyID, keyID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	return http.DefaultClient.Do(req)
}

// newSignedStreamRequest builds (but does not send) a signed GET request,
// for the long-lived SSE stream connection.
func newSignedStreamRequest(state *State, path string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, state.Server+path, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	ts := time.Now()
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	sig := httpsig.Sign(http.MethodGet, path, "", nil, state.DeviceID, ts, nonce, ed25519.PrivateKey(state.DevicePriv))

	req.Header.Set(httpsig.HeaderKeyID, state.DeviceID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	return req, nil
}
