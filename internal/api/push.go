package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"

	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// pushNotifyTimeout bounds how long a wake-notification request is
// allowed to take, so a slow or dead distributor endpoint can never pile
// up goroutines.
const pushNotifyTimeout = 10 * time.Second

// notifyPush best-effort wakes a device via its registered push
// subscription. The plaintext payload is empty -- no content or metadata,
// matching this project's "server never sees plaintext" stance; the
// wake carries no information beyond "go sync", exactly as if the
// recipient had just reconnected. RFC 8291 requires the *transport* to
// the distributor be encrypted regardless of how little the payload
// says, so this still goes through full Web Push encryption
// (ECDH P-256 + HKDF + AES-128-GCM, via webpush-go) using the
// subscription's p256dh/auth and this server's one VAPID keypair.
//
// Failures are logged, never surfaced -- the durable queue and a future
// poll/SSE reconnect are the actual delivery guarantee; this is only a
// convenience wake-up. logger may be nil (as in tests), same convention
// as elsewhere in this package.
//
// Deliberately uses context.Background(), not the triggering request's
// context: this runs in its own goroutine after the HTTP handler has
// already responded, so the request's context would already be canceled.
func notifyPush(client webpush.HTTPClient, logger *slog.Logger, vapidPublicKey, vapidPrivateKey string, sub store.PushSubscription) {
	ctx, cancel := context.WithTimeout(context.Background(), pushNotifyTimeout)
	defer cancel()

	resp, err := webpush.SendNotificationWithContext(ctx, nil, &webpush.Subscription{
		Endpoint: sub.Endpoint,
		Keys:     webpush.Keys{P256dh: sub.P256dh, Auth: sub.Auth},
	}, &webpush.Options{
		HTTPClient:      client,
		Subscriber:      "mailto:admin@localhost",
		VAPIDPublicKey:  vapidPublicKey,
		VAPIDPrivateKey: vapidPrivateKey,
		TTL:             60,
	})
	if err != nil {
		if logger != nil {
			logger.Debug("push: wake request failed", "error", err)
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && logger != nil {
		logger.Debug("push: wake request rejected", "status", resp.StatusCode)
	}
}

// notifyPushViaGateway best-effort wakes a device via a freizone-gateway
// instance (see gatewayURL, this server's own PushGatewayURL config),
// for devices that registered an FCM/APNs push target instead of a
// UnifiedPush subscription (see store.PushTarget). Like notifyPush, the
// request carries no message content or metadata -- just which platform
// and token to wake, exactly what the gateway needs to relay the wake
// and nothing else.
//
// The request is signed with this server's own relay identity
// (relayPubKey/relayPrivKey, see store.InitRelayIdentity) using the same
// per-request Ed25519 signature scheme (pkg/httpsig) devices use to
// authenticate to this server -- except here the key ID *is* the public
// key itself, since the gateway has no prior registration for this
// server to look up (see freizone-gateway's README for why).
//
// Failures are logged, never surfaced -- same convention as notifyPush.
// Deliberately uses context.Background(), not the triggering request's
// context, for the same reason: this runs in its own goroutine after the
// HTTP handler has already responded.
func notifyPushViaGateway(client *http.Client, logger *slog.Logger, gatewayURL string, relayPubKey ed25519.PublicKey, relayPrivKey ed25519.PrivateKey, target store.PushTarget) {
	ctx, cancel := context.WithTimeout(context.Background(), pushNotifyTimeout)
	defer cancel()

	body, err := json.Marshal(map[string]string{"platform": target.Platform, "token": target.Token})
	if err != nil {
		if logger != nil {
			logger.Debug("push: marshaling gateway request failed", "error", err)
		}
		return
	}

	const path = "/v1/push/send"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gatewayURL+path, bytes.NewReader(body))
	if err != nil {
		if logger != nil {
			logger.Debug("push: building gateway request failed", "error", err)
		}
		return
	}
	req.Header.Set("Content-Type", "application/json")

	keyID := base64.StdEncoding.EncodeToString(relayPubKey)
	ts := time.Now()
	nonce, err := randomNonce()
	if err != nil {
		if logger != nil {
			logger.Debug("push: generating gateway request nonce failed", "error", err)
		}
		return
	}
	sig := httpsig.Sign(http.MethodPost, path, "", body, keyID, ts, nonce, relayPrivKey)
	req.Header.Set(httpsig.HeaderKeyID, keyID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	resp, err := client.Do(req)
	if err != nil {
		if logger != nil {
			logger.Debug("push: gateway request failed", "error", err)
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && logger != nil {
		logger.Debug("push: gateway request rejected", "status", resp.StatusCode)
	}
}

// randomNonce generates a client-random nonce for a signed request, same
// shape as cmd/devclient's own helper of the same name.
func randomNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// handleGetVAPIDPublicKey returns this server's VAPID public key
// (not secret -- needed by clients so their chosen UnifiedPush
// distributor can be told which application server may push to it, per
// RFC 8292; some distributors reject registration without one).
func (a *API) handleGetVAPIDPublicKey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"key": a.VAPIDPublicKey})
}
