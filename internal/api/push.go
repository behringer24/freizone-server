package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
// convenience wake-up. a.Logger may be nil (as in tests), same convention
// as elsewhere in this package. The one failure that is acted on is a
// permanently gone subscription (see dropDeadSubscription).
//
// Deliberately uses context.Background(), not the triggering request's
// context: this runs in its own goroutine after the HTTP handler has
// already responded, so the request's context would already be canceled.
func (a *API) notifyPush(deviceID string, sub store.PushSubscription) {
	ctx, cancel := context.WithTimeout(context.Background(), pushNotifyTimeout)
	defer cancel()

	resp, err := webpush.SendNotificationWithContext(ctx, nil, &webpush.Subscription{
		Endpoint: sub.Endpoint,
		Keys:     webpush.Keys{P256dh: sub.P256dh, Auth: sub.Auth},
	}, &webpush.Options{
		HTTPClient:      a.PushClient,
		Subscriber:      "mailto:admin@localhost",
		VAPIDPublicKey:  a.VAPIDPublicKey,
		VAPIDPrivateKey: a.VAPIDPrivateKey,
		TTL:             60,
	})
	if err != nil {
		if a.Logger != nil {
			a.Logger.Debug("push: wake request failed", "error", err)
		}
		return
	}
	defer resp.Body.Close()

	// 404/410 from a push service means the subscription is permanently
	// gone (the browser/distributor dropped it), per the Web Push
	// protocol's own guidance to stop sending to it.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		a.dropDeadSubscription(deviceID, resp.StatusCode)
		return
	}
	if resp.StatusCode >= 300 && a.Logger != nil {
		a.Logger.Debug("push: wake request rejected", "status", resp.StatusCode)
	}
}

// dropDeadSubscription clears a device's Web Push subscription after the
// push service reported it permanently gone. Without this, every future
// message to that device would keep paying for a wake request that can
// never arrive, and the device would look push-capable while being
// unreachable. The device itself is untouched: it stays active and keeps
// receiving messages over SSE/poll, and re-registers a fresh subscription
// on its next app start.
func (a *API) dropDeadSubscription(deviceID string, status int) {
	if err := store.SetDevicePushSubscription(a.DB, deviceID, nil); err != nil {
		if a.Logger != nil {
			a.Logger.Warn("push: clearing dead subscription failed", "device_id", deviceID, "error", err)
		}
		return
	}
	if a.Logger != nil {
		a.Logger.Info("push: dropped dead web push subscription", "device_id", deviceID, "status", status)
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
// The one failure that is acted on is a permanently dead token, which the
// gateway reports as 410 Gone (see dropDeadPushTarget).
// Deliberately uses context.Background(), not the triggering request's
// context, for the same reason: this runs in its own goroutine after the
// HTTP handler has already responded.
func (a *API) notifyPushViaGateway(deviceID string, target store.PushTarget) {
	ctx, cancel := context.WithTimeout(context.Background(), pushNotifyTimeout)
	defer cancel()

	body, err := json.Marshal(map[string]string{"platform": target.Platform, "token": target.Token})
	if err != nil {
		if a.Logger != nil {
			a.Logger.Debug("push: marshaling gateway request failed", "error", err)
		}
		return
	}

	const path = "/v1/push/send"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Config.PushGatewayURL+path, bytes.NewReader(body))
	if err != nil {
		if a.Logger != nil {
			a.Logger.Debug("push: building gateway request failed", "error", err)
		}
		return
	}
	req.Header.Set("Content-Type", "application/json")

	keyID := base64.StdEncoding.EncodeToString(a.RelayPubKey)
	ts := time.Now()
	nonce, err := randomNonce()
	if err != nil {
		if a.Logger != nil {
			a.Logger.Debug("push: generating gateway request nonce failed", "error", err)
		}
		return
	}
	sig := httpsig.Sign(http.MethodPost, path, "", body, keyID, ts, nonce, a.RelayPrivKey)
	req.Header.Set(httpsig.HeaderKeyID, keyID)
	req.Header.Set(httpsig.HeaderTimestamp, httpsig.FormatTimestamp(ts))
	req.Header.Set(httpsig.HeaderNonce, nonce)
	req.Header.Set(httpsig.HeaderSignature, sig)

	resp, err := a.GatewayClient.Do(req)
	if err != nil {
		if a.Logger != nil {
			a.Logger.Debug("push: gateway request failed", "error", err)
		}
		return
	}
	defer resp.Body.Close()

	// 410 Gone is the gateway's signal that the upstream service
	// permanently rejected this token (app uninstalled, data cleared,
	// wrong sender) -- distinct from a 502, which just means this attempt
	// failed and the token may still be fine.
	if resp.StatusCode == http.StatusGone {
		a.dropDeadPushTarget(deviceID, target.Platform)
		return
	}
	if resp.StatusCode >= 300 && a.Logger != nil {
		a.Logger.Debug("push: gateway request rejected", "status", resp.StatusCode)
	}
}

// dropDeadPushTarget clears a device's FCM/APNs registration after the
// gateway reported the token permanently invalid. Same reasoning as
// dropDeadSubscription: the device stays active and reachable over
// SSE/poll, and registers a fresh token on its next app start -- what's
// removed is only the dead wake address, which would otherwise be
// retried on every single message forever.
func (a *API) dropDeadPushTarget(deviceID, platform string) {
	if err := store.SetDevicePushTarget(a.DB, deviceID, nil); err != nil {
		if a.Logger != nil {
			a.Logger.Warn("push: clearing dead push target failed", "device_id", deviceID, "error", err)
		}
		return
	}
	if a.Logger != nil {
		a.Logger.Info("push: dropped dead push target", "device_id", deviceID, "platform", platform)
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
