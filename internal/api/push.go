package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"

	"github.com/behringer24/freizone-server/internal/store"
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

// handleGetVAPIDPublicKey returns this server's VAPID public key
// (not secret -- needed by clients so their chosen UnifiedPush
// distributor can be told which application server may push to it, per
// RFC 8292; some distributors reject registration without one).
func (a *API) handleGetVAPIDPublicKey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"key": a.VAPIDPublicKey})
}
