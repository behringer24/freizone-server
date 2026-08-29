// Package api implements the Freizone HTTP API: the identity/bootstrap
// surface (accounts, devices, invites) described in docs/PROTOCOL.md.
package api

import (
	"crypto/ed25519"
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/auth"
	"github.com/behringer24/freizone-server/internal/blobstore"
	"github.com/behringer24/freizone-server/internal/config"
)

// API holds the shared dependencies used by all handlers.
type API struct {
	DB     *sql.DB
	Config *config.Config
	Auth   *auth.Middleware
	Logger *slog.Logger
	// Now returns the current time; overridable in tests.
	Now func() time.Time
	// broker fans out newly-queued messages to connected SSE streams.
	broker *messageBroker
	// wakes collapses repeated push wakes for the same device into at most
	// one per Config.PushCoalesceWindow (see wakecoalesce.go). Every wake
	// goes through it; a window of 0 makes it a pass-through.
	wakes *wakeCoalescer
	// PushClient sends push-wake requests to device-registered UnifiedPush
	// endpoints (see push.go's notifyPush). It is hardened against SSRF
	// (newUnifiedPushClient: no redirects, hard timeout, internal-address
	// denylist), because the endpoint is chosen by an untrusted device.
	// Overridable in tests to point at a fake distributor served over TLS.
	PushClient *http.Client
	// GatewayClient sends push-relay requests to the operator-configured
	// freizone-gateway (see push.go's notifyPushViaGateway). Same redirect/
	// timeout hardening as PushClient but no internal-address denylist: the
	// gateway URL is trusted config and a gateway legitimately runs on an
	// internal address. Overridable in tests to point at a fake gateway.
	GatewayClient *http.Client
	// VAPIDPublicKey/VAPIDPrivateKey are this server's one push-signing
	// keypair (RFC 8292), set by main.go after store.InitVAPIDKeys.
	VAPIDPublicKey  string
	VAPIDPrivateKey string
	// RelayPubKey/RelayPrivKey are this server's Ed25519 identity used to
	// sign outgoing requests to a freizone-gateway (see push.go's
	// notifyPushViaGateway), set by main.go after store.InitRelayIdentity.
	RelayPubKey  ed25519.PublicKey
	RelayPrivKey ed25519.PrivateKey
	// Blobs stores encrypted attachment ciphertext (see blobs.go), set by
	// main.go. Nil disables the blob routes -- they answer 404, the same as
	// an operator turning BlobsEnabled off.
	Blobs *blobstore.Store
}

// New builds an API with the given dependencies.
func New(db *sql.DB, cfg *config.Config, authMW *auth.Middleware, logger *slog.Logger) *API {
	a := &API{
		DB: db, Config: cfg, Auth: authMW, Logger: logger, Now: time.Now,
		broker:        newMessageBroker(),
		PushClient:    newUnifiedPushClient(),
		GatewayClient: newGatewayClient(),
	}
	// Each emitted wake gets its own goroutine, exactly as wakeDevice used
	// to start one per call: dispatchWake reads the device and then makes a
	// network call, and neither belongs on a request path that has already
	// answered.
	a.wakes = newWakeCoalescer(cfg.PushCoalesceWindow, func(deviceID string) {
		go a.dispatchWake(deviceID)
	})
	return a
}

// FlushPendingWakes emits any wake still held by the coalescing window.
// main.go calls this during shutdown, after the listener has stopped, so a
// restart does not swallow the notification for messages that arrived in
// the last window.
func (a *API) FlushPendingWakes() {
	if a.wakes != nil {
		a.wakes.flush()
	}
}

// EvictIdleWakeState drops coalescing state for devices whose window has
// closed. main.go calls this periodically; nothing breaks if it never runs,
// the map just keeps an entry per device ever woken.
func (a *API) EvictIdleWakeState() {
	if a.wakes != nil {
		a.wakes.evictIdle()
	}
}

// Router builds the full HTTP route table.
func (a *API) Router() http.Handler {
	mux := http.NewServeMux()

	// Exactly "/" (the {$} anchor), never a catch-all: unknown paths still
	// fall through to the mux's default 404, so this never shadows the /v1/
	// API or its JSON error contract. See handleLanding for the rest.
	//
	// Registered only when LandingPageEnabled (SRV-21): an operator who
	// wants the bare domain to give no sign anything is running there needs
	// net/http's plain 404, not a route that exists but answers differently
	// -- so the route is skipped here rather than made conditional inside
	// handleLanding.
	if a.Config.LandingPageEnabled {
		mux.HandleFunc("GET /{$}", a.handleLanding)
	}

	mux.HandleFunc("GET /healthz", a.handleHealth)

	mux.HandleFunc("POST /v1/bootstrap/claim", a.handleBootstrapClaim)
	mux.HandleFunc("POST /v1/accounts", a.handleRegisterAccount)
	// Public, not wrapped in a.Auth.Require: like federation/messages, this
	// handler authenticates itself inline -- with the account's root-key
	// signature -- because recovery happens precisely when no active device
	// (which Middleware would look up) exists. See handleRecoverAccount.
	mux.HandleFunc("POST /v1/accounts/{id}/recover", a.handleRecoverAccount)
	mux.HandleFunc("GET /v1/accounts/{id}", a.handleGetAccount)
	mux.Handle("DELETE /v1/accounts/{id}", a.Auth.Require(http.HandlerFunc(a.handleDeleteOwnAccount)))
	mux.HandleFunc("GET /v1/vapid-public-key", a.handleGetVAPIDPublicKey)
	mux.HandleFunc("GET /v1/server-status", a.handleGetServerStatus)

	mux.Handle("POST /v1/devices", a.Auth.Require(http.HandlerFunc(a.handleAddDevice)))
	mux.Handle("POST /v1/devices/{device_id}/revoke", a.Auth.Require(http.HandlerFunc(a.handleRevokeDevice)))
	mux.Handle("PUT /v1/devices/{device_id}/push-endpoint", a.Auth.Require(http.HandlerFunc(a.handleSetPushEndpoint)))
	mux.Handle("PUT /v1/devices/{device_id}/push-target", a.Auth.Require(http.HandlerFunc(a.handleSetPushTarget)))
	mux.Handle("POST /v1/admin/invites", a.Auth.Require(http.HandlerFunc(a.handleCreateInvite)))

	mux.Handle("GET /v1/admin/accounts", a.Auth.Require(http.HandlerFunc(a.handleListAccounts)))
	mux.Handle("POST /v1/admin/accounts/{id}/role", a.Auth.Require(http.HandlerFunc(a.handleSetAccountRole)))
	mux.Handle("POST /v1/admin/accounts/{id}/block", a.Auth.Require(http.HandlerFunc(a.handleBlockAccount)))
	mux.Handle("POST /v1/admin/accounts/{id}/unblock", a.Auth.Require(http.HandlerFunc(a.handleUnblockAccount)))
	mux.Handle("DELETE /v1/admin/accounts/{id}", a.Auth.Require(http.HandlerFunc(a.handleDeleteAccount)))
	mux.Handle("GET /v1/admin/registration-policy", a.Auth.Require(http.HandlerFunc(a.handleGetRegistrationPolicy)))
	mux.Handle("PUT /v1/admin/registration-policy", a.Auth.Require(http.HandlerFunc(a.handleSetRegistrationPolicy)))
	mux.Handle("GET /v1/admin/federation", a.Auth.Require(http.HandlerFunc(a.handleGetFederationEnabled)))
	mux.Handle("PUT /v1/admin/federation", a.Auth.Require(http.HandlerFunc(a.handleSetFederationEnabled)))
	mux.Handle("GET /v1/admin/license", a.Auth.Require(http.HandlerFunc(a.handleGetLicenseStatus)))
	mux.Handle("GET /v1/admin/stats", a.Auth.Require(http.HandlerFunc(a.handleGetServerStats)))
	mux.Handle("GET /v1/admin/stats/history", a.Auth.Require(http.HandlerFunc(a.handleGetServerStatsHistory)))

	mux.Handle("GET /v1/admin/federation-blocklist", a.Auth.Require(http.HandlerFunc(a.handleListFederationBlocklist)))
	mux.Handle("POST /v1/admin/federation-blocklist", a.Auth.Require(http.HandlerFunc(a.handleBlockFederationSender)))
	mux.Handle("DELETE /v1/admin/federation-blocklist/{account_id}", a.Auth.Require(http.HandlerFunc(a.handleUnblockFederationSender)))

	mux.Handle("POST /v1/devices/{device_id}/prekeys", a.Auth.Require(http.HandlerFunc(a.handleUploadPrekeys)))
	mux.Handle("GET /v1/devices/{device_id}/prekey-status", a.Auth.Require(http.HandlerFunc(a.handleGetPrekeyStatus)))
	mux.HandleFunc("POST /v1/devices/{device_id}/prekey-bundle", a.handleClaimPrekeyBundle)

	mux.Handle("POST /v1/messages", a.Auth.Require(http.HandlerFunc(a.handleSendMessage)))
	// Batch delivery (SRV-01), for group fan-out: one request per distinct
	// recipient server instead of one per recipient device. Registered as its
	// own path rather than an optional shape of POST /v1/messages, so a client
	// can discover it -- an older server simply 404s here, and
	// GET /v1/server-status advertises it where it exists.
	mux.Handle("POST /v1/messages/batch", a.Auth.Require(http.HandlerFunc(a.handleSendMessageBatch)))
	// Public, not wrapped in a.Auth.Require: this handler verifies a
	// cross-server sender's self-certifying identity chain inline (see
	// federation.go) instead of the local-device-lookup Middleware
	// performs -- a foreign sender has no local device row to look up.
	mux.HandleFunc("POST /v1/federation/messages", a.handleReceiveFederatedMessage)
	mux.HandleFunc("POST /v1/federation/messages/batch", a.handleReceiveFederatedMessageBatch)
	// Blob transport (SRV-07). The upload's body is raw ciphertext, far over
	// the global body cap -- see the per-path override in cmd/server/main.go
	// and the streamed-body authentication in internal/auth.
	mux.Handle("POST /v1/blobs", a.Auth.Require(http.HandlerFunc(a.handleUploadBlob)))
	// Public for the same reason as federation/messages: a sender on another
	// server has no local device row for the middleware to resolve, so this
	// handler verifies its identity chain inline.
	mux.HandleFunc("POST /v1/federation/blobs", a.handleUploadFederatedBlob)
	mux.Handle("GET /v1/blobs/{blob_id}", a.Auth.Require(http.HandlerFunc(a.handleDownloadBlob)))
	mux.Handle("DELETE /v1/blobs/{blob_id}", a.Auth.Require(http.HandlerFunc(a.handleDeleteBlob)))

	mux.Handle("GET /v1/messages", a.Auth.Require(http.HandlerFunc(a.handleListMessages)))
	mux.Handle("DELETE /v1/messages/{message_id}", a.Auth.Require(http.HandlerFunc(a.handleDeleteMessage)))
	mux.Handle("GET /v1/messages/stream", a.Auth.Require(http.HandlerFunc(a.handleMessageStream)))

	return mux
}
