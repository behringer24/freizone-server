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
	// PushClient sends push-wake requests (see push.go); overridable in
	// tests to point at a fake distributor/gateway, including one served
	// over TLS with a test certificate.
	PushClient *http.Client
	// VAPIDPublicKey/VAPIDPrivateKey are this server's one push-signing
	// keypair (RFC 8292), set by main.go after store.InitVAPIDKeys.
	VAPIDPublicKey  string
	VAPIDPrivateKey string
	// RelayPubKey/RelayPrivKey are this server's Ed25519 identity used to
	// sign outgoing requests to a freizone-gateway (see push.go's
	// notifyPushViaGateway), set by main.go after store.InitRelayIdentity.
	RelayPubKey  ed25519.PublicKey
	RelayPrivKey ed25519.PrivateKey
}

// New builds an API with the given dependencies.
func New(db *sql.DB, cfg *config.Config, authMW *auth.Middleware, logger *slog.Logger) *API {
	return &API{
		DB: db, Config: cfg, Auth: authMW, Logger: logger, Now: time.Now,
		broker: newMessageBroker(), PushClient: http.DefaultClient,
	}
}

// Router builds the full HTTP route table.
func (a *API) Router() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", a.handleHealth)

	mux.HandleFunc("POST /v1/bootstrap/claim", a.handleBootstrapClaim)
	mux.HandleFunc("POST /v1/accounts", a.handleRegisterAccount)
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

	mux.Handle("GET /v1/admin/federation-blocklist", a.Auth.Require(http.HandlerFunc(a.handleListFederationBlocklist)))
	mux.Handle("POST /v1/admin/federation-blocklist", a.Auth.Require(http.HandlerFunc(a.handleBlockFederationSender)))
	mux.Handle("DELETE /v1/admin/federation-blocklist/{account_id}", a.Auth.Require(http.HandlerFunc(a.handleUnblockFederationSender)))

	mux.Handle("POST /v1/devices/{device_id}/prekeys", a.Auth.Require(http.HandlerFunc(a.handleUploadPrekeys)))
	mux.HandleFunc("POST /v1/devices/{device_id}/prekey-bundle", a.handleClaimPrekeyBundle)

	mux.Handle("POST /v1/messages", a.Auth.Require(http.HandlerFunc(a.handleSendMessage)))
	// Public, not wrapped in a.Auth.Require: this handler verifies a
	// cross-server sender's self-certifying identity chain inline (see
	// federation.go) instead of the local-device-lookup Middleware
	// performs -- a foreign sender has no local device row to look up.
	mux.HandleFunc("POST /v1/federation/messages", a.handleReceiveFederatedMessage)
	mux.Handle("GET /v1/messages", a.Auth.Require(http.HandlerFunc(a.handleListMessages)))
	mux.Handle("DELETE /v1/messages/{message_id}", a.Auth.Require(http.HandlerFunc(a.handleDeleteMessage)))
	mux.Handle("GET /v1/messages/stream", a.Auth.Require(http.HandlerFunc(a.handleMessageStream)))

	return mux
}
