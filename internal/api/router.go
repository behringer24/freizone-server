// Package api implements the Freizone HTTP API: the identity/bootstrap
// surface (accounts, devices, invites) described in docs/PROTOCOL.md.
package api

import (
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
}

// New builds an API with the given dependencies.
func New(db *sql.DB, cfg *config.Config, authMW *auth.Middleware, logger *slog.Logger) *API {
	return &API{DB: db, Config: cfg, Auth: authMW, Logger: logger, Now: time.Now}
}

// Router builds the full HTTP route table.
func (a *API) Router() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", a.handleHealth)

	mux.HandleFunc("POST /v1/bootstrap/claim", a.handleBootstrapClaim)
	mux.HandleFunc("POST /v1/accounts", a.handleRegisterAccount)
	mux.HandleFunc("GET /v1/accounts/{id}", a.handleGetAccount)

	mux.Handle("POST /v1/devices", a.Auth.Require(http.HandlerFunc(a.handleAddDevice)))
	mux.Handle("POST /v1/devices/{device_id}/revoke", a.Auth.Require(http.HandlerFunc(a.handleRevokeDevice)))
	mux.Handle("POST /v1/admin/invites", a.Auth.Require(http.HandlerFunc(a.handleCreateInvite)))

	return mux
}
