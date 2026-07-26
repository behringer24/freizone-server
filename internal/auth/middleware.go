package auth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/behringer24/freizone-server/internal/store"
	"github.com/behringer24/freizone-server/pkg/httpsig"
)

// MaxClockSkew is the maximum allowed difference between a request's
// Signature-Timestamp and the server's clock, in either direction.
const MaxClockSkew = 5 * time.Minute

// Middleware authenticates incoming requests using per-request Ed25519
// signatures (see signature.go) against devices registered in db.
type Middleware struct {
	DB     store.DBTX
	Logger *slog.Logger
	// Now returns the current time; overridable in tests.
	Now func() time.Time
	// nonces is the in-memory signature-replay guard. It replaces a
	// per-request write to the used_nonces table (the hottest write path):
	// nonces are purely ephemeral (5-min TTL) and need not survive a restart.
	nonces *nonceCache
}

// NewMiddleware builds a Middleware backed by db, logging authentication
// failures (at Warn level, with detail) to logger. The nonce replay cache is
// created internally, so callers (and tests) need not manage it.
func NewMiddleware(db store.DBTX, logger *slog.Logger) *Middleware {
	return &Middleware{DB: db, Logger: logger, Now: time.Now, nonces: newNonceCache()}
}

// PurgeExpiredNonces drops replay-cache entries whose skew window has passed,
// returning the number removed. Intended to be called periodically from the
// server's cleanup ticker to keep the cache bounded during idle periods.
func (m *Middleware) PurgeExpiredNonces(now time.Time) int {
	return m.nonces.purgeExpired(now)
}

// Require wraps next so it only runs for requests with a valid signature,
// injecting the resulting Identity into the request context. Every failure
// mode (unknown key, bad signature, expired timestamp, replayed nonce,
// revoked device) produces the same generic 401 response, so as not to give
// an attacker an oracle; specifics go only to the log.
func (m *Middleware) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := m.authenticate(r)
		if err != nil {
			if m.Logger != nil {
				m.Logger.Warn("request authentication failed", "error", err, "path", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":{"code":"unauthorized","message":"authentication failed"}}`))
			return
		}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), identity)))
	})
}

func (m *Middleware) authenticate(r *http.Request) (Identity, error) {
	headers, err := httpsig.ParseRequestHeaders(r)
	if err != nil {
		return Identity{}, err
	}

	ts, err := httpsig.ParseTimestamp(headers.Timestamp)
	if err != nil {
		return Identity{}, err
	}
	now := m.Now()
	if !httpsig.WithinSkew(ts, now, MaxClockSkew) {
		return Identity{}, errors.New("auth: timestamp outside allowed skew")
	}

	device, err := store.GetDevice(m.DB, headers.KeyID)
	if err != nil {
		return Identity{}, fmt.Errorf("auth: looking up device: %w", err)
	}
	if device.Status != store.DeviceStatusActive {
		return Identity{}, errors.New("auth: device is not active")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return Identity{}, fmt.Errorf("auth: reading body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	canonical := httpsig.CanonicalStringFromRequest(r, headers, body)
	if err := httpsig.Verify(canonical, headers.Signature, device.DevicePubKey); err != nil {
		return Identity{}, err
	}

	// expires_at = ts + MaxClockSkew: once real time has moved this far past
	// ts, a replay of this exact timestamp would already be rejected by the
	// skew check above, making the nonce record safe to purge.
	if ok := m.nonces.record(headers.KeyID, headers.Nonce, now, ts.Add(MaxClockSkew)); !ok {
		return Identity{}, errors.New("auth: replayed nonce")
	}

	account, err := store.GetAccount(m.DB, device.AccountID)
	if err != nil {
		return Identity{}, fmt.Errorf("auth: loading account: %w", err)
	}
	if account.Status != store.AccountStatusActive {
		return Identity{}, errors.New("auth: account is not active")
	}

	return Identity{AccountID: device.AccountID, DeviceID: device.DeviceID, Role: account.Role}, nil
}
