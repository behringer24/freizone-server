package auth

import "context"

// Identity is the authenticated caller of a signed request, injected into
// the request context by Middleware.Require.
type Identity struct {
	AccountID string
	DeviceID  string
	IsAdmin   bool
}

type contextKey int

const identityContextKey contextKey = iota

// WithIdentity returns a context carrying id.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityContextKey, id)
}

// IdentityFromContext retrieves the Identity injected by Middleware.Require.
// ok is false if the request was never authenticated.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityContextKey).(Identity)
	return id, ok
}
