package store

import "errors"

var (
	// ErrNotFound is returned when a lookup finds no matching row.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when an insert violates a uniqueness constraint.
	ErrConflict = errors.New("store: already exists")
	// ErrIDPrefixConflict is returned by CreateAccount when the account id's
	// first 5 characters collide with an already-registered account on this
	// server. Unlike ErrConflict (the same exact id already exists, which
	// only happens if the same root key is registered twice), this is
	// expected to happen occasionally by design -- the caller's fix is to
	// generate a fresh identity (a new root key derives a new id) and
	// retry, not to treat it as a hard failure.
	ErrIDPrefixConflict = errors.New("store: account id prefix already taken on this server")
	// ErrInvalidToken is returned by ClaimSetupToken when the supplied token
	// doesn't match, was already used, or no setup token exists.
	ErrInvalidToken = errors.New("store: invalid or already-used setup token")
	// ErrInviteAlreadyUsed is returned by ConsumeInviteCode for a code that
	// has already been redeemed.
	ErrInviteAlreadyUsed = errors.New("store: invite code already used")
	// ErrInviteExpired is returned by ConsumeInviteCode for a code past its
	// expiry time.
	ErrInviteExpired = errors.New("store: invite code expired")
)
