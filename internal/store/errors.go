package store

import "errors"

var (
	// ErrNotFound is returned when a lookup finds no matching row.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when an insert violates a uniqueness constraint.
	ErrConflict = errors.New("store: already exists")
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
