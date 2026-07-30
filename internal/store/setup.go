package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/behringer24/freizone-server/pkg/humancode"
)

// setupTokenSymbols * 5 bits = 40 bits of entropy (see pkg/humancode for the
// alphabet and why it is the one it is). That's far less than the 256 bits
// this token used to carry, but the token is a single-use,
// server-side-locked-out secret (see MaxSetupTokenAttempts below), not a
// long-term key -- it only has to resist online guessing for the short
// window between server start and the admin's claim, not offline brute
// force. 8 symbols is short enough to type into a phone without a QR code.
//
// Note this reasoning does NOT carry over to invite codes, which are longer
// on purpose: there are many of them outstanding at once and no per-code
// lockout is possible, so their length has to do the work this token's
// lockout does. See inviteCodeSymbols in invites.go.
const setupTokenSymbols = 8

// MaxSetupTokenAttempts caps failed claim attempts before the token is
// permanently locked out (the operator must then run --reset-setup-token).
// This is what actually makes a short token safe: without it, an attacker
// with network access could brute-force setupTokenSymbols's 40 bits over an
// extended window since the endpoint has no other rate limiting.
const MaxSetupTokenAttempts = 10

// InitSetupToken ensures a setup token row exists, generating one if this is
// the very first boot. Only the token's hash is ever stored, so the
// plaintext returned here is the only time it's ever available again --
// callers must print/display it immediately. created reports whether a new
// token was generated (false means a token row already existed, whether or
// not it has since been claimed).
func InitSetupToken(db DBTX, now time.Time) (token string, created bool, err error) {
	var existing int
	err = db.QueryRow(`SELECT COUNT(*) FROM setup_tokens WHERE id = 1`).Scan(&existing)
	if err != nil {
		return "", false, fmt.Errorf("store: checking for existing setup token: %w", err)
	}
	if existing > 0 {
		return "", false, nil
	}

	token, err = generateSetupToken()
	if err != nil {
		return "", false, err
	}

	_, err = db.Exec(
		`INSERT INTO setup_tokens (id, token_hash, created_at) VALUES (1, ?, ?)`,
		hashToken(token), formatTime(now),
	)
	if err != nil {
		return "", false, fmt.Errorf("store: storing setup token: %w", err)
	}
	return token, true, nil
}

func generateSetupToken() (string, error) {
	token, err := humancode.Generate(setupTokenSymbols)
	if err != nil {
		return "", fmt.Errorf("store: generating setup token: %w", err)
	}
	return token, nil
}

// NormalizeSetupToken makes a hand-retyped token match the canonical form
// used for hashing and comparison -- case, cosmetic separators and the
// digit/letter confusions the alphabet was chosen to avoid. See
// humancode.Normalize for exactly what is forgiven and why.
func NormalizeSetupToken(token string) string {
	return humancode.Normalize(token)
}

// ResetSetupToken deletes any existing setup token row, so the next
// InitSetupToken call generates a fresh one. Intended as an explicit
// operator escape hatch for a token that was lost (e.g. server restarted
// before the printed log line was saved) before it could be claimed.
func ResetSetupToken(db DBTX) error {
	if _, err := db.Exec(`DELETE FROM setup_tokens WHERE id = 1`); err != nil {
		return fmt.Errorf("store: resetting setup token: %w", err)
	}
	return nil
}

// ClaimSetupToken marks the setup token as used by accountID, if token
// (after normalization) matches the stored hash, hasn't already been used,
// and hasn't been locked out by too many failed attempts. It returns
// ErrInvalidToken for every failure case (wrong token, already used, locked
// out, or none exists) -- deliberately not distinguishing which, to avoid
// giving an attacker an oracle.
//
// This only attempts the claim -- it deliberately does NOT record a failed
// attempt itself. Callers that run this inside a transaction shared with
// other work (e.g. account/device creation) must call
// RecordFailedSetupTokenAttempt against a non-transactional DBTX (the raw
// *sql.DB, not that tx) when this returns ErrInvalidToken; otherwise a
// rollback on failure -- the normal, correct behavior for the rest of the
// transaction -- would silently undo the failure count too, defeating the
// lockout that keeps a short token safe against online guessing (this
// endpoint has no other rate limiting).
func ClaimSetupToken(db DBTX, token, accountID string, now time.Time) error {
	normalized := NormalizeSetupToken(token)

	res, err := db.Exec(
		`UPDATE setup_tokens
		 SET used_at = ?, used_by_account_id = ?
		 WHERE id = 1 AND token_hash = ? AND used_at IS NULL AND failed_attempts < ?`,
		formatTime(now), accountID, hashToken(normalized), MaxSetupTokenAttempts,
	)
	if err != nil {
		return fmt.Errorf("store: claiming setup token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for setup token claim: %w", err)
	}
	if n > 0 {
		return nil
	}
	return ErrInvalidToken
}

// RecordFailedSetupTokenAttempt increments the setup token's failed-attempt
// counter (a no-op if the token has already been claimed). Must be called
// against a DBTX that commits independently of whatever transaction the
// failed ClaimSetupToken call ran in -- see its doc comment.
func RecordFailedSetupTokenAttempt(db DBTX) error {
	if _, err := db.Exec(
		`UPDATE setup_tokens SET failed_attempts = failed_attempts + 1 WHERE id = 1 AND used_at IS NULL`,
	); err != nil {
		return fmt.Errorf("store: recording failed setup token attempt: %w", err)
	}
	return nil
}

// SetupTokenClaimed reports whether the setup token has already been used.
// It returns (false, nil) if no setup token row exists at all.
func SetupTokenClaimed(db DBTX) (bool, error) {
	var usedAt sql.NullString
	err := db.QueryRow(`SELECT used_at FROM setup_tokens WHERE id = 1`).Scan(&usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: checking setup token claim status: %w", err)
	}
	return usedAt.Valid, nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
