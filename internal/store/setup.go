package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const setupTokenBytes = 32

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

	raw := make([]byte, setupTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", false, fmt.Errorf("store: generating setup token: %w", err)
	}
	token = hex.EncodeToString(raw)

	_, err = db.Exec(
		`INSERT INTO setup_tokens (id, token_hash, created_at) VALUES (1, ?, ?)`,
		hashToken(token), formatTime(now),
	)
	if err != nil {
		return "", false, fmt.Errorf("store: storing setup token: %w", err)
	}
	return token, true, nil
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
// matches the stored hash and hasn't already been used. It returns
// ErrInvalidToken otherwise (wrong token, already used, or none exists) --
// deliberately not distinguishing which, to avoid giving an attacker an
// oracle.
func ClaimSetupToken(db DBTX, token, accountID string, now time.Time) error {
	res, err := db.Exec(
		`UPDATE setup_tokens SET used_at = ?, used_by_account_id = ? WHERE id = 1 AND token_hash = ? AND used_at IS NULL`,
		formatTime(now), accountID, hashToken(token),
	)
	if err != nil {
		return fmt.Errorf("store: claiming setup token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for setup token claim: %w", err)
	}
	if n == 0 {
		return ErrInvalidToken
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
