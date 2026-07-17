package store

import (
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	AccountStatusActive   = "active"
	AccountStatusDisabled = "disabled"
)

// Account is an account's public identity record: its root public key and
// bookkeeping fields. It never stores anything secret.
type Account struct {
	ID            string
	RootPubKey    ed25519.PublicKey
	VersionMarker int
	Status        string
	IsAdmin       bool
	CreatedAt     time.Time
}

// CreateAccount inserts a new account. It returns ErrConflict if the id is
// already taken.
func CreateAccount(db DBTX, acc Account) error {
	_, err := db.Exec(
		`INSERT INTO accounts (id, root_pubkey, version_marker, status, is_admin, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		acc.ID, []byte(acc.RootPubKey), acc.VersionMarker, acc.Status, boolToInt(acc.IsAdmin), formatTime(acc.CreatedAt),
	)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: account %s", ErrConflict, acc.ID)
		}
		return fmt.Errorf("store: creating account: %w", err)
	}
	return nil
}

// GetAccount looks up an account by id. It returns ErrNotFound if no such
// account exists.
func GetAccount(db DBTX, id string) (*Account, error) {
	row := db.QueryRow(
		`SELECT id, root_pubkey, version_marker, status, is_admin, created_at FROM accounts WHERE id = ?`,
		id,
	)
	return scanAccount(row)
}

func scanAccount(row *sql.Row) (*Account, error) {
	var acc Account
	var pubkey []byte
	var isAdmin int
	var createdAt string

	if err := row.Scan(&acc.ID, &pubkey, &acc.VersionMarker, &acc.Status, &isAdmin, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scanning account: %w", err)
	}

	acc.RootPubKey = ed25519.PublicKey(pubkey)
	acc.IsAdmin = isAdmin != 0

	t, err := parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("store: parsing account created_at: %w", err)
	}
	acc.CreatedAt = t

	return &acc, nil
}

// AnyAdminExists reports whether an admin account has already been created,
// used to guard the one-time bootstrap claim.
func AnyAdminExists(db DBTX) (bool, error) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE is_admin = 1`).Scan(&count); err != nil {
		return false, fmt.Errorf("store: checking for existing admin: %w", err)
	}
	return count > 0, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// isUniqueConstraintErr reports whether err came from a SQLite UNIQUE (or
// PRIMARY KEY) constraint violation. Matching on message text is unglamorous
// but is the portable option across sqlite driver versions.
func isUniqueConstraintErr(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}
