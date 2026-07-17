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

// Role is an account's server-wide privilege level. Admins have full
// control (registration policy, the user list, granting/revoking roles,
// blocking/deleting accounts, invites); moderators get a restricted subset
// (view the user list, create invites) and can never touch roles or
// account status themselves -- only an admin can promote/demote/block/
// delete, so privilege escalation stays admin-only.
type Role string

const (
	RoleUser      Role = "user"
	RoleModerator Role = "moderator"
	RoleAdmin     Role = "admin"
)

// ParseRole validates s against the known role values.
func ParseRole(s string) (Role, bool) {
	switch Role(s) {
	case RoleUser, RoleModerator, RoleAdmin:
		return Role(s), true
	default:
		return "", false
	}
}

// Account is an account's public identity record: its root public key and
// bookkeeping fields. It never stores anything secret.
type Account struct {
	ID            string
	RootPubKey    ed25519.PublicKey
	VersionMarker int
	Status        string
	Role          Role
	CreatedAt     time.Time
}

// CreateAccount inserts a new account. It returns ErrConflict if the id is
// already taken.
func CreateAccount(db DBTX, acc Account) error {
	_, err := db.Exec(
		`INSERT INTO accounts (id, root_pubkey, version_marker, status, role, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		acc.ID, []byte(acc.RootPubKey), acc.VersionMarker, acc.Status, string(acc.Role), formatTime(acc.CreatedAt),
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
		`SELECT id, root_pubkey, version_marker, status, role, created_at FROM accounts WHERE id = ?`,
		id,
	)
	return scanAccount(row)
}

// ListAccounts returns every account, oldest first.
func ListAccounts(db DBTX) ([]Account, error) {
	rows, err := db.Query(`SELECT id, root_pubkey, version_marker, status, role, created_at FROM accounts ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: listing accounts: %w", err)
	}
	defer rows.Close()

	var accounts []Account
	for rows.Next() {
		var acc Account
		var pubkey []byte
		var role, createdAt string
		if err := rows.Scan(&acc.ID, &pubkey, &acc.VersionMarker, &acc.Status, &role, &createdAt); err != nil {
			return nil, fmt.Errorf("store: scanning account: %w", err)
		}
		acc.RootPubKey = ed25519.PublicKey(pubkey)
		acc.Role = Role(role)
		t, err := parseTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("store: parsing account created_at: %w", err)
		}
		acc.CreatedAt = t
		accounts = append(accounts, acc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listing accounts: %w", err)
	}
	return accounts, nil
}

func scanAccount(row *sql.Row) (*Account, error) {
	var acc Account
	var pubkey []byte
	var role string
	var createdAt string

	if err := row.Scan(&acc.ID, &pubkey, &acc.VersionMarker, &acc.Status, &role, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scanning account: %w", err)
	}

	acc.RootPubKey = ed25519.PublicKey(pubkey)
	acc.Role = Role(role)

	t, err := parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("store: parsing account created_at: %w", err)
	}
	acc.CreatedAt = t

	return &acc, nil
}

// SetAccountRole changes an account's role. Callers are responsible for
// any "would this leave zero active admins" check (see CountActiveAdmins)
// before calling this -- it applies the change unconditionally.
func SetAccountRole(db DBTX, id string, role Role) error {
	res, err := db.Exec(`UPDATE accounts SET role = ? WHERE id = ?`, string(role), id)
	if err != nil {
		return fmt.Errorf("store: setting account role: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for role update: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetAccountStatus changes an account's status (AccountStatusActive /
// AccountStatusDisabled) -- this is what blocking/unblocking an account
// does. Enforced by internal/auth's Middleware, which rejects requests
// from a non-active account.
func SetAccountStatus(db DBTX, id, status string) error {
	res, err := db.Exec(`UPDATE accounts SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return fmt.Errorf("store: setting account status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for status update: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteAccount permanently removes an account. Cascades (via foreign
// keys) through its devices to their prekeys and queued messages-as-
// recipient, and through invite_codes it created (deleted) or used
// (used_by_account_id cleared) -- see migrations/0005 for the FK clauses
// that make this safe.
func DeleteAccount(db DBTX, id string) error {
	res, err := db.Exec(`DELETE FROM accounts WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: deleting account: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for account delete: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountActiveAdmins reports how many accounts currently have RoleAdmin and
// AccountStatusActive. Used as the shared "would this leave the server
// with zero usable admins" guard before demoting, blocking, or deleting
// an account -- and, historically, to gate the one-time bootstrap claim
// (see internal/api/bootstrap.go for why that gate was removed).
func CountActiveAdmins(db DBTX) (int, error) {
	var count int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM accounts WHERE role = ? AND status = ?`,
		string(RoleAdmin), AccountStatusActive,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("store: counting active admins: %w", err)
	}
	return count, nil
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
