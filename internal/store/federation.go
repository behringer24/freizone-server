package store

import (
	"database/sql"
	"fmt"
	"time"
)

// FederationBlockEntry is one blocked remote account, for admin display.
type FederationBlockEntry struct {
	AccountID string
	BlockedAt time.Time
	BlockedBy string
	Reason    *string
}

// IsFederationBlocked reports whether accountID is on this server's
// federation blocklist.
func IsFederationBlocked(db DBTX, accountID string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(1) FROM federation_blocklist WHERE account_id = ?`, accountID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: checking federation blocklist: %w", err)
	}
	return n > 0, nil
}

// BlockFederationSender adds accountID to the federation blocklist, or
// replaces the existing entry (re-blocking with a new reason/blockedBy is
// fine -- idempotent, not an error).
func BlockFederationSender(db DBTX, accountID, blockedBy string, reason *string, blockedAt time.Time) error {
	_, err := db.Exec(
		`INSERT INTO federation_blocklist (account_id, blocked_at, blocked_by, reason) VALUES (?, ?, ?, ?)
		 ON CONFLICT(account_id) DO UPDATE SET blocked_at = excluded.blocked_at, blocked_by = excluded.blocked_by, reason = excluded.reason`,
		accountID, formatTime(blockedAt), blockedBy, reason,
	)
	if err != nil {
		return fmt.Errorf("store: blocking federation sender: %w", err)
	}
	return nil
}

// UnblockFederationSender removes accountID from the federation
// blocklist. It returns ErrNotFound if it wasn't blocked.
func UnblockFederationSender(db DBTX, accountID string) error {
	res, err := db.Exec(`DELETE FROM federation_blocklist WHERE account_id = ?`, accountID)
	if err != nil {
		return fmt.Errorf("store: unblocking federation sender: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for federation unblock: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListFederationBlocklist returns every blocked account, most recently
// blocked first.
func ListFederationBlocklist(db DBTX) ([]FederationBlockEntry, error) {
	rows, err := db.Query(`SELECT account_id, blocked_at, blocked_by, reason FROM federation_blocklist ORDER BY blocked_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: listing federation blocklist: %w", err)
	}
	defer rows.Close()

	var entries []FederationBlockEntry
	for rows.Next() {
		var e FederationBlockEntry
		var blockedAt string
		var reason sql.NullString
		if err := rows.Scan(&e.AccountID, &blockedAt, &e.BlockedBy, &reason); err != nil {
			return nil, fmt.Errorf("store: scanning federation blocklist entry: %w", err)
		}
		t, err := parseTime(blockedAt)
		if err != nil {
			return nil, fmt.Errorf("store: parsing federation blocklist blocked_at: %w", err)
		}
		e.BlockedAt = t
		if reason.Valid {
			e.Reason = &reason.String
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
