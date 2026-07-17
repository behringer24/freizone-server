package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const inviteCodeBytes = 16

// InviteCode is a single-use registration invite issued by an admin.
type InviteCode struct {
	Code               string
	CreatedByAccountID string
	CreatedAt          time.Time
	ExpiresAt          *time.Time
	UsedAt             *time.Time
	UsedByAccountID    *string
}

// CreateInviteCode generates and stores a new single-use invite code.
// expiresAt may be nil for a code that never expires.
func CreateInviteCode(db DBTX, createdByAccountID string, expiresAt *time.Time, now time.Time) (string, error) {
	raw := make([]byte, inviteCodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: generating invite code: %w", err)
	}
	code := hex.EncodeToString(raw)

	var expiresAtStr any
	if expiresAt != nil {
		expiresAtStr = formatTime(*expiresAt)
	}

	_, err := db.Exec(
		`INSERT INTO invite_codes (code, created_by_account_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		code, createdByAccountID, formatTime(now), expiresAtStr,
	)
	if err != nil {
		return "", fmt.Errorf("store: storing invite code: %w", err)
	}
	return code, nil
}

// GetInviteCode looks up an invite code. It returns ErrNotFound if no such
// code exists.
func GetInviteCode(db DBTX, code string) (*InviteCode, error) {
	row := db.QueryRow(
		`SELECT code, created_by_account_id, created_at, expires_at, used_at, used_by_account_id
		 FROM invite_codes WHERE code = ?`,
		code,
	)

	var inv InviteCode
	var createdAt string
	var expiresAt, usedAt, usedBy sql.NullString

	if err := row.Scan(&inv.Code, &inv.CreatedByAccountID, &createdAt, &expiresAt, &usedAt, &usedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scanning invite code: %w", err)
	}

	t, err := parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("store: parsing invite code created_at: %w", err)
	}
	inv.CreatedAt = t

	if expiresAt.Valid {
		t, err := parseTime(expiresAt.String)
		if err != nil {
			return nil, fmt.Errorf("store: parsing invite code expires_at: %w", err)
		}
		inv.ExpiresAt = &t
	}
	if usedAt.Valid {
		t, err := parseTime(usedAt.String)
		if err != nil {
			return nil, fmt.Errorf("store: parsing invite code used_at: %w", err)
		}
		inv.UsedAt = &t
	}
	if usedBy.Valid {
		inv.UsedByAccountID = &usedBy.String
	}

	return &inv, nil
}

// ConsumeInviteCode atomically redeems an invite code for usedByAccountID.
// It returns ErrNotFound, ErrInviteAlreadyUsed, or ErrInviteExpired as
// appropriate.
func ConsumeInviteCode(db DBTX, code, usedByAccountID string, now time.Time) error {
	res, err := db.Exec(
		`UPDATE invite_codes SET used_at = ?, used_by_account_id = ?
		 WHERE code = ? AND used_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
		formatTime(now), usedByAccountID, code, formatTime(now),
	)
	if err != nil {
		return fmt.Errorf("store: consuming invite code: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for invite code: %w", err)
	}
	if n > 0 {
		return nil
	}

	inv, err := GetInviteCode(db, code)
	if err != nil {
		return err
	}
	if inv.UsedAt != nil {
		return ErrInviteAlreadyUsed
	}
	if inv.ExpiresAt != nil && !inv.ExpiresAt.After(now) {
		return ErrInviteExpired
	}
	return ErrInviteAlreadyUsed
}
