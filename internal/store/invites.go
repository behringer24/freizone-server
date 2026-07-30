package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/behringer24/freizone-server/pkg/humancode"
)

// inviteCodeSymbols * 5 bits = 60 bits of entropy, deliberately longer than
// the 8-symbol setup token (see setupTokenSymbols) even though both are
// hand-typed secrets in the same alphabet. The token's shortness is bought
// by a lockout counter; none of that is available here:
//
//   - Many invite codes are outstanding at once, and any unused one grants
//     registration. A guesser doesn't have to hit a *particular* code, so
//     every additional outstanding code shaves a bit off the effective
//     strength.
//   - A per-code lockout is therefore meaningless -- a failed guess
//     identifies no code to lock -- and the registration endpoint has no
//     rate limiting of its own.
//
// So the length has to do the work the token's lockout does. At 60 bits it
// does so comfortably: even with dozens of codes outstanding and an
// implausibly fast guesser, the expected search dwarfs any code's lifetime.
const inviteCodeSymbols = 12

// inviteCodeGroup is how a code is grouped for display and sharing:
// "ABCD-EFGH-JKMN". Purely cosmetic -- humancode.Normalize strips it again,
// so a code works typed with or without the hyphens.
const inviteCodeGroup = 4

// InviteCode is a single-use registration invite issued by an admin or
// moderator. There is deliberately no plaintext code field: only a hash of
// the code is ever stored (see CreateInviteCode), so a lookup can confirm a
// code but never reproduce one.
type InviteCode struct {
	CreatedByAccountID string
	CreatedAt          time.Time
	ExpiresAt          *time.Time
	UsedAt             *time.Time
	UsedByAccountID    *string
}

// CreateInviteCode generates and stores a new single-use invite code,
// returning it in its grouped display form. expiresAt may be nil for a code
// that never expires -- callers are expected to pass the operator's
// configured default rather than nil (see internal/api's invite handler);
// nil here means "no expiry at all", which only exists as an explicit
// operator choice.
//
// Only a SHA-256 hash of the normalized code is persisted, exactly as for
// the setup token: a leaked database then yields no working invites, and
// since there is no endpoint that lists codes, nothing needs the plaintext
// after this call returns. The flip side is that a code cannot be shown
// again later -- a lost one has to be reissued.
func CreateInviteCode(db DBTX, createdByAccountID string, expiresAt *time.Time, now time.Time) (string, error) {
	code, err := humancode.Generate(inviteCodeSymbols)
	if err != nil {
		return "", fmt.Errorf("store: generating invite code: %w", err)
	}

	var expiresAtStr any
	if expiresAt != nil {
		expiresAtStr = formatTime(*expiresAt)
	}

	if _, err := db.Exec(
		`INSERT INTO invite_codes (code_hash, created_by_account_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		hashToken(code), createdByAccountID, formatTime(now), expiresAtStr,
	); err != nil {
		return "", fmt.Errorf("store: storing invite code: %w", err)
	}
	return humancode.Format(code, inviteCodeGroup), nil
}

// inviteCodeHash normalizes whatever was typed or scanned and hashes it the
// same way CreateInviteCode did, so lookups are case-insensitive and
// indifferent to grouping hyphens.
func inviteCodeHash(code string) string {
	return hashToken(humancode.Normalize(code))
}

// GetInviteCode looks up an invite code, accepting it in any form a person
// might have typed it (see humancode.Normalize). It returns ErrNotFound if
// no such code exists.
func GetInviteCode(db DBTX, code string) (*InviteCode, error) {
	row := db.QueryRow(
		`SELECT created_by_account_id, created_at, expires_at, used_at, used_by_account_id
		 FROM invite_codes WHERE code_hash = ?`,
		inviteCodeHash(code),
	)

	var inv InviteCode
	var createdAt string
	var expiresAt, usedAt, usedBy sql.NullString

	if err := row.Scan(&inv.CreatedByAccountID, &createdAt, &expiresAt, &usedAt, &usedBy); err != nil {
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

// ConsumeInviteCode atomically redeems an invite code for usedByAccountID,
// accepting it in any form a person might have typed it (see
// humancode.Normalize). It returns ErrNotFound, ErrInviteAlreadyUsed, or
// ErrInviteExpired as appropriate.
func ConsumeInviteCode(db DBTX, code, usedByAccountID string, now time.Time) error {
	res, err := db.Exec(
		`UPDATE invite_codes SET used_at = ?, used_by_account_id = ?
		 WHERE code_hash = ? AND used_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
		formatTime(now), usedByAccountID, inviteCodeHash(code), formatTime(now),
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
