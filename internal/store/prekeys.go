package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SignedPrekey is a device's current rotatable X3DH signed prekey. There is
// at most one per device; uploading a new one replaces it.
type SignedPrekey struct {
	DeviceID  string
	KeyID     uint32
	PubKey    []byte
	Signature []byte
	IssuedAt  time.Time
	CreatedAt time.Time
}

// UpsertSignedPrekey replaces the device's current signed prekey.
func UpsertSignedPrekey(db DBTX, sp SignedPrekey) error {
	_, err := db.Exec(
		`INSERT INTO signed_prekeys (device_id, key_id, pubkey, signature, issued_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(device_id) DO UPDATE SET
		   key_id = excluded.key_id, pubkey = excluded.pubkey, signature = excluded.signature,
		   issued_at = excluded.issued_at, created_at = excluded.created_at`,
		sp.DeviceID, sp.KeyID, sp.PubKey, sp.Signature, formatTime(sp.IssuedAt), formatTime(sp.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("store: upserting signed prekey: %w", err)
	}
	return nil
}

// GetSignedPrekey looks up a device's current signed prekey. It returns
// ErrNotFound if the device has never uploaded one.
func GetSignedPrekey(db DBTX, deviceID string) (*SignedPrekey, error) {
	row := db.QueryRow(
		`SELECT device_id, key_id, pubkey, signature, issued_at, created_at FROM signed_prekeys WHERE device_id = ?`,
		deviceID,
	)

	var sp SignedPrekey
	var issuedAt, createdAt string
	if err := row.Scan(&sp.DeviceID, &sp.KeyID, &sp.PubKey, &sp.Signature, &issuedAt, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scanning signed prekey: %w", err)
	}

	t, err := parseTime(issuedAt)
	if err != nil {
		return nil, fmt.Errorf("store: parsing signed prekey issued_at: %w", err)
	}
	sp.IssuedAt = t
	t, err = parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("store: parsing signed prekey created_at: %w", err)
	}
	sp.CreatedAt = t

	return &sp, nil
}

// OneTimePrekeyInput is one key to append to a device's one-time prekey
// pool.
type OneTimePrekeyInput struct {
	KeyID  uint32
	PubKey []byte
}

// AddOneTimePrekeys appends new one-time prekeys to a device's pool
// (existing, unclaimed keys are left untouched -- this is how a device
// replenishes its pool).
func AddOneTimePrekeys(db DBTX, deviceID string, keys []OneTimePrekeyInput, now time.Time) error {
	for _, k := range keys {
		if _, err := db.Exec(
			`INSERT INTO one_time_prekeys (device_id, key_id, pubkey, created_at) VALUES (?, ?, ?, ?)`,
			deviceID, k.KeyID, k.PubKey, formatTime(now),
		); err != nil {
			return fmt.Errorf("store: adding one-time prekey: %w", err)
		}
	}
	return nil
}

// ClaimedOneTimePrekey is a one-time prekey atomically removed from a
// device's pool for use by an X3DH initiator.
type ClaimedOneTimePrekey struct {
	KeyID  uint32
	PubKey []byte
}

// CountOneTimePrekeys returns how many unclaimed one-time prekeys remain in
// the device's pool, so a client (or the server, to decide whether to wake
// a dormant device) can tell when it's running low.
func CountOneTimePrekeys(db DBTX, deviceID string) (int, error) {
	var count int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = ?`,
		deviceID,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("store: counting one-time prekeys: %w", err)
	}
	return count, nil
}

// ClaimOneTimePrekey atomically removes and returns one one-time prekey
// from the device's pool, or (nil, nil) if the pool is empty -- an empty
// pool is a normal, expected condition (X3DH can proceed without one), not
// an error.
func ClaimOneTimePrekey(db DBTX, deviceID string) (*ClaimedOneTimePrekey, error) {
	row := db.QueryRow(
		`DELETE FROM one_time_prekeys
		 WHERE id = (SELECT id FROM one_time_prekeys WHERE device_id = ? ORDER BY id LIMIT 1)
		 RETURNING key_id, pubkey`,
		deviceID,
	)

	var claimed ClaimedOneTimePrekey
	if err := row.Scan(&claimed.KeyID, &claimed.PubKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: claiming one-time prekey: %w", err)
	}
	return &claimed, nil
}
