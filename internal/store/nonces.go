package store

import (
	"fmt"
	"time"
)

// RecordNonce attempts to record a (device_id, nonce) pair as used. It
// returns ok=true if this is the first time the pair has been seen, and
// ok=false if it was already recorded (i.e. a replay).
func RecordNonce(db DBTX, deviceID, nonce string, requestTimestamp, expiresAt time.Time) (ok bool, err error) {
	res, err := db.Exec(
		`INSERT OR IGNORE INTO used_nonces (device_id, nonce, request_timestamp, expires_at) VALUES (?, ?, ?, ?)`,
		deviceID, nonce, formatTime(requestTimestamp), formatTime(expiresAt),
	)
	if err != nil {
		return false, fmt.Errorf("store: recording nonce: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: checking rows affected for nonce: %w", err)
	}
	return n > 0, nil
}

// PurgeExpiredNonces deletes all nonce records whose expiry has passed,
// returning the number of rows removed. Intended to be called periodically
// (e.g. from a ticker) to keep the table small.
func PurgeExpiredNonces(db DBTX, now time.Time) (int64, error) {
	res, err := db.Exec(`DELETE FROM used_nonces WHERE expires_at < ?`, formatTime(now))
	if err != nil {
		return 0, fmt.Errorf("store: purging expired nonces: %w", err)
	}
	return res.RowsAffected()
}
