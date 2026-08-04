package store

import (
	"database/sql"
	"fmt"
	"time"
)

// AccountActivity is what the Server Admin user list needs to tell an account
// that is in use apart from one that was abandoned (SRV-09): how much is
// waiting undelivered for it, since when, and how much attachment storage it
// occupies.
//
// Aggregate counts only -- deliberately nothing about *who* an account talks
// to or what it sends. This is the material an operator needs to clean up a
// server, and it stops exactly there.
type AccountActivity struct {
	// PendingMessages is how many messages are queued across all of the
	// account's devices, and OldestPendingAt when the earliest of them was
	// sent (zero when there are none). Age is the useful signal: a large
	// queue that is minutes old is a busy account, the same queue three weeks
	// old is a device that never came back.
	PendingMessages int
	OldestPendingAt time.Time

	// BlobCount / BlobBytes are the account's stored attachment ciphertext
	// (SRV-07), summed across its devices.
	BlobCount int
	BlobBytes int64

	// DeviceCount is every device row the account has, revoked ones included.
	// The blob quota is enforced per device (config.MaxBlobBytesPerDevice), so
	// this is the multiplier that turns it into the account's real ceiling --
	// and it has to include revoked devices, because a revoked device keeps
	// its blobs until the row itself is deleted. Counting only active ones
	// could put usage above the limit it is displayed against.
	DeviceCount int
}

// AccountActivityByAccount returns the activity summary for every account that
// has any, keyed by account id. Accounts with nothing queued, no attachments
// and no devices are simply absent -- callers should treat a missing entry as
// the zero value.
//
// Two aggregate queries for the whole server, not one pair per account: the
// admin list is unpaginated, so anything per-account here would be an N+1 over
// however many accounts exist. Deliberately not built on ListPendingMessages
// either -- that one is per-device and materializes every payload, which is
// the last thing a summary count should do.
func AccountActivityByAccount(db DBTX) (map[string]AccountActivity, error) {
	activity := make(map[string]AccountActivity)

	// sent_at is RFC3339 in UTC throughout (see formatTime), so it is
	// fixed-width with a 'Z' suffix and lexical MIN is chronological MIN --
	// the same assumption ListPendingMessages' ORDER BY already makes.
	rows, err := db.Query(
		`SELECT recipient_account_id, COUNT(1), MIN(sent_at)
		   FROM messages GROUP BY recipient_account_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("store: aggregating pending messages: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var accountID string
		var count int
		var oldest sql.NullString
		if err := rows.Scan(&accountID, &count, &oldest); err != nil {
			return nil, fmt.Errorf("store: scanning pending message stats: %w", err)
		}
		entry := activity[accountID]
		entry.PendingMessages = count
		if oldest.Valid {
			t, err := parseTime(oldest.String)
			if err != nil {
				return nil, fmt.Errorf("store: parsing oldest pending sent_at: %w", err)
			}
			entry.OldestPendingAt = t
		}
		activity[accountID] = entry
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: aggregating pending messages: %w", err)
	}

	// LEFT JOIN so an account with devices but no attachments still reports
	// its device count -- which is what the quota is measured against, so
	// dropping it would leave the usage figure without a denominator. The
	// join multiplies device rows by their blobs, hence COUNT(DISTINCT) for
	// devices and COUNT over the blob id (which skips the NULLs) for blobs.
	//
	// Reached through blob_recipients since SRV-18, so a blob shared with
	// several members counts once per recipient device -- the same figure the
	// quota is enforced on, which is the point of showing it.
	blobRows, err := db.Query(
		`SELECT d.account_id, COUNT(DISTINCT d.device_id), COUNT(b.blob_id), COALESCE(SUM(b.size_bytes), 0)
		   FROM devices d
		   LEFT JOIN blob_recipients r ON r.recipient_device_id = d.device_id
		   LEFT JOIN blobs b ON b.blob_id = r.blob_id
		  GROUP BY d.account_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("store: aggregating blob usage: %w", err)
	}
	defer blobRows.Close()

	for blobRows.Next() {
		var accountID string
		var deviceCount, blobCount int
		var blobBytes int64
		if err := blobRows.Scan(&accountID, &deviceCount, &blobCount, &blobBytes); err != nil {
			return nil, fmt.Errorf("store: scanning blob usage stats: %w", err)
		}
		entry := activity[accountID]
		entry.DeviceCount = deviceCount
		entry.BlobCount = blobCount
		entry.BlobBytes = blobBytes
		activity[accountID] = entry
	}
	if err := blobRows.Err(); err != nil {
		return nil, fmt.Errorf("store: aggregating blob usage: %w", err)
	}

	return activity, nil
}

// InviterByAccount maps each account that joined with an invite to the account
// that issued it (SRV-14), for accounts where both sides still exist.
//
// Absent for an account that registered under an open policy -- there was no
// invite -- and, importantly, also for one whose *inviter* has since been
// deleted: `invite_codes.created_by_account_id` cascades, so the row goes with
// them and the origin is gone for good. Callers must treat a missing entry as
// "not known", never as "nobody".
//
// The one place the server holds a link between two accounts, so it is read
// only where that is the point: exposed to admins alone (see
// handleListAccounts), and never joined against anything else.
func InviterByAccount(db DBTX) (map[string]string, error) {
	rows, err := db.Query(
		`SELECT used_by_account_id, created_by_account_id
		   FROM invite_codes WHERE used_by_account_id IS NOT NULL`,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing invite origins: %w", err)
	}
	defer rows.Close()

	inviters := make(map[string]string)
	for rows.Next() {
		var invitee, inviter string
		if err := rows.Scan(&invitee, &inviter); err != nil {
			return nil, fmt.Errorf("store: scanning invite origin: %w", err)
		}
		inviters[invitee] = inviter
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listing invite origins: %w", err)
	}
	return inviters, nil
}
