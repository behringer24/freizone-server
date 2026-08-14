package store

import (
	"database/sql"
	"fmt"
	"time"
)

// StatsSnapshot is one measurement of server size/load for the admin
// statistics page (see docs -- "how belastet ist der Server, ist er
// gesund"): how many accounts/devices/blobs/messages exist right now, how
// much storage they occupy, and how full the disk is.
//
// DiskFreeBytes/DiskTotalBytes and DBBytes are filled in by the caller
// (internal/api/stats.go, cmd/server/main.go's snapshot ticker) rather than
// by ComputeCurrentStats below -- they come from the filesystem, not the
// database, and store deliberately has no filesystem dependency.
//
// FederationEnabled, by contrast, IS read by ComputeCurrentStats: it is the
// runtime-mutable server_settings value (store.GetFederationEnabled), the
// same one GET /v1/admin/federation reports -- not the config.go env var,
// which is only ever the seed for that setting's first boot.
type StatsSnapshot struct {
	ID         int64
	CapturedAt time.Time

	AccountCount       int
	ActiveAccountCount int
	DeviceCount        int

	BlobCount int
	BlobBytes int64
	DBBytes   int64

	// PendingMessageCount is simply every row in messages: that table is
	// queue storage, not a log, so nothing here has to distinguish
	// "pending" from "total" (see the migration's comment).
	PendingMessageCount int

	DiskFreeBytes  int64
	DiskTotalBytes int64

	FederationEnabled         bool
	FederationBlocklistCount int
}

// ComputeCurrentStats gathers a fresh StatsSnapshot from the database alone
// (DiskFreeBytes, DiskTotalBytes and DBBytes are left at their zero value --
// the caller fills those in from the filesystem).
func ComputeCurrentStats(db DBTX) (StatsSnapshot, error) {
	var s StatsSnapshot

	federationEnabled, err := GetFederationEnabled(db)
	if err != nil {
		return StatsSnapshot{}, err
	}
	s.FederationEnabled = federationEnabled

	if err := db.QueryRow(
		`SELECT COUNT(*), COUNT(CASE WHEN status = ? THEN 1 END) FROM accounts`,
		AccountStatusActive,
	).Scan(&s.AccountCount, &s.ActiveAccountCount); err != nil {
		return StatsSnapshot{}, fmt.Errorf("store: counting accounts for stats: %w", err)
	}

	if err := db.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&s.DeviceCount); err != nil {
		return StatsSnapshot{}, fmt.Errorf("store: counting devices for stats: %w", err)
	}

	if err := db.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM blobs`,
	).Scan(&s.BlobCount, &s.BlobBytes); err != nil {
		return StatsSnapshot{}, fmt.Errorf("store: aggregating blobs for stats: %w", err)
	}

	if err := db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&s.PendingMessageCount); err != nil {
		return StatsSnapshot{}, fmt.Errorf("store: counting messages for stats: %w", err)
	}

	if err := db.QueryRow(`SELECT COUNT(*) FROM federation_blocklist`).Scan(&s.FederationBlocklistCount); err != nil {
		return StatsSnapshot{}, fmt.Errorf("store: counting federation blocklist for stats: %w", err)
	}

	return s, nil
}

// InsertStatsSnapshot records s as a new row in stats_snapshots. Callers are
// expected to have already filled in the filesystem-derived fields
// (DBBytes, DiskFreeBytes, DiskTotalBytes) -- see ComputeCurrentStats's doc
// comment.
func InsertStatsSnapshot(db DBTX, s StatsSnapshot) error {
	_, err := db.Exec(
		`INSERT INTO stats_snapshots (
			captured_at, account_count, active_account_count, device_count,
			blob_count, blob_bytes, db_bytes, pending_message_count,
			disk_free_bytes, disk_total_bytes,
			federation_enabled, federation_blocklist_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		formatTime(s.CapturedAt), s.AccountCount, s.ActiveAccountCount, s.DeviceCount,
		s.BlobCount, s.BlobBytes, s.DBBytes, s.PendingMessageCount,
		s.DiskFreeBytes, s.DiskTotalBytes,
		boolToInt(s.FederationEnabled), s.FederationBlocklistCount,
	)
	if err != nil {
		return fmt.Errorf("store: inserting stats snapshot: %w", err)
	}
	return nil
}

// StatsHistory returns every snapshot captured at or after since, oldest
// first -- the series a history chart plots.
func StatsHistory(db DBTX, since time.Time) ([]StatsSnapshot, error) {
	rows, err := db.Query(
		`SELECT id, captured_at, account_count, active_account_count, device_count,
			blob_count, blob_bytes, db_bytes, pending_message_count,
			disk_free_bytes, disk_total_bytes,
			federation_enabled, federation_blocklist_count
		   FROM stats_snapshots
		  WHERE captured_at >= ?
		  ORDER BY captured_at ASC`,
		formatTime(since),
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing stats history: %w", err)
	}
	defer rows.Close()

	var history []StatsSnapshot
	for rows.Next() {
		s, err := scanStatsSnapshot(rows)
		if err != nil {
			return nil, err
		}
		history = append(history, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listing stats history: %w", err)
	}
	return history, nil
}

func scanStatsSnapshot(rows *sql.Rows) (StatsSnapshot, error) {
	var s StatsSnapshot
	var capturedAt string
	var federationEnabled int64
	if err := rows.Scan(
		&s.ID, &capturedAt, &s.AccountCount, &s.ActiveAccountCount, &s.DeviceCount,
		&s.BlobCount, &s.BlobBytes, &s.DBBytes, &s.PendingMessageCount,
		&s.DiskFreeBytes, &s.DiskTotalBytes,
		&federationEnabled, &s.FederationBlocklistCount,
	); err != nil {
		return StatsSnapshot{}, fmt.Errorf("store: scanning stats snapshot: %w", err)
	}
	s.FederationEnabled = federationEnabled != 0
	t, err := parseTime(capturedAt)
	if err != nil {
		return StatsSnapshot{}, fmt.Errorf("store: parsing stats snapshot captured_at: %w", err)
	}
	s.CapturedAt = t
	return s, nil
}

// BlobExpiryBucket is how much stored attachment ciphertext expires on one
// calendar day (UTC), for the storage forecast on the admin statistics page.
type BlobExpiryBucket struct {
	// Day is the UTC date the bytes expire on, as "2006-01-02".
	Day   string
	Bytes int64
	Count int
}

// BlobExpiryBuckets reports what expires when, oldest first. Days already past
// come back too: a blob whose window closed is still on disk until the cleanup
// ticker's next pass, so leaving it out would understate what is stored.
//
// One grouped query rather than one per day: a blob expires within
// BlobRetentionDays of its upload, so there are only ever about that many
// distinct days to return, however many blobs there are. Grouping by the date
// prefix works because expires_at is fixed-width RFC3339 in UTC throughout
// (see formatTime) -- the same property ListExpiredBlobs' range comparison
// already relies on.
func BlobExpiryBuckets(db DBTX) ([]BlobExpiryBucket, error) {
	rows, err := db.Query(
		`SELECT substr(expires_at, 1, 10) AS day, COALESCE(SUM(size_bytes), 0), COUNT(1)
		   FROM blobs
		  GROUP BY day
		  ORDER BY day ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("store: aggregating blob expiry: %w", err)
	}
	defer rows.Close()

	var buckets []BlobExpiryBucket
	for rows.Next() {
		var b BlobExpiryBucket
		if err := rows.Scan(&b.Day, &b.Bytes, &b.Count); err != nil {
			return nil, fmt.Errorf("store: scanning blob expiry bucket: %w", err)
		}
		buckets = append(buckets, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: aggregating blob expiry: %w", err)
	}
	return buckets, nil
}

// BlobBytesCreatedSince reports how much attachment ciphertext was stored since
// a point in time -- the measured upload rate the forecast extrapolates from.
//
// Exact only while the window is shorter than the retention period, because
// nothing uploaded inside it can have expired yet; callers pick the window with
// that in mind rather than assuming any span is safe.
func BlobBytesCreatedSince(db DBTX, since time.Time) (int64, error) {
	var bytes int64
	if err := db.QueryRow(
		`SELECT COALESCE(SUM(size_bytes), 0) FROM blobs WHERE created_at >= ?`,
		formatTime(since),
	).Scan(&bytes); err != nil {
		return 0, fmt.Errorf("store: summing recently created blobs: %w", err)
	}
	return bytes, nil
}

// PruneStatsSnapshots deletes every snapshot captured before olderThan and
// reports how many rows were removed. Run periodically by the snapshot
// ticker (cmd/server/main.go) to bound the table to its retention window --
// unlike messages/blobs, nothing else ever deletes from this table, so
// without this it would grow forever.
func PruneStatsSnapshots(db DBTX, olderThan time.Time) (int64, error) {
	res, err := db.Exec(`DELETE FROM stats_snapshots WHERE captured_at < ?`, formatTime(olderThan))
	if err != nil {
		return 0, fmt.Errorf("store: pruning stats snapshots: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: checking rows affected for stats snapshot prune: %w", err)
	}
	return n, nil
}
