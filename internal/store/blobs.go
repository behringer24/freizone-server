package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Blob is the metadata for one uploaded, end-to-end-encrypted attachment
// (SRV-07). The ciphertext itself lives on disk (internal/blobstore); the
// server holds only what it needs to enforce ownership, quota and expiry --
// it can no more read a blob than it can read a message payload.
//
// Its recipients live in blob_recipients, one row each (SRV-18): a group
// picture is uploaded once per recipient *server* and fetched by every member
// there. Each recipient is charged the full size and may only fetch what was
// addressed to them, so the ownership rules are per recipient exactly as
// before -- what changed is that there may be more than one.
//
// Deliberately no sender field: the recipient learns who sent it from the
// message that carries the blob id, which is end-to-end encrypted. Recording
// it here would hand the server a plaintext sender/recipient pair it does not
// otherwise need.
type Blob struct {
	BlobID    string
	SizeBytes int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateBlob records an uploaded blob and the devices it was addressed to.
// Returns ErrConflict if BlobID is already in use (it is 32 random bytes, so
// only a bug or a replay).
//
// Two statements, so db should be a transaction: a blob row without its
// recipients is unreachable, and the file on disk would outlive any way of
// fetching it.
func CreateBlob(db DBTX, b Blob, recipientDeviceIDs []string) error {
	if len(recipientDeviceIDs) == 0 {
		return fmt.Errorf("store: creating blob %s: no recipients", b.BlobID)
	}
	_, err := db.Exec(
		`INSERT INTO blobs (blob_id, size_bytes, created_at, expires_at)
		 VALUES (?, ?, ?, ?)`,
		b.BlobID, b.SizeBytes, formatTime(b.CreatedAt), formatTime(b.ExpiresAt),
	)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: blob %s", ErrConflict, b.BlobID)
		}
		return fmt.Errorf("store: creating blob: %w", err)
	}

	for _, deviceID := range recipientDeviceIDs {
		if _, err := db.Exec(
			`INSERT INTO blob_recipients (blob_id, recipient_device_id) VALUES (?, ?)`,
			b.BlobID, deviceID,
		); err != nil {
			return fmt.Errorf("store: adding blob recipient: %w", err)
		}
	}
	return nil
}

// CreateBlobWithQuota records an uploaded blob for those of candidateDeviceIDs
// that still fit their per-device quota, re-checking that quota *inside* db's
// transaction. It returns the device ids actually stored and those refused for
// quota (count would reach maxBlobs, or bytes would exceed maxBytesPerDevice).
//
// This exists to close a TOCTOU window (security audit H3): the caller does a
// pre-flight quota check to size the upload, then streams the body -- which can
// take minutes -- and only then commits. Several uploads racing to the same
// device could each pass the pre-flight and all commit, blowing past the quota.
// Re-checking here, under the store's single-writer transaction (which
// serializes check-and-insert against every other upload), makes the decision
// authoritative at commit time.
//
// If no candidate fits, no blob row is written (a blob row with no recipients
// is unreachable) and stored is empty -- the caller removes the file it wrote.
// db must be a transaction.
func CreateBlobWithQuota(db DBTX, b Blob, candidateDeviceIDs []string, maxBlobs int, maxBytesPerDevice int64) (stored, quotaExceeded []string, err error) {
	for _, deviceID := range candidateDeviceIDs {
		count, totalBytes, err := BlobUsage(db, deviceID)
		if err != nil {
			return nil, nil, err
		}
		// Mirrors the pre-flight test in checkBlobRecipient exactly: a device
		// at its count cap, or one this blob would push over its byte cap, is
		// refused. totalBytes+size > limit is the headroom check restated.
		if count >= maxBlobs || totalBytes+b.SizeBytes > maxBytesPerDevice {
			quotaExceeded = append(quotaExceeded, deviceID)
			continue
		}
		stored = append(stored, deviceID)
	}
	if len(stored) == 0 {
		return nil, quotaExceeded, nil
	}
	if err := CreateBlob(db, b, stored); err != nil {
		return nil, nil, err
	}
	return stored, quotaExceeded, nil
}

// GetBlobForDevice looks up a blob, but only if it was addressed to
// recipientDeviceID -- returning ErrNotFound both for "no such blob" and
// "not yours", so a caller cannot probe which blob ids exist.
func GetBlobForDevice(db DBTX, blobID, recipientDeviceID string) (*Blob, error) {
	row := db.QueryRow(
		`SELECT b.blob_id, b.size_bytes, b.created_at, b.expires_at
		   FROM blobs b JOIN blob_recipients r ON r.blob_id = b.blob_id
		  WHERE b.blob_id = ? AND r.recipient_device_id = ?`,
		blobID, recipientDeviceID,
	)
	return scanBlob(row)
}

// BlobUsage reports how many blobs recipientDeviceID currently holds and
// their total size -- checked against the per-device caps before accepting
// an upload, the blob counterpart to CountPendingMessages. Both numbers come
// from one query since they are always needed together.
//
// A blob shared with other recipients counts in full here: the quota measures
// what this device may still fetch, not its share of the disk. Charging a
// fraction would let a sender multiply one device's effective allowance by
// naming co-recipients.
func BlobUsage(db DBTX, recipientDeviceID string) (count int, totalBytes int64, err error) {
	// COALESCE because SUM over no rows is NULL, not 0.
	row := db.QueryRow(
		`SELECT COUNT(1), COALESCE(SUM(b.size_bytes), 0)
		   FROM blob_recipients r JOIN blobs b ON b.blob_id = r.blob_id
		  WHERE r.recipient_device_id = ?`,
		recipientDeviceID,
	)
	if err := row.Scan(&count, &totalBytes); err != nil {
		return 0, 0, fmt.Errorf("store: counting blob usage: %w", err)
	}
	return count, totalBytes, nil
}

// DeleteBlobForDevice drops one recipient's claim on a blob, and the blob
// itself once that was the last claim -- reported as unreferenced, so the
// caller knows whether to remove the file. Returns ErrNotFound if there is no
// such blob for that device.
//
// Two statements again, so db should be a transaction: a blob left with no
// recipients but its row intact would be invisible to everyone and still
// occupy disk until the cleanup ticker noticed.
func DeleteBlobForDevice(db DBTX, blobID, recipientDeviceID string) (unreferenced bool, err error) {
	res, err := db.Exec(
		`DELETE FROM blob_recipients WHERE blob_id = ? AND recipient_device_id = ?`,
		blobID, recipientDeviceID,
	)
	if err != nil {
		return false, fmt.Errorf("store: deleting blob recipient: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: checking rows affected for blob deletion: %w", err)
	}
	if n == 0 {
		return false, ErrNotFound
	}

	var remaining int
	if err := db.QueryRow(
		`SELECT COUNT(1) FROM blob_recipients WHERE blob_id = ?`, blobID,
	).Scan(&remaining); err != nil {
		return false, fmt.Errorf("store: counting remaining blob recipients: %w", err)
	}
	if remaining > 0 {
		return false, nil
	}

	if _, err := db.Exec(`DELETE FROM blobs WHERE blob_id = ?`, blobID); err != nil {
		return false, fmt.Errorf("store: deleting blob: %w", err)
	}
	return true, nil
}

// ListExpiredBlobs returns up to limit blobs past their retention window.
//
// Batched, unlike the message queue's purge: each row here also owns a file
// that has to be unlinked, so the caller works through expired blobs in
// bounded chunks rather than loading an unbounded backlog at once -- the
// mistake ListPendingMessages makes, which this transport must not repeat at
// image sizes.
func ListExpiredBlobs(db DBTX, now time.Time, limit int) ([]Blob, error) {
	rows, err := db.Query(
		`SELECT blob_id, size_bytes, created_at, expires_at
		 FROM blobs WHERE expires_at < ? ORDER BY expires_at ASC LIMIT ?`,
		formatTime(now), limit,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing expired blobs: %w", err)
	}
	defer rows.Close()
	return scanBlobs(rows)
}

// ListUnreferencedBlobs returns up to limit blobs nobody is a recipient of
// any more.
//
// The ordinary DELETE path retires such a blob immediately
// (DeleteBlobForDevice), but a device removal reaches blob_recipients through
// an ON DELETE CASCADE, which cannot notice that it took the last claim with
// it. That is the backstop -- explicit first, swept second, the same split the
// orphan *file* sweep already uses.
func ListUnreferencedBlobs(db DBTX, limit int) ([]Blob, error) {
	rows, err := db.Query(
		`SELECT b.blob_id, b.size_bytes, b.created_at, b.expires_at
		   FROM blobs b
		  WHERE NOT EXISTS (SELECT 1 FROM blob_recipients r WHERE r.blob_id = b.blob_id)
		  ORDER BY b.created_at ASC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing unreferenced blobs: %w", err)
	}
	defer rows.Close()
	return scanBlobs(rows)
}

// DeleteBlobByID removes a blob's metadata row regardless of owner, taking
// its recipient rows with it -- for the expiry sweep, which acts on the
// server's behalf rather than a device's.
func DeleteBlobByID(db DBTX, blobID string) error {
	if _, err := db.Exec(`DELETE FROM blobs WHERE blob_id = ?`, blobID); err != nil {
		return fmt.Errorf("store: deleting blob by id: %w", err)
	}
	return nil
}

// BlobIDExists reports whether a blob row exists, regardless of owner. Used
// only by the orphan sweep, to tell a file whose row is gone from one whose
// row is simply owned by someone else.
func BlobIDExists(db DBTX, blobID string) (bool, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(1) FROM blobs WHERE blob_id = ?`, blobID).Scan(&n); err != nil {
		return false, fmt.Errorf("store: checking blob existence: %w", err)
	}
	return n > 0, nil
}

// BlobRecipients lists the devices a blob was addressed to, in no particular
// order. Only tests and diagnostics need this -- the transport itself always
// asks the narrower "is it mine?" question via GetBlobForDevice.
func BlobRecipients(db DBTX, blobID string) ([]string, error) {
	rows, err := db.Query(
		`SELECT recipient_device_id FROM blob_recipients WHERE blob_id = ?`, blobID)
	if err != nil {
		return nil, fmt.Errorf("store: listing blob recipients: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: scanning blob recipient: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows, so scanBlob can
// serve the single-row lookups and the batched listings alike.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanBlobs(rows *sql.Rows) ([]Blob, error) {
	var blobs []Blob
	for rows.Next() {
		b, err := scanBlob(rows)
		if err != nil {
			return nil, err
		}
		blobs = append(blobs, *b)
	}
	return blobs, rows.Err()
}

func scanBlob(row rowScanner) (*Blob, error) {
	var b Blob
	var createdAt, expiresAt string
	if err := row.Scan(&b.BlobID, &b.SizeBytes, &createdAt, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scanning blob: %w", err)
	}

	t, err := parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("store: parsing blob created_at: %w", err)
	}
	b.CreatedAt = t

	t, err = parseTime(expiresAt)
	if err != nil {
		return nil, fmt.Errorf("store: parsing blob expires_at: %w", err)
	}
	b.ExpiresAt = t

	return &b, nil
}
