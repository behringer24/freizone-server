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
// Deliberately no sender field: the recipient learns who sent it from the
// message that carries the blob id, which is end-to-end encrypted. Recording
// it here would hand the server a plaintext sender/recipient pair it does not
// otherwise need.
type Blob struct {
	BlobID            string
	RecipientDeviceID string
	SizeBytes         int64
	CreatedAt         time.Time
	ExpiresAt         time.Time
}

// CreateBlob records an uploaded blob. Returns ErrConflict if BlobID is
// already in use (it is 32 random bytes, so only a bug or a replay).
func CreateBlob(db DBTX, b Blob) error {
	_, err := db.Exec(
		`INSERT INTO blobs (blob_id, recipient_device_id, size_bytes, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		b.BlobID, b.RecipientDeviceID, b.SizeBytes, formatTime(b.CreatedAt), formatTime(b.ExpiresAt),
	)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("%w: blob %s", ErrConflict, b.BlobID)
		}
		return fmt.Errorf("store: creating blob: %w", err)
	}
	return nil
}

// GetBlobForDevice looks up a blob, but only if it belongs to
// recipientDeviceID -- returning ErrNotFound both for "no such blob" and
// "not yours", so a caller cannot probe which blob ids exist.
func GetBlobForDevice(db DBTX, blobID, recipientDeviceID string) (*Blob, error) {
	row := db.QueryRow(
		`SELECT blob_id, recipient_device_id, size_bytes, created_at, expires_at
		 FROM blobs WHERE blob_id = ? AND recipient_device_id = ?`,
		blobID, recipientDeviceID,
	)
	return scanBlob(row)
}

// BlobUsage reports how many blobs recipientDeviceID currently holds and
// their total size -- checked against the per-device caps before accepting
// an upload, the blob counterpart to CountPendingMessages. Both numbers come
// from one query since they are always needed together.
func BlobUsage(db DBTX, recipientDeviceID string) (count int, totalBytes int64, err error) {
	// COALESCE because SUM over no rows is NULL, not 0.
	row := db.QueryRow(
		`SELECT COUNT(1), COALESCE(SUM(size_bytes), 0) FROM blobs WHERE recipient_device_id = ?`,
		recipientDeviceID,
	)
	if err := row.Scan(&count, &totalBytes); err != nil {
		return 0, 0, fmt.Errorf("store: counting blob usage: %w", err)
	}
	return count, totalBytes, nil
}

// DeleteBlobForDevice removes a blob's metadata row, only for its owning
// recipient device. Returns ErrNotFound if there is no such blob for that
// device. The caller is responsible for removing the file afterwards.
func DeleteBlobForDevice(db DBTX, blobID, recipientDeviceID string) error {
	res, err := db.Exec(
		`DELETE FROM blobs WHERE blob_id = ? AND recipient_device_id = ?`,
		blobID, recipientDeviceID,
	)
	if err != nil {
		return fmt.Errorf("store: deleting blob: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking rows affected for blob deletion: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
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
		`SELECT blob_id, recipient_device_id, size_bytes, created_at, expires_at
		 FROM blobs WHERE expires_at < ? ORDER BY expires_at ASC LIMIT ?`,
		formatTime(now), limit,
	)
	if err != nil {
		return nil, fmt.Errorf("store: listing expired blobs: %w", err)
	}
	defer rows.Close()

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

// DeleteBlobByID removes a blob's metadata row regardless of owner -- for
// the expiry sweep, which acts on the server's behalf rather than a device's.
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

// rowScanner is satisfied by both *sql.Row and *sql.Rows, so scanBlob can
// serve the single-row lookups and the batched listing alike.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanBlob(row rowScanner) (*Blob, error) {
	var b Blob
	var createdAt, expiresAt string
	if err := row.Scan(&b.BlobID, &b.RecipientDeviceID, &b.SizeBytes, &createdAt, &expiresAt); err != nil {
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
