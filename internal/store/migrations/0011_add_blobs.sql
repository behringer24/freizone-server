-- Encrypted blob transport (SRV-07), the companion to freizone-app's
-- multimedia messaging (APP-04). A blob is opaque ciphertext the server
-- cannot read, uploaded by a sender for one recipient device and fetched
-- by that device once it decrypts the message carrying the blob id.
--
-- Only metadata lives here. The ciphertext itself is a file on disk (see
-- internal/blobstore) because the SQLite driver has no incremental blob
-- I/O -- storing megabytes in a column would materialize whole files in
-- memory on the same single-writer connection that serves authentication.
--
-- NOTE: keep semicolons out of these comments. The migration runner splits
-- a script on the statement separator (splitStatements in migrate.go), so
-- one inside a comment cuts the statement in half and the remaining prose
-- is then parsed as SQL.
CREATE TABLE blobs (
    blob_id             TEXT PRIMARY KEY,
    -- Cascade so a revoked/removed device takes its undelivered blobs with
    -- it, exactly as it does its queued messages.
    recipient_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    size_bytes          INTEGER NOT NULL,
    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL
);

-- Serves both the per-device quota check (COUNT/SUM before accepting an
-- upload) and the ownership lookup on download.
CREATE INDEX idx_blobs_recipient_device_id ON blobs(recipient_device_id);
CREATE INDEX idx_blobs_expires_at ON blobs(expires_at);
