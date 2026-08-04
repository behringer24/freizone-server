-- Multi-recipient blobs (SRV-18): one stored object, several recipients.
--
-- SRV-07 bound a blob to exactly one device, which is right for a one-to-one
-- attachment and wrong for a group: a picture sent to ten members on the same
-- server cost ten uploads and ten copies on disk. The recipients move out of
-- the blob row into their own table, so the sender uploads once per recipient
-- SERVER and the server stores one file.
--
-- Quota, expiry and ownership are unchanged in meaning -- each recipient is
-- still charged the full size and may still only fetch what was addressed to
-- them. What changes is that "the recipient" is now a set.
--
-- Order matters here. blob_recipients is created only AFTER the old table is
-- gone: with foreign_keys(1), DROP TABLE performs an implicit DELETE, so a
-- child table carrying ON DELETE CASCADE that already held the migrated rows
-- would have them cascaded away by the very drop that is supposed to retire
-- the old shape.
--
-- NOTE: keep semicolons out of these comments. The migration runner splits
-- a script on the statement separator (splitStatements in migrate.go), so
-- one inside a comment cuts the statement in half and the remaining prose
-- is then parsed as SQL.
ALTER TABLE blobs RENAME TO blobs_old;

CREATE TABLE blobs (
    blob_id    TEXT PRIMARY KEY,
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    -- One upload is one event and gets one retention window, however many
    -- recipients it was addressed to.
    expires_at TEXT NOT NULL
);

INSERT INTO blobs (blob_id, size_bytes, created_at, expires_at)
SELECT blob_id, size_bytes, created_at, expires_at FROM blobs_old;

CREATE TABLE blob_recipients (
    -- Cascade from the blob so the expiry sweep drops a whole object in one
    -- statement, and from the device so a revoked/removed device takes its
    -- claims with it, exactly as it does its queued messages. A blob whose
    -- last recipient row goes that way is left unreferenced, which the
    -- cleanup ticker collects (cmd/server/main.go).
    blob_id             TEXT NOT NULL REFERENCES blobs(blob_id) ON DELETE CASCADE,
    recipient_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    PRIMARY KEY (blob_id, recipient_device_id)
);

INSERT INTO blob_recipients (blob_id, recipient_device_id)
SELECT blob_id, recipient_device_id FROM blobs_old;

DROP TABLE blobs_old;

CREATE INDEX idx_blobs_expires_at ON blobs(expires_at);

-- Serves the per-device quota check (COUNT/SUM before accepting an upload)
-- and the admin activity aggregate. The lookup by blob id on download is
-- already covered by the primary key.
CREATE INDEX idx_blob_recipients_device_id ON blob_recipients(recipient_device_id);
