-- Server health/capacity snapshots for the admin statistics page: how many
-- accounts/devices/blobs exist, how much storage they use, and how full the
-- disk is -- captured periodically (cmd/server/main.go's snapshot ticker) so
-- an admin can see growth over time (are registrations climbing, is storage
-- running out) rather than just a single point-in-time reading.
--
-- A history table is the only way to answer that: accounts get blocked or
-- deleted, blobs expire and get swept, so the *current* state of those tables
-- cannot be replayed backwards to reconstruct what it looked like last month.
-- Each row here is therefore an independent, self-contained measurement --
-- nothing here is a foreign key into anything else, and nothing here is
-- pruned except by age (see PruneStatsSnapshots).
--
-- NOTE: keep semicolons out of these comments. The migration runner splits
-- a script on the statement separator (splitStatements in migrate.go), so
-- one inside a comment cuts the statement in half and the remaining prose
-- is then parsed as SQL.
CREATE TABLE stats_snapshots (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at                TEXT NOT NULL,
    account_count              INTEGER NOT NULL,
    active_account_count       INTEGER NOT NULL,
    device_count               INTEGER NOT NULL,
    blob_count                 INTEGER NOT NULL,
    blob_bytes                 INTEGER NOT NULL,
    db_bytes                   INTEGER NOT NULL,
    -- messages is queue storage, not a log -- a row here only ever exists
    -- between send and delivery/expiry (see store.DeleteMessage /
    -- PurgeExpiredMessages), so its row count already IS the pending count.
    -- There is no separate "messages ever sent" figure to also capture.
    pending_message_count      INTEGER NOT NULL,
    disk_free_bytes            INTEGER NOT NULL,
    disk_total_bytes           INTEGER NOT NULL,
    federation_enabled         INTEGER NOT NULL,
    federation_blocklist_count INTEGER NOT NULL
);

-- Serves the history endpoint's range query (captured_at >= ?) and the
-- retention prune (captured_at < ?).
CREATE INDEX idx_stats_snapshots_captured_at ON stats_snapshots (captured_at);
