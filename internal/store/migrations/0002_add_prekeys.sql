ALTER TABLE devices ADD COLUMN dh_identity_pubkey BLOB;
ALTER TABLE devices ADD COLUMN dh_identity_issued_at TEXT;
ALTER TABLE devices ADD COLUMN dh_identity_signature BLOB;

CREATE TABLE signed_prekeys (
    device_id  TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
    key_id     INTEGER NOT NULL,
    pubkey     BLOB NOT NULL,
    signature  BLOB NOT NULL,
    issued_at  TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE one_time_prekeys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    key_id     INTEGER NOT NULL,
    pubkey     BLOB NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_one_time_prekeys_device_id ON one_time_prekeys(device_id);
