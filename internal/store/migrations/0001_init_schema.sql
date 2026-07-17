CREATE TABLE accounts (
    id             TEXT PRIMARY KEY,
    root_pubkey    BLOB NOT NULL,
    version_marker INTEGER NOT NULL,
    status         TEXT NOT NULL DEFAULT 'active',
    is_admin       INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL
);

CREATE TABLE devices (
    device_id      TEXT PRIMARY KEY,
    account_id     TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_pubkey  BLOB NOT NULL,
    cert_issued_at TEXT NOT NULL,
    cert_signature BLOB NOT NULL,
    status         TEXT NOT NULL DEFAULT 'active',
    revoked_at     TEXT,
    created_at     TEXT NOT NULL
);

CREATE INDEX idx_devices_account_id ON devices(account_id);

CREATE TABLE used_nonces (
    device_id         TEXT NOT NULL,
    nonce             TEXT NOT NULL,
    request_timestamp TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    PRIMARY KEY (device_id, nonce)
);

CREATE INDEX idx_used_nonces_expires_at ON used_nonces(expires_at);

CREATE TABLE setup_tokens (
    id                 INTEGER PRIMARY KEY CHECK (id = 1),
    token_hash         TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    used_at            TEXT,
    used_by_account_id TEXT REFERENCES accounts(id)
);

CREATE TABLE invite_codes (
    code                  TEXT PRIMARY KEY,
    created_by_account_id TEXT NOT NULL REFERENCES accounts(id),
    created_at            TEXT NOT NULL,
    expires_at            TEXT,
    used_at               TEXT,
    used_by_account_id    TEXT REFERENCES accounts(id)
);
