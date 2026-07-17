CREATE TABLE messages (
    message_id          TEXT PRIMARY KEY,
    sender_account_id    TEXT NOT NULL,
    sender_device_id     TEXT NOT NULL,
    recipient_account_id TEXT NOT NULL,
    recipient_device_id  TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    payload              TEXT NOT NULL,
    sent_at              TEXT NOT NULL,
    expires_at           TEXT NOT NULL
);

CREATE INDEX idx_messages_recipient_device_id ON messages(recipient_device_id, sent_at);
CREATE INDEX idx_messages_expires_at ON messages(expires_at);
