-- One database per account. Nothing here is keyed by account id, because a
-- second account is a second file -- which is what lets a bot run many
-- identities in one process without every query carrying a discriminator.

-- Exactly one row, enforced by the CHECK: this file *is* the account.
CREATE TABLE identity (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    account_id            TEXT    NOT NULL,
    server                TEXT    NOT NULL,
    root_pub              BLOB    NOT NULL,
    root_priv             BLOB    NOT NULL,
    device_id             TEXT    NOT NULL,
    device_pub            BLOB    NOT NULL,
    device_priv           BLOB    NOT NULL,
    dh_identity_pub       BLOB,
    dh_identity_priv      BLOB,
    signed_prekey_id      INTEGER NOT NULL DEFAULT 0,
    signed_prekey_pub     BLOB,
    signed_prekey_priv    BLOB,
    next_signed_prekey_id INTEGER NOT NULL DEFAULT 0,
    next_otpk_key_id      INTEGER NOT NULL DEFAULT 0,
    recovery_backup_done  INTEGER NOT NULL DEFAULT 0,
    push_registered_at    TEXT,
    push_mechanism        TEXT
);

-- Uploaded one-time prekeys, held until a peer actually claims one. The server
-- never says which it handed out, so they are dropped on use, not on upload.
CREATE TABLE one_time_prekeys (
    key_id INTEGER PRIMARY KEY,
    pub    BLOB NOT NULL,
    priv   BLOB NOT NULL
);

-- Double Ratchet sessions, one row per peer and kind.
--
-- 'sending' is the session this device sends on. 'inbound' is kept for READING
-- only: when two sides establish at the same moment, each holds its own
-- initiator session and neither can read the other's, so a tie-break on the
-- lower account id decides which one both will send on (PROTOCOL.md §5) and
-- the loser is kept here rather than discarded -- otherwise the messages
-- already in flight on it are stranded and look like a desync.
CREATE TABLE sessions (
    peer_account_id TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('sending', 'inbound')),
    session         BLOB NOT NULL,
    PRIMARY KEY (peer_account_id, kind)
) WITHOUT ROWID;

-- Message ids already decrypted and stored.
--
-- Delivery is at-least-once and the server keeps a message queued until the
-- client deletes it, a delete that can be lost. Reprocessing is destructive:
-- it advances the ratchet twice for one message, and a redelivered X3DH
-- initial rebuilds the responder session over the advanced one.
--
-- seq is an explicit insertion counter rather than a rowid so eviction order
-- survives a vacuum, and so re-marking an id already present leaves its
-- position alone -- matching the app, where re-adding to a LinkedHashSet does
-- not move the entry to the end.
CREATE TABLE processed_messages (
    message_id TEXT    PRIMARY KEY,
    seq        INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX processed_messages_by_seq ON processed_messages (seq);

-- How often each still-undelivered message has failed to decrypt, so one that
-- can never be decrypted is eventually dropped instead of blocking the queue.
-- Persisted, not in memory: a background push wake is torn down between
-- deliveries, so an in-RAM counter would restart at zero every time and never
-- reach the limit.
CREATE TABLE decrypt_failures (
    message_id TEXT    PRIMARY KEY,
    attempts   INTEGER NOT NULL,
    seq        INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX decrypt_failures_by_seq ON decrypt_failures (seq);

-- Present only for peers something has actually gone wrong with. Drives the
-- automatic session recovery in SRV-03.
CREATE TABLE peer_session_health (
    peer_account_id  TEXT    PRIMARY KEY,
    desync_evidence  INTEGER NOT NULL DEFAULT 0,
    first_failure_at TEXT,
    last_rekey_at    TEXT
) WITHOUT ROWID;

-- Conversation metadata -- deliberately without the transcript, which lands in
-- its own table next. local_state.dart calls conversations "the UI/history
-- layer on top of sessions's crypto layer"; this migration is the crypto layer
-- plus only as much of the history layer as the crypto layer's own rules
-- reference (desync evidence is recorded only for peers a conversation exists
-- for, which bounds that table against invented account ids).
CREATE TABLE conversations (
    peer_account_id             TEXT PRIMARY KEY,
    peer_server                 TEXT,
    peer_device_id              TEXT,
    peer_device_pub_key         BLOB,
    last_activity_at            TEXT,
    has_unread                  INTEGER NOT NULL DEFAULT 0,
    blocked                     INTEGER NOT NULL DEFAULT 0,
    pending_approval            INTEGER NOT NULL DEFAULT 0,
    peer_delivered_up_to        TEXT,
    peer_read_up_to             TEXT,
    sent_delivered_receipt_up_to TEXT,
    sent_read_receipt_up_to     TEXT
) WITHOUT ROWID;

-- Peers ever accepted or reached out to -- "not a stranger", independent of
-- whether a conversation still exists. Outlives deleting a conversation, so
-- clearing a chat never regresses a known contact back to a message request.
CREATE TABLE known_peers (
    peer_account_id TEXT PRIMARY KEY
) WITHOUT ROWID;

-- Locally blocked peers, snapshotted at block time and kept independent of
-- conversations: deleting a blocked peer's chat must not silently unblock them,
-- and there would be no conversation left to unblock them from either.
CREATE TABLE blocked_peers (
    peer_account_id TEXT PRIMARY KEY,
    peer_server     TEXT
) WITHOUT ROWID;
