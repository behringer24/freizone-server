-- The transcript: the history layer on top of 001's crypto layer.
--
-- chat_id is a peer account id or a group id without distinguishing between
-- them, following the app: both are 21-character bech32m strings differing
-- only in a version marker, so anything keyed by a chat needs no second form.
-- That is what lets group transcripts land here unchanged when the group's own
-- signed fact set arrives later.

CREATE TABLE messages (
    chat_id    TEXT    NOT NULL,
    message_id TEXT    NOT NULL,

    -- Arrival order, and the only ordering the transcript is ever read in.
    -- Deliberately NOT the timestamp: the app appends and never sorts, so a
    -- message that arrived out of order, or was decrypted late, sits where it
    -- arrived. Ordering by time instead would silently rearrange exactly those
    -- transcripts, and system lines have no sender clock at all.
    seq INTEGER NOT NULL,

    text      TEXT    NOT NULL,
    mine      INTEGER NOT NULL,

    -- When this device recorded the line. sender_sent_at is the sender's own
    -- clock from inside the envelope, absent for our own messages and for
    -- senders predating the field -- which is why receipts anchor on it only
    -- when it is there.
    timestamp      TEXT NOT NULL,
    sender_sent_at TEXT,

    -- Null for our own messages and in a one-to-one chat, where the peer is
    -- the conversation. A group transcript needs it to name the author.
    sender_account_id TEXT,

    -- A reply carries a snapshot of what it answers, not a live lookup: the
    -- quoted message may since have been deleted locally, and a quote that
    -- vanishes when the original does is worse than a stale one.
    reply_to_id             TEXT,
    reply_preview_text      TEXT,
    reply_preview_mine      INTEGER,
    reply_preview_author_id TEXT,

    -- system_info is a local, never-transmitted line rendered centred, e.g.
    -- "Secure session was reset".
    kind TEXT NOT NULL CHECK (kind IN ('normal', 'system_info')),

    -- How far one of our own outgoing messages got. Received messages are
    -- always 'sent'. A row left 'pending' by a process that died is rewritten
    -- to 'failed' when the database is opened, not when it is read -- see
    -- Open: nothing is in flight in a process that no longer exists, but a send
    -- genuinely in flight in *this* process must keep reading back as pending.
    send_state TEXT NOT NULL CHECK (send_state IN ('pending', 'sent', 'failed')),

    PRIMARY KEY (chat_id, message_id)
) WITHOUT ROWID;

CREATE INDEX messages_by_seq ON messages (chat_id, seq);

-- Attachment metadata. The bytes themselves never live in the database: a blob
-- is fetched from the server encrypted and cached as a file, and only the
-- little that describes it belongs here.
CREATE TABLE message_attachments (
    chat_id    TEXT    NOT NULL,
    message_id TEXT    NOT NULL,
    position   INTEGER NOT NULL,

    kind      TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    blob_id   TEXT NOT NULL,

    -- Freshly generated per attachment and deliberately not derived from the
    -- ratchet: the blob outlives the message on the server, so resetting a
    -- secure session must not make already-received pictures undownloadable.
    key BLOB NOT NULL,

    mime_type TEXT    NOT NULL,
    byte_size INTEGER NOT NULL,

    -- Pixel dimensions, so a bubble can reserve the right aspect ratio before
    -- the download finishes and the transcript does not jump.
    width  INTEGER NOT NULL,
    height INTEGER NOT NULL,

    -- A tiny JPEG shown blurred while the real file downloads. Null when the
    -- sender included none.
    thumb BLOB,

    PRIMARY KEY (chat_id, message_id, position),
    FOREIGN KEY (chat_id, message_id)
        REFERENCES messages (chat_id, message_id) ON DELETE CASCADE
) WITHOUT ROWID;

-- One recipient's copy of a group message. A group send is N separately
-- encrypted copies, so "sent" is not one state but N, and a retry has to be
-- able to address only the ones that failed.
CREATE TABLE group_deliveries (
    chat_id    TEXT NOT NULL,
    message_id TEXT NOT NULL,
    account_id TEXT NOT NULL,

    -- Random and per recipient: sharing the message's own id across recipients
    -- makes two members on the same server collide, the second copy answered
    -- 409 and recorded as delivered to somebody who never got it.
    wire_message_id TEXT NOT NULL,

    state TEXT NOT NULL CHECK (state IN ('pending', 'sent', 'failed')),

    -- This member got the caption but not the picture, because their server
    -- does not store attachments or would not take this one. Not a delivery
    -- failure -- the message itself arrived -- so it needs its own flag rather
    -- than riding on state, and it stays true: a retry cannot fix it.
    attachment_skipped INTEGER NOT NULL DEFAULT 0,

    PRIMARY KEY (chat_id, message_id, account_id),
    FOREIGN KEY (chat_id, message_id)
        REFERENCES messages (chat_id, message_id) ON DELETE CASCADE
) WITHOUT ROWID;

-- Locally pinned messages, oldest-pinned first, never sent to anyone. Cascades
-- with the message: a pin pointing at a deleted message renders nothing either
-- way, and letting the row linger only invites a later query to trip over it.
CREATE TABLE pinned_messages (
    chat_id    TEXT    NOT NULL,
    message_id TEXT    NOT NULL,
    seq        INTEGER NOT NULL,

    PRIMARY KEY (chat_id, message_id),
    FOREIGN KEY (chat_id, message_id)
        REFERENCES messages (chat_id, message_id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX pinned_messages_by_seq ON pinned_messages (chat_id, seq);
