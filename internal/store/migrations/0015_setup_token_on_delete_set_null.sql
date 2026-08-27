-- Clear setup_tokens.used_by_account_id on account deletion (audit L3).
--
-- The setup_tokens table (0001) references accounts(id) with no ON DELETE
-- clause, unlike every other account reference (invite_codes got CASCADE/SET
-- NULL in 0005/0012, devices CASCADE). With foreign_keys enforced, deleting
-- the bootstrap admin -- the account that claimed the setup token -- therefore
-- fails the constraint, surfacing as a generic 500 and leaving the first admin
-- permanently undeletable (both self-delete and admin-delete). SET NULL keeps
-- the historical token row while letting the account go.
--
-- SQLite cannot alter a foreign-key clause in place, so the table is rebuilt.
-- Nothing references setup_tokens, so the rebuild is safe with foreign keys
-- enforced -- no other table's references are affected. Column order matches
-- 0001 plus 0004's failed_attempts.
CREATE TABLE setup_tokens_new (
    id                 INTEGER PRIMARY KEY CHECK (id = 1),
    token_hash         TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    used_at            TEXT,
    used_by_account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
    failed_attempts    INTEGER NOT NULL DEFAULT 0
);

INSERT INTO setup_tokens_new (id, token_hash, created_at, used_at, used_by_account_id, failed_attempts)
    SELECT id, token_hash, created_at, used_at, used_by_account_id, failed_attempts FROM setup_tokens;

DROP TABLE setup_tokens;

ALTER TABLE setup_tokens_new RENAME TO setup_tokens;
