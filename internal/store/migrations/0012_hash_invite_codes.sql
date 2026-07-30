-- Invite codes are now short, hand-typeable Crockford-Base32 codes (12
-- symbols, "ABCD-EFGH-JKMN") and, like the setup token, only their SHA-256
-- hash is stored -- so a leaked database yields no working invites. See
-- internal/store/invites.go and docs/PROTOCOL.md.
--
-- Migrations here are plain SQL and SQLite has no sha256(), so the hash of an
-- existing plaintext code cannot be computed at migration time. Consequences,
-- both deliberate:
--
--   * Unused codes are DROPPED. They could not be carried into the hashed
--     column, and leaving them behind un-hashed would defeat the point of
--     hashing. Any invite handed out but not yet redeemed stops working and
--     has to be reissued. On a server with an invite policy that is a handful
--     of codes at most, and reissuing is a single request.
--   * Already-used codes are KEPT as history -- who invited whom, and when --
--     with a placeholder in place of the hash. The placeholder cannot collide
--     with, or be matched by, any real lookup: hashToken always produces 64
--     lowercase hex characters, and "legacy:<rowid>" is neither.
CREATE TABLE invite_codes_new (
    code_hash             TEXT PRIMARY KEY,
    created_by_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at            TEXT NOT NULL,
    expires_at            TEXT,
    used_at               TEXT,
    used_by_account_id    TEXT REFERENCES accounts(id) ON DELETE SET NULL
);

INSERT INTO invite_codes_new (code_hash, created_by_account_id, created_at, expires_at, used_at, used_by_account_id)
SELECT 'legacy:' || rowid, created_by_account_id, created_at, expires_at, used_at, used_by_account_id
FROM invite_codes
WHERE used_at IS NOT NULL;

DROP TABLE invite_codes;
ALTER TABLE invite_codes_new RENAME TO invite_codes;
