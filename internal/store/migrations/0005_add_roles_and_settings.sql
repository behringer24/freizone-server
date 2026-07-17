ALTER TABLE accounts ADD COLUMN role TEXT NOT NULL DEFAULT 'user';
UPDATE accounts SET role = 'admin' WHERE is_admin = 1;
ALTER TABLE accounts DROP COLUMN is_admin;

CREATE TABLE server_settings (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    registration_policy TEXT NOT NULL
);

-- invite_codes' account references have no ON DELETE clause, so deleting
-- any account that ever created or used an invite would fail a
-- foreign-key check outright. SQLite can't ALTER a column's REFERENCES
-- clause in place, so rebuild the table: a creator's invites go with them
-- (CASCADE, consistent with this project's already-minimal server-side
-- retention), a past user's own "used_by" reference is just cleared
-- (SET NULL) since the invite record itself is still meaningful history.
CREATE TABLE invite_codes_new (
    code                  TEXT PRIMARY KEY,
    created_by_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at            TEXT NOT NULL,
    expires_at            TEXT,
    used_at               TEXT,
    used_by_account_id    TEXT REFERENCES accounts(id) ON DELETE SET NULL
);
INSERT INTO invite_codes_new SELECT * FROM invite_codes;
DROP TABLE invite_codes;
ALTER TABLE invite_codes_new RENAME TO invite_codes;
