-- id_prefix is the first 5 characters of an account id (the version
-- marker plus 4 real characters of entropy, per pkg/address's
-- FormatForDisplay grouping) -- enforced unique per server so it can
-- double as a short, typeable "lookup key" for the full id. Existing
-- accounts are backfilled so the constraint is meaningful immediately,
-- not just for accounts created from here on.
ALTER TABLE accounts ADD COLUMN id_prefix TEXT;
UPDATE accounts SET id_prefix = substr(id, 1, 5);
CREATE UNIQUE INDEX idx_accounts_id_prefix ON accounts(id_prefix);
