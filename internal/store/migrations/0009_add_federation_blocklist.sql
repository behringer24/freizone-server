-- Federation abuse mitigation: a server operator can block a specific
-- remote account from delivering messages here, via POST/DELETE
-- /v1/admin/federation-blocklist. Blocking is necessarily per-account,
-- not per-origin-server -- nothing in the federation protocol reliably
-- ties an account to a claimed hostname (that's a deliberate property
-- of self-certifying identity, see docs/PROTOCOL.md), so there is no
-- "server" to block, only accounts.
CREATE TABLE federation_blocklist (
    account_id TEXT PRIMARY KEY,
    blocked_at TEXT NOT NULL,
    blocked_by TEXT NOT NULL,
    reason     TEXT
);
