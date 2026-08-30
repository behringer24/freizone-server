-- Reports: a member telling an operator that an account is a problem (SRV-33).
--
-- One table for both directions, because a server holds two kinds and the
-- admin view needs both: reports about its *own* accounts (what it moderates)
-- and reports its own users filed about accounts elsewhere (what justifies a
-- federation blocklist entry).
--
-- Addresses are split into id and server rather than stored as one `id*server`
-- string, so the local case -- server = '' -- joins against accounts(id) for
-- the per-account counters and the role checks that gate who may see a report.
--
-- No foreign key, deliberately: either side may live on another server, so
-- there is no row to point at in half the cases, and a constraint that only
-- sometimes applies is worse than none. The consequence is explicit and lives
-- in the account-deletion path, which clears reports naming that account on
-- either side in the same transaction as the account itself -- a report about
-- somebody who no longer exists is a claim nobody can answer.
CREATE TABLE reports (
    id                INTEGER PRIMARY KEY,

    reported_id       TEXT NOT NULL,
    reported_server   TEXT NOT NULL DEFAULT '',
    reporter_id       TEXT NOT NULL,
    reporter_server   TEXT NOT NULL DEFAULT '',

    category          TEXT NOT NULL,

    -- The SRV-32 profile claims the reporter held for that account, as JSON
    -- and as received, signatures included. evidence_verified records whether
    -- this server could check them, which it can only do for a local target.
    evidence          TEXT,
    evidence_verified INTEGER NOT NULL DEFAULT 0,

    -- open | actioned | dismissed | abusive. Resolving is not deleting: the
    -- value of a report a year later is that the next moderator can see there
    -- was one and how it went.
    state             TEXT NOT NULL DEFAULT 'open',

    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    resolved_by       TEXT,
    resolved_at       TEXT
);

-- One reporter counts once per reported account. Reporting again updates the
-- category and evidence; it never adds a row and never raises a count.
CREATE UNIQUE INDEX idx_reports_pair
    ON reports (reporter_id, reporter_server, reported_id, reported_server);

-- The counter query: open reports about one account, split by where they came
-- from.
CREATE INDEX idx_reports_reported
    ON reports (reported_id, reported_server, state);

-- The mirror: how much one account has filed, and how much of it was abusive.
CREATE INDEX idx_reports_reporter
    ON reports (reporter_id, reporter_server, state);

-- The retention sweep.
CREATE INDEX idx_reports_created_at ON reports (created_at);
