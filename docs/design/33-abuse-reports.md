# Design: Reporting an account to its operator

Status: **planned** · Roadmap: [SRV-33](../ROADMAP.md) · Client half: freizone-app APP-28
· Depends on: [SRV-32](32-profile-name.md) for the evidence it carries

Blocking is what a user does about somebody; there is nothing they can do
*with* somebody. An operator has `block` and `delete` (§4) but no way to learn
that either is warranted, since the content is end-to-end encrypted and
nothing else is a signal. This adds the missing channel: a member tells the
operator that an account is a problem, and the operator gets enough to start a
conversation.

That is the whole ambition. A report is an assertion with no proof behind it —
the server cannot see what was said, and never will. So the counter is a
**reason to talk to someone**, never a finding, and the design refuses every
shape that would pretend otherwise.

## Reporting is named, and that is the point

A reporter is stored, and shown to staff, with their address. Accusation
carries responsibility, and an operator who cannot ask "what happened?" cannot
do anything useful with a number.

An earlier draft stored `HMAC(server_secret, reporter || reported)` instead, so
that uniqueness could be enforced without the server holding a readable link
between two accounts. **Rejected**: it defeats the follow-up conversation,
which is the main thing an operator does with a report. Named reporting is
also the better defence against brigading — two hundred reports from one
account are visible as such, which is why nothing else in this design needs an
anti-brigading mechanism.

What follows from it:

- **The app says so before the report is sent**, in APP-28. Responsibility the
  reporter did not know they were taking is a trap, not a principle.
- **The reported account never learns who reported it.** Responsibility runs
  towards the operator, not towards the accused; the other reading turns every
  report into a fight between two users and ends reporting altogether. No
  endpoint tells an account anything about reports against it.
- **A report can be withdrawn.** Somebody who bears responsibility must be
  able to change their mind, and the counter drops when they do.
- **A report can be marked abusive**, which counts against the *reporter*.
  Without it, "responsibility" costs nothing and exists only on paper.

Worth stating plainly rather than dressing up: this is access control in the
application, not a cryptographic guarantee. The server holds the link in the
clear and an operator with database access reads it regardless. That is
acceptable — a report is a deliberate act aimed at the operator, not a
by-product of chatting, and it is a *case*, not a relationship — but the app
must not describe it as confidential.

## Data model

One table, because a server holds reports in both directions and the admin
view needs both: reports about **its own** accounts (what it moderates) and
reports **its own users filed** about accounts elsewhere (what justifies a
federation blocklist entry).

```sql
CREATE TABLE reports (
  id                 INTEGER PRIMARY KEY,
  reported_address   TEXT NOT NULL,   -- canonical id*server
  reporter_address   TEXT NOT NULL,   -- canonical id*server
  reported_is_local  INTEGER NOT NULL,
  reporter_is_local  INTEGER NOT NULL,
  category           TEXT NOT NULL,   -- spam | harassment | fraud | other
  evidence           TEXT,            -- JSON: SRV-32 claims, as received
  evidence_verified  INTEGER NOT NULL,
  state              TEXT NOT NULL,   -- open | actioned | dismissed | abusive
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL,
  resolved_by        TEXT,
  resolved_at        TEXT,
  UNIQUE(reporter_address, reported_address)
);
```

**Addresses, not foreign keys.** Either side may live on another server, so
there is no row to point at in half the cases, and a schema with a foreign key
that only sometimes applies is worse than none. The consequence is explicit:
`DELETE /v1/accounts/{id}` and the admin delete must clear reports naming that
account on **either** side by hand, and that deletion belongs in the same
transaction as the account's, not in a sweeper — a report about an account
that no longer exists is a claim nobody can answer.

**`UNIQUE(reporter, reported)` is the whole of "one reporter counts once".**
Reporting again updates category and evidence and touches `updated_at`; it
does not add a row and does not raise the count. Re-reporting an account whose
report was resolved reopens *that* row rather than creating a second.

## Endpoints

- **`POST /v1/reports`** (signed) — a local account reports any address, local
  or federated. `{"reported": "id*server", "category": "...", "evidence": [...]}`.
  `201`, or `200` when it updated an existing row.
  `400` on an unparseable address, an unknown category or oversized evidence ·
  `403` reporting yourself · `409 report_limit` past the per-reporter cap on
  open reports.
- **`DELETE /v1/reports/{reported}`** (signed) — withdrawal by the reporter,
  where `{reported}` is the canonical address in one path segment (`*` is a
  legal sub-delimiter). `404` if this reporter has no report on that address.
- **`POST /v1/federation/reports`** (public — does its own authentication) —
  a reporter on another server, about a **local** account. Body and
  authentication exactly as `POST /v1/federation/messages` (§9): sender
  account id, root public key, device certificate, signed with the
  self-describing-key variant, plus the report fields above.
  `404 federation_disabled`, `403` for a sender on the federation blocklist,
  `400` for a certificate that does not verify — the same three answers, for
  the same reasons. Withdrawal is `DELETE /v1/federation/reports/{reported}`
  with the same authentication.
- **`GET /v1/admin/reports`** (signed, admin or moderator) — filterable by
  state and direction. Each entry carries both addresses, category, state,
  timestamps, resolver, and the evidence with its verification result.
- **`POST /v1/admin/reports/{id}/resolve`** (signed, admin or moderator)
  — `{"outcome": "actioned" | "dismissed" | "abusive"}`. Resolving is not
  deleting: the row stays, and the badge counts only `open`. There is
  deliberately **no counter reset** — the whole value of a report a year later
  is that the next moderator can see there was one, and how it went. Bulk
  resolve is a client-side loop, not an endpoint.

**No server-to-server relay, per §9.** `POST /v1/reports` on the reporter's
own server never forwards anything. A reporter who also wants the target's
operator to know posts to that server's `POST /v1/federation/reports` itself,
exactly as it delivers a federated message itself — and it is the reporter's
choice whether to do so, because handing your identity to an operator you do
not know is not always the right move. Filing with your own server always
happens: it is the operator who knows you, and the one who can act via the
federation blocklist.

Counters join `GET /v1/admin/accounts` alongside SRV-09's activity signals,
`0` rather than absent so "none" is distinguishable from an older server:
`reports_local` and `reports_federated` (open reports **about** this account,
never summed — a mixed figure is trivially inflated from outside and therefore
worthless), `reports_filed` (open reports this account has **made**) and
`reports_abusive` (how often one of its reports was resolved as abusive).

`GET /v1/server-status` gains `reports_enabled`, absent meaning **off**, on
`blobs_enabled`'s precedent — a client checks its own server before offering
the button at all, and the target's server before offering to forward. The
operator switch is `FREIZONE_REPORTS_ENABLED`, default on.

## Roles

- **Anyone may report anyone**, staff included. The server does not look at
  the target's role when accepting. Reporting is a user's act, not a
  moderator's, and an admin who cannot be reported is an admin nobody can
  raise a problem about.
- **Moderators see and resolve reports whose target is a `user`.** Reports
  targeting a moderator or an admin are **admin-only** — the handler does not
  run the query for a moderator at all, on SRV-14's precedent that the rule
  should live in what is asked for and not only in what is serialized. A
  moderator investigating a colleague is not a moderation case any more, it is
  the operator's; and showing an accusation to someone forbidden to act on it
  produces exactly the corridor gossip this avoids. The same rule hides the
  per-account counters for staff rows from a moderator.
- **Acting stays under SRV-08's rules.** Block and unblock reach regular
  members for a moderator, everything for an admin; role changes and delete
  stay admin-only. Nothing here widens any of that.
- **`abusive` against a staff reporter is admin-only**, for the same reason as
  above in the mirror direction.

**One limit that cannot be designed away:** when the reported account is the
server's only admin, the report is delivered to the person it is about. There
is nothing above one's own operator in a federated system. It is named here so
nobody assumes otherwise, and APP-28 says it plainly in the UI at the moment
it applies rather than letting a reporter find out afterwards.

## Evidence

`evidence` is the SRV-32 profile claims the reporter holds for that account,
as received and with their signatures — the name the account asserted, not the
name the reporter gave it locally. That distinction is the reason the two are
stored apart on the client (APP-27); it must never be possible for a private
petname to leave the device through this path, and a report with **no** claim
sends an absent field rather than any substitute.

The server verifies each claim when the target is local, since it has the root
key and device certificates for it, and stores `evidence_verified`
accordingly; for a federated target it stores them unverified rather than
fetching a stranger's key material on an unauthenticated caller's say-so. The
admin client verifies again itself, on the general principle that a client
does not have to take the server's word for a signature. Bound the field —
a small number of claims, a few kilobytes — and reject anything larger.

Categories are a fixed set (`spam`, `harassment`, `fraud`, `other`), validated
server-side. **No free text.** A free-text field on the server is a store of
personal allegations, and incidentally a channel for writing at the operator
that nothing moderates.

## Retention

Reports expire, resolved and open alike, on SRV-13's pattern: a purge over
`created_at` older than `FREIZONE_REPORT_RETENTION_DAYS` (default 90), run
where the invite purge already runs. A counter that never falls becomes a
criminal record for something that was never proven, and the evidence goes
with the row, which keeps the server's holdings minimal by construction.

## What the server now knows that it did not

Two things: the reporter→reported link, and the profile names carried as
evidence. Both arrive only through a deliberate user action, both are visible
only to staff, and both expire. But "the server knows nothing about you" stops
being literally true once this ships, and the honest phrasing after it is that
the server knows nothing you did not deliberately hand it.
