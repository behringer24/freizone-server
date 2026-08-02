# Design: Purging invite codes that expired unredeemed

Status: **done** · Roadmap: [SRV-13](../ROADMAP.md)

Nothing ever deleted an invite code. The periodic sweeps covered nonces,
messages and blobs, but `invite_codes` only ever grew — noticed while
reviewing SRV-12, not by anything failing.

An expired *unredeemed* code is pure dead weight: `ConsumeInviteCode`'s
`WHERE` clause already refuses it, so the row can never do anything again.
`store.PurgeExpiredInviteCodes` now removes those, on a 6-hourly ticker
(`runInviteCleanup`, `cmd/server/main.go`) — generous on purpose, since
expiry is measured in days and a code is unusable the instant it lapses;
the sweep only reclaims the row.

Deliberately narrow, on two counts:

- **Redeemed codes are kept.** Their row records `created_by` and `used_by`
  — which account issued an invite and which account joined with it. That is
  the one piece of moderation history this server keeps, and worth having
  when an account turns out to be a problem. Deleting either account clears
  its side already (cascade / set-null, from migration 0005). There is still
  no invite-list route; SRV-14 later exposed the `created_by` half — and only
  that half — as `invited_by` on the admin account list, to admins alone.
- **Codes with no expiry are left alone**, so flipping
  `FREIZONE_INVITE_EXPIRY_DAYS` to a non-zero value cannot retroactively
  sweep away codes that were issued to live until redeemed.

Considered and not chosen: a retention window for redeemed rows too, or
nulling `used_by` after a while to keep the statistics without the pairing.
That would fit the project's minimal-retention stance better — this table is
now the only one holding anything indefinitely — but the moderation value of
knowing who invited whom was judged the higher good. Worth revisiting if a
public server ever makes the invite graph large enough to matter.
