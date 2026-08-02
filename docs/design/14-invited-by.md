# Design: Exposing who invited an account

Status: **done** · Roadmap: [SRV-14](../ROADMAP.md)

`invite_codes.created_by_account_id` records which account issued the invite
another joined with, and SRV-13 keeps redeemed rows precisely so that history
survives — but nothing could read it short of opening the database. The
admin-side user detail view (APP-11) is the place it is actually useful: when
an account turns out to be a problem, the next question is who vouched for it.

`store.InviterByAccount` aggregates it in one query and `GET /v1/admin/accounts`
carries it as `invited_by`, alongside SRV-09's activity signals.

**Admins only, and deliberately narrower than everything else on that
endpoint.** A moderator gets the activity figures but not this: queue lengths
and stored bytes are aggregates about one account, whereas "who invited whom"
is a link *between* accounts — the only one this server holds — and that is a
different kind of thing to hand out. The handler doesn't even run the query for
a non-admin caller, so the rule is enforced by what it asks for rather than
only by what it serializes.

Only the `created_by` half is exposed, never `used_by`: an admin looking at an
account can see who vouched for it, and cannot enumerate everyone a given
account brought in. The reverse direction would be the same data read as a
recruitment graph, and nothing needs it yet.

Absent means "not known here", never "registered openly" — the field is equally
missing for an account that needed no invite and for one whose inviter has since
been deleted, since the invite row cascades with its creator. Documented that
way in PROTOCOL §4, because a client that read absence as "joined openly" would
be quietly wrong on every server that has ever deleted an account.
