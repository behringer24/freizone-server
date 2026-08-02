# Design: Moderator global block/unblock

Status: **done** · Roadmap: [SRV-08](../ROADMAP.md)

`POST /v1/admin/accounts/{id}/block` and `/unblock` (`handleBlockAccount`/
`handleUnblockAccount`, `internal/api/admin.go`, routed in
`internal/api/router.go`) already disable the account
**server-wide** — `internal/auth`'s middleware rejects every request from a
disabled account, so this is already a global block, not a per-viewer one.
But both are gated `requireAdmin`; moderators currently see the Server Admin
Users list fully read-only (no tap targets at all, per the comment atop
`admin_screen.dart`), so they can't use it at all.

Widen just the block/unblock gate to `requireAdminOrModerator` (role changes
and delete stay `requireAdmin` — those are more consequential and rarer).
Client-side: give moderators the same per-row action for block/unblock
(still no set-role/delete). Since freizone-app also has a personal,
per-contact block (`peer_profile_screen.dart`, "Block this contact" —
affects only the blocking user's own view of that contact, nothing
server-side), relabel the admin-page actions to **"Block for all"** /
**"Unblock for all"** so the scope is unambiguous next to the personal one.

**Shipped 2026-08-02**, with one rule the plan above didn't account for: a
moderator may only block/unblock accounts whose role is `user`. Widening the
gate alone would have quietly broken PROTOCOL §4's own promise that account
removal never comes from a moderator — blocking *is* removal by another name
(a disabled account cannot make one authenticated request), and the
`last_admin` guard is no substitute, since it only refuses the *final* admin
and would happily let a moderator disable one of two. So `setAccountStatus`
now gates on `requireAdminOrModerator` plus a `403` when a non-admin caller
targets staff; `admin_screen.dart` mirrors it, showing a moderator the block
entry alone and only on regular members. Relabelled as planned, and the
blocked-status subtitle now reads "blocked for all" for the same reason the
menu does.
