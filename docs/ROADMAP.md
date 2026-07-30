# Freizone Roadmap — freizone-server (core)

Planned changes whose **essential** work lands in this repo. freizone-server is
the project core, so cross-repo and protocol-level items live here by default.

Each item has a short **reference code** used to discuss it. Codes are
per-repo, so the prefix tells you which repo's `docs/ROADMAP.md` owns the item:

- `SRV-` — freizone-server (this file, core)
- `APP-` — freizone-app
- `GAW-`  — freizone-gateway

A change that spans several repos is listed **once**, in the repo where the
essential work happens; its entry names the other repos it touches.

Status values: `planned` · `in progress` · `done` · `deferred`.

## Planned

### SRV-01 — Groups / broadcast
Status: planned · Also affects: freizone-app
Group and broadcast messaging. Today none of it exists (no tables, no API, no
UI); a group send is conceptually just N direct sends. Needs protocol design
first (membership, key distribution, fan-out) before any implementation.

### SRV-02 — Multi-device linking
Status: planned · Also affects: freizone-app, shared Go core
Add a second device to an existing identity via a QR + Noise handshake, with
the server acting as a **blind relay** (it never sees the linking secrets).
Distinct from today's QR, which is only for registration invites — not device
linking. Prerequisite for SRV-03-style history transfer (see APP-02).

### SRV-03 — Session recovery on ratchet desync
Status: in progress · Also affects: freizone-app
The Double Ratchet had no self-healing: once `sessions[peer]` desynced, all
further messages from that peer stayed undecryptable and piled up in the
server queue. The desync *trigger* (cross-isolate push/foreground race) was
fixed 2026-07-22.

**Manual variant shipped 2026-07-26** (freizone-app): the receive path now
accepts an incoming X3DH `initial` as a re-key even when a session already
exists, replacing it only once it actually decrypts the envelope (a failed
attempt falls back safely, without burning a one-time prekey); an
undecryptable "poison" envelope is dropped from the server queue after a few
attempts instead of re-failing forever; and a user-triggered "Reset secure
session" action (peer profile + chat long-press) discards the local session
so the next outgoing message re-establishes X3DH, with a visible
"Secure session was reset" system-message marker on both sides. Recovers a
desynced conversation once **both** participants run a build with the
receive-path change — a one-sided reset alone did not work before this.

**Root causes of *permanent* desync closed 2026-07-28**, found while chasing
a "no background push notifications" report back to its actual source (the
messages simply never decrypted): (1) `pkg/ratchet.Session.Decrypt` mutated
the session step-by-step with no rollback, so a single undecryptable message
(a duplicate, a stale straggler, a corrupted envelope) left it permanently
wedged — `Decrypt` now works on a clone and commits only once the message
authenticates, and rejects an outright duplicate before it can consume the
next message key; (2) freizone-app's background push isolate and foreground
session both applied a whole-profile last-writer-wins save, so a resume that
raced a push-driven decrypt silently rolled the ratchet back by however many
messages the wake had just processed — an exclusive cross-isolate lock now
serializes each account's load-decrypt-save sequence; (3) redelivered
messages (delivery is at-least-once) were processed a second time, which for
a redelivered X3DH initial meant rebuilding and overwriting the already-
advanced session — freizone-app now tracks processed message ids and skips
a repeat. Verified end-to-end on real devices after resetting two sessions
this had already broken.

**Still open:** automatic detection (repeated decrypt failure → auto-discard
→ fresh X3DH) instead of requiring the user to notice and manually reset --
a UX nicety now, not a correctness gap: with the above fixed, a *desync in
the first place* should be rare rather than something the app merely
recovers well from.

### SRV-04 — Authenticate the prekey-bundle claim
Status: planned
The prekey-bundle claim (`router.go`) is currently unauthenticated — a small
forward-secrecy risk, not a confidentiality problem. Harden it.

### SRV-05 — REST resource-model build-out
Status: planned
Incremental completeness of the REST surface. No concrete gap known; tracked so
detail work has a home.

### SRV-06 — Root-key-authenticated device recovery
Status: done · Also affects: freizone-app (APP-01)
Companion to APP-01 (seed recovery). Today a device can only be added to an
existing account by a request signed by an *already-active* device
(`POST /v1/devices`, devices.go), and re-registering an existing account is
rejected (`409 account_exists`, accounts.go) — so after total device loss
there is no way back into the account, even with the root key from the seed.

Add a recovery path authenticated by a **root-key signature** on the request
(not a device signature — the root key is the account's ultimate authority
and already signs every device cert and revocation, see PROTOCOL §2): accept a
new device cert (signed by that root key) for an existing account, mark it
active, and in the same root-authenticated step revoke the lost device(s) so
their keys stop being valid. This is what lets a user keep their existing id /
short id (`account_id == hash(root_pubkey)`) after losing all devices; without
it, recovery could only mint a brand-new account (new id). Needs a small
PROTOCOL addition (root-key request-signing scheme, extending §3's
device-signature model) and a new/extended endpoint.

**Server side shipped 2026-07-26:** `POST /v1/accounts/{id}/recover` (public,
inline-authenticated). The root-key request-signing scheme reuses §3's exact
canonical string but with `Signature-Key-Id = base64(root_pubkey)` (the
"self-describing-key" variant, same convention federation already uses), so no
new signing format was needed — the root signature covers the whole body
(the new device cert) and a fresh timestamp+nonce make it replay-proof. On
success it adds the new device and revokes every other device in one
root-authenticated step (revoke-all-others: total loss is the premise). See
PROTOCOL §3 (self-describing-key variant) and §4. **App-side seed
backup/restore UI shipped and verified end-to-end 2026-07-27** (APP-01,
freizone-app) — same account id/short id restored, old device revoked,
account role (admin/moderator) intact since it lives on the account row, not
the device.

### SRV-07 — Encrypted blob transport (attachments)
Status: in progress · Also affects: freizone-app (APP-04)
Out-of-band transport for message attachments, so multimedia messaging
(APP-04) doesn't have to ride inside a message payload. A blob is opaque
ciphertext the server cannot read; the message carries only a reference and
the decryption key, inside its existing end-to-end encryption.

Why a separate transport rather than simply raising the message size limit:
the global body cap is 512 KiB (~370 KB of binary after base64), and
federation is client-direct — a sender posts to the *recipient's* server, so
what applies is the **remote operator's** limit. Inlining photos would
therefore require every peer operator to raise a security-relevant,
anti-flood limit in lockstep. On top of that, the message queue is the wrong
home for megabytes: payloads live in a SQLite `TEXT` column, `ListPendingMessages`
has no `LIMIT` (it materializes every pending payload in memory), and SSE
writes a whole payload on one `data:` line.

**Blobs live on the recipient's server**, the same direction messages already
travel — so a recipient only ever fetches from its own server and never
reveals its IP to a stranger's. The trade-off, accepted deliberately: the
upload route accepts uploads from unregistered federated senders, defended
like federated messages (kill switch, blocklist, per-device quota, TTL). This
also generalizes better to groups (SRV-01): one upload per recipient *server*
rather than N members fetching from the smallest server in the group.

**Shipped 2026-07-29:** `POST /v1/blobs` (device-signed) and
`POST /v1/federation/blobs` (self-describing key, sender identity in headers
since the body is raw bytes, sharing federation.go's verification via a
common helper), plus recipient-only `GET`/`DELETE /v1/blobs/{blob_id}`.
Bodies are raw `application/octet-stream`, authenticated by a new
streamed-body signature variant (PROTOCOL §3): the client states
`Blob-Digest: sha256=…`, the server verifies the signature from headers
*before reading a byte*, then streams to disk through a hasher and rejects a
mismatch — so a forged upload costs no disk, and stored bytes are always
exactly what was signed. Enabled per route, so the header cannot substitute
an unsigned body anywhere else.

Storage is the filesystem with metadata in SQLite (the driver has no
incremental blob I/O, so a column would materialize whole files in memory on
the single-writer connection); temp-file + fsync + rename, random 32-byte ids
rather than content hashes (content addressing would leak file-equality and
allow existence probing). Deliberately **no list endpoint**, so the
unbounded-fetch mistake of the message queue cannot recur here. An hourly
ticker expires blobs in bounded batches, sweeps abandoned uploads, and
daily sweeps orphan files. `GET /v1/server-status` advertises `blobs_enabled`
and `max_blob_bytes` so a sender can size an attachment to the recipient
server's limits instead of discovering them via a 413. See PROTOCOL §10.

**Still open:** the app-side image UI that uses this (APP-04), and
resumable/chunked uploads (only needed once video lands).

### SRV-08 — Moderator global block/unblock via Server Admin
Status: planned · Also affects: freizone-app
`POST /v1/accounts/{id}/block` and `/unblock` (`handleBlockAccount`/
`handleUnblockAccount`, `internal/api/admin.go`) already disable the account
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

### SRV-09 — Admin user-list activity signals (pending messages, quota)
Status: planned · Also affects: freizone-app
The Server Admin Users list (`admin_screen.dart`) shows only role and blocked
status per account (`AdminAccountSummary`: id, role, status, created_at) —
nothing that distinguishes an active account from an abandoned one. Add, per
account: queued/pending message count and the age of its oldest pending
message (`store.ListPendingMessages` is per-*device* today; needs aggregating
across an account's devices), plus attachment/blob quota usage
(`store.BlobUsage`, also per-device, SRV-07) shown as e.g. "3.2/50 MB". The
goal is spotting unused accounts, not live monitoring, so this can ride the
same request that already lists accounts rather than need push updates.

### SRV-12 — Forward/backward compatibility as a standing constraint
Status: planned · Also affects: freizone-app
Federation means any app-version/server-version combination is permanently
in the field — a new feature must degrade gracefully rather than assume the
peer app, the user's own server, or a remote federated server already knows
about it. Policy (see also `freizone-claude/freizone-shared.md`): capability
is *discovered*, never assumed, via explicit status fields (`GET
/v1/server-status`'s `federation_enabled`, `blobs_enabled`, `max_blob_bytes`)
or by whether an optional response field is present at all — an absent
field falls back to its documented default (precedent: a pre-federation-flag
server omits `federation_enabled`, treated as `true`) rather than crashing
or silently misbehaving. When a feature genuinely isn't available on the
other side, either hide the affected UI or tell the user plainly why (e.g.
"this contact's app can't receive images yet") — never fail silently. A
**baseline feature set needs no per-call capability check**: everything
already shipped as of today, including image attachments once APP-04/SRV-07
land end-to-end — only features newer than that need a discovery step.

Already following this pattern: `federation_enabled`'s absence-means-true
default (consumed in `app_session.dart`); the reserved-but-forward-compatible
`attachments` field in `MessageContent` (freizone-app), so an old client's
JSON parser ignores fields it doesn't understand instead of failing.

**Not yet audited:** whether `blobs_enabled`/`max_blob_bytes` (shipped with
SRV-07) are actually consumed anywhere client-side yet — they aren't as of
this writing, since the app-side image UI (APP-04) hasn't been built. Once
it is, this is the first real test of the pattern for a feature that isn't
just on/off but has a numeric limit. Worth a pass over existing endpoints/UI
to check none of them silently assume a capability instead of checking for
it, before the surface area grows further (groups/SRV-01, multi-device/
SRV-02).
