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

**Automatic detection + re-key implemented 2026-08-01** — no manual "Reset
secure session" needed, and no waiting for the user to type something. Four
pieces:

1. **A failure taxonomy** (`pkg/ratchet/failure.go`): `Session.Decrypt`'s
   errors are now sentinels behind an exported `FailureCode` /
   `SuggestsDesync`, so a caller can tell a routine redelivery
   (`duplicate_message`) from diverged keys (`authentication_failed`,
   `too_many_skipped`, `no_receiving_chain`) without matching error text.
   Carried across freizone-app's cgo boundary as a `code` field on the core's
   JSON result envelope (an `error` value can't cross it) and surfaced in Dart
   as `FreizoneCoreException.code`.
2. **Per-peer evidence** (freizone-app `AppState.peerSessionHealth`, persisted):
   an envelope counts once, only after it has exhausted its retries *and* only
   if its code meant desync -- plus the one desync shape that produces no error
   at all, a non-`initial` envelope from a sender we have no session for (our
   own state lost/rolled back). Any successful decrypt clears the evidence. A
   background push wake can only *detect* (it has no sending machinery), which
   is why this lives in the profile rather than in memory: the next live session
   acts on what a wake recorded.
3. **The invisible re-key envelope** (PROTOCOL §6, `v: 3 / kind: rekey`): a
   control payload alongside receipts, never stored or notified. A desync breaks
   *receiving*, so the peer keeps sending into a session we can't read and
   nothing they do fixes it -- only a fresh `prekey` block from our side does,
   and it needs a message to ride on. The manual reset now sends one too, so it
   finally works one-sided. Cost of the format choice: a build predating `v: 3`
   shows the generic "newer app feature" placeholder for what should have been
   invisible.
4. **Two rules against making it worse** (`session_recovery.dart`, pure and
   unit-tested): both sides re-keying at once leaves both broken again round
   after round, so the **lower** `account_id` goes first and the higher one only
   after a grace period; and since each re-key burns one of the peer's one-time
   prekeys, attempts per peer are spaced. Ineligible peers are skipped entirely
   (blocked, an unaccepted message request -- answering one invisibly would tell
   a stranger we're there -- or federation switched off).

Tested at every layer that can be: the failure taxonomy and the envelope shape
directly, the policy as a pure function (`test/session_recovery_test.dart`), and
the whole crypto loop in `pkg/ratchet/rekey_test.go` -- a deliberately desynced
pair, the repeated identical `authentication_failed` a client detects it by, the
re-key that heals it in both directions, and the guard that a stale `prekey`
block cannot break a healthy session.

**Still open:** the same loop end-to-end through two real app instances,
including across a background push wake (where detection and recovery happen in
different isolates). Worth an explicit desync injector in a debug build: with the
2026-07-28 root causes closed, a desync should now be *rare* rather than merely
recoverable, so this path will seldom run in the field -- which is exactly why it
needs a way to exercise it on purpose to stay trustworthy.

Two adjacent gaps found while building this, both pre-existing and both left
alone: `_getOrCreateCryptoSession` stores a fresh initiator session before the
send that carries its `initial` succeeds, so a failed first send loses the
handshake material (the recovery loop above now papers over it for existing
conversations, but not for genuine first contact); and `cmd/devclient` never
accepts a re-key over an existing session, so it cannot participate in recovery
at all.

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
Status: done · Also affects: freizone-app (APP-04)
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

**Complete as of 2026-07-30.** The app-side UI that consumes this shipped
with freizone-app 0.12.0–0.12.3 (APP-04 phase 1): pick from the gallery,
encrypt, upload to the recipient's server, render in the bubble, view
full-screen, and delete the blob once it is stored locally. The one item
originally listed as still open here — resumable/chunked uploads — is only
needed once video lands and now has its own entry, **SRV-11**.

### SRV-08 — Moderator global block/unblock via Server Admin
Status: planned · Also affects: freizone-app
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

### SRV-10 — Forward/backward compatibility as a standing constraint
Status: planned · Also affects: freizone-app
(Renumbered from SRV-12 on 2026-07-30 to close an accidental gap in the
codes; SRV-10 and SRV-11 had never been issued. Older notes or commit
messages may still say SRV-12.)
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
"this contact's app can't receive images yet") — never fail silently.

A **baseline feature set needs no per-call capability check**: everything
already shipped and in the field, only newer features need a discovery step.
Attachments are the deliberate exception to that, even though they have
shipped — not because they are new, but because the server that has to
support them is the *recipient's*, which this client never controls and
whose operator may have them switched off or capped differently (see the
`blobs_enabled` discussion below). "Already shipped" only makes something
baseline when it is a property of *our* side.

Already following this pattern: `federation_enabled`'s absence-means-true
default (consumed in `app_session.dart`); and the `attachments` list in
`MessageContent` (freizone-app), which was carried as a reserved, always-empty
field from the day the v1 envelope was introduced — so when APP-04 finally
filled it, no format change was needed and builds predating it still render
the caption instead of failing to parse.

`blobs_enabled`/`max_blob_bytes` were the first test of this pattern for a
capability that isn't just on/off but carries a numeric limit, and they went
unconsumed for a while after SRV-07 shipped: APP-04's first version simply
assumed attachments worked. Now closed — the app reads both, and does so
from the **recipient's** server rather than its own, since that is where a
blob is stored. A peer whose server has attachments off gets no picture
button at all, and one over the size cap is refused with the actual limit
named instead of a bare `413`. An unreachable or erroring status call means
*unknown*, never *unsupported*, so the feature isn't hidden by a hiccup.

Note the default differs from `federation_enabled` on purpose: an absent
`blobs_enabled` means **off**, because a server that doesn't advertise the
field predates SRV-07 and has no blob endpoints — whereas absent
`federation_enabled` means on, because federation predates its own flag.
The rule is "fall back to what that specific field's absence actually
implies", not one global default.

**Still worth doing:** a pass over existing endpoints/UI to check none of
them silently assume a capability instead of checking for it, before the
surface area grows further (groups/SRV-01, multi-device/SRV-02).

### SRV-11 — Resumable/chunked blob uploads
Status: planned · Blocks: APP-04 phase 2 (video)
Split out of SRV-07, which shipped without it. A blob upload is one shot
today: `POST /v1/blobs` streams the whole ciphertext in a single request,
verified against the `Blob-Digest` the client signed up front (PROTOCOL §3,
§10). That is fine for photos — they are capped at a few MiB after the
downscale — but a video is large enough that a dropped connection at 90%
means starting over, and mobile connections drop.

Needs a protocol addition, not just a server change: some way to open an
upload, send ranges, and commit it, while keeping SRV-07's two guarantees —
that the signature is verified *before* any bytes are written, so a forged
upload costs no disk, and that the stored bytes are exactly what was signed.
A per-range digest, or a session whose overall digest is stated at open time
and enforced at commit, are the obvious candidates. The abandoned-upload
sweep that already exists (hourly ticker) is what would reclaim a session
the client never commits.

Deliberately not started: it is only worth designing alongside video
(APP-04 phase 2), since the chunk size and resume semantics should be driven
by a real payload rather than guessed at.

### SRV-12 — Short, hand-typeable invite codes
Status: done · Also affects: freizone-app
Invite codes were 32 hex characters (16 random bytes) — fine to scan, awful
to read aloud or type. Now 12 symbols of Crockford Base32 grouped in fours,
`ABCD-EFGH-JKMN`, the same alphabet and normalization the setup token already
used, extracted into `pkg/humancode` so both share one implementation.

Input is deliberately forgiving, because every variation is the same code to
the person entering it: case is ignored, `-`/`_`/whitespace are stripped (so
the grouped display form and the compact form in a QR are interchangeable),
and `I`/`L` read as `1`, `O` as `0` — unambiguous precisely because the
alphabet cannot produce those letters. `U` is left alone, since no digit it
plausibly stands for. Normalization happens server-side in `store`, so the
typed path and the QR path cannot diverge.

**12 symbols, not the token's 8** — 60 bits rather than 40. The token's
shortness is bought by `MaxSetupTokenAttempts`: it is a singleton, so a
failed guess identifies the one thing to lock out. Invite codes break both
halves of that. Many are outstanding at once and *any* unused one grants
registration, so a guesser need not target a particular code (each extra
outstanding code shaves a bit off), and a failed guess names no code to lock.
With no rate limiting on registration either, the length has to do the work
the lockout does. Shipped alongside:

- **Only the code's SHA-256 hash is stored**, as for the setup token — a
  leaked database yields no working invites. Possible because no endpoint
  lists codes; the cost is that a lost code cannot be re-shown and must be
  reissued.
- **A default expiry** (`FREIZONE_INVITE_EXPIRY_DAYS`, 14 days; `0` opts
  out). An unbounded window is what makes guessing worth attempting at any
  length. The app now shows "Valid until …" next to a freshly issued code,
  since otherwise someone hands one out unaware it has a deadline.

**Migration note:** migrations here are plain SQL and SQLite has no
`sha256()`, so existing plaintext codes could not be hashed in place.
`0012_hash_invite_codes.sql` therefore **drops unredeemed codes** — any
invite handed out but not yet used stops working and has to be reissued —
while keeping already-used rows as history behind a placeholder that no
lookup can match. Leaving old codes un-hashed would have defeated the point.

Considered and not done: a global rate limit / attempt counter on the
registration path. It would be the real backstop and would make even 8
symbols defensible, but at 60 bits the length already carries it, and this
was not the moment to add a new failure mode to the registration flow.

### SRV-13 — Purge invite codes that expired unredeemed
Status: done
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
  when an account turns out to be a problem. It is never exposed through any
  endpoint (there is no invite-list route), so only the operator can read it,
  and deleting either account clears its side already (cascade / set-null,
  from migration 0005).
- **Codes with no expiry are left alone**, so flipping
  `FREIZONE_INVITE_EXPIRY_DAYS` to a non-zero value cannot retroactively
  sweep away codes that were issued to live until redeemed.

Considered and not chosen: a retention window for redeemed rows too, or
nulling `used_by` after a while to keep the statistics without the pairing.
That would fit the project's minimal-retention stance better — this table is
now the only one holding anything indefinitely — but the moderation value of
knowing who invited whom was judged the higher good. Worth revisiting if a
public server ever makes the invite graph large enough to matter.
