# Roadmap — freizone-server (core)

Planned and shipped work whose **essential** part lands in this repo.
freizone-server is the project core, so cross-repo and protocol-level items live
here by default.

Each item has a short **reference code** used to discuss it. Codes are per-repo,
so the prefix says which repo's `docs/ROADMAP.md` owns the item:

- `SRV-` — freizone-server (this file, core)
- `APP-` — freizone-app
- `GAW-` — freizone-gateway

A change spanning several repos is listed **once**, in the repo where the
essential work happens; its entry names the others it touches.

Status values: `planned` · `in progress` · `done` · `deferred`.

## How to read this file

Entries here are deliberately short: what the item is, its status, and a dated
log of what actually happened. The reasoning — why an approach was chosen, what
was rejected, which trade-offs were accepted — lives in a per-topic design
document under [`design/`](design/), linked from the entry. Items small enough to
state in a few lines have no separate document; splitting those would cost
clarity rather than add it.

Released versions and what each contained: [`CHANGELOG.md`](CHANGELOG.md).
The wire protocol itself is specified in [`PROTOCOL.md`](PROTOCOL.md) — that is a
contract, not a plan, and does not follow this file's structure.

## Items

### SRV-01 — Groups
Status: `done` · Also affects: freizone-app (APP-16)
Design: [design/01-groups.md](design/01-groups.md)

Group messaging with a founder/admin/moderator authority model. The group is a
self-certifying cryptographic object, not a server object — messages ride the
existing pairwise ratchets with no group key, and membership/roles are a
grow-only set of signed facts that converges via a `state_hash` carried on every
message. Broadcast, previously part of this item, split out as SRV-16.

- 2026-08-02 — designed, then phase 1 shipped: `pkg/group` (event types and
  signing bytes, signature and certificate-chain verification, the
  order-independent fold, `state_hash`, snapshot merge) plus version-aware id
  derivation in `pkg/address`, so a group id reuses every line of the account-id
  encoding under a different marker. Pure Go, no I/O, no server change yet.
  Four plan corrections the tests forced are recorded in the design document —
  the notable one being that two moderators cannot in fact remove each other
- 2026-08-02 — phase 2 shipped: `POST /v1/messages/batch` and its federated
  twin, advertised as `batch_messages`/`max_batch_messages` on
  `GET /v1/server-status` and bounded by `FREIZONE_MAX_BATCH_MESSAGES`. Per-item
  outcomes, so one recipient's full queue costs only their own copy. Unifying
  the four handlers onto one enqueue path also closed two older gaps: the
  same-server path never checked the recipient *account*'s status, and a
  payload of literal `null` was queued rather than rejected
- 2026-08-02 — phase 3 shipped: `devclient group`, verified across both local
  Docker instances with a federated member. Four accounts converge on an
  identical `state_hash`, batch delivery is used per recipient server, and
  unauthorized acts are rejected identically by every member's own fold. Three
  design corrections the run forced, in the design document — the significant
  one being that **simultaneous X3DH establishment is routine in a group**,
  which needed a tie-break plus a read-only session and is now in PROTOCOL §5
- 2026-08-03 — three-party convergence measured with `devclient` against both
  local Docker instances, federated, after the app made it look slow. Results:
  a clean third-member invite converges in **one** round (all three on the same
  `state_hash`, every message delivered). A *lost* fact costs **one message plus
  two control envelopes** and needs a third member online in between — the
  member behind converged only on its second drain, which is exactly the "took
  several messages" report; the lost message itself never arrived at all, since
  `devclient` has neither the app's snapshot debts nor its group outbox.
  **Simultaneous establishment** (forced cleanly by crossing two accepts) is
  handled correctly and losslessly today: both sides decrypt, the lower account
  id keeps the sending session, the loser's session is retained read-only
  (`inbound_sessions`), traffic flows both ways afterwards — at the cost of two
  extra snapshots from the resulting hash mismatch. So the reported slowness was
  the lost-fact path, not the ratchet. Not covered: the app's own Dart
  implementation of the tie-break, which is separate code
- 2026-08-03 — `pkg/group` refuses to *sign* an event whose group id, or whose
  subject on the granting side (genesis, `member_add`, `role_grant`,
  `join_accept`), is a cosmetic spelling or an id-prefix rather than the
  canonical id. Found by testing the app's invite (APP-16): such an event is
  perfectly verifiable but folds in a **phantom member** — listed and invited,
  yet impossible to session with, since the subject's certificates are all
  signed over the canonical id. Admission stays tolerant, and the undoing side
  (`member_remove`/`leave`/`role_revoke`) stays signable with whatever spelling
  is in the fold, so a phantom can still be cleaned up
- 2026-08-04 — `cmd/devclient`'s **one-to-one** path handles simultaneous X3DH
  establishment too, which was this repo's last loose end from this item: it
  established a session only when it had none, so a prekey block arriving over
  an existing session was ignored and the message behind it was unreadable
  forever. Fixed by extracting the establishment logic the group watcher already
  had into one shared `session.go` — a second copy is how one path silently ends
  up handling fewer cases than the other, which is precisely what had happened.
  Measured before and after against the local Docker instances with a
  deliberately crossed establishment: the pre-fix binary answers
  `ratchet: message authentication failed`, the fixed one decrypts, the lower
  account id keeps its initiator session with the loser's kept read-only
  (`inbound_sessions`), the higher adopts the winner's outright, and messages and
  receipts flow both ways afterwards with nothing stranded. Two things came with
  it: the same path now also follows a peer's *deliberate* re-key (SRV-03's
  "Reset secure session") in a one-to-one chat, which it likewise could not
  before; and `newIdentity` initializes every map `LoadState` guarantees, since
  `InboundSessions` was written on a path that only ever runs after a reload
  today — a nil map waiting for the order of commands to change
- 2026-08-05 — **done.** The app side (APP-16) closed with a clean device run of
  its last two pieces, and this repo's own loose ends are closed above.
  Attachments in a group needed a core change of their own and shipped as
  SRV-18; broadcast, once part of this item, is SRV-16 and is now designable —
  it was deliberately left until groups shipped. The accepted weaknesses stay
  as recorded in the design document: self-asserted timestamps, a late fact that
  can retroactively invalidate an event, and equivocation being detectable
  rather than preventable

### SRV-02 — Multi-device linking
Status: `planned` · Also affects: freizone-app, shared Go core

Add a second device to an existing identity via a QR + Noise handshake, with the
server as a **blind relay** that never sees the linking secrets. Distinct from
today's QR, which is only for registration invites. Prerequisite for history
transfer (APP-02).

### SRV-03 — Session recovery on ratchet desync
Status: `in progress` · Also affects: freizone-app
Design: [design/03-session-recovery.md](design/03-session-recovery.md)

The Double Ratchet had no self-healing: once a session desynced, every further
message from that peer stayed undecryptable and piled up in the queue. Now both
detected and repaired automatically, over an invisible re-key envelope.

- 2026-07-22 — the desync *trigger* (cross-isolate push/foreground race) fixed
- 2026-07-26 — manual "Reset secure session" plus a receive path that accepts a
  re-key over an existing session
- 2026-07-28 — the three root causes of *permanent* desync closed: non-atomic
  `Decrypt`, last-writer-wins profile saves across isolates, reprocessed
  redeliveries
- 2026-08-01 — automatic detection and re-key: a typed failure taxonomy
  (`pkg/ratchet/failure.go`), per-peer evidence, the `v: 3 / kind: rekey`
  control envelope, and the ordering rule that stops both sides re-keying at once
- **Open** — the whole loop end-to-end through two real app instances, including
  across a background push wake. Wants a deliberate desync injector in a debug
  build, since a desync should now be rare enough never to occur by accident

### SRV-04 — Authenticate the prekey-bundle claim
Status: `done` · Also affects: freizone-app
Design: [design/04-authenticated-prekey-claim.md](design/04-authenticated-prekey-claim.md)

The prekey-bundle claim was unauthenticated, so anyone could drain a device's
one-time-prekey pool by claiming repeatedly. A claimant is now identified before
it may consume a key; an anonymous claim still gets a usable bundle, without one.

- 2026-08-02 — shipped in two stages. Server gates the one-time prekey and
  accepts either a local device signature or a federated claimant's inline
  certificate chain, respecting the federation switch; app and `cmd/devclient`
  sign their claims

### SRV-05 — REST resource-model build-out
Status: `planned`

Incremental completeness of the REST surface. No concrete gap known; tracked so
detail work has a home.

### SRV-06 — Root-key-authenticated device recovery
Status: `done` · Also affects: freizone-app (APP-01)
Design: [design/06-device-recovery.md](design/06-device-recovery.md)

After total device loss there was no way back into an account, even holding the
root key from the recovery seed. `POST /v1/accounts/{id}/recover` accepts a new
device certificate signed by the root key and revokes the lost devices in the
same step, so the account keeps its id.

- 2026-07-26 — server side shipped
- 2026-07-27 — app-side backup/restore UI shipped and verified end-to-end
  (APP-01): same account id, old device revoked, role intact

### SRV-07 — Encrypted blob transport (attachments)
Status: `done` · Also affects: freizone-app (APP-04)
Design: [design/07-blob-transport.md](design/07-blob-transport.md)

Out-of-band transport for attachments, so multimedia messaging need not ride
inside a message payload. A blob is opaque ciphertext stored on the
*recipient's* server; the message carries only a reference and the key, inside
its existing end-to-end encryption.

- 2026-07-29 — shipped: upload/fetch/delete routes, a streamed-body signature
  variant that verifies before reading a byte, filesystem storage with SQLite
  metadata, expiry and orphan sweeps
- 2026-07-30 — complete once the app-side UI landed (freizone-app 0.12.0–0.12.3).
  Resumable uploads, originally listed here, became SRV-11
- 2026-08-14 — **regression found and fixed: nothing had been releasing blobs
  since 2026-08-10.** PROTOCOL §10 has the recipient `DELETE` its claim once the
  plaintext is on disk, with retention only as the backstop; the SRV-23 cut moved
  downloads out of the app's Dart path into `pkg/client` and left the release
  behind, so every attachment held its recipient's quota for the full 14 days
  instead of until it was read. Restored in `pkg/client`'s `EnsureAttachment` —
  one place for app, `cmd/devclient` and a later bot. Noticed only while
  designing the storage forecast for SRV-25, which is worth recording: the gap
  was invisible from the outside, because a best-effort call that stops being
  made looks exactly like one that succeeds. It now has tests, including one for
  `DeleteBlob`'s own return value (the route answers `204` with an empty body,
  which the client used to read as "not a Freizone server")

### SRV-08 — Moderator global block/unblock via Server Admin
Status: `done` · Also affects: freizone-app
Design: [design/08-moderator-block.md](design/08-moderator-block.md)

Blocking already disabled an account server-wide, but was admin-only, so
moderating a server meant being an admin. Moderators may now block and unblock —
regular members only, since blocking staff would amount to removing them.

- 2026-08-02 — shipped, including the role limit the original plan had missed,
  and the "Block for all" wording that distinguishes this from the app's
  personal per-contact block

### SRV-09 — Admin user-list activity signals
Status: `done` · Also affects: freizone-app
Design: [design/09-admin-activity-signals.md](design/09-admin-activity-signals.md)

The Server Admin user list showed role and status only, so an account in daily
use looked identical to one abandoned a year ago. Each entry now also carries its
queued-message count, the age of the oldest, and attachment usage against quota.

- 2026-08-02 — shipped: two aggregate queries for the whole server, and a quota
  denominator of per-device limit × device count

### SRV-10 — Forward/backward compatibility as a standing constraint
Status: `planned` (ongoing policy) · Also affects: freizone-app
Design: [design/10-compatibility.md](design/10-compatibility.md)

Federation means every app-version/server-version combination is permanently in
the field. Capability is *discovered*, never assumed; an absent optional field
falls back to what that specific field's absence implies. Renumbered from SRV-12
on 2026-07-30, so older notes may use the old code.

- Closed — `blobs_enabled` / `max_blob_bytes` are now read from the
  *recipient's* server, the first capability carrying a numeric limit rather
  than a flag
- **Open** — a pass over existing endpoints and UI to check none silently
  assumes a capability, before groups (SRV-01) and multi-device (SRV-02) grow
  the surface further

### SRV-11 — Resumable/chunked blob uploads
Status: `planned` · Blocks: APP-04 phase 2 (video)
Design: [design/11-resumable-blob-uploads.md](design/11-resumable-blob-uploads.md)

An upload is one shot today, which is fine for a downscaled photo and wrong for
video, where a drop at 90% means starting over. Needs a protocol addition that
keeps SRV-07's two guarantees. Deliberately not started until video gives it a
real payload to be designed against.

### SRV-12 — Short, hand-typeable invite codes
Status: `done` · Also affects: freizone-app
Design: [design/12-short-invite-codes.md](design/12-short-invite-codes.md)

32 hex characters were fine to scan and awful to read aloud. Now 12 symbols of
Crockford Base32 as `ABCD-EFGH-JKMN`, stored only as a SHA-256 hash, with a
default expiry.

- Shipped — including forgiving input normalization shared with the setup token
  (`pkg/humancode`). Migration `0012` **drops unredeemed codes**, which had to be
  reissued

### SRV-13 — Purge invite codes that expired unredeemed
Status: `done`
Design: [design/13-purge-expired-invites.md](design/13-purge-expired-invites.md)

Nothing ever deleted an invite code, so `invite_codes` only grew. Expired
unredeemed rows are now swept on a 6-hourly ticker. Redeemed rows are kept
deliberately: they are the only moderation history this server holds.

### SRV-14 — Expose who invited an account (admin only)
Status: `done` · Also affects: freizone-app (APP-11)
Design: [design/14-invited-by.md](design/14-invited-by.md)

`invite_codes.created_by_account_id` was unreadable short of opening the
database. Now `invited_by` on the admin account list — **to admins only**, since
it is the one account-to-account link this server holds.

- 2026-08-02 — shipped. Only the `created_by` half is exposed, never `used_by`;
  absent means "not known here", never "registered openly"

### SRV-15 — "community" registration policy: users may invite too
Status: `planned` · Also affects: freizone-app
Design: [design/15-community-policy.md](design/15-community-policy.md)

A fourth policy value between `open` and `invite`: nobody joins without an
invite, but any existing user may issue one, not just staff. Registration itself
needs no change — what differs is authorization on invite creation. The hard part
is abuse: every member becomes a registration vector, so a bound on outstanding
codes per account is needed before this ships.

### SRV-16 — Broadcast lists
Status: `planned` · Also affects: freizone-app
Design: [design/16-broadcast.md](design/16-broadcast.md)

Split out of SRV-01 on 2026-08-02. Shares that item's fan-out and identity
model, but is not a flag on a group: a broadcast's recipient list must
specifically *not* be shared with its recipients, which removes the whole
snapshot / `state_hash` convergence layer *toward them* and makes delivery
one-directional. Designed once groups shipped, and grown in the process: a
list also needs to carry notifications from future Freizone bots, so it gets
its own founder/admin/sender authority tier that *does* converge normally
among itself, plus an `open`/`apply` subscribe policy for recipients joining
themselves rather than always being added.

### SRV-17 — Say in the prekey block whether it is a re-key
Status: `done` · Also affects: freizone-app

A `prekey` block arriving over an existing session is ambiguous: it is either a
peer who deliberately discarded their session (SRV-03) or one who established
at the same moment we did (routine in a group, SRV-01). The two need opposite
handling — adopt unconditionally versus apply the lower-`account_id`
tie-break — and PROTOCOL §5 currently has the receiver infer which from the
decrypted content, treating a `v: 3` re-key envelope as the deliberate case.

That works for our own clients, which always send it, and leaves a gap: the
envelope is only *recommended*, so a client that re-keys on an ordinary message
is read as establishing simultaneously, and a higher-id peer's recovery then
does not take. The fix is one field in the block saying which it is, so nothing
has to be inferred.

- 2026-08-03 — shipped as a **tri-state** `rekey` in the `prekey` block:
  `true` deliberate, `false` ordinary establishment, *absent* "this sender says
  nothing". `false` and absent are deliberately different facts — only that
  distinction lets the content-sniffing fallback ever be deleted, and a sender
  that states it is never guessed about. Not signature-covered (nothing over the
  prekey block is): tampering can misdirect the handling of one establishment,
  which the ratchet recovers from, and cannot make anything decrypt.
  `pkg/wire.NewEnvelopeRekey` plus the FFI core, the app's send and receive
  paths, and `devclient` — whose *group* receive path had no deliberate-re-key
  handling at all and now honours the flag. Interoperates both ways with no
  negotiation, so the `v: 3` re-key envelope stays worth sending: it is what an
  older receiver reads. Measured beforehand (see SRV-01's log) that the
  inference already works between our own clients — this closes the case it
  cannot cover, rather than a bug in the field

### SRV-18 — Multi-recipient blobs (attachments in a group)
Status: `done` · Also affects: freizone-app (APP-16) · Part of: SRV-01
Design: [design/18-multi-recipient-blobs.md](design/18-multi-recipient-blobs.md)

Attachments are the last large piece of groups, and the send side is blocked
in this repo: SRV-07 binds a blob to exactly one device, so a group picture
costs one upload per *member* rather than the one per recipient *server*
SRV-01's design assumed. One blob, several recipients — `blob_recipients` as
its own table, a repeated `recipient_device_id` on the upload, per-recipient
outcomes, and the file dropped when the last recipient row goes.

- 2026-08-03 — designed. Option chosen over two alternatives: leaving it at N
  uploads (rejected on a 20-member group's 30 MB of uplink for one 3 MB photo)
  and dropping the recipient binding in favour of the random blob id alone
  (rejected because quota, expiry and deletion would lose their owner, which is
  what lets SRV-07 accept uploads from strangers at all). Two follow-ups
  settled with it: a sender encodes once at its normal target and re-encodes
  **only** for a server with a smaller `max_blob_bytes`, rather than letting one
  frugal server set the quality for the whole group; and members whose server
  has blobs off get the text plus a stated "cannot receive pictures", never a
  silent failure or a blocked send. New capability `max_blob_recipients`, whose
  absence means **1** — an older server would otherwise store the blob for the
  first recipient only and still answer `201`
- 2026-08-03 — core shipped: migration `0013` (recipients into their own
  table), the upload handler with per-recipient outcomes, `DELETE` dropping
  only the caller's claim, an unreferenced-blob pass in the cleanup ticker,
  `max_blob_recipients` on `GET /v1/server-status`, and PROTOCOL §4/§10.
  Verified against both local Docker instances, **federated**: three members
  on one server share one 300 KB file, each fetches it, an unnamed device gets
  `404`, and the same works from a sender on the other server over
  `POST /v1/federation/blobs`. Three corrections in the design document — the
  significant one being that the stream must be bounded by the *largest*
  recipient's remaining quota, not the smallest: the plan had it backwards, and
  as written one member with a full quota would have cost every other member
  the picture with a shared `413`
- 2026-08-04 — the app side shipped too (APP-16), so pictures in a group work
  end to end: the group bubble renders through the same widget the one-to-one
  bubble uses, and the fan-out resolves its recipients before encrypting so it
  can upload once per distinct recipient server. Two things worth recording
  here. The client keys each copy's reference **per member**, not per server:
  a server advertising `max_blob_recipients: 1` — which is what silence means —
  stores a blob per device, and a per-server key cannot express that. And the
  *re-encode* half of this item's second follow-up was **not** built: producing
  a smaller rendition for a server with a smaller `max_blob_bytes` needs a Dart
  JPEG encoder the app deliberately has no dependency on, so those members are
  treated like a server with blobs off (caption plus a stated note) rather than
  the picture being shrunk for everyone — which is the option that decision
  ruled out. Reasoning in freizone-app's `docs/design/16-groups.md`

### SRV-19 — Attested servers
Status: `done` · Also affects: freizone-app (APP-22)
Design: [design/19-attested-servers.md](design/19-attested-servers.md)

A server may carry a signed attestation issued by the project — domain, tier,
display subject, expiry — which clients verify themselves against issuer public
keys compiled into the shared core, with nothing to consult online. Operators
running a server in agreement with the project can be recognised as such, and
the signal cannot be forged by whoever operates the server being described.
Here: `pkg/attest`, `FREIZONE_ATTESTATION`, a start-up check that warns rather
than refusing to boot, the field on `GET /v1/server-status`, and the
landing-page badge.

- 2026-08-05 — designed. Domain-bound rather than key-bound, no revocation
  mechanism beyond expiry, several trust anchors shipped from the start, `tier`
  open-ended per SRV-10, and `pkg/attest` permissively licensed so third-party
  clients can verify without taking on copyleft
- 2026-08-05 — `pkg/attest` shipped: the wire form, canonical signing bytes,
  `Sign`/`Verify`/`Valid` split (genuineness vs. domain-and-expiry, mirroring
  `pkg/devicecert`'s own separation), `Encode`/`Decode` for the opaque token,
  and `TrustedIssuers` as an empty, populate-later set — no genesis key exists
  yet, and an empty set is treated as "no attestation support in this build",
  never an error. `FREIZONE_ATTESTATION` carries the token unvalidated at
  config-load time; a startup check decodes, verifies and checks validity, and
  only ever warns. Served on `GET /v1/server-status` as `attestation`
  (`omitempty`), documented in PROTOCOL.md §4
- 2026-08-05 — landing-page badge shipped: `internal/api/web/index.html`
  decodes the token client-side purely for display (tier label, subject,
  domain match against `location.hostname`, expiry) and never verifies the
  signature there — the page is served by the very server it describes, so
  signature-checking it would be theater. Live-tested against a real running
  instance in a real browser: valid token showed the badge; wrong domain,
  expired, and unset all correctly showed nothing
- 2026-08-05 — fixed a self-check false positive found while verifying the
  first two real attestations issued against genesis keys (`chat.behringer24.de`,
  `chatcentral.de`): both run behind an external reverse proxy that terminates
  TLS itself, so neither container sets `FREIZONE_DOMAIN` at all -- correct
  per that field's own doc comment, and this repo's own production compose
  does exactly the same. `checkAttestation` was comparing the attestation's
  domain against an *empty* `cfg.Domain` and warning on every single startup
  despite nothing being wrong. Now: an empty `FREIZONE_DOMAIN` short-circuits
  straight after the signature check, at `Info`, not `Warn` -- this server
  genuinely cannot confirm which domain it's reached at in that deployment
  shape, and a real client checks that for itself against the domain it
  actually connected to regardless. Covered by `cmd/server/attestation_test.go`
  (new -- this package had no tests before). Not yet done: issuance and the
  app-side badge (APP-22), both outside this repo
- 2026-08-06 — app-side badge (APP-22) shipped in freizone-app: native-core
  verification importing this repo's `pkg/attest` directly (no reimplemented
  format, no drift risk), placement in the setup wizard, the account switcher,
  a peer's profile, one's own profile, and the admin area with an expiry
  warning. Issuance (`freizone-licensing`, `LIC-01`–`LIC-03`) also shipped; the
  two attestations already live on this repo's own production servers
  (`chat.behringer24.de`, `chatcentral.de`) were issued through it

### SRV-20 — Object-storage-backed blob storage
Status: `planned`

`FREIZONE_BLOB_DIR` stores attachment ciphertext as plain files on disk,
which Litestream-based database replication (see
[HIGH-AVAILABILITY.md](HIGH-AVAILABILITY.md)) doesn't cover — a warm-standby
failover can lose attachments uploaded since the last periodic `rclone`/`rsync`
pass even though the database row referencing them survived intact. An
option to store blob bytes directly in an S3-compatible bucket instead of
local disk would let one replication mechanism (the bucket) cover both the
database and attachments, closing that gap architecturally instead of
working around it.

- 2026-08-06 — raised while writing `docs/HIGH-AVAILABILITY.md`; not designed
  yet. Open questions include whether this replaces local-disk storage
  outright or becomes a second backend selected by config, and how it
  interacts with streamed blob I/O (the store package deliberately avoids
  loading whole files into memory today, per the config reference's note on
  why blobs are files rather than DB rows)

### SRV-21 — Landing page opt-out
Status: `done`

`handleLanding` (`internal/api/landing.go`) always serves the root-path page
explaining that the host is a Freizone server. Not every operator wants that:
a server run privately or internally may prefer the bare domain to give
whoever hits it net/http's plain 404 rather than confirmation that anything
is running there at all. Same operator-kill-switch shape as
`FederationEnabled`/`BlobsEnabled` (`internal/config/config.go`) — an env var,
default on, that skips registering the route when off rather than changing
what it returns.

- 2026-08-06 — raised while thinking through a separate, unrelated question
  about operator publicity preferences: declining to advertise being a
  Freizone server at all is a real, common case, and this is the lever for
  it
- 2026-08-07 — shipped as `FREIZONE_LANDING_PAGE_ENABLED` (default `true`),
  exactly the shape sketched above: `Router()` skips the
  `GET /{$}` registration when it is off, so the root falls through to the
  mux's own 404 rather than to a handler that answers differently.
  Deliberately *not* the `BlobsEnabled` treatment of a route that exists and
  returns `404 not_found` with a JSON body explaining itself — that body is
  itself the confirmation this switch exists to withhold. Also deliberately
  not surfaced on `GET /v1/server-status` and not runtime-switchable via an
  admin endpoint the way federation is: no client behaviour depends on it
  (nothing but a browser ever fetches `/`), so there is nothing for a peer to
  adapt to, and a DB-backed setting would only add a query to a hot path for
  a decision an operator makes once at deploy time

### SRV-22 — Seat/capacity display for admins
Status: `done` · Design: [design/19-attested-servers.md](design/19-attested-servers.md)

An attestation (`pkg/attest`) can carry `Seats`, an advisory account-count
ceiling from freizone-licensing (`LIC-08`), shown only to the operator's own
admins against the server's real active-account count — never on `GET
/v1/server-status` or the landing page, both reachable by anyone.

- 2026-08-06 — shipped. `pkg/attest` gained `Version2` (`Seats uint32`, `0` =
  unspecified/unlimited); `Decode` still reads `Version1` tokens, with `Seats`
  coming back `0`. `Sign` always produces `Version2` now. New
  `store.CountActiveAccounts` (status-active, any role) and admin-only `GET
  /v1/admin/license` (`internal/api/license.go`) compare it against `Seats`
  and report `over_limit`. The landing page's own token parser
  (`internal/api/web/index.html`) updated to skip the new field on a
  `Version2` token without ever reading it — verified against both a real
  `Version2` token and a hand-built `Version1` one run through the actual
  parser in Node, not just reasoned about

### SRV-23 — Shared protocol client core
Status: `in progress` · Also affects: freizone-app, future freizone-bot
Design: [design/23-shared-client-core.md](design/23-shared-client-core.md)

The protocol is implemented twice: `cmd/devclient` (3,236 lines of Go) and
freizone-app's Dart state layer (~12,400 lines of non-UI Dart,
`lib/state/app_session.dart` alone 4,461). Both build on the same `pkg/`
primitives, so the cryptography is shared — the orchestration around it is
not, and nothing forces the two to agree. A new `pkg/client` holds state,
persistence, network and every protocol decision once, consumed by the CLI, by
freizone-app through its cgo core, and later by freizone-bot. Staged, each
stage shipping on its own; local storage moves to SQLite, which costs testers
a one-time reset. No wire-format change.

- 2026-08-07 — raised out of a different question: whether to drop Flutter for
  two natively written apps (Kotlin, Swift). The measurement said the blocker
  is not the UI framework but that half the protocol lives in Dart, so going
  native would mean hand-writing the session lifecycle two more times — with
  divergence landing where it destroys messages rather than pixels, and no iOS
  device to catch it. Decided: core first, UI question re-asked afterwards,
  when each additional UI is view code over one implementation. Flutter stays
  meanwhile. Two things settled the same day: the closed-beta tester circle
  makes a data reset acceptable, which frees the storage format from
  compatibility and puts SQLite (`modernc.org/sqlite`, pure Go — the c-shared
  build has to reach `ios/arm64`) in place of the monolithic JSON store; and a
  planned Go-based freizone-bot as a third consumer, which fixes the core's API
  as idiomatic Go rather than the app's FFI shape, concurrent, and
  multi-identity. Not started — implementation waits for explicit go-ahead
- 2026-08-07 — stage 0 done on `dev_go`: `pkg/conformance` holds nine authored
  receive-path vectors (expectations written from PROTOCOL.md, deliberately not
  recorded from either implementation, so a vector can fail on both sides and
  still be right), and `cmd/devclient/conformance_test.go` runs this repo's
  client against them. Four pass — first contact, the tie-break both ways, the
  SRV-17 re-key override — and five fail, all real defects here: no
  processed-message-id tracking, the ratchet's `FailureCode`/`SuggestsDesync`
  classification discarded by an `fmt.Errorf` without `%w` (so a harmless
  redelivery is indistinguishable from a desync), a one-time prekey consumed
  before the responder session has decrypted anything, and no content fallback
  for a pre-SRV-17 sender's re-key. Recorded in the test's `knownDivergences`
  with their causes so the suite stays green while the defects stay visible;
  the list fails if a listed step starts conforming, which makes emptying it
  the completion signal. Design doc carries the findings, and one expectation
  the vectors disproved
- 2026-08-07 — app half of the suite running too, and it changes the plan's
  shape: **freizone-app passes all nine vectors, this client four.** Where the
  two disagree the app is right every time, so `pkg/client` is not "extract
  devclient and tidy up" — the app is the specification and devclient is what
  gets raised to it. Reaching that measurement needed a host build of the core:
  the bindings only ever loaded the Android `.so` and fell back to
  `DynamicLibrary.process()`, which finds nothing in a test process, so all
  8,700 lines of the app's `lib/state/` were untestable on a dev host. Now
  buildable via a new `native/build_desktop.ps1` (mingw-w64 for cgo; the NDK's
  clang only targets Android) plus a test-only `libraryPath` parameter that
  leaves the production loader alone. That capability outlasts the vectors —
  it is what makes the whole state layer testable for the first time
- 2026-08-07 — stage 1 (first slice) on `dev_go`: `pkg/client` exists, with the
  crypto-layer state on SQLite — identity, one-time prekeys, sending/inbound
  sessions, processed-message ids, decrypt-failure counts, per-peer session
  health, and the conversation metadata those rules reference. Cut there
  deliberately: local_state.dart calls conversations "the UI/history layer on
  top of sessions's crypto layer", so the transcript is the next slice rather
  than a half-finished part of this one. The app's semantics are reproduced
  exactly, including the ones easy to get subtly wrong — re-marking a processed
  id does not refresh its eviction position, reaching the decrypt-failure limit
  clears the counter as it reports it, and desync evidence is refused for a peer
  with no conversation so a stranger cannot grow the database one row per
  invented account id. 17 tests, including concurrent writers and two accounts
  in one process. Size, measured not estimated: `pkg/client` costs +7.04 MB on
  an `android/arm64` c-shared build, taking the shipped core from 5.96 MB to
  ~13 MB and the release APK from 78.1 MB to ~85 MB (+9%). Design doc carries
  the numbers and two corrections they force — the pure-Go argument for
  `modernc.org/sqlite` is weaker than written, since the core is already cgo,
  and the driver choice is a one-function change behind `database/sql`, so it
  need not be settled now
- 2026-08-07 — stage 1 finished: the transcript. Messages, attachment metadata,
  per-recipient group deliveries and local pins, keyed by a `chat_id` that is a
  peer account id or a group id without distinguishing — following the app,
  where both are 21-character bech32m strings differing only in a version
  marker, so stage 5 inherits working group transcripts and has only the signed
  fact set left to add. Three rules the modelling turned up are in the design
  doc: the transcript is read in arrival order and never by timestamp (the app
  appends and never sorts, so a late-decrypted message stays where it arrived);
  a `pending` send is settled to `failed` when the database is *opened* rather
  than when it is read, since transcribing the app's load-time rule as a
  read-time one would report a send genuinely in flight in this process as
  already failed; and attachments, deliveries and pins cascade with their
  message. 10 further tests, 27 in total. `local_state.dart` is now covered
  except for `pendingGroupEvents`, `groupSnapshotDebts` and
  `groupPeerStateHashes`, which are group coordination rather than storage and
  belong with stage 5
- 2026-08-07 — stage 2 begun (first slice): the signed HTTP transport in
  `pkg/client`. All three auth modes (public, device-signed, and the federated
  one that names the key by its base64 public key because a foreign server has
  no row to look a device id up in), the error model, and
  `GET /v1/server-status`. Everything takes a `context.Context` and the HTTP
  client carries no timeout of its own, since the message stream is a long-lived
  response and the context is the real deadline. Two things worth the design
  doc: failures are split into `APIError` (a Freizone server refusing in its own
  JSON) and `NotFreizoneServerError` (a host answering HTML or nothing), because
  "the server said no" and "you typed the wrong address" need different words in
  front of a user; and `ServerStatus` decodes through pointers so the two
  capability silences that mean the opposite of Go's zero value —
  `federation_enabled` absent is *true*, `max_blob_recipients` absent is *1* —
  are applied rather than guessed. 13 tests, 39 in the package; the signature
  test verifies with `pkg/httpsig`'s own `Verify` against a real `httptest`
  server rather than restating the canonical string, so a disagreement about
  what it covers surfaces here instead of in the field. Still to come in this
  stage: the message endpoints, the SSE stream and the event channel
- 2026-08-07 — stage 2 finished: message endpoints and the SSE stream.
  `Client.Stream` returns one channel of a tagged union (connected, message,
  disconnected, failed) rather than a channel per concern — in Go merely fine,
  but right because the FFI wrapper can only offer a blocking "next event" call
  and would otherwise have to multiplex on the side least able to test it.
  Events drop when the buffer fills rather than blocking, since a consumer that
  went away must not stall a connection the server cannot tell from a listening
  one. The app's reconnect policy is reproduced whole, including its two
  distinct regimes: a stream that came up and dropped retries in ~500ms with the
  backoff *reset*, while one that never came up backs off 3s→30s with ±20%
  jitter. Its per-attempt-client trick — which exists because a dead-but-routed
  host otherwise leaves a SYN-SENT dial per retry — becomes a cancellable
  context per attempt, with the deadline covering *reaching* the stream and not
  reading from it, since a healthy stream is idle but for a heartbeat every 25s.
  Also fixed a bug in the previous slice found while writing this one: the
  transport probed for a JSON object to detect a non-Freizone host, which would
  have misreported every `GET /v1/messages` (a bare array) as a wrong address.
  `SendMessage` counts 409 as delivered and `AckMessage` counts 404 as success,
  both for reasons the design doc records. 22 further tests, 50 in the package,
  and the package is clean under `-race` — newly possible at all, since the race
  detector needs cgo and the mingw toolchain only arrived with the Dart half of
  stage 0
- 2026-08-07 — FFI surface for the core, in freizone-app's `native/`
  (`CoreOpen`/`CoreClose`/`CoreSetIdentity`/`CoreStreamStart`/`CoreStreamStop`/
  `CorePoll`). Taken before stages 3-5 on purpose: the plan's own decision point
  after stage 2 was to get the core genuinely running on the device rather than
  spend another nine sessions with nothing shippable, and `SetIdentity` is what
  makes that possible before the app's state layer has migrated — the identity
  is handed across once and the core can then sign and stream on its own. The
  bridge is a cgo-free file so the handle lifecycle and poll semantics are
  covered by `go test`; `CorePoll` returns a batch rather than one event per
  crossing; event kinds cross as strings so a version mismatch fails visibly;
  and `disconnected` carries no error text, matching the app's rule that only a
  failed connect attempt reaches the user. 9 tests, 40 in the native package.
  This is also the commit where SQLite's dependencies actually land in the app
  module. Next: the Dart bindings and replacing `sse_client.dart` in
  `AppSession._startStream`, which is what puts the core on the Pixel
- 2026-08-08 — `sse_client.dart` replaced by `CoreStream`: the message stream
  now runs through the core over the FFI bridge, and `AppSession` changed by a
  type name because `CoreStream` keeps the old class's shape deliberately. Four
  host tests drive the whole chain — Dart to FFI to core to a real HTTP server
  and back — and caught three defects none of which would have shown on a
  device: the poll isolate opened the core with no library path (invisible on
  Android, where it is found by name anyway), a throwing poll escaped as an
  unhandled async error and killed the stream silently, and the database path
  was not injectable so no plain `flutter test` could reach it. Verified that
  the existing VS Code build/deploy tasks are unaffected: `build_android.ps1`
  produces both ABIs in 25s and `flutter build apk --debug` succeeds.
  **Size, now measured on the real core rather than estimated from a probe:
  arm64-v8a 5.96 → 15.07 MB and x86_64 6.40 → 15.83 MB, so about +9.1 MB and
  not the +7.04 MB the probe suggested** — a probe linking fewer packages than
  the real thing understates the delta. Release APK lands around 87 MB, ~+12%
- 2026-08-09 — stream reached the device, and two defects only real hardware
  could show. The stream never opened: Go negotiates HTTP/2 by default and the
  app's Dart client never did, so this was the first h2 stream against that
  nginx, and the first request on a fresh h2 connection got no response headers.
  h2 is now off, and a test asserts it stays off against a server that offers
  it. Disabling the transport alone was not enough and briefly made it worse —
  ALPN still offered h2, so the reply arrived as h2 frames an HTTP/1.1 transport
  tried to read as a status line; the test that should have caught it had
  substituted away the very field that was wrong. Connect failures now name the
  layer that stalled, because the connect deadline was masking the diagnosis by
  replacing whatever the stack was about to report
- 2026-08-09 — **SQLite dropped for plain files, reversing the stage 1
  decision.** `modernc.org/sqlite` cannot run on android/amd64 at all: its libc
  emulation calls `lstat`, Android's seccomp kills the process, and the app died
  at startup on every x86_64 device and emulator. The newest upstream still does
  it and every other pure-Go driver is modernc underneath; the cgo driver works
  but makes cgo mandatory for every consumer, which a planned Flutter desktop
  client turns into a cross-compilation matrix. The original reasoning was the
  weak part — "the server already uses SQLite" carried an answer across from
  relational, queried, multi-tenant data to one account with a handful of chats
  and no query at all. The replacement keeps one rule: nothing costs more as
  history grows. Transcripts are append-only logs, sessions and conversation
  metadata are one small file each, deletions and state changes are appended
  records naming their message rather than edits to a line, and the chat-list
  preview reads a bounded window instead of replaying. **All 27 stage-1 tests
  passed unchanged** — they assert behaviour, not storage — with 26 more since.
  Core is 15.09 → 9.10 MB on arm64-v8a, `native/go.mod` is back to one direct
  and one indirect dependency from twelve, cgo is optional again, and the
  emulator that SQLite killed runs
- 2026-08-09 — stage 2 confirmed on real hardware: background resume reconnects
  in under a second, live messages arrive, and the airplane-mode cycle
  recovers. Verified from the device's own data and logs rather than only by
  eye — core state directories present for every account, contact names
  untouched, and the layered probe doing its job on the unreachable local test
  accounts (`resolves to …; but tcp/18080 did not connect: i/o timeout`).
- 2026-08-09 — closed a gap the device test exposed by *not* logging anything:
  the stream had no idle timeout, so a connection that dies without saying so
  — half-open socket, network handover, a proxy dropping it mid-flight — was
  never noticed. The connect deadline is long over by then and a read that will
  never return does not fail on its own; the symptom is "messages sometimes
  just don't arrive" with nothing in any log. `sse_client.dart` had the same
  gap, inherited faithfully, and it is closed now that the reconnect lives
  somewhere testable. Safe because the server heartbeats every 25s, so a
  healthy stream is never quiet longer than that: the default silence timeout
  is 60s and every line resets it, keepalives included. Two tests, and the
  second is the one that matters — a heartbeating idle stream must survive
  several timeout periods, which the fix without that reset would fail while
  looking entirely reasonable
- 2026-08-09 — stage 3: the receive pipeline lands in `pkg/client`
  (`receive.go`, `content.go`, `recovery.go`). **It passes all nine conformance
  vectors** — against `cmd/devclient`'s four — so none of the four decisions
  that client gets wrong were inherited by extracting it. Passing on the first
  run being the least trustworthy green, each of those four was re-broken
  deliberately to confirm the vectors bite here rather than merely load. No
  `knownDivergences` list beside this runner: a failure has nowhere to go but a
  fix, since this implementation has no history to stay compatible with. The
  plaintext content model (v1 text, v2 receipt, v3 re-key, v4/v5 group) is
  modelled once instead of one-and-a-half times across Dart and devclient, and
  the automatic-recovery policy moved across as a pure function. The larger,
  unvectored half — notification rules, blocked peers, receipt watermarks, the
  re-key transcript marker — has its own tests, and two of the quietest were
  negative-controlled too. Group envelopes are decrypted and handed back
  undigested until stage 5 owns group state; that is the one seam left in the
  receive path. Not yet wired into the app: the UI still reads Dart state, so
  the Dart removal is its own slice
- 2026-08-09 — stage 4: the send path lands in `pkg/client` (`send.go`,
  `prekeys_api.go`, `peers_resolve.go`). The core can now hold a conversation
  by itself — resolve an address, publish and claim prekeys, establish, send,
  retry, confirm, re-key — and the tests run two real clients through a stub
  server, so every round trip is an actual envelope opened by the actual
  receive path rather than an asserted request body. That is what caught the
  one real defect in the headline rule, which was mine: `Session` returns a
  fresh value per call, so handing the same one to the rollback copy and to the
  encryption meant the rollback restored the advance it existed to undo.
  Nothing failed — the send worked, the retry worked, and the peer accumulated
  a gap per failed attempt. Three decisions recorded: topping up re-asserts the
  signed prekey rather than rotating it (devclient rotates on every upload); a
  session established without a one-time prekey is reported rather than
  refused; and the stale-device rule forgets the id and the session together.
  Recovery is closed end to end — stage 3 could only report that a re-key was
  due, since acting means sending. Attachments deliberately still out: the
  blobs live elsewhere, so a retry refuses rather than re-send a caption alone.
  Still not wired into the app
- 2026-08-09 — stage 4b: attachments (`blobs.go`, `media.go`). Never scheduled
  in the original plan, and done before groups because a group picture is
  uploaded once with every member's device named on it — building the fan-out
  on a blob-less send path would force it to reach outside itself mid-loop. The
  key is per attachment and deliberately not derived from the ratchet: the
  bytes outlive the message, so binding them to a session would make resetting
  one destroy every picture already received. Inline preview and blob are
  separated — the preview is written on arrival even on a background wake,
  the blob only when somebody looks — and the sender's own copy is written
  before the upload, which is what lets a retry finish an interrupted one. A
  retry names an existing blob again rather than uploading a second copy.
  `Options.MediaPath` makes the media directory movable, since pictures are the
  one thing here that is large and platform-opinionated.
- 2026-08-09 — the question that came with stage 4b turned up a real gap:
  **blocking was never a rule, it was a screen.** The receive side was complete
  and ported; the send side did not exist, because the Dart original says
  outright that "sending is disabled in the UI while blocked". A background
  retry, a queued receipt, a re-key signal or a bot with no interface would each
  have gone on talking to a blocked contact. The guard now sits in `deliver`, so
  it covers every path rather than every path a person starts — removing it
  makes two envelopes reach a blocked contact in the test, both machinery
- **Open**: a peer whose *account* no longer exists has no local state. The
  dead-device/dead-account distinction is sharp (`IsStaleDevice`) and a dead
  device heals itself on the next send, but an account an admin removed just
  fails every retry forever. Dart handles it only in the group path, and only
  because group facts cannot express "this member ceased to exist". Doing it for
  one-to-one needs a decision about what the user is shown — Andreas' call, not
  SRV-23's
- 2026-08-09 — stage 5a: the receiving half of groups (`groups.go`,
  `groupnarration.go`), which closes the last seam stage 3 left open — a group
  envelope is folded here rather than handed up. It has to be: the ratchet has
  advanced and the id is marked before the payload is even read, so an envelope
  nobody folds loses its facts for good, and a background wake with nothing
  attached still has to finish the job. Four rules, three of them quietly
  wrong-able: a re-invitation is an invitation (the facts survive a removal, so
  "is this group new" swallows every one); an event that overtook its genesis is
  held to a bound, and only for the one rejection a later fact can change —
  now `group.RejectNoGenesis` rather than a literal string both clients matched;
  a blocked member's group message leaves one collapsed line, because a shared
  transcript with invisible holes reads as delivery loss; and a snapshot's id
  comes from its genesis, not from the sender's claim. Membership changes are
  narrated from the before/after fold, so every device writes the same
  transcript independently. One test proved nothing until its negative control
  said so — it delivered a premature event and then a snapshot containing the
  same fact, so holding was never exercised; fixed by capturing the snapshot
  before the event exists
- **Next**: stage 5b, the sending half of groups — fan-out, snapshot debt,
  reconciliation against a peer's stated view, sync requests, per-member
  receipts. `GroupOutcome` already reports what it needs; nothing acts on it yet
- 2026-08-09 — stage 5b: the sending half of groups (`groupsend.go`,
  `groupactions.go`), and with it **the core is complete** — found, invite,
  accept, roles, remove, leave, dissolve, send, attach, repair. Tests drive
  three real clients through the stub server, so every group envelope is
  encrypted per member and folded by the code that has to fold it. Two rules
  about failure pointing opposite ways: a ratchet advance is never rolled back
  in a fan-out (a partial success means some peers moved on and some did not,
  so the delivery record carries who is behind), but an *establishment* is — the
  tests found that as a real defect, since a first copy that fails to post
  leaves a session the peer never saw established and every later message to
  them is then unopenable, silently and permanently. A rejected action is never
  broadcast, which needed care: `State.Apply` only checks form and signature,
  while *authority* is the fold's decision and the fold just ignores what it
  will not honour, so the check is "did the fold change" rather than any error.
  Self-healing in three parts, each covering what the others cannot: persisted
  snapshot debt, reconciliation against the hash every envelope carries
  (answered at most once per foreign hash, and persisted — a restart otherwise
  re-opens the loop), and asking outright for the one case no hash can signal,
  a member holding no facts at all. Batch delivery where advertised, one post
  per message otherwise, and the same fallback when a batch is refused. Group
  receipts are filed per member and never passed on. The cached peer device
  moved off `Conversation` into `peers/<id>/device.json` — a group member is
  addressed without necessarily having a chat with them
- **Next**: the app swap. `pkg/client` now owns state, network, receive, send,
  attachments and groups; the Dart side still holds the UI's state and would be
  the last thing to move. Worth doing as one cut rather than three, and it needs
  the data reset the design doc has planned since the start
- 2026-08-09 — stage 6, first slice: the FFI surface. Two small additions here
  (`IsGroupID`, `AttachmentPath`/`AttachmentThumbPath`) plus the whole surface
  in freizone-app's `native/`. Two decisions shape it. **Attachment bytes travel
  as paths, never through the boundary** — the shell has a file reader and an
  image decoder that want a file anyway, so a multi-megabyte round trip through
  a JSON envelope would cost more than the download did; and the attachment key
  never crosses at all, which a test pins by searching the encoded response for
  it. **One send call serves peers and groups**, because a chat id says which it
  is: account and group ids differ by a version marker, so dispatching is exact
  rather than a guess and the shell never has to track the distinction
- 2026-08-09 — the remaining cut is specified in the design doc rather than
  started: it is one indivisible piece (receive + read + send together, because
  a bridge that rebuilds `AppState` from the core overwrites whatever the Dart
  send path wrote), and half-applying it is the one state worse than either end.
  The measurements are recorded so they need not be retaken — 83 `session.state`
  call sites, which is why the screens do not change and `AppState` stays as the
  view model, and 60 + 76 lines for `sendMessage`/`_deliver`. Step 5 is where
  the data reset takes effect; the Pixel backup exists for exactly that moment
- 2026-08-15 — **`ForgetGroup`**, the one thing the cut left the app unable to
  do. Removing a group from a device was a Dart-side deletion before; afterwards
  the app could clear a group's transcript and media but not its facts, and
  `Groups()` is a directory listing — so a group one had left kept its row in
  the chat list, with the known limitation written into
  `AppSession.declineGroupInvite` rather than fixed. Removes the whole
  `groups/<id>` directory: facts, held events, per-member sync state and the
  chat state a list reads. Deliberately
  *not* part of leaving, and it makes no membership check of its own — the fold
  cannot tell "left" from "never joined" once the facts are gone, so the rule
  that this is only ever right for a group one is out of belongs with the caller
  that knows (freizone-app's `group_actions.dart` gates exactly that). The test
  pins the distinction the call exists for: being removed from a group does not
  take it off the list, forgetting it does

- 2026-08-15 — `DeleteMessage` takes the message's stored media with it. It
  already cascaded the pin, the attachments and the group deliveries, but the
  bytes on disk stayed: the transcript line is the only thing that names
  `<media>/<chat>/<message>`, so deleting it left the picture unreachable and
  permanent — the same broken promise freizone-app 0.23.0 fixed for a whole
  account, one message at a time. Found in the cut audit (see freizone-app's
  APP-21 note of the same date), which turned up the other half in the app:
  pin, unpin and per-message deletion never reached this client at all,
  despite `PinMessage`/`UnpinMessage`/`DeleteMessage` sitting here since
  stage 1 — the read half (pins on the chat summary) was wired, the write
  half was not, so both silently reverted on the next rebuild from the core

### SRV-24 — Let a server move house
Status: `planned` · Also affects: freizone-app, shared Go core

An account's address names its server, so today a server is forever: an
operator who wants to move to another host, another domain, or hand the whole
thing to somebody else has no move that keeps their users reachable. Everyone
who ever wrote the old address down — every peer's contact list, every group
fact naming a member's server — keeps pointing at a machine that is gone.

The shape suggested is HTTP redirection: the old host answers `301`/`302`
pointing at the new one, and clients follow it and remember. Cheap for the
operator and invisible to the user, which is the appeal. What it does not
settle, and what the design has to:

- **What actually moves.** A redirect only forwards requests; it does not
  carry accounts. The new host has to already hold the root keys, device
  certificates, prekeys and queues, or every redirected request 404s. So the
  redirect is the last step of a migration, not the migration.
- **Why a client should believe it.** A redirect is an unauthenticated
  instruction to send someone's traffic elsewhere, and the thing it moves is
  where messages for that account go. Following one blindly is a redirection
  attack with a `Location` header. Something has to be signed — plausibly by
  the old server's identity, or by each account's own root key — before a
  client rewrites a stored address.
- **Permanent vs temporary.** `301` and `302` mean different things to a
  client that persists what it learns: one rewrites the address in the
  contact list and the group facts, the other is followed for this request
  and forgotten. Group facts are signed and grow-only, which makes rewriting
  a member's server a fact-set question rather than a string replacement.
- **When the old host stops answering.** A redirect only works while the old
  address still resolves and serves. Anyone offline for longer than the old
  domain lives never sees it, so there is probably also a need for the new
  server to be discoverable from what a peer already holds.

- 2026-08-11 — raised by Andreas while reviewing how the app words a failure
  to reach a server. A server that is unreachable was noted to be ordinary
  rather than exceptional in this architecture — down, switched off for good,
  or reused for something else — and permanent relocation is the case worth
  supporting properly instead of leaving accounts stranded. Filed as its own
  item; nothing started

### SRV-25 — Server statistics for admins
Status: `done` · Also affects: freizone-app (APP-24)

An operator has no way to see how their own server is doing. Whether it is
filling its disk, whether registrations are climbing, whether a queue is
backing up — all of it sits in the database and none of it is readable
without a shell on the host. The figures are also exactly the kind that must
not be public: `SRV-22`'s reasoning applies unchanged, so this is admin-only
and stays off `GET /v1/server-status` and the landing page.

Current readings answer "is it healthy now". They cannot answer "is it
getting worse", because the tables they are computed from forget: a blocked
account, an expired blob and a delivered message all leave no trace behind,
so last month's size is not recoverable from today's state. Growth therefore
needs a recorded history of its own rather than a cleverer query. A
round-robin database (RRDtool's model) was considered and dropped: the pure-Go
ports are either unmaintained (`tgres`) or bring their own on-disk format and
one file per metric (`go-whisper`), which for a dozen gauges is a second thing
to back up and migrate beside the SQLite file that already gets both.

- 2026-08-14 — shipped. `stats_snapshots` (migration `0014`) and
  `internal/store/stats.go`: `ComputeCurrentStats` aggregates accounts,
  devices, blob count/bytes, queued messages and the federation blocklist,
  while `InsertStatsSnapshot` / `StatsHistory` / `PruneStatsSnapshots` keep the
  recorded series. Admin-only `GET /v1/admin/stats` (live) and `GET
  /v1/admin/stats/history?days=N` (`internal/api/stats.go`), both behind
  `requireAdmin` rather than `requireAdminOrModerator`, matching `GET
  /v1/admin/license`. A ticker in `cmd/server/main.go` records a snapshot
  every six hours — four a day, enough to resolve a same-day spike without
  filling the table — plus one immediately at startup so a fresh install has a
  first point rather than an empty chart, and prunes past two years, since
  nothing else ever deletes from that table. Blob bytes are read from
  `blobs.size_bytes`, not by walking the blob directory: the column is written
  from the bytes actually stored, so the walk would cost a full traversal per
  request for a figure already in the database. Disk space comes from a new
  `internal/diskstat` — `syscall.Statfs` on linux/darwin, and a `0, 0` stub
  elsewhere meaning "unknown" rather than an error, so a Windows development
  build still starts
- 2026-08-14 — **storage forecast**, the part the current readings could not
  answer: not "how much is stored" but "where is this going". `GET
  /v1/admin/stats` gained a `forecast` object with two series. The first is
  arithmetic on facts rather than a prediction — every blob carries its own
  `expires_at`, fixed at upload and never extended, so what is stored today has
  a known decay (`store.BlobExpiryBuckets`, one grouped query: a blob expires
  within the retention window of its upload, so there are only ever about that
  many distinct days to return, however many blobs exist). The second adds
  uploads continuing at the rate actually measured over the last
  `min(7, retention/2)` days (`store.BlobBytesCreatedSince`) — a window kept
  shorter than the retention period precisely so nothing inside it can have
  expired yet, which is what makes the figure exact instead of an undercount.
  Those new uploads live one window too, so the second series converges on
  `inflow × retention` and stops there. That convergence is the useful answer to
  "will this server run out of room": with a fixed retention window storage
  *cannot* grow without limit, so a straight-line extrapolation of the recorded
  history would have been alarming and wrong. The forecast rides in the same
  response as the live figures rather than on a route of its own, because it
  starts at the stored total that response reports and two requests would let an
  upload land in between — leaving a chart's measured line and its projection
  joined at two different values. The drain series is an *upper* bound, and
  only became one again with 0.18.1: while nothing released a delivered blob it
  was simply the normal case

### SRV-26 — Landing page background
Status: `done` · Touches: freizone-app (shares the artwork's motif vocabulary)

The root page (`SRV-21`) is correct but anonymous: nothing about it says it
belongs to the same product as the app's chat screen. Giving it the chat
background's pattern, plus a quiet animation in front of it, is the cheap way
to make a bare domain recognisable.

The interesting constraint is what the animation is allowed to *mean*. A
decoration driven by real activity would be a metadata leak in a product whose
whole point is that the server learns as little as possible — and account and
seat counts are already deliberately kept off this page (see `SRV-22` and the
`seats` note in `PROTOCOL.md`). So the rule is the narrow one: the background
may only restate facts the page already prints in words.

- 2026-08-15 — shipped. The pattern is the app's motif vocabulary (cranes,
  speech bubbles, racks, a shield, node constellations, dot grids) *redrawn*
  as a 3.5 KB seamless SVG tile rather than the app's own asset, which is an
  860 KB alpha-mask PNG and would have been over a megabyte inline. Applied
  the same way the app applies it — a flat tint behind a mask, not a coloured
  image — so one tile serves both themes and only `--pattern-tint` swaps.
  Seamlessness is structural rather than hand-fitted: a ring of nine `<use>`
  copies inside the SVG redraws anything crossing an edge one tile over.
  In front of it, a canvas constellation whose every input is already on the
  page: `location.host` seeds the node layout, so a server always draws the
  same figure and two servers draw different ones (an identicon that moves,
  disclosing nothing the address bar does not — `host` rather than `hostname`
  so that two instances behind one name are still told apart, as the two
  local development servers are); `federation_enabled`
  decides whether edges run off the frame or the graph is a closed island;
  `registration_policy` decides how newcomers appear — on their own when
  open, only after an existing node reaches out when invite-only, not at all
  when closed; and an unclaimed server sits dimmed and still. Packets crossing
  the graph never change size or colour at a node, which is the E2E claim
  stated as a picture, and they are timed on a clock rather than on anything
  real — sparse enough not to be misread as a live traffic view. Nothing here
  scales with usage, not even indirectly via node count or tempo, which is
  what keeps it a restatement rather than a second data source. A failed
  status read leaves the understated defaults standing (no peers, no
  arrivals): a decoration must not imply a capability the server may not have.
  `prefers-reduced-motion` gets one still frame and no animation loop at all,
  a hidden tab gets none, and the page still pulls in nothing — the CSP that
  already forbade subresources needed no change, and a test now pins both
  that and the page's size ceiling. The page grew 21 KB → 43 KB, which is
  also why `handleLanding` finally got an `ETag` and revalidation
- 2026-08-15 — tuned after seeing it on a real screen. Edges and nodes were
  too faint to register and the drift was imperceptible, so both went up
  (roughly 1.5× on the alphas, 2× on the drift amplitude over a shorter
  period). More consequentially, the graph is now guaranteed to be *one*
  graph: proximity alone reliably stranded the odd node and split the field
  into islands, which reads as a picture that failed to finish loading
  rather than as a network. A nearest-neighbour spanning tree over the
  resting positions is now always drawn beneath the proximity edges, with a
  floor under its weight so a long span cannot fade out and appear to break;
  arrivals hang off whoever admitted them, which for invite-only is the node
  that just reached out. Checking that mechanically — connected components
  over the edges actually drawn — turned up a frame-ordering bug the eye
  would have struggled to catch: `edges()` ran before the join/leave step,
  so a newcomer spent its first frame drawn with no edge attached, and a
  departure left the edge list pointing at a node already gone. Membership
  is now settled before edges are computed, and a packet in flight to a node
  that leaves is dropped with it

### SRV-27 — A full subscriber buffer swallows its own push wake
Status: `planned`

`queueAndNotify` (`internal/api/messages.go:236-242`) publishes to the
broker, then wakes the device only if it has no subscriber:

```go
a.broker.publish(msg.RecipientDeviceID, msg)
if !a.broker.hasSubscribers(msg.RecipientDeviceID) {
    a.wakeDevice(recipientDevice)
}
```

But `publish` drops silently when a subscriber's channel is full — the bare
`default:` at `internal/api/broker.go:65-70` — while `hasSubscribers`
(`broker.go:52-56`) only counts entries: `len(b.subs[deviceID]) > 0`. So the
one case where a connected device most needs a fallback nudge, its 16-slot
buffer (`broker.go:25`) having overflowed, is exactly the case where the
wake is suppressed. The message is safe in the durable queue; what is lost
is any signal to go and get it, until the device reconnects or polls of its
own accord.

The comment at `broker.go:58-61` acknowledges the drop and points at "their
next poll or reconnect" as the fallback. It does not note that the drop also
cancels the wake, which is the part that turns a slow delivery into an
indefinite one.

Same predicate gates the second wake trigger, `internal/api/prekeys.go:361`.

Worth fixing as a correctness matter rather than a capacity one: it is the
server-side twin of the app bug found on 2026-08-15, where a device that had
silently stopped receiving went on believing it was connected.

- 2026-08-15 — found while answering a question about how many concurrent
  stream subscribers a server holds. Not observed in the wild: it needs 16
  messages to a device faster than its stream drains them

### SRV-28 — Nothing bounds or sheds SSE subscribers
Status: `planned`

There is no cap on concurrent stream subscribers — not in total, not per
account, device or IP. `internal/api/broker.go:24-29` appends to a map that
only grows, and `internal/config/config.go` has limits for body size, queued
messages, batches and blobs but none for connections.

Compounding it, the `http.Server` sets **no timeouts at all**: no
`ReadTimeout`, `WriteTimeout`, `IdleTimeout` or `ReadHeaderTimeout` anywhere
in `internal/server/`. So nothing sheds a connection either. A half-open TCP
peer counts as a live subscriber until the handler returns, and without a
`WriteTimeout` a write to one can block that handler indefinitely — while
also suppressing the device's push wakes, per `SRV-27`'s predicate. A client
with a reconnect bug accumulates subscribers with nothing to stop it.

Individually a subscriber is cheap: one 16-slot channel, one 25s heartbeat
ticker (`internal/api/messages.go:16-17`), a slice slot, plus net/http's own
per-connection goroutine. The effective ceiling is therefore the process's
file-descriptor limit, inherited from whatever the Docker daemon defaults to
— an accident of the host rather than a decision made here. Neither the
Dockerfile nor freizone-farm's compose files set `ulimits`.

Not a scaling item: `docs/HIGH-AVAILABILITY.md` rules out scale-out on
purpose, and a self-hosted server for a known population will not run into
this by growing. The argument for doing something is that the failure mode
is discovered by falling over, and that a `WriteTimeout` and a
`ReadHeaderTimeout` are cheap insurance regardless of population.

- 2026-08-15 — raised alongside `SRV-27`, from the same question. No
  incident behind it; both are things the code permits rather than things
  that have happened
