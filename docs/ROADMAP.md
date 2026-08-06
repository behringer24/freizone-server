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

Split out of SRV-01 on 2026-08-02. Shares that item's fan-out and identity
model, but is not a flag on a group: a broadcast's recipient list must
specifically *not* be shared with its recipients, which removes the whole
snapshot / `state_hash` convergence layer and makes delivery one-directional.
Deliberately not designed until groups ship.

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
