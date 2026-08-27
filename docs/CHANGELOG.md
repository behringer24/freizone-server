# Changelog

All notable changes to freizone-server are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Reference codes in parentheses (e.g. `SRV-07`) point at the item in
[`ROADMAP.md`](ROADMAP.md), which in turn links the full design document. This
file records *what shipped when*; the reasoning lives there.

Releases are cut as annotated git tags. Entries before 0.11.0 were reconstructed
from those tags and the commits between them, which is why the earliest ones are
terser than what follows — the tag was the changelog at the time.

## [Unreleased]

A security-hardening pass from an internal pre-release audit of the server:
fixes and defensive changes across authentication, federation, the blob
transport, and the toolchain. Nothing here changes the wire protocol for a
client that was already behaving — the one new response (`507`) and the one new
setting are noted below.

### Security

* **Device revocation is scoped to the requesting account.** `POST
  /v1/devices/{id}/revoke` acted on the device id alone, and device ids are
  public — so a request signed by one account could revoke another account's
  device and lock it out. Revocation now only touches a device that belongs to
  the signing account.
* **The federation blocklist matches the canonical address form.** A blocked
  remote sender could slip past the exact-string blocklist by re-spelling their
  id (hyphens, case, whitespace), which the address check still accepts. Both
  the block (admin) and the inbound check now normalise first.
* **Per-device blob and message-queue caps are enforced inside the write
  transaction.** The count/quota was read and then written non-atomically, so
  concurrent uploads or sends to one device could each pass the check and all
  commit, overshooting the cap. The check-and-insert is now one transaction.
* **Push-wake requests to device-registered endpoints are hardened against
  SSRF.** The wake client no longer follows redirects and refuses to connect to
  loopback, link-local (including cloud-metadata), private, or ULA addresses,
  checked against the resolved IP. The gateway path (operator-configured, often
  internal) uses a separate client and is unaffected.
* **The ratchet's skipped-message-key buffer is bounded in aggregate**
  (`pkg/ratchet`, client-side). The per-run cap did not bound the buffer across
  a long-lived session, so a peer leaving unfilled gaps could grow it without
  limit; it now evicts the oldest keys past an aggregate ceiling. The on-disk
  session format stays backward-compatible.
* **Signature verification rejects a wrong-length public key** instead of
  risking a panic (`ed25519.Verify` panics on a non-32-byte key). Defensive — no
  current caller can trigger it.
* **The inbound-federation check order was tightened** so a caller cannot probe
  whether an account is blocked without first presenting a valid request
  signature, and the cheap timestamp/skew check runs before the expensive
  signature verifications.
* **The streamed-body (blob upload) authentication path matches its route
  exactly** rather than by prefix, so a future `POST /v1/blobs/...` route cannot
  silently inherit digest-only body authentication.
* **Added [`SECURITY.md`](../SECURITY.md)** with a private
  vulnerability-reporting process, so GitHub offers a "Report a vulnerability"
  flow.
* **Toolchain bumped to Go 1.26.6**, closing six standard-library advisories
  that affected 1.26.4; `golang-jwt/jwt/v5` bumped to 5.2.2. Building from
  source now needs Go 1.26.6+ (the toolchain auto-upgrades via `GOTOOLCHAIN`).

### Added

* **`FREIZONE_MAX_BLOB_BYTES_TOTAL`** — an optional whole-server cap on the
  combined size of all stored attachment ciphertext (default `0`, disabled). The
  per-device quotas only bound what one recipient holds; this bounds the total.
  An upload that would exceed it is refused with `507`.

### Fixed

* **The bootstrap admin account can be deleted.** `setup_tokens` referenced the
  claiming account with no `ON DELETE` rule, so with foreign keys enforced,
  deleting the first admin failed the constraint (surfacing as a generic `500`).
  A migration rebuilds the table with `ON DELETE SET NULL`; the reference now
  clears on delete, applied automatically on upgrade.

## [0.24.0] — 2026-08-23

One addition to `pkg/address`, needed by anything that accepts the short address
form a person actually copies.

### Added

* **`address.VersionMarkerOf` reads what kind of id something is from one
  character (`SRV-31`).** Whether an id names an account or a group is decided by
  its first character, but `VersionOf` normalises before reading it and so
  demands the whole 21-character id. Anything accepting the short prefix form the
  app displays therefore could not check it — leaving a caller to either skip the
  check or copy this package's character table, which is exactly what giving the
  address format one home was meant to prevent. `VersionOf` now builds on the new
  function, so the two differ by the validation and nothing else

## [0.23.0] — 2026-08-21

The release the first freizone-bot is built on. Everything here is in
`pkg/client` and `pkg/address` rather than in the server itself: three things a
headless consumer needed and only a first consumer would notice were missing,
plus one distinction the app had been unable to draw.

### Fixed

* **Two programs sharing one account's data can no longer corrupt it
  (`SRV-30`).** Opening the same account from a second program is now refused
  outright, and opening it twice inside one program hands back the one already
  open. This closes a real hazard in the Android app, where a notification
  arriving while the app is on screen made two independent copies of the
  encryption state for the same account — enough to lose the thread of a
  conversation and force it to be re-established

### Added

* **A one-to-one chat says when the other side's account is confirmed gone
  (`SRV-29`).** Previously, an account an admin removed just failed every
  retry forever, silently — the same distinction between a dead device
  (heals on its own) and a dead account (permanent) that groups already had.
  The chat now shows one plain line saying so and stops trying to send;
  everything already in it stays readable

* **Registering an account is part of the client library now (`SRV-30`).** It
  had been written three times outside it — in `cmd/devclient`, in this
  package's own test helper, and in the Android app — and not once inside.
  Registration is also no longer able to leave an orphan behind: a crash
  between the server creating an account and the caller learning of it used to
  make a restart register a *second* account under a different address, having
  spent a second invite code on it

* **Connecting also clears whatever arrived while disconnected (`SRV-30`).**
  Every consumer had to write the queue drain, the acknowledgement rule and the
  race against the live stream for itself, and nothing tested the two paths
  together. One call does it, and one function owns both paths — which is the
  shape three separate drifts in this project have argued for

* **A peer on another server can be addressed at all (`SRV-31`).** The address
  form `id*server` — what a person copies out of the app and pastes anywhere
  else — had no reader in Go: `pkg/address` handled the id half and knew
  nothing about a server, so the only parser of the whole thing was the app's
  Dart side. Anything else resolved every recipient on its own server, in a
  product whose premise is that servers federate. `pkg/address` now parses,
  renders and compares the whole form, in two entry points split by strictness:
  one accepts a prefix because interactive completion needs it, one requires the
  full checksummed id because configuration does

## [0.22.0] — 2026-08-15

What the stream endpoint never bounded, now bounded (`SRV-27`, `SRV-28`), plus
a pass over the landing page's light theme.

### Added

* **A cap on concurrent message streams per device (`SRV-28`).**
  `FREIZONE_MAX_STREAMS_PER_DEVICE` (default 4) bounds how many
  `GET /v1/messages/stream` connections one device may hold at once; a
  further attempt gets `429 too_many_streams`, refused before the event
  stream opens so a client is told rather than handed a stream that ends
  immediately. Nothing bounded this before — the subscriber map only grew,
  so a client with a reconnect bug ran the process out of file descriptors.
  Per device rather than server-wide, so one runaway client cannot cost
  everybody else their live delivery
* **Connection timeouts on every listener (`SRV-28`).**
  `ReadHeaderTimeout` (15s) and `IdleTimeout` (150s), where the server
  previously set none at all, so nothing ever shed a half-open connection.
  `ReadTimeout` and `WriteTimeout` are deliberately still unset: a blob
  upload over a slow link and a message stream open for hours each
  legitimately outlast any useful value, and a `WriteTimeout` in particular
  would cut every stream at the timeout no matter how healthy it was. The
  stream handler bounds each individual write instead (30s), which is what
  stops a peer that has stopped reading from holding a connection forever

### Fixed

* **A message that overflows a device's stream buffer no longer loses its
  push wake (`SRV-27`).** The server published to any live stream and then
  asked separately whether the device had one, to decide about a push
  notification — but a stream whose buffer is full drops the message while
  still counting as connected, so the one case that most needed a fallback
  nudge was exactly the case that suppressed it. The message was always safe
  in the queue; what went missing was any signal to go and fetch it, until
  the device happened to reconnect. Publishing now reports whether the
  message actually landed, and that is what decides the wake

### Changed

* **The landing page's light theme, which had almost no contrast in it
  (`SRV-26`).** The page, the pattern, the constellation and the card all sat
  within a few percent of each other and read as one flat sheet, so the ground
  goes down to `#e4ebe9` and the layers above it come up to meet it. The card
  is frosted rather than opaque — translucent with the backdrop blurred, so
  what is underneath carries through instead of being cut out by a rectangle,
  with the opaque colour kept as the fallback where `backdrop-filter` is not
  supported. A vignette settles the far edges; the first attempt was sized so
  that the screen's corner fell at 65.9% of the gradient at every resolution,
  which made it invisible, and it is now sized to the corner. And the logo,
  pale line-art drawn for a dark ground and measuring 1.06:1 against a light
  page, sits on a deep teal disc in light mode rather than shipping a second,
  recoloured copy of itself. Body text stays above 13:1 throughout, and the
  page is still one request

## [0.21.1] — 2026-08-15

One fix, from an audit rather than a report: deleting a single message left
its picture on disk with nothing left to name it. The same shape as the two
before it — a cleanup that quietly stopped happening looks exactly like one
that succeeds.

### Fixed

* **`Client.DeleteMessage` removes the message's stored media too (`SRV-23`).**
  It already cascaded the pin, the attachment records and the group
  deliveries; the bytes on disk stayed behind, unreachable — the transcript
  line is the only thing that names them, and nothing else ever cleans them
  up. Found in the cut audit of 2026-08-15 alongside the app-side half (see
  freizone-app): pin, unpin and per-message deletion never called this
  client at all

## [0.21.0] — 2026-08-15

One fix, traced from a group counter that would not reach three of three. It
turned out not to be about groups, or about counting: a message arriving in a
chat that is already on screen was never confirmed read at all, in any chat,
and could not be later either — the unread flag it would have needed is
deliberately never set for a chat the user is already looking at.

### Fixed

* **A message arriving in the chat on screen is now confirmed read.** Read
  receipts only ever went out when a chat was *opened*, and a message landing
  in an already-open one is never opened again: the receive path skips its
  unread flag precisely because the user is looking at it, so the next open
  found nothing to act on and returned early. Nothing else ever sent one, so
  the sender stayed on "Received" permanently — reported as a group counter
  stuck at "Read by 2 of 3" with the third member's row reading *Received*
  rather than *Read*. `GroupOutcome` and `ReceiveResult` gained a `ReadUpTo`
  watermark, set only when the message's own chat was the one on screen, so
  the side that already decided "not unread" is the side that says "and
  therefore read" — rather than leaving a caller to re-derive it from
  `ReceiveOptions.OpenChatID`, which is how the two halves came apart in the
  first place. A chat nobody is looking at still confirms nothing: claiming a
  read that never happened is worse than a counter that lags

## [0.20.0] — 2026-08-15

Two unrelated things. `Client.ForgetGroup` (`SRV-23`) is what finally takes a
group an account has left off its chat list. The rest is the landing page
(`SRV-26`), which now looks like it belongs to the same product as the app —
without telling a visitor anything about the server it was not already telling
them in words.

### Added

* **`Client.ForgetGroup` (`SRV-23`).** Discards everything an account holds
  about a group — its facts, the events still waiting on facts that never
  arrived, each member's last known view, and the chat state a list reads. The
  transcript and the media are not in there and stay the caller's to clear, a
  group chat being a chat like any other. This is what actually takes a group
  off a chat list: `Client.Groups` is a directory listing, so leaving one does
  not, and deliberately so — the fold keeps a member who left precisely so a
  message arriving afterwards is still recognised. Only ever right for a group
  the account is out of, and the check for that belongs to the caller, since
  once the facts are gone the fold can no longer tell "left" from "never
  joined". Nothing server-side changes
* **A background for the landing page (`SRV-26`).** The root page now carries
  the app's chat-screen pattern — redrawn as a 3.5 KB seamless SVG tile, since
  the app's own artwork is an 860 KB PNG — and, in front of it, a slow
  constellation of nodes and edges. What the constellation shows is limited on
  purpose to facts the page already prints: the address seeds the layout, so
  each server draws its own recognisable figure; federation decides whether
  edges leave the frame; the registration policy decides how newcomers appear,
  or whether they appear at all; an unclaimed server sits dimmed and still.
  Packets crossing the graph never change at a node — the end-to-end promise as
  a picture — and are timed on a clock, not on traffic. Nothing here is derived
  from usage, not even a node count, and a failed status read leaves the
  understated defaults in place rather than implying a capability the server may
  not have. Honours `prefers-reduced-motion` with a single still frame, stops
  entirely in a hidden tab, and still fetches nothing: the page remains one
  request, as its unchanged CSP already required
* **`ETag` and revalidation on the landing page.** It had no cache validators at
  all and was re-sent in full on every hit — tolerable at 21 KB, less so now
  that the artwork rides along inline. Repeat visitors get a `304`

## [0.19.0] — 2026-08-14

The statistics from 0.18.0 said how much is stored. This adds where it is going
(`SRV-25`) — and, because a fixed retention window means storage converges
rather than grows, an actual ceiling instead of an extrapolation.

### Added

* **A storage forecast on `GET /v1/admin/stats`.** A `forecast` object with two
  series continuing past today. `drain` is arithmetic on facts, not a
  prediction: every blob carries its own `expires_at`, fixed at upload and never
  extended, so what is stored now has a known decay — and it is an *upper*
  bound, since a recipient releasing its claim after fetching only makes the
  real curve fall faster. `with_inflow` adds uploads continuing at
  `inflow_bytes_per_day`, which live one retention window as well, so it
  flattens out on `equilibrium_bytes`
* **`equilibrium_bytes`, the figure worth acting on.** With a fixed retention
  window storage cannot grow without limit: it converges on inflow × window.
  That is the honest answer to "will this server run out of room", where a
  straight-line extrapolation of the recorded history ignores everything about
  to expire and produces a number that is alarming and false
* **`inflow_bytes_per_day` is measured, not guessed** — the ciphertext actually
  stored over `inflow_window_days`, which is `min(7, retention/2)` so that
  nothing inside the window can have expired yet, making the figure exact rather
  than an undercount. Backed by one grouped query over the expiry dates
  (`store.BlobExpiryBuckets`): a blob expires within the retention window of its
  upload, so there are only ever about that many distinct days to return,
  however many blobs a server holds

The forecast rides in the same response as the live figures rather than on a
route of its own: both series start at the stored total that response reports,
and two requests would let an upload land in between — leaving a chart's
measured line and its projection joined at two different values.

## [0.18.1] — 2026-08-14

### Fixed

* **Delivered attachments are freed again (`SRV-07`).** A recipient gives up its
  claim on a blob once the plaintext is on its own disk, which is what
  `docs/PROTOCOL.md` §10 has always specified, with retention as the backstop
  rather than the normal path. That release stopped happening on 2026-08-10:
  it lived in the app's Dart download path, the `SRV-23` cut moved downloads
  into `pkg/client`, and nothing there called it. Since then every attachment
  held its recipient's quota — and this server's disk — for the full retention
  window even after everybody had it. Restored in `pkg/client`'s
  `EnsureAttachment`, so the app, `cmd/devclient` and a later bot all honour it
  from one place. In a group only the reading member's claim goes; the file
  follows the last one, unchanged
* **`Client.DeleteBlob` could never report success.** `DELETE /v1/blobs/{id}` is
  the only route answering `204` with an empty body, and the client reads a
  bodyless reply as "this host is not a Freizone server" — the tell for a
  mistyped address. A request may now declare that it expects no body, which is
  opt-in rather than a blanket relaxation of that check, and a `404` counts as
  success the way `AckMessage`'s already does

## [0.18.0] — 2026-08-14

An operator could not see the state of their own server without a shell on the
host. This release adds the figures — and, because the tables they come from
forget what they used to hold, a recorded history to read growth from
(`SRV-25`).

### Added

* **Admin-only server statistics (`SRV-25`).** `GET /v1/admin/stats` reports
  the current size and load: accounts (total and active), devices, stored
  attachments and their bytes, the SQLite file's size, free disk space, queued
  messages, and whether federation is on together with how many senders are
  blocked. `GET /v1/admin/stats/history?days=N` returns the same shape as a
  series, oldest first, for a growth chart. Both sit behind `requireAdmin` —
  not `requireAdminOrModerator` — and are deliberately absent from `GET
  /v1/server-status` and the landing page, for the reason `SRV-22` states: a
  usage figure turns "a server exists" into "a server worth attacking"
* **A recorded history to read growth from.** A background ticker writes one
  `stats_snapshots` row every six hours, plus one at startup so a fresh install
  has a data point immediately instead of an empty chart, and prunes anything
  older than two years — nothing else ever deletes from that table. None of it
  is derivable after the fact: a blocked account, an expired blob and a
  delivered message all leave the tables that would otherwise be counted, so
  last month's size only exists if it was written down at the time
* **`internal/diskstat`**, free and total space for the volume holding the data
  directory: `syscall.Statfs` on linux/darwin, and `0, 0` meaning "unknown" —
  never an error — anywhere else, so a non-Unix development build still starts
  rather than failing over a figure that is only ever displayed

## [0.17.0] — 2026-08-12

The protocol was implemented twice — once here in `cmd/devclient`, once in
freizone-app's Dart state layer — and nothing forced the two to agree. This
release is the third implementation that replaces both: `pkg/client` (`SRV-23`).
The server's own wire behaviour is almost entirely unchanged; what changed is
that there is now one place where a client's protocol decisions live.

### Added

* **`pkg/client`, the shared protocol client core (`SRV-23`).** Holds
  identity, persistence, transport and every protocol decision a client makes:
  signed HTTP requests, the message endpoints and the SSE stream with its
  reconnect policy, the receive path (decrypt, fold, acknowledge, receipt),
  the send path including X3DH first contact, attachments, and groups end to
  end. Consumed by freizone-app through its cgo core, by `cmd/devclient`, and
  later by freizone-bot. Persistence is plain files rather than the SQLite
  first planned — an append-only transcript log per chat, compacted, which
  survives a half-written record where a rewritten blob does not
* **Groups in the core.** Fan-out encrypts once per member into that member's
  own ratchet, with a delivery record per member: what happened, why not if it
  did not, and the wire id their server de-duplicates by. `RetryGroupMessage`
  re-addresses only the members whose copy never arrived, reusing that id, so
  a retry cannot deliver the message a second time to somebody who already has
  it. Receipts are per author and cumulative — confirming an author's newest
  message confirms every earlier one of theirs — and a member who could not be
  reached is owed the group's facts until they can be
* **Receive-path conformance vectors (`pkg/conformance`, `SRV-23` stage 0).**
  Nine authored cases, written from `PROTOCOL.md` rather than recorded from an
  implementation, so a vector can fail on both sides and still be right. Run
  by `cmd/devclient/conformance_test.go` and by the app
* **An integration test against two real servers** (`pkg/client`'s `TestLive`,
  skipped unless `FREIZONE_LIVE_A`/`_B` are set). Drives a group split across a
  federation boundary and stops one of the two servers mid-test — the failure
  a stub cannot reproduce, since a stub fails by being told to rather than by
  not being there
* **`replace_one_time_prekeys` on the prekey upload endpoint.** Discards the
  published pool before adding, instead of appending to it. Safe
  unconditionally: every unclaimed row is by definition unbuilt-against, since
  a claim deletes atomically. Needed because a device that has published an id
  it holds no private half for cannot recover by adding more — the server
  hands out the oldest unclaimed key first, so the unusable one is always
  claimed again

### Changed

* A failed group copy now records **two** things: a sentence for the person
  who sent it ("Their server could not be reached.") and, separately, the
  technical text behind it. In a federation nobody operates every server, so a
  host that does not answer is an ordinary event rather than an incident, and
  the wrapped error chain that used to be shown said only "something technical
  went wrong"
* `client.IsUnreachable` distinguishes a server that was not there from one
  that answered and refused. The two call for opposite treatment — one retries
  itself and is not worth reporting, the other is a fact about the account
  that retrying will not change
* The client no longer offers HTTP/2, and a stream connect that times out says
  which layer stalled (DNS, TCP, the request itself) instead of "context
  canceled"
* A message stream that dies without saying so is now noticed, rather than
  leaving a client connected to nothing

### Fixed

* A retried group message was delivered again to members who already had it,
  because each attempt minted a fresh wire id and the recipient's server had
  nothing to recognise the duplicate by. The id is persisted with the delivery
  record and reused. Found as an unending flood of notifications on a test
  device
* Batch delivery read a per-item status the server never sends (`accepted`),
  so every copy in a batch was recorded as failed while arriving perfectly —
  `queued` and `duplicate` are what "delivered" looks like. The test stub had
  no batch endpoint at all, which is why nothing caught it
* A group picture was uploaded once for all recipients, which fails as soon as
  two members are on different servers: a blob is granted to devices on one
  server. Uploaded once per recipient server now (`SRV-18`)
* A receipt could name a moment fractionally before the message it confirmed,
  leaving it unconfirmed forever — the anchor is truncated where it is minted
* Group facts were re-requested from every peer on every open, and owed
  forever to accounts that no longer exist. Asked only where a recorded state
  hash says somebody is behind, and settled when the account is gone

## [0.16.0] — 2026-08-07

### Added

* Landing page opt-out (`SRV-21`): `FREIZONE_LANDING_PAGE_ENABLED=false`
  skips registering the root route entirely, so a privately-run server
  answers its bare domain with net/http's plain `404` instead of a page
  announcing that it is a Freizone server. Default unchanged (`true`)

### Changed

* Stale-device rule: the delivery-path `404`s now carry distinct error codes
  instead of a uniform `not_found`, so a sender holding a dead cached device
  id can tell "re-resolve this peer's device list" apart from "this server
  won't talk to me": the prekey-bundle claim answers `unknown_device` /
  `no_prekey_bundle` / `federation_disabled`, message and blob delivery
  answer `unknown_recipient` (the word their batch forms always used
  per-item), and the federation endpoints answer `federation_disabled` when
  switched off. HTTP statuses, message texts, and batch per-item statuses are
  all unchanged. `docs/PROTOCOL.md` §4 now specifies the client reaction
  (discard the cached device id, re-fetch `GET /v1/accounts/{id}`, retry
  once) — the healing half of §9's known cross-server revocation gap, found
  via a live group where one member's re-created account left every peer
  claiming a prekey bundle for a device id that no longer existed

## [0.15.0] — 2026-08-06

### Added

* Seat/capacity display for admins (`SRV-22`): an attestation (`SRV-19`) can
  now carry an advisory account-count ceiling (`pkg/attest`'s `Seats`,
  format bumped to `v2`, `v1` tokens still verify). Shown only to the
  server's own admins via the new admin-only `GET /v1/admin/license`, never
  on `GET /v1/server-status` or the landing page — how many accounts a
  server has is attack-surface information, not something a visitor needs

## [0.14.0] — 2026-08-06

### Added

* Server attestations (`SRV-19`): an operator running in agreement with the
  project can carry a signed, unforgeable statement about their server —
  domain, tier, display subject, expiry — verified by a client itself against
  issuer keys compiled in, with nothing ever consulted online. Configured via
  `FREIZONE_ATTESTATION`, served on `GET /v1/server-status`, and shown as a
  small checkmark badge on the server's own landing page. The client-side
  badge (`freizone-app`, `APP-22`) and the issuing tool (`freizone-licensing`)
  ship alongside this
* `docs/INSTALL.md`, `docs/HIGH-AVAILABILITY.md`, and `docs/DEVCLIENT.md` —
  operator-facing documentation for the Docker Compose fast path, warm-standby
  failover via Litestream, and diagnosing a server with `devclient`

## [0.13.1] — 2026-08-05

No change to the server itself: the development client and the documentation
only. Groups (`SRV-01`) are complete as of this release.

### Fixed

* `devclient`: a one-to-one chat could not read a message from a peer who
  established a session at the same moment it did, or who deliberately reset
  their secure session — both cases left the message permanently undecryptable
  (`SRV-01`, `SRV-03`). The interactive chat and the group watcher now share one
  establishment path, so neither can handle fewer cases than the other

## [0.13.0] — 2026-08-04

### Added

* An attachment upload may name several recipient devices at once, so a picture
  sent into a group costs one upload per recipient *server* instead of one per
  member — on a ten-member server, one copy of the bytes rather than ten
  (`SRV-18`). Advertised as `max_blob_recipients` on `GET /v1/server-status`,
  whose absence means one, so a sender talking to an older server falls back to
  uploading per member instead of silently delivering to one of them
* Per-recipient outcomes on the upload response, matching batch message
  delivery: one member at their storage quota no longer costs the other members
  their copy (`SRV-18`)

### Changed

* Deleting an attachment now drops only the calling device's own claim on it.
  The stored bytes go when the last recipient deletes them, so one group member
  clearing their copy cannot take the picture away from the rest (`SRV-18`)

## [0.12.0] — 2026-08-03

### Added

* Moderators can block and unblock regular members server-wide, so moderating a
  server no longer requires an admin account (`SRV-08`)
* The admin user list carries per-account activity: queued messages, the age of
  the oldest, and attachment usage against quota (`SRV-09`)
* `invited_by` on the admin user list, exposed to admins only (`SRV-14`)

### Changed

* A one-time prekey is handed out only to a claimant the server can identify.
  An anonymous prekey-bundle claim still succeeds and still yields a usable
  bundle, just without a one-time prekey, so clients predating the change keep
  working unaltered (`SRV-04`)

### Added

* The `prekey` block says whether it is a deliberate re-key or an ordinary
  establishment (`rekey`, a tri-state: `true`/`false`/absent), so a receiver
  finding a prekey block for a session it already holds no longer has to infer
  the sender's intent from the decrypted content. Absent keeps the old inference,
  so old and new clients interoperate in both directions with no negotiation
  (`SRV-17`)

### Fixed

* `pkg/group` refuses to *sign* a group event whose subject or group id is a
  cosmetic spelling (dash-grouped, spaced, upper-case) or a short id-prefix
  rather than the canonical id. Such an event is admissible and verifiable but
  useless: the subject's certificates are all signed over the canonical id, so
  the member it folds in is a phantom nobody can ever establish a session with.
  Admission stays tolerant, and `member_remove`/`leave`/`role_revoke` stay
  signable with whatever spelling is already in the fold, so a phantom can still
  be cleaned up (`SRV-01`)

### Security

* Closes one-time-prekey pool exhaustion: an anonymous caller could previously
  drain a device's pool by claiming repeatedly, costing that device forward
  secrecy on the first message of every subsequent session (`SRV-04`)
* Closes a push-wake amplifier on the same route — a claim that dropped the pool
  below its low-water mark fired a push wake, so any caller could make the
  server wake an arbitrary device on demand (`SRV-04`)

## [0.11.0] — 2026-08-01

### Added

* Automatic recovery from a desynced ratchet session: a typed decrypt-failure
  taxonomy, per-peer evidence, an invisible re-key envelope, and an ordering rule
  that stops both sides re-keying at once (`SRV-03`)
* Invite codes are now 12 symbols of Crockford Base32, hashed at rest, with a
  default expiry (`SRV-12`)
* A periodic sweep of invite codes that expired unredeemed (`SRV-13`)

### Changed

* **Breaking for outstanding invites:** migration `0012` drops unredeemed invite
  codes, since SQLite cannot hash them in place. Any code handed out before this
  release stopped working and had to be reissued (`SRV-12`)

## [0.10.2] — 2026-07-30

### Documentation

* Blob capability discovery documented as closed (`SRV-10`, then numbered SRV-12)

## [0.10.1] — 2026-07-30

### Documentation

* The blob lifetime contract, and roadmap entries for `SRV-08`, `SRV-09` and
  `SRV-10`

## [0.10.0] — 2026-07-29

### Added

* Encrypted blob transport for attachments: upload, fetch and delete routes, a
  streamed-body signature variant that authenticates before reading a byte,
  filesystem storage with SQLite metadata, and expiry and orphan sweeps
  (`SRV-07`)

## [0.9.0] — 2026-07-27

### Added

* Configurable log level

### Changed

* Dead push registrations are dropped when the gateway reports them unregistered

## [0.8.1] — 2026-07-28

Tagged after 0.9.0, as a patch on the 0.8 line.

### Fixed

* `ratchet.Session.Decrypt` is atomic: it works on a clone and commits only once
  the message authenticates, so one undecryptable message no longer wedges a
  session permanently (`SRV-03`)
* An outright duplicate message is rejected before it can consume the next
  message key (`SRV-03`)

## [0.8.0] — 2026-07-26

### Added

* Root-key-authenticated account recovery: `POST /v1/accounts/{id}/recover`
  accepts a new device certificate signed by the account's root key and revokes
  the lost devices in the same step, so an account survives total device loss
  with its id intact (`SRV-06`)
* BIP-39 mnemonic support in the shared Go core (`pkg/mnemonic`), so the 32-byte
  seed never crosses into Dart

## [0.7.0] — 2026-07-23

### Added

* Federation can be toggled at runtime by an admin, persisted across restarts
* AGPL-3.0 license

## [0.6.0] — 2026-07-23

### Changed

* Higher message throughput: WAL with `synchronous=NORMAL`, a single write
  connection, and an in-memory nonce cache
* `devclient`: interoperable receipts, a cleartext/package view, round-trip
  timing, verbose mode, and a load-test command

## [0.5.0] — 2026-07-22

### Added

* A small branded landing page at the site root
* GitHub Actions workflow building and publishing the Docker image to GHCR

### Fixed

* `devclient` resolving a peer by short id prefix

## [0.4.0] — 2026-07-21

### Added

* One-time-prekey pool status endpoint, and a low-pool wake trigger
* Self-service account deletion (`DELETE /v1/accounts/{id}`)

## [0.3.2] — 2026-07-20

### Documentation

* Documentation fixes

## [0.3.1] — 2026-07-19

### Documentation

* The chat-invite QR scheme (`freizone://chat`)

## [0.3.0] — 2026-07-19

### Added

* Federation: direct cross-server message delivery, posted by the sender to the
  recipient's own server

## [0.2.0] — 2026-07-19

### Added

* FCM/APNs push relay via freizone-gateway

## [0.1.0] — 2026-07-18

First working single-server encrypted chat: registration, device certificates,
per-request signature authentication, X3DH and Double Ratchet, and the message
queue with SSE delivery.
