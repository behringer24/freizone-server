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
