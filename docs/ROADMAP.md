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
