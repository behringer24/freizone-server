# Freizone Wire Protocol — Identity, Auth & E2E Messaging (v2)

This document is the cross-repo contract between the server (this repo) and
any client (mobile app, or `cmd/devclient` — a reference implementation in
this repo) implementation. It covers: addressing, device
certificates/revocations, per-request signature authentication, the
identity/bootstrap REST surface, X3DH + Double Ratchet end-to-end
encryption, and the prekey/message REST surface that carries it.

Out of scope here (future milestones): groups/broadcast, and the QR
device-linking handshake itself (only its *result* — a signed device
certificate — is consumed by this API). Federation (§9) and push
notifications (§7) are both implemented.

## 1. Addressing

An account address is `id*server` (e.g. `q2xjx*chat.example.org`), where
`server` is the home server's address and `id` is a 21-character string
derived from the account's root Ed25519 public key. `*local` (or omitting
the `*...` part entirely) means "whatever server this is being resolved
against right now" — see §9 for when an explicit, different `server` is
required (a federated address) versus when it's just the caller's own.

1. Compute `SHA-256(root_pubkey)` (32 bytes).
2. Take the leading 9 bytes (72 bits) and convert to 5-bit groups MSB-first,
   keeping only the first 14 groups (70 bits) — i.e. discard the trailing 2
   bits of the 9th byte.
3. Prepend a 5-bit version marker group. The only currently defined version
   is `0`. This gives 15 payload groups (75 bits) total.
4. Compute a 6-group bech32m checksum (BIP-350: charset
   `qpzry9x8gf2tvdw0s3jn54khce6mua7l`, XOR constant `0x2bc830a3`) over the 15
   payload groups, using the fixed internal domain-separation tag `"frz"` —
   this tag is **never part of the resulting string**, it exists only so a
   Freizone ID can't collide with an unrelated bech32m string that happens
   to use a real human-readable prefix.
5. Map all 21 groups (15 payload + 6 checksum) through the bech32m charset.

The result is a plain 21-character string — **no human-readable prefix, no
`1` separator** (unlike standard bech32/bech32m). For display, it may be
shown in 5-character dash-separated blocks (`qk5x9-p2qan-7f3xy-zqeh8-m`-style)
purely for readability; this is cosmetic and not part of the canonical form.
5 (not 4) is deliberate: the first character is always the version marker,
so a 5-character first group carries 4 real characters of entropy — see the
id-prefix uniqueness note below.

The ID is **self-certifying**: any party can recompute
`hash(delivered_root_pubkey) == id` themselves. No server can substitute a
different key without it being immediately detectable from the address
itself.

Normalization for comparison/lookup: lowercase, strip `-`/whitespace, verify
length (21) and bech32m checksum.

**id-prefix uniqueness**: a server also enforces that each account's first 5
characters (the version marker + 4 real characters of entropy, i.e.
`32^4 = 1,048,576` possible values) are unique among its own accounts. This
doesn't change how ids are derived — an id is still always `hash(root_pubkey)`
— it just means `POST /v1/accounts` and `POST /v1/bootstrap/claim` reject a
freshly-derived id whose prefix collides with an existing account on that
server (`409 id_prefix_taken`), and the client is expected to generate a new
identity and retry. This makes the first displayed group usable as a short,
typeable, locally-unique lookup key for the full id, without weakening
self-certification or introducing a chosen/squattable handle.

## 2. Key hierarchy

```
Root Key (Ed25519, per account, generated once)
   │  signs
   ▼
Device Certificate ──► Device Identity Key (Ed25519, per device)
                            │  signs (see §5)
                            ▼
                       DH Identity Certificate ──► DH Identity Key (X25519, per device)
                            │  signs
                            ▼
                       Signed Prekey Certificate ──► Signed Prekey (X25519, rotatable)
                                                      + One-Time Prekeys (X25519, single-use, unsigned)
```

The root key never leaves the primary device and is never used to encrypt
or to sign requests — only to sign device certificates and revocations.
The device identity key is Ed25519 and is used for HTTP request signatures
and for signing the device's own X3DH key material below — it is
deliberately **not** reused as an X3DH Diffie-Hellman key (no XEdDSA-style
conversion): a device holds a second, separate X25519 keypair for that,
authenticated by its own certificate (§5).

### Device Certificate

Fields:

| Field | Type |
|---|---|
| `account_id` | string (the 21-char address id) |
| `device_id` | 8 random bytes, hex-encoded (16 hex chars) |
| `device_pubkey` | Ed25519 public key, 32 bytes |
| `issued_at` | timestamp |
| `signature` | Ed25519 signature by the **root private key** |

Signing bytes (exact, deterministic binary encoding — not JSON, since JSON
key ordering/whitespace is not a safe cross-implementation contract):

```
uint16BE(len(account_id))  || account_id (UTF-8 bytes)
|| device_id (8 raw bytes, decoded from hex)
|| device_pubkey (32 raw bytes)
|| uint16BE(len(issued_at_str)) || issued_at_str (UTF-8 bytes)
```

where `issued_at_str` is `issued_at` formatted as UTC RFC 3339
(`2006-01-02T15:04:05Z07:00`).

`signature = Ed25519.Sign(root_private_key, signing_bytes)`.

### Device Revocation

Same pattern, over `(account_id, device_id, revoked_at)`:

```
uint16BE(len(account_id)) || account_id
|| device_id (8 raw bytes)
|| uint16BE(len(revoked_at_str)) || revoked_at_str
```

Signed with the root private key.

## 3. Per-request signature authentication (RFC 9421-inspired)

Every authenticated API request is signed with the calling **device's**
Ed25519 identity key — no passwords, sessions, or cookies. This is a
simplified, custom canonicalization (not literal RFC 9421 compliance).

Headers:

| Header | Value |
|---|---|
| `Signature-Key-Id` | the device id (16 hex chars) |
| `Signature-Timestamp` | Unix seconds, decimal string |
| `Signature-Nonce` | client-random string, unique per (device, request) |
| `Signature` | base64 (standard encoding) of the 64-byte Ed25519 signature |

Canonical string (newline-joined, no trailing newline):

```
{METHOD}\n{url_path}\n{raw_query}\n{Signature-Timestamp}\n{Signature-Nonce}\n{Signature-Key-Id}\n{lowercase_hex(sha256(body))}
```

- `METHOD` is the uppercase HTTP method (`POST`, `GET`, ...).
- `url_path` is the request path only (no scheme/host/query), e.g.
  `/v1/devices`.
- `raw_query` is the raw query string with no leading `?` (empty string if
  none).
- `body` is the exact bytes of the request body (empty-body requests hash
  the empty byte string).

`signature = base64(Ed25519.Sign(device_private_key, canonical_string_utf8_bytes))`.

Server-side verification: look up the device by `Signature-Key-Id` (must be
`active`), check `|now - Signature-Timestamp| <= 5 minutes`, verify the
signature, and reject replayed `(device_id, nonce)` pairs. **Every failure
mode returns the same generic 401** — unknown device, bad signature,
expired timestamp, replayed nonce, or revoked device are not distinguished
in the response, to avoid giving an attacker an oracle.

### Self-describing-key variant (public, inline-authenticated endpoints)

A few endpoints authenticate a caller that has **no local device row** to look
up: a cross-server federation sender (§9), or an account being recovered from
its seed phrase when no device survives (`POST /v1/accounts/{id}/recover`, §4).
These reuse the *exact same* canonical string and headers, with two
differences:

- `Signature-Key-Id` is the **base64-encoded public key that signed the
  request**, not a device id. The endpoint verifies the signature against that
  very key and then, separately, establishes that the key is authorized (a
  device cert chained to the sender's root key for federation; equality with
  the account's stored `root_pubkey` for recovery — i.e. the request is signed
  by the account's **root** key, its ultimate authority, which already signs
  every device cert and revocation, see §2).
- The nonce is recorded in the persistent `used_nonces` store rather than the
  device-auth in-memory cache, but the 5-minute skew window and generic-401
  rule are identical.

### Streamed-body variant (`Blob-Digest`)

The canonical string ends in `sha256(body)`, which normally means the server
must buffer the whole request before it can authenticate it. That is fine for
a chat message and unacceptable for a multi-megabyte blob upload (§10), so
those routes — and **only** those — take the body hash from a header instead:

| Header | Value |
|---|---|
| `Blob-Digest` | `sha256=<lowercase hex>` (a bare hex digest is also accepted) |

The client signs exactly the same canonical string, with that digest as its
last field. The server then:

1. verifies the signature from the headers alone, **before reading any body**
   — so a forged or unauthorized upload costs no disk at all;
2. streams the body to storage while hashing it, and rejects it with `400
   digest_mismatch` (discarding what it wrote) if the bytes do not match the
   signed digest.

This keeps the body cryptographically bound to the signature: a caller can
only store bytes it actually signed for. The variant applies to the two blob
upload routes and nowhere else: `POST /v1/blobs` has it enabled per route in
the authentication middleware, and `POST /v1/federation/blobs` — which is not
behind that middleware, since a federated sender has no device row to look up
(§9) — performs the equivalent check inline in its handler. On every other
endpoint a `Blob-Digest` header is ignored and the body itself is hashed, so
it can never be used to substitute an unsigned body elsewhere.

## 4. REST endpoints

All paths are under `/v1/`. All bodies/responses are JSON. Byte fields
(`root_pubkey`, `device_pubkey`, `signature`, etc.) are base64 (standard
encoding). Error responses: `{"error":{"code":"...","message":"..."}}`.

### `GET /healthz`
No auth. `200 {"status":"ok"}`, or `503` if the database is unavailable.

### `POST /v1/bootstrap/claim`
No auth (gated by the one-time setup token printed to the server's log on
first boot). Claims the first admin account.

The setup token is 8 symbols from Crockford's Base32 alphabet
(`0123456789ABCDEFGHJKMNPQRSTVWXYZ` -- excludes I, L, O, U to avoid
transcription errors), 40 bits, printed dash-grouped (`ABCD-1234`) for
readability. Dashes and case are cosmetic: the server strips
separators/whitespace and uppercases before comparing, so `abcd-1234` and
`ABCD1234` are equivalent. Deliberately short enough to type by hand into a
phone without needing a QR code.

Unlike per-request signatures, this endpoint has no other rate limiting, so
the token's safety against online guessing comes from a **lockout, not raw
entropy**: after 10 failed claim attempts the token is permanently rejected
(even a subsequently-correct guess), and the operator must restart the
server with `--reset-setup-token` to generate a fresh one.

Request:
```json
{
  "setup_token": "...",
  "root_pubkey": "base64...",
  "device_id": "16hexchars",
  "device_pubkey": "base64...",
  "device_cert_issued_at": "2026-07-17T12:00:00Z",
  "device_cert_signature": "base64..."
}
```
`201` with an account response (see below) on success.
`401` invalid, already-used, or locked-out token · `400` invalid certificate ·
`409` `id_prefix_taken` (see §1's id-prefix uniqueness note) -- retry with a
freshly generated identity. There is no "an admin already exists" check —
claiming with a valid, unused setup token always succeeds regardless of how
many admins already exist; minting a fresh token (`--reset-setup-token` /
`--reset-admin`) is the intended way to add an additional or replacement
admin.

### `POST /v1/accounts`
No auth (registration policy-gated: `open` / `invite` / `closed`). Same
certificate-bearing shape as bootstrap, plus an optional `invite_code`:
```json
{
  "root_pubkey": "base64...",
  "device_id": "16hexchars",
  "device_pubkey": "base64...",
  "device_cert_issued_at": "2026-07-17T12:00:00Z",
  "device_cert_signature": "base64...",
  "invite_code": "optional, required under the invite policy"
}
```
`201` account response · `403` registration closed / invite code required ·
`404` unknown invite code · `410` invite code expired or already used ·
`409` account or device id collision, or `id_prefix_taken` (see §1's
id-prefix uniqueness note) -- retry with a freshly generated identity.

### `POST /v1/accounts/{id}/recover` (public — root-key signed)
Recover an **existing** account after total device loss (SRV-06; client
companion APP-01). Neither of the normal paths works here: `POST /v1/devices`
needs an already-active device to sign the request, and `POST /v1/accounts`
rejects an existing account (`409 account_exists`). Since
`account_id == hash(root_pubkey)`, restoring the root key from the seed phrase
restores the same account, and this endpoint lets that restored key mint a new
device without any surviving device.

Authenticated inline by a **root-key** per-request signature (§3's
self-describing-key variant): `Signature-Key-Id` is `base64(root_pubkey)` and
must equal the target account's stored `root_pubkey`; the signature is verified
against it. The body carries a new device certificate signed by that same root
key (identical fields to `POST /v1/accounts`, minus `root_pubkey`/`invite_code`
— the account is named by the path `{id}`):
```json
{
  "device_id": "16hexchars",
  "device_pubkey": "base64...",
  "device_cert_issued_at": "2026-07-26T12:00:00Z",
  "device_cert_signature": "base64..."
}
```
On success the new device is created `active` and **every other device on the
account is revoked in the same step** (total loss is the premise; old devices
are assumed gone or compromised). `201` account response (with the new device
active and the rest `revoked`) · `400` malformed body or invalid device
certificate · `401` root signature invalid / stale / replayed (generic, per
§3) · `403` account not active · `404` unknown account · `409` device id
collision (a repeat recovery must use a fresh device id). Chat history is not
restored — the server keeps none; peers re-establish ratchet sessions against
the new device (see §5 / SRV-03).

### `GET /v1/server-status`
No auth — lets a client decide which setup path applies before it has any
identity: bootstrap (no admin claimed yet), self-register (open policy),
invite-code registration, or "closed" -- registration fully blocked, not
even with an invite code (the invite-code check in `POST /v1/accounts` is
never reached while the policy is `closed`).
`200`:
```json
{
  "claimed": true,
  "registration_policy": "open",
  "federation_enabled": true,
  "blobs_enabled": true,
  "max_blob_bytes": 8388608
}
```
`claimed` is whether the one-time setup token has already been used
(i.e. an admin exists) — not sensitive, same trust level as the
registration policy itself, which has to be knowable before someone can
register at all. `federation_enabled` reflects whether this server accepts
inbound federation (§9); it is public because clients rely on it to decide
whether their own users may reach other servers at all — with it off, a
peer's replies would be blocked inbound, so an honest client won't start or
send into such a cross-server conversation (older servers omit the field;
clients treat its absence as `true`).

`blobs_enabled` and `max_blob_bytes` describe this server's attachment
transport (§10), so a sender can size an attachment to what the *recipient's*
server will actually take instead of discovering the limit as a `413`
mid-upload. Note the absence rule is the opposite of `federation_enabled`'s:
a server that omits `blobs_enabled` predates §10 and has no blob endpoints at
all, so clients must treat its absence as **off**, not on. `max_blob_bytes`
absent or `0` means "no limit stated" — an oversized upload then still fails
server-side, as it would have anyway.

### `GET /v1/accounts/{id}`
No auth — a public key directory, analogous to a keyserver. `200`:
```json
{
  "id": "k5x9p2qan7f3xyzqeh8m1",
  "root_pubkey": "base64...",
  "devices": [
    {
      "device_id": "16hexchars",
      "device_pubkey": "base64...",
      "issued_at": "2026-07-17T12:00:00Z",
      "signature": "base64...",
      "status": "active",
      "revoked_at": null
    }
  ]
}
```
`signature` is the device certificate's signature (§2) — include it so a
client can verify the **full** self-certifying chain itself
(`hash(root_pubkey) == id`, then `Ed25519.Verify(root_pubkey, device
signing bytes, signature)`) instead of trusting the server's word for which
devices belong to an account. Both active and revoked devices are listed
(with their status). `{id}` also accepts the shorter, unchecksummed
PrefixLength (5-character) form as an alias for the full id (see §1's
id-prefix uniqueness note) -- either way, the response's own `"id"` is
always the true full id, which is what a caller must actually verify
against `root_pubkey`, never the shorthand it looked up with. `404` if
`{id}` is unknown or fails address normalization (full form) / charset
validation (prefix form).

### `DELETE /v1/accounts/{id}` (signed, caller must be that account)
Permanently deletes the caller's own account, cascading (via FK) through
its devices to their prekeys and queued messages, and through invite
codes it issued (deleted) or used (`used_by_account_id` cleared) — the
same cascade as the admin delete (§4's server admin endpoints), just
self-service rather than requiring admin privileges. `{id}` is checked
against the signing device's own account as defense in depth, but the
actual target is always the identity the request's signature already
established, never `{id}` taken at face value — a request signed by
account A can never delete account B, no matter what `{id}` names.
Irreversible: a deleted account can never be recreated with the same id
on this or any other server, since a new registration under the same
root key would collide with (or rather, no longer exist to collide with,
but the private key itself isn't gone anywhere) nothing — there's simply
no path back to the same identity.

A chat partner who writes to a deleted account afterward gets an
immediate `404 not_found` (their client has no device to deliver to,
since the cascade already removed it) — not a silently growing queue.
Messages already sent to others *before* deletion, if not yet fetched,
are unaffected: they remain deliverable, same as already-sent mail isn't
recalled by deleting the sender's mailbox.

`200 {"status":"ok"}` · `403` `{id}` does not match the signing device's
own account · `404` unknown account · `409 last_admin` deleting the
server's only remaining admin (same guard as the admin delete).

### `GET /v1/vapid-public-key`
No auth — this server's VAPID public key (RFC 8292), not secret. Clients
pass this to their UnifiedPush distributor at registration time (some
distributors reject registration without one); it identifies which
application server may push to that subscription. `200`:
```json
{ "key": "base64url-encoded P-256 public key" }
```

### `POST /v1/devices` (signed)
Adds a device to an account. Must be signed by a device already active on
that account. Body carries a new device certificate pre-signed by the
account's root key:
```json
{
  "account_id": "k5x9p2qan7f3xyzqeh8m1",
  "device_id": "16hexchars",
  "device_pubkey": "base64...",
  "issued_at": "2026-07-17T12:00:00Z",
  "signature": "base64..."
}
```
`201` device response · `403` the signing device's account doesn't match
`account_id` · `400` invalid certificate · `404` unknown account · `409`
device id collision.

### `POST /v1/devices/{device_id}/revoke` (signed)
Revokes a device. Must be signed by a device already active on the account.
Body carries a root-key-signed revocation record:
```json
{
  "account_id": "k5x9p2qan7f3xyzqeh8m1",
  "device_id": "16hexchars",
  "revoked_at": "2026-07-17T12:00:00Z",
  "signature": "base64..."
}
```
`{device_id}` in the path must match the body. `200
{"status":"revoked"}` · `400` path/body mismatch or invalid revocation
signature · `403` account mismatch · `404` unknown account/device or
already revoked.

### `PUT /v1/devices/{device_id}/push-endpoint` (signed, caller must be that device)
Registers, or (with an empty body) clears, this device's push subscription
— see §7's note on push under `POST /v1/messages`. This is a standard Web
Push subscription (the same shape browsers hand you from
`PushManager.subscribe()`): `p256dh`/`auth` are the device's own ECDH
public key and auth secret, which the server uses to RFC 8291-encrypt the
(content-free) wake payload it sends to `endpoint`.
```json
{
  "endpoint": "https://distributor.example/wake/abc123",
  "p256dh": "base64url-encoded uncompressed P-256 point",
  "auth": "base64url-encoded 16-byte secret"
}
```
All three fields must be given together, or all omitted/null to
unregister. `endpoint` must be an `https://` URL. `200 {"status":"ok"}` ·
`400` missing/partial/non-https fields · `403` path device_id isn't the
signing device · `404` unknown device.

### `PUT /v1/devices/{device_id}/push-target` (signed, caller must be that device)
Registers, or (with an empty body) clears, this device's FCM/APNs push
target — the counterpart to `push-endpoint` above for devices delivered
through a [freizone-gateway](https://github.com/behringer24/freizone-gateway)
instance instead of UnifiedPush/Web Push. `platform` is `"fcm"` or
`"apns"`; `token` is that platform's own addressing token (an FCM
registration token, or an APNs device token).
```json
{
  "platform": "fcm",
  "token": "the platform's own registration/device token"
}
```
Both fields must be given together, or both omitted/null to unregister.
Registering a push target clears any existing push subscription (and
vice versa) — a device uses exactly one wake mechanism at a time. `200
{"status":"ok"}` · `400` missing/partial fields or unknown platform ·
`403` path device_id isn't the signing device · `404` unknown device.

### `POST /v1/admin/invites` (signed, admin or moderator)
Issues a single-use invite code (for the `invite` registration policy) —
typically rendered by the app as a QR code (see §8) for the caller to
hand out, but short enough to read aloud or write down.
```json
{ "expires_at": "optional RFC3339; omitted means the server's default expiry" }
```
`201`:
```json
{ "code": "ABCD-EFGH-JKMN", "expires_at": "optional" }
```
`403` if the caller is neither admin nor moderator.

**Code format.** 12 symbols of Crockford Base32 — the alphabet
`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, which omits `I`, `L`, `O` and `U` —
returned grouped in fours for legibility. That is 60 bits of entropy.

A redeemed code is **normalized before comparison**, so a client may send
whatever the user actually typed and need not clean it up first:

- case is ignored;
- `-`, `_`, spaces, tabs and newlines are stripped, so the grouped display
  form and the compact form a QR carries are the same code;
- `I` and `L` are read as `1`, and `O` as `0` — unambiguous precisely
  because the alphabet cannot produce those letters, so encountering one can
  only mean a misread digit. `U` is left alone: nothing it plausibly stands
  for, so it simply fails to match rather than being rewritten.

The server stores only a SHA-256 hash of the normalized code, as it does for
the setup token (§3) — a leaked database yields no working invites. Nothing
needs the plaintext after this response, since there is deliberately no
endpoint that lists codes; the flip side is that a lost code cannot be shown
again and must be reissued.

**What is retained.** A code that expires without being redeemed is deleted
by a periodic sweep: it can never be accepted again, so the row is dead
weight. A **redeemed** code's row is kept, and with it `created_by` and
`used_by` — i.e. which account issued the invite and which account joined
with it. That pairing is retained deliberately, as the one piece of
moderation history this server keeps ("who let that account in?"); it is
never exposed through any endpoint, so only the operator can see it. Deleting
either account clears its side (the issuer's invites cascade away, a joiner's
reference is set to null).

**Why 12 symbols and not the setup token's 8.** The token gets away with 40
bits because it is a singleton protected by a lockout counter
(`MaxSetupTokenAttempts`). Neither applies here: many invite codes are
outstanding at once and *any* unused one grants registration, so a guesser
need not target a particular code, and a failed guess identifies no code to
lock out. The length therefore has to do the work the token's lockout does.
Codes also carry a default expiry (`FREIZONE_INVITE_EXPIRY_DAYS`, 14 days),
because an unbounded window is what would make guessing worth attempting at
all.

### Server admin endpoints
Moderators get read-only visibility plus invite creation: the account list,
the current registration policy, the federation switch (all `GET`), and
`POST /v1/admin/invites` (documented above). They may additionally
**block/unblock a regular member** — the one account-changing action they
get, so moderating a server does not require handing out admin. Everything
else that changes an account or the server — role changes, deleting, setting
the registration policy, toggling federation — stays admin-only, so
privilege escalation and account removal can never come from a moderator.

A moderator's block is confined to accounts whose role is `user`; targeting
another moderator or an admin is `403`. Blocking is removal by another name
(a disabled account cannot make a single authenticated request), so without
that limit a moderator would hold over staff exactly the power this model
reserves for admins — and the `last_admin` guard below is no substitute,
since it only refuses the *final* admin.

Every one of these (except `GET`) that targets an admin account rejects
the change with `409 last_admin` if it would leave the server with zero
active admins.

- **`GET /v1/admin/accounts`** (signed, admin or moderator) — the full
  account list, each entry carrying the activity signals that distinguish an
  account in use from an abandoned one.
  `200`:
  ```json
  [{
    "id": "...", "role": "user|moderator|admin", "status": "active|disabled", "created_at": "...",
    "pending_messages": 3, "oldest_pending_at": "...",
    "blob_count": 2, "blob_bytes": 3355443, "blob_bytes_limit": 268435456, "device_count": 2,
    "invited_by": "..."
  }]
  ```
  The counts are summed across the account's devices. `oldest_pending_at` is
  **omitted** when the queue is empty (there is no such timestamp); every
  other field is always present, zero rather than absent, so a client can
  tell "nothing queued" from an older server that doesn't report this at all.
  `blob_bytes_limit` is the per-device quota (`FREIZONE_MAX_BLOB_BYTES_PER_DEVICE`)
  times `device_count`, because that is where the limit is actually enforced —
  it is therefore 0 for an account with no devices, which means "no meaningful
  limit", not "a limit of nothing", and it moves as devices are added or
  revoked. Revoked devices count: a revoked device keeps its blobs until its
  row is deleted, so excluding it could put usage above its own limit.

  These are aggregates only — how much is waiting and how much is stored,
  never who an account talks to or what it sends. Moderators see them along
  with the rest of the list; the whole point is being able to clean up a
  server without being an admin.

  `invited_by` is the exception: the account that issued the invite this one
  joined with, and **sent to admins only** — a moderator's response omits the
  field entirely, and the server doesn't even look it up for them. It is the
  one account-to-account link this server holds, which is a different kind of
  thing from a queue length. Omitted whenever there is nothing to say, and a
  client must read that as "not known here" rather than "registered openly":
  the field is equally absent for an account that needed no invite and for one
  whose inviter has since been deleted, since the invite row cascades with its
  creator.
- **`POST /v1/admin/accounts/{id}/role`** (signed, admin only) — `{"role": "user|moderator|admin"}`.
  `200 {"status":"ok"}` · `400` invalid role · `404` unknown account ·
  `409 last_admin` demoting the server's only remaining admin.
- **`POST /v1/admin/accounts/{id}/block`** / **`.../unblock`** (signed,
  admin, or moderator targeting a `user`) — no body. Blocking sets the
  account `disabled`, which `internal/auth`'s middleware then rejects on
  every subsequent request from that account, from any of its devices.
  `200 {"status":"ok"}` · `403` a moderator targeting a moderator or an
  admin · `404` unknown account · `409 last_admin` blocking the server's
  only remaining admin.
- **`DELETE /v1/admin/accounts/{id}`** (signed, admin only) — permanently
  removes the account, cascading through its devices to their
  prekeys/queued messages and any invite codes it issued.
  `200 {"status":"ok"}` · `404` unknown account · `409 last_admin`
  deleting the server's only remaining admin.
- **`GET /v1/admin/registration-policy`** (signed, admin or moderator) /
  **`PUT /v1/admin/registration-policy`** (signed, admin only) —
  `{"policy": "open|invite|closed"}` in both directions. This is the
  *runtime* policy (see [README.md](../README.md)'s config reference):
  `FREIZONE_REGISTRATION_POLICY` only seeds it on first boot, this
  endpoint is what actually governs it afterwards, and the change
  persists across restarts.
  `200 {"policy": "..."}` · `400` invalid policy value.
- **`GET /v1/admin/federation`** (signed, admin or moderator) /
  **`PUT /v1/admin/federation`** (signed, admin only) —
  `{"enabled": true|false}` in both directions. Turns inbound federation
  (§9) on/off at *runtime*, mirroring the registration-policy endpoint:
  `FREIZONE_FEDERATION_ENABLED` only seeds it on first boot, this endpoint
  governs it afterwards, and the change persists across restarts and is
  reflected in `GET /v1/server-status`'s `federation_enabled`.
  `200 {"enabled": ...}`.

### `POST /v1/devices/{device_id}/prekeys` (signed, caller must be that device)
Uploads/replaces a device's X3DH key material. `dh_identity_cert` is
required on the very first upload (to establish the device's long-term DH
identity key), optional afterwards (include it again only to rotate that
key). `signed_prekey` is always required and replaces the previous one.
`one_time_prekeys` appends to the pool (existing, unclaimed ones aren't
touched — this is how a device replenishes its supply).
```json
{
  "dh_identity_cert": {
    "dh_pubkey": "base64 X25519, 32 bytes",
    "issued_at": "2026-07-17T12:00:00Z",
    "signature": "base64 Ed25519, by the device's own signing key"
  },
  "signed_prekey": {
    "key_id": 1,
    "dh_identity_pubkey": "base64, must match the device's dh identity key",
    "pubkey": "base64 X25519, 32 bytes",
    "issued_at": "2026-07-17T12:00:00Z",
    "signature": "base64 Ed25519, by the device's own signing key"
  },
  "one_time_prekeys": [
    { "key_id": 101, "pubkey": "base64 X25519, 32 bytes" }
  ]
}
```
`200 {"status":"ok"}` · `403` wrong device · `400` invalid/mismatched
certificate, or no `dh_identity_cert` on a device's first-ever upload ·
`404` unknown device.

### `POST /v1/devices/{device_id}/prekey-bundle`
No auth — a public claim endpoint, like the account directory: no trust in
the server is required, only in the certificate chain the caller verifies
itself. **Atomically** removes one one-time prekey from the pool (if any
remain) and returns it — each one-time prekey is handed out at most once.
```json
{
  "device_id": "16hexchars",
  "dh_identity_pubkey": "base64...",
  "dh_identity_cert": { "dh_pubkey": "base64...", "issued_at": "...", "signature": "base64..." },
  "signed_prekey": { "key_id": 1, "dh_identity_pubkey": "base64...", "pubkey": "base64...", "issued_at": "...", "signature": "base64..." },
  "one_time_prekey": { "key_id": 101, "pubkey": "base64..." }
}
```
`one_time_prekey` is omitted (`null`) once the pool is empty — X3DH
proceeds without it (§5), with reduced forward secrecy for that first
message only. `404` if the device is unknown, inactive, or has never
uploaded prekeys. If this claim leaves the pool below a low-water mark and
the device has no live SSE stream open, the server fires a push wake (see
"Push notifications" below) so a rarely-opened device gets a chance to
replenish before the pool actually runs dry.

### `GET /v1/devices/{device_id}/prekey-status` (signed, caller must be that device)
Non-destructive counterpart to the claim endpoint above — reports the pool
size without consuming a key, so a device can decide whether to top up.
```json
{ "one_time_prekeys_remaining": 7 }
```
`200` · `403` wrong device · `401` unauthenticated.

## 5. X3DH + Double Ratchet

### DH Identity Certificate & Signed Prekey Certificate

Same deterministic length-prefixed binary signing pattern as the Device
Certificate (§2), but signed with the **device's own Ed25519 private key**
(not the root key) — a device already certified by the root is vouching
for its own X3DH material.

DH Identity Certificate, over `(account_id, device_id, dh_pubkey, issued_at)`:
```
uint16BE(len(account_id)) || account_id
|| device_id (8 raw bytes)
|| dh_pubkey (32 raw bytes, X25519)
|| uint16BE(len(issued_at_str)) || issued_at_str
```

Signed Prekey Certificate, over `(account_id, device_id, key_id, dh_identity_pubkey, prekey_pubkey, issued_at)`
— binding the prekey to a specific DH identity key is what stops the
signature being replayed against a substituted identity key:
```
uint16BE(len(account_id)) || account_id
|| device_id (8 raw bytes)
|| uint32BE(key_id)
|| dh_identity_pubkey (32 raw bytes)
|| prekey_pubkey (32 raw bytes)
|| uint16BE(len(issued_at_str)) || issued_at_str
```

One-time prekeys are **not** individually signed (matches the X3DH spec —
their authenticity comes from being fetched as part of the same
server-side bundle tied to an already-verified device).

Client-side only — the server never sees plaintext, key material beyond
public keys/certificates, or ratchet state. Implemented in
`pkg/ratchet` (public, so other Go modules — e.g. the mobile app's shared
core — can import it directly instead of re-implementing it), following
[the X3DH spec](https://www.signal.org/docs/specifications/x3dh/) and
[the Double Ratchet spec](https://www.signal.org/docs/specifications/doubleratchet/)
with these concrete choices:

- **Curve:** X25519 throughout (`crypto/ecdh` in Go).
- **X3DH SK derivation:** HKDF-SHA256, `IKM = 0xFF×32 || DH1 || DH2 || DH3 [|| DH4]`,
  salt = 32 zero bytes, info = `"Freizone-X3DH-v1"` → 32-byte SK.
- **Session AD:** `Encode(initiator's DH identity pubkey) || Encode(responder's)`,
  fixed for the life of the session by **role** (whoever sent the first
  "prekey" message is the initiator) — never swapped based on who's
  currently sending.
- **Double Ratchet KDF_RK:** HKDF-SHA256(salt=current RK, ikm=DH output,
  info=`"Freizone-DR-RK-v1"`) → 64 bytes → new RK (32) + new chain key (32).
- **Double Ratchet KDF_CK:** HMAC-SHA256(key=chain key, msg=`0x01`) →
  message key; HMAC-SHA256(key=chain key, msg=`0x02`) → next chain key.
- **Message encryption:** AES-256-GCM. Per message,
  HKDF-SHA256(ikm=message key, info=`"Freizone-DR-msg-v1"`, 44 bytes) → a
  32-byte AES key + 12-byte nonce (safe here specifically because each
  message key is used exactly once). AEAD associated data = session AD ||
  header bytes (`dh_pub(32) || pn(uint32BE) || n(uint32BE)`).
- **Bootstrap:** the initiator generates a **fresh** X25519 keypair for its
  first ratchet step (never reuses its X3DH ephemeral key) and ratchets
  forward immediately using the responder's signed-prekey public key. The
  responder reuses its signed-prekey keypair as its initial ratchet
  keypair and only generates a fresh one once it processes the initiator's
  first message.

**Known limitation, accepted for now:** `prekey-bundle` claims are
unauthenticated, so anyone can exhaust a device's one-time-prekey pool —
degrades forward secrecy for that session's first message, not
confidentiality. Revisit before any real deployment.

**Session recovery / re-key (client behavior):** a `prekey` block is normally
only meaningful when the recipient has no existing session with that sender
(first contact). A client MAY also accept one when a session **already**
exists — e.g. the sender reset their local session after a ratchet
desync — but only as a proposal: it must attempt a fresh responder
establishment from it and adopt the resulting session **only if it actually
decrypts** the accompanying message, falling back to the existing session
otherwise (a stale/redelivered `prekey` block must not be able to disrupt a
still-healthy session). This is safe because responder establishment always
re-verifies the sender's full self-certifying cert chain (§2, §5) — accepting
a re-key is not a new trust decision, just a repeat of the same one. See
freizone-app's `AppSession.resetSecureSession` / `processIncomingMessage` for
a reference implementation.

Because a re-key must ride on *some* message, a client that has just discarded
its session SHOULD send the invisible `rekey` control envelope (§6) rather than
wait for the user to type something. What a desync breaks is **receiving**: the
peer keeps sending into a session this side can no longer read, and no action of
theirs will change that until a fresh `prekey` block from this side re-points
them at a working session.

**Detecting a desync (client behavior).** `Session.Decrypt` classifies its
failures (`pkg/ratchet`'s `FailureCode`), and only some of them say anything
about the session:

| Code | Meaning | Evidence of desync |
| --- | --- | --- |
| `duplicate_message` | Redelivery of an envelope already decrypted. Delivery is at-least-once (§7), so this is routine. | no |
| `authentication_failed` | The AEAD tag didn't verify — the message key derived here is not the one the sender used. | yes |
| `too_many_skipped` | The header's message number is too far ahead of this side's receiving chain to bridge. | yes |
| `no_receiving_chain` | A message for a chain that doesn't exist here yet. | yes |
| *(none)* | Anything else — a malformed header, corrupt persisted state. No diagnosis. | no |

A **single** such failure is not proof: an envelope can fail once because it
raced a session change. Repetition is, since decrypting the same ciphertext
against the same session is deterministic — so a client SHOULD count failures
per envelope, give up on one after a few attempts (dropping it from the queue,
§7), and only then count it as one unit of evidence against the *session*.
A separate case carries the same weight and produces no error at all: an
envelope with **no `prekey` block from a sender there is no session for**, which
is what a client whose own session state was lost or rolled back sees. Any
successful decrypt clears the evidence — it is the only proof the session works.

On enough evidence a client MAY discard its session and re-key as above. Two
rules keep that from making things worse:

- **Order it.** If both sides re-key at once, each adopts a responder session
  built from the other's `prekey` block while discarding the initiator session
  the other just adopted — leaving both broken again, symmetrically, every
  round. Ordering is derived from data both sides already have: the **lower**
  `account_id` re-keys immediately, the higher one only if that hasn't fixed
  things within a grace period.
- **Space it.** Each re-key consumes one of the peer's one-time prekeys, so a
  client MUST bound how often it will re-key with the same peer.

Recovery is lossy — anything still queued on the old chain becomes
undecryptable — so it is a last resort, and a client SHOULD record it visibly
in the conversation rather than silently.

## 6. Message envelope & queue

A message's `payload` (§7) is an opaque JSON blob the server never parses —
defined here purely as a client-to-client contract, implemented in
`pkg/wire`:

```json
{
  "prekey": {
    "sender_dh_identity_pub": "base64 X25519, 32 bytes",
    "sender_ephemeral_pub": "base64 X25519, 32 bytes",
    "signed_prekey_id": 1,
    "one_time_prekey_id": 101
  },
  "header": {
    "dh_pub": "base64 X25519, 32 bytes",
    "pn": 0,
    "n": 0
  },
  "ciphertext": "base64..."
}
```

`prekey` is present **only** on the first message of a new session (Signal
calls this shape a "PreKeySignalMessage" vs. a plain "SignalMessage" for
everything after), or when re-keying an existing one (§5);
`one_time_prekey_id` is omitted if none was used. `header` is the Double
Ratchet header (§5) and is always present.

### The plaintext inside (client-to-client)

What `ciphertext` decrypts to is a JSON object whose `v` selects the shape.
Nothing here ever reaches the server; it is documented so independent clients
interoperate, and implemented in freizone-app (`lib/state/`).

| `v` | Shape | Shown to the user |
| --- | --- | --- |
| absent / not JSON | Legacy: the raw bytes are the message text. | yes |
| `1` | Chat content — text, message id, reply reference, attachment references (§10). | yes |
| `2` | Delivery/read receipt. | no |
| `3` | Session re-key signal (below). | no |

`v: 1` is frozen: ordinary chat messages never change shape, so every later
control envelope gets its own version. A client that meets a `v` it does not
know MUST NOT fail the message — it renders a neutral "newer feature"
placeholder, which is also what a client predating a control envelope will show
for one. That is the accepted cost of the scheme: an older peer displays a
placeholder for a message that should have been invisible, rather than silently
mishandling it.

**Session re-key signal (`v: 3`)** — the invisible carrier for a re-key (§5):

```json
{
  "v": 3,
  "kind": "rekey",
  "reason": "decrypt_failures | user_requested | unspecified"
}
```

It deliberately carries nothing else. Its entire purpose is that sending *any*
message right after discarding the local session puts a fresh `prekey` block on
the wire; this payload is what goes inside so the recovery costs no visible
message. A recipient MUST NOT store or notify it, and MUST still delete it from
its queue (§7) like any other processed envelope. `reason` is informational —
useful for wording the transcript marker (a recovery the user triggered reads
differently from one the app performed) and for diagnostics; an unrecognized
value is treated as `unspecified` and never affects any security decision.

## 7. Message REST endpoints

### `POST /v1/messages` (signed)
Enqueues a message envelope (§6) for a recipient device.
```json
{
  "message_id": "client-generated, e.g. a random hex/UUID string",
  "recipient_device_id": "16hexchars",
  "payload": { "...the envelope from §6..." }
}
```
`202 {"status":"queued"}` — durably queued, not yet necessarily delivered ·
`404` unknown/inactive recipient device · `409` `message_id` already used ·
`429` recipient device's queue is already at `FREIZONE_MAX_QUEUED_MESSAGES_PER_DEVICE`
(§9) · `413` request body exceeds `FREIZONE_MAX_REQUEST_BODY_BYTES` (enforced
as middleware ahead of every route *except* the two blob upload routes, which
are capped by `FREIZONE_MAX_BLOB_BYTES` instead — see §10 — since an
attachment is legitimately far larger than any message; so in practice a
same-server signed request this large is rejected by the auth middleware's own
body read first, surfacing as the generic `401` §3 already documents for every
auth failure, rather than this `413`).

If the recipient device has no live SSE stream (`GET /v1/messages/stream`)
open, the server fires one best-effort wake, via whichever of the two
mechanisms the device has registered (a device has at most one at a
time). The same wake is also fired when `POST /v1/devices/{device_id}/prekey-bundle`
(§4) leaves a device's one-time-prekey pool below the low-water mark — the
wake carries no indication of which reason triggered it (see below), so
this reuses the identical mechanism rather than needing a second one:

- **Push subscription** (`PUT /v1/devices/{device_id}/push-endpoint`):
  a Web Push notification, RFC 8291-encrypted via this server's one
  VAPID keypair (RFC 8292), sent directly to the registered
  UnifiedPush/Web Push distributor endpoint.
- **Push target** (`PUT /v1/devices/{device_id}/push-target`): this
  server signs a request with its own relay identity (an Ed25519
  keypair generated on first boot, see `server_settings.relay_pubkey` —
  never exposed via any endpoint, only used as the `Signature-Key-Id` on
  outgoing relay requests) and POSTs `{"platform": ..., "token": ...}`
  to `POST /v1/push/send` on the [freizone-gateway](https://github.com/behringer24/freizone-gateway)
  instance configured via `FREIZONE_PUSH_GATEWAY_URL`, which holds the
  actual FCM/APNs credentials and relays the wake. There is no
  registration step with the gateway: it verifies the request against
  the public key embedded in `Signature-Key-Id` itself, the same
  self-certifying pattern this protocol already uses for account ids
  (§1). Skipped entirely if `FREIZONE_PUSH_GATEWAY_URL` isn't
  configured.

Either way, the wake itself carries no content or metadata whatsoever —
not the message, not its sender, not even that it's specifically a "new
message" wake as opposed to any other reason (the Web Push path's
encrypted plaintext is itself empty; the push-target path's body is only
ever `{"platform", "token"}`, nothing message-related). The recipient is
expected to react to any wake by syncing over this same authenticated
API, exactly as if it had just reconnected — fetching queued messages
*and* checking `GET /v1/devices/{device_id}/prekey-status` (§4), since a
wake can't tell the client which of the two actually needs attention.
Delivery of the wake itself is not guaranteed (no retry, short timeout) —
the durable queue and the client's own reconnect/poll remain the actual
delivery guarantee, same as before push existed.

### `GET /v1/messages` (signed)
Polls for messages queued for the caller's device. `200`, an array of:
```json
{
  "message_id": "...",
  "sender_account_id": "...",
  "sender_device_id": "...",
  "sent_at": "2026-07-17T12:00:00Z",
  "payload": { "...the envelope from §6..." }
}
```

### `DELETE /v1/messages/{message_id}` (signed)
Acknowledges a message, removing it from the queue once durably processed.
`200 {"status":"deleted"}` · `404` unknown message, or it doesn't belong to
the caller's device.

### `GET /v1/messages/stream` (signed, SSE)
`Content-Type: text/event-stream`. On connect, flushes every currently
pending message (same shape as the `GET /v1/messages` poll, one per SSE
`event: message` / `data: ...` pair), then pushes newly-arrived messages
live for as long as the client stays connected. A `: heartbeat` comment is
sent roughly every 25s to keep the connection alive through proxies. This
is process-local (no cross-instance fan-out) — fine for a single server,
revisit for horizontal scaling.

Messages are never stored long-term: each is deleted immediately on
acknowledgment, or automatically after `FREIZONE_MESSAGE_RETENTION_DAYS`
(default 14) if never acknowledged.

## 8. Invite QR codes (`freizone://join`)

Client-side convention, not a server endpoint: a URI that lets one device
hand another everything it needs to join a server, without typing an
address or invite code by hand. An app renders this as a QR code (whoever
can currently invite — see §4's `POST /v1/admin/invites` — on an `invite`
server, or anyone on an `open` server); another instance's setup wizard
scans it in place of the manual address-entry step.

```
freizone://join?server=<url>&code=<invite code>
```

- `server` (required): the same address a user would otherwise type into
  the setup wizard, e.g. `https://chat.example.org`.
- `code` (optional): a single-use invite code from `POST
  /v1/admin/invites`. Omitted entirely when the target server's
  registration policy is `open` (no code needed) — a QR for an `open`
  server carries only `server`. Best encoded in the **compact** form
  (`ABCDEFGHJKMN`) rather than the grouped form the endpoint returns
  (`ABCD-EFGH-JKMN`): the code redeems either way, since the server
  normalizes it (§4), so dropping the hyphens is purely about keeping the QR
  sparse. A scanner must not assume the compact form, though — normalization
  means a QR produced by another client with hyphens in it is equally valid.

There's no case for an unclaimed (not-yet-bootstrapped) server: bootstrap
needs a one-time setup token, which isn't part of this format, since QR
invites are only ever generated by a server that's already been claimed.
Scanning a QR pointing at an unclaimed server just falls through to the
ordinary manual bootstrap step, address pre-filled — not an error, just
no extra automation for a case that shouldn't occur.

## 9. Federation

A message to `id*server` where `server` isn't the sender's own home
server is delivered **directly by the sending client to the recipient's
home server** — there is no server-to-server relay, and no registration
or handshake between the two servers beforehand. This follows directly
from §1's self-certifying identity: since any party can independently
verify `hash(root_pubkey) == id` and a device certificate's signature,
the recipient's server can verify a stranger's request purely
cryptographically, with no need to trust (or even know about) the
sender's home server.

**Account/prekey lookup** needs no new endpoint: `GET /v1/accounts/{id}`
and `POST /v1/devices/{device_id}/prekey-bundle` (§4) are already public
and already answer only about this server's own accounts — calling them
against the recipient's server (instead of the caller's own) works
unchanged.

**Message delivery** does need a dedicated endpoint, since `POST
/v1/messages` (§7) is authenticated by looking up the signing device in
this server's own `devices` table — which a foreign device, by
definition, isn't in.

### `POST /v1/federation/messages` (public — does its own authentication)

Request body:

```json
{
  "sender_account_id": "...",
  "sender_root_pub_key": "base64",
  "sender_device_cert": {
    "device_id": "...",
    "device_pub_key": "base64",
    "issued_at": "2025-01-01T00:00:00Z",
    "signature": "base64"
  },
  "recipient_account_id": "...",
  "recipient_device_id": "...",
  "message_id": "...",
  "payload": { "...same envelope shape as §6/§7..." }
}
```

Signed exactly like any other request (§3), with one difference:
**`Signature-Key-Id` is the sender device's own base64-encoded public
key** (`sender_device_cert.device_pub_key`), not a device id — there is
no local row to look a device id up in. This is the same
self-describing-key convention [freizone-gateway](https://github.com/behringer24/freizone-gateway)
already uses for its own no-registration caller model.

Server-side verification, in order:

1. `hash(sender_root_pub_key) == sender_account_id` (§1).
2. `sender_device_cert` is validly signed by `sender_root_pub_key` — the
   same check §4's `POST /v1/devices` does once, at registration time,
   for a local device; here it's done inline, per request, since the
   sender was never registered here.
3. `sender_account_id` is not on this server's federation blocklist (see
   below).
4. `Signature-Key-Id` equals `sender_device_cert.device_pub_key` exactly
   — binding "the signature proves possession of this key" to "the
   certificate proves this key is certified under this account."
5. The request signature verifies against that key, within the usual
   clock skew, and its nonce hasn't been replayed (§3, unchanged).
6. `recipient_device_id` names an active local device, whose account is
   also active.
7. `message_id` hasn't already been used (§7's existing idempotency
   guard).

On success the message is queued and delivered to the recipient exactly
as any same-server message would be (§6/§7's SSE stream and push-wake
path) — the recipient's client can't tell, and doesn't need to, whether
a message arrived from this server or a federated one.

**Learning the sender's server, for replies.** Nothing above ties
`sender_account_id` to any particular hostname — that's deliberate;
self-certifying identity is host-independent by design, so there's no
reliable "which server is this account's home" fact for this endpoint to
assert or check. Instead, a client sending cross-server includes its own
server address inside the *encrypted message content* (not this
delivery-layer request), on every such message. This keeps the fact out
of anything a server ever sees in the clear, and makes a recipient's
knowledge of the sender's server self-healing (it's refreshed on every
message, not just the first) rather than a one-time fact that a lost
local device could never recover.

**Abuse mitigation is per-account, not per-server.** An admin can block a
specific remote `account_id` from delivering messages here:

- `GET /v1/admin/federation-blocklist` — list blocked accounts (admin or
  moderator).
- `POST /v1/admin/federation-blocklist` `{"account_id": "...", "reason":
  "..."}` — block one (admin only).
- `DELETE /v1/admin/federation-blocklist/{account_id}` — unblock (admin
  only).

There is no per-origin-server block, because nothing here reliably
identifies one — the whole point of self-certifying identity is that no
server (including the recipient's own) is in a position to assert "this
account really lives at that hostname." Blocking one abusive account
doesn't stop a determined operator from minting another; that's a known,
accepted limitation of this first version, not something this design
solves.

**Queue and body-size limits.** Since federation accepts a caller that
was never registered here, a message-flooding sender no longer even
needs an account on this server (same-server sending is still bounded
by whatever `FREIZONE_REGISTRATION_POLICY` requires). Two limits guard
against this, applied identically to same-server and federated
delivery: `FREIZONE_MAX_QUEUED_MESSAGES_PER_DEVICE` (default 1000)
caps how many undelivered messages one recipient device's queue may
hold at once (`429` once full), and `FREIZONE_MAX_REQUEST_BODY_BYTES`
(default 512 KiB, enforced as middleware ahead of every route, not
just message delivery) caps a single request's size. Neither existed
before federation did — the same unbounded-queue/unbounded-body gap
existed for plain same-server sending too, federation just removed the
"you need an account here first" friction that limited who could
exploit it.

**Known gap: cross-server device revocation.** §4's `POST
/v1/devices/{id}/revoke` only updates *this* server's own `devices`
table. If a sender's device is revoked on its home server, a recipient
elsewhere has no channel to learn that — unlike same-server auth, where
a revocation takes effect on the very next request. A live check against
the sender's claimed home server was considered and rejected: the
"server" a message claims to come from is self-reported and
unauthenticated (see above), so exactly the attacker this would catch —
someone using a stolen, not-yet-revoked device key — can trivially omit
or falsify it, or simply wait out a transient unreachability window. A
best-effort version remains a natural future addition (reusing the
already-public `GET /v1/accounts/{id}`, no new endpoint needed) but isn't
built in this version.

**`FREIZONE_FEDERATION_ENABLED`** (default `true`): seeds the inbound-
federation switch on first boot. Turned off, `POST /v1/federation/messages`
returns `404` for an operator who wants no inbound federation at all. Like
the registration policy, this is only the *seed*: the authoritative value
lives in the DB and is changed at runtime via `PUT /v1/admin/federation`
(§4), surfaced publicly on `GET /v1/server-status` so honest clients also
stop *sending* outbound federation when their home server has it off (a
peer's reply would otherwise be blocked here, stranding the conversation).

**Explicitly out of scope**: groups (a future group send is simply N
parallel invocations of this same per-recipient delivery, fanned out
per member — nothing here assumes a single recipient server or a shared
delivery transaction across members), account portability/migrating
servers, and server discovery — not needed, since an address already
names the exact server.

## 10. Encrypted blob transport (attachments)

Messages carry text; anything larger — an image, later video or audio —
travels out of band as a **blob**. The message itself only carries a
reference plus the key to decrypt it, inside the end-to-end encrypted
payload, so the server learns no more about an attachment than it does about
a message: it stores ciphertext it cannot read.

**A blob lives on the recipient's server**, not the sender's. This mirrors
the direction messages already travel (§9: the sender pushes to the
recipient's server), and means a recipient only ever fetches from its own,
trusted server — it never has to contact a stranger's server and reveal its
IP to an operator it has no relationship with. The cost is that the upload
route, like federated messages, accepts uploads from senders who never
registered here, and is defended the same way: the federation kill switch,
the blocklist, per-device quotas, and a retention window.

Flow:

1. Sender encrypts the attachment with a **fresh random key** (not derived
   from the ratchet, so re-downloading still works after a session reset).
2. Sender uploads the ciphertext to the **recipient's** server and gets a
   `blob_id`.
3. Sender sends a normal message whose encrypted payload carries the
   `blob_id` and the key.
4. Recipient decrypts the message, fetches the blob from **its own** server,
   and decrypts it locally.

### The attachment reference (client-to-client)

Step 3's reference is a client-to-client contract, not something the server
ever parses — it lives inside the encrypted payload envelope of §6, in that
envelope's `attachments` list. Documented here for the same reason the
envelope itself is: anyone writing a second client needs it to interoperate.

```json
{
  "kind": "image",
  "alg": "aes-256-gcm",
  "blob_id": "64 hex chars",
  "key": "base64 (32 bytes)",
  "mime": "image/jpeg",
  "size": 214512,
  "w": 1600,
  "h": 1200,
  "thumb": "base64 (optional, ≤ 2 KiB)"
}
```

- `kind` — `"image"` today. An unrecognized kind must render as an
  unsupported-attachment placeholder rather than break the message, which is
  what lets video/audio be added without a format change.
- `alg` — a string rather than an implied cipher, so changing ciphers stays
  additive.
- `key` — this blob's own symmetric key, freshly generated per attachment and
  deliberately **not** ratchet-derived, so the picture stays decryptable after
  a secure-session reset (§5) discards ratchet state.
- `size`, `w`, `h` — the pixel dimensions let a client reserve the final
  aspect ratio before the blob has downloaded, so a transcript does not reflow
  as pictures arrive.
- `thumb` — an optional inline preview, small enough to ride inside the
  message itself (**at most 2 KiB**), shown blurred until the real blob lands.
  The cap must be enforced when *decoding* as well as encoding: otherwise a
  buggy or hostile peer could inflate the receiver's stored history through
  this field.
- Deliberately absent: any `server` field (a blob always lives on the
  recipient's own server, so the fetching client already knows where to look)
  and any filename (it would leak device paths and camera details for no
  benefit).

A malformed entry — no `blob_id`, no `key`, an oversized `thumb` — should be
dropped on its own rather than failing the whole message: the text still
deserves to arrive.

### Endpoints

| Method | Path | Auth |
|---|---|---|
| `POST` | `/v1/blobs?recipient_device_id=…` | device signature (§3) + `Blob-Digest` |
| `POST` | `/v1/federation/blobs?recipient_device_id=…` | self-describing key (§3) + `Blob-Digest` |
| `GET` | `/v1/blobs/{blob_id}` | device signature (§3), recipient only |
| `DELETE` | `/v1/blobs/{blob_id}` | device signature (§3), recipient only |

Upload bodies are `application/octet-stream` — raw ciphertext, not base64
(the server never parses it, and base64 would add a third). They are
authenticated by the streamed-body variant in §3, so the signature is checked
before any bytes are read and the stored bytes are verified against the
signed digest.

On the federated route the sender's identity moves from JSON fields into
headers, since the body is raw bytes: `Freizone-Sender-Account-Id`,
`-Root-Pub-Key`, `-Device-Id`, `-Device-Pub-Key`, `-Cert-Issued-At`,
`-Cert-Signature`. They are verified exactly as §9 verifies a federated
message sender.

Success returns `201` with `{"blob_id", "size", "expires_at"}`.

`blob_id` is 32 random bytes, hex-encoded — deliberately **not** a content
hash, which would let anyone holding a file test whether someone else
uploaded the same one, and would turn the id into an existence probe.

### Retrieval and errors

`GET` serves the ciphertext via range-capable responses, so an interrupted
download can resume. A blob that does not exist and one belonging to another
device both answer `404`, so the endpoint cannot be used to discover blob ids.

| Status | Meaning |
|---|---|
| `400 digest_mismatch` | body did not match the signed `Blob-Digest` |
| `401` | signature/auth failure (generic, as everywhere) |
| `403` | federated sender is blocked |
| `404` | blobs disabled, unknown/inactive recipient device, or unknown/not-yours blob |
| `413 payload_too_large` | over `FREIZONE_MAX_BLOB_BYTES` |
| `429 blob_quota_exceeded` | recipient device is at its blob count or byte quota |

### Limits and lifetime

Operator-configurable: `FREIZONE_MAX_BLOB_BYTES` (default 8 MiB),
`FREIZONE_MAX_BLOB_BYTES_PER_DEVICE` (128 MiB), `FREIZONE_MAX_BLOBS_PER_DEVICE`
(200), `FREIZONE_BLOB_RETENTION_DAYS` (defaults to the message retention
window and may not be shorter, so a blob outlives the message referencing
it), `FREIZONE_BLOBS_ENABLED`, `FREIZONE_BLOB_DIR`.

Because these are the *recipient* server's limits and a federated sender
cannot know them in advance, `GET /v1/server-status` (§4) advertises
`blobs_enabled` and `max_blob_bytes` — a sender sizes or recompresses an
attachment against those rather than discovering them via a `413` after
uploading.

Blobs are deleted when the recipient `DELETE`s them, when the retention
window expires, or when their recipient device is removed (cascade).

The server does **not** delete on `GET`: a read proves nothing about whether
the client decrypted and stored the bytes, and range requests make "finished
downloading" ambiguous anyway. Instead the recipient is expected to `DELETE`
the blob once it has the plaintext safely on disk — the same
process-then-remove contract as the message queue (§5). Retention is the
backstop for blobs whose recipient never comes back.

Only the recipient can retrieve a blob, so a sender cannot re-fetch what it
uploaded; its own copy is whatever it kept locally at send time.

## 11. Chat invite QR codes (`freizone://chat`)

Client-side convention, not a server endpoint — the counterpart to §8's
`freizone://join`, but for contact initiation rather than server
registration: a URI that lets one already-registered account hand
another its own address, so the scanning device can start a
conversation directly (federated per §9 if the two accounts are on
different servers) instead of typing an `id*server` address by hand.

```
freizone://chat?id=<account id>&server=<url>&name=<display name>
```

- `id` (required): the sharer's account id, in its canonical (unhyphenated)
  form.
- `server` (required): the sharer's home server, in the same form as
  §8's `server` param.
- `name` (optional): a display-name suggestion for the conversation the
  scanning device creates — purely a local default on the recipient's
  side, not authoritative and freely overridden there.

Unlike §8's join invite, this carries no secret or capability: an
account's `id*server` address is already public information (it's
exactly what `GET /v1/accounts/{id}` on `server` answers about, per
§4/§9), so there's nothing here to expire or revoke. The QR is purely a
convenience encoding of already-public data, equivalent in trust terms
to reading the address off a screen and typing it in by hand — the
actual identity verification happens the same way it would for a
manually-typed address, via the existing account/prekey lookup and
device-certificate checks (§2, §9), not anything carried by this URI.
