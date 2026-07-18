# Freizone Wire Protocol — Identity, Auth & E2E Messaging (v2)

This document is the cross-repo contract between the server (this repo) and
any client (mobile app, or `cmd/devclient` — a reference implementation in
this repo) implementation. It covers: addressing, device
certificates/revocations, per-request signature authentication, the
identity/bootstrap REST surface, X3DH + Double Ratchet end-to-end
encryption, and the prekey/message REST surface that carries it.

Out of scope here (future milestones): federation (server-to-server
delivery — everything below is single-server, 1:1 only), groups/broadcast,
push notifications, and the QR device-linking handshake itself (only its
*result* — a signed device certificate — is consumed by this API).

## 1. Addressing

An account address is `id@domain`, where `domain` is the home server's
domain and `id` is a 21-character string derived from the account's root
Ed25519 public key:

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
shown in 4-character dash-separated blocks (`k5x9-p2qa-n7f3-xyzq-eh8m`-style)
purely for readability; this is cosmetic and not part of the canonical form.

The ID is **self-certifying**: any party can recompute
`hash(delivered_root_pubkey) == id` themselves. No server can substitute a
different key without it being immediately detectable from the address
itself.

Normalization for comparison/lookup: lowercase, strip `-`/whitespace, verify
length (21) and bech32m checksum.

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
`401` invalid, already-used, or locked-out token · `400` invalid certificate · `409` an
admin already exists.

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
`409` account or device id collision.

### `GET /v1/server-status`
No auth — lets a client decide which setup path applies before it has any
identity: bootstrap (no admin claimed yet), self-register (open policy),
invite-code registration, or "closed" -- registration fully blocked, not
even with an invite code (the invite-code check in `POST /v1/accounts` is
never reached while the policy is `closed`).
`200`:
```json
{ "claimed": true, "registration_policy": "open" }
```
`claimed` is whether the one-time setup token has already been used
(i.e. an admin exists) — not sensitive, same trust level as the
registration policy itself, which has to be knowable before someone can
register at all.

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
(with their status). `404` if `{id}` is unknown or fails address
normalization.

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

### `POST /v1/admin/invites` (signed, admin or moderator)
Issues a single-use invite code (for the `invite` registration policy) —
typically rendered by the app as a QR code (see §8) for the caller to
hand out.
```json
{ "expires_at": "optional RFC3339, omit for a code that never expires" }
```
`201`:
```json
{ "code": "...", "expires_at": "optional" }
```
`403` if the caller is neither admin nor moderator.

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
uploaded prekeys.

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
everything after); `one_time_prekey_id` is omitted if none was used.
`header` is the Double Ratchet header (§5) and is always present.

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
`404` unknown/inactive recipient device · `409` `message_id` already used.

If the recipient device has no live SSE stream (`GET /v1/messages/stream`)
open and has registered a push subscription (see `PUT
/v1/devices/{device_id}/push-endpoint`), the server fires a best-effort
Web Push notification (RFC 8291-encrypted via this server's one VAPID
keypair, RFC 8292) to wake the recipient. The encrypted plaintext is
itself empty — the wake carries no content or metadata whatsoever, not
the message, not its sender, not even that it's specifically a "new
message" wake as opposed to any other reason. Encryption here is purely a
transport requirement of the Web Push/UnifiedPush protocol, not a way to
communicate anything: the recipient is expected to react to any wake by
syncing over this same authenticated API, exactly as if it had just
reconnected. Delivery of the wake itself is not guaranteed (no retry,
short timeout) — the durable queue and the client's own reconnect/poll
remain the actual delivery guarantee, same as before push existed.

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
  server carries only `server`.

There's no case for an unclaimed (not-yet-bootstrapped) server: bootstrap
needs a one-time setup token, which isn't part of this format, since QR
invites are only ever generated by a server that's already been claimed.
Scanning a QR pointing at an unclaimed server just falls through to the
ordinary manual bootstrap step, address pre-filled — not an error, just
no extra automation for a case that shouldn't occur.
