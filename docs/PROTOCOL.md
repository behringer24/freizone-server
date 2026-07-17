# Freizone Wire Protocol — Identity & Auth (v1)

This document is the cross-repo contract between the server (this repo) and
any client (mobile app) implementation. It covers only what's implemented in
this milestone: addressing, device certificates/revocations, per-request
signature authentication, and the identity/bootstrap REST surface.

Out of scope here (future milestones): X3DH/Double Ratchet message
encryption, federation, groups/broadcast, message queue/history, push
notifications, and the QR device-linking handshake itself (only its
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
                            │  (not covered by this milestone: signs
                            │   Signed/One-Time Prekeys for X3DH)
```

The root key never leaves the primary device and is never used to encrypt
or to sign requests — only to sign device certificates and revocations.

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
`401` invalid/already-used token · `400` invalid certificate · `409` an
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
      "status": "active",
      "revoked_at": null
    }
  ]
}
```
Both active and revoked devices are listed (with their status). `404` if
`{id}` is unknown or fails address normalization.

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

### `POST /v1/admin/invites` (signed, admin only)
Issues a single-use invite code (for the `invite` registration policy) —
typically rendered by the app as a QR code for the admin to hand out.
```json
{ "expires_at": "optional RFC3339, omit for a code that never expires" }
```
`201`:
```json
{ "code": "...", "expires_at": "optional" }
```
`403` if the caller isn't an admin.
