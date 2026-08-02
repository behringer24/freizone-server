# Design: Root-key-authenticated device recovery

Status: **done** · Roadmap: [SRV-06](../ROADMAP.md)

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
