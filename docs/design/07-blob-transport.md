# Design: Encrypted blob transport for attachments

Status: **done** · Roadmap: [SRV-07](../ROADMAP.md)

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

**Correction, 2026-08-14.** The last item in that list — deleting the blob once
it is stored locally — stopped happening on 2026-08-10 and this paragraph went
on claiming it for four days. The release lived in the app's Dart download path
(`AppSession.ensureAttachmentDownloaded`); the SRV-23 cut moved downloads into
`pkg/client` and nothing there called it, so every attachment occupied its
recipient's quota for the full retention window instead of until it was read.
Restored the same day in `pkg/client`'s `EnsureAttachment`, which is where the
download now lives — so the app, `cmd/devclient` and a later bot all honour the
contract from one place. Two things had to be fixed first: `Client.DeleteBlob`
could never report success, because this is the only route answering `204` with
an empty body and the client reads a bodyless reply as "not a Freizone server";
and the test stub deleted blobs outright rather than per claim, which would have
let one group member's read take the picture from the rest. Both now have tests
of their own — a release that is discarded best-effort is invisible when it
breaks, which is how it stayed unnoticed the first time.
