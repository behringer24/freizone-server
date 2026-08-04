# Design: Multi-recipient blobs (attachments in a group)

Status: **done** — core 2026-08-03, app 2026-08-04 · Roadmap:
[SRV-18](../ROADMAP.md)

Attachments are the last large piece of groups. The receive half already
exists in freizone-app (APP-16): a group message keeps its `attachments`, and
the download is keyed on a chat-neutral id. What is missing is the rendering
and the **send** side — and the send side is blocked here, in the core.

[design/01-groups.md](01-groups.md) promised one upload per distinct recipient
*server*, "not per recipient". That is not implementable against SRV-07 as
shipped: a blob is bound to exactly one device. `POST /v1/blobs` takes a single
`recipient_device_id`, `blobs.recipient_device_id` is a column on the blob
itself, and `store.GetBlobForDevice` authorizes the download against it. In a
group that means one upload per *member*, so the promise is off by the group
size:

| 20-member group, 10 members on one server, 3 MB photo | uplink from the phone | disk on that server |
|---|---|---|
| today (one blob per member) | 30 MB | 30 MB |
| one blob per server | 3 MB | 3 MB |

The recipient-side quota is charged the same either way — every member has to
be allowed to fetch it, so every member holds 3 MB against their own cap. What
changes is the sender's uplink and the server's disk, and on mobile data that
is the difference between a feature that works and one that does not.

## Why the one-device binding was right, and why it now has to give

Everything about a blob hangs off its recipient: quota is charged to them
(SRV-07's defence against a federated stranger filling the disk), expiry runs
from their retention window, the download is authorized as "you are the
recipient", and deletion is theirs. That is exactly right for one-to-one, and
it is the reason SRV-07 could accept uploads from senders who never registered
here. None of it needs to change — only the assumption that there is exactly
*one* such recipient per stored object.

## What was rejected

- **Leave it: N uploads per server.** No core change; the whole feature could
  be built in the app alone. Rejected on the table above — a five-member group
  would be fine and a twenty-member group would not, and the send path would
  then have to be rewritten a second time when this lands anyway.
- **Drop the recipient binding entirely** and protect the blob only by its
  256-bit random id, so that anyone holding the id (i.e. anyone who decrypted
  the message) may fetch. It is the smallest change and it leaks the least —
  the server would not learn the recipient set at all. Rejected because it
  leaves the stored object with no owner: quota has nobody to charge, deletion
  nobody to perform, and the federated upload route — open to strangers by
  design — would become an unowned write. Capability-by-secrecy is a fine
  supplement to an owner and a poor replacement for one.
- **One blob id per recipient, sharing a storage key.** Keeps the `blobs` table
  and the download path untouched: add a `storage_key` column, write the file
  once, drop it when the last row referencing it is gone. Rejected because it
  introduces a second id space for one object — the blob id would no longer be
  the file name, so the orphan sweep (which walks the blob directory and asks
  `BlobIDExists`) would have to reason about both, and every future reader of
  this code would have to learn which id they are holding. The refcount is
  better named than hidden.

## The shape

One blob, several recipients. The blob row becomes the stored object; the
recipients move to their own table.

```sql
-- 0013_multi_recipient_blobs.sql
CREATE TABLE blob_recipients (
    blob_id             TEXT NOT NULL REFERENCES blobs(blob_id) ON DELETE CASCADE,
    recipient_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    PRIMARY KEY (blob_id, recipient_device_id)
);
```

`blobs` keeps `blob_id`, `size_bytes`, `created_at`, `expires_at` and loses
`recipient_device_id`; existing rows migrate one-to-one into
`blob_recipients`. `expires_at` stays on the blob: one upload is one event and
gets one retention window, whoever it was addressed to.

**Request.** The recipient list is a *repeated* `recipient_device_id` query
parameter, not a new comma-separated one:

```
POST /v1/blobs?recipient_device_id=A&recipient_device_id=B&recipient_device_id=C
```

A one-recipient upload is then byte-identical to what clients send today, and
the signature already covers the raw query string, so the recipient set is
signed with no change to §3. Duplicates are collapsed before anything else, so
naming a device twice charges its quota once.

**Response.** Per-recipient outcomes, the same shape `POST /v1/messages/batch`
established — one member at their quota must not cost the others their copy:

```json
{
  "blob_id": "64 hex chars",
  "size": 3145728,
  "expires_at": "2026-09-02T10:00:00Z",
  "recipients": [
    {"recipient_device_id": "…", "status": "stored"},
    {"recipient_device_id": "…", "status": "quota_exceeded"},
    {"recipient_device_id": "…", "status": "unknown_recipient"}
  ]
}
```

`unknown_recipient` is spelled exactly as the batch endpoint spells it. The
status code splits by form, so the old contract survives untouched: **one**
recipient keeps answering `201` (and `404`/`429` on failure) exactly as today,
with the `recipients` array added as a field an older parser ignores;
**several** recipients answer `200`, because nothing was created at a single
location and "all three failed" is not a `201`.

**Quota is still checked before a byte is read.** Each recipient is checked
first; those that fail are dropped and recorded. If none survive, the answer
goes out without touching the disk at all — the existing single-recipient path
already answers before `Blobs.Put` reads the body, so this is that behaviour
generalized rather than a new one. `maxThisBlob` becomes the *minimum*
headroom across the surviving recipients, so no one of them can be pushed over
their cap by an upload that fits the others.

**Deletion and the refcount.** A recipient's `DELETE` removes only their own
row. When the last row for a blob goes, the blob row and the file go with it,
in the same transaction — disk is freed as soon as the last reader is done,
which is the point of the per-recipient `DELETE` in the first place. The
device-removal cascade cannot do that (SQLite will drop the recipient rows
without noticing the blob is now unreferenced), so the existing expiry sweep
also collects **unreferenced blobs**. Prompt on the ordinary path, swept on the
cascade path — the same "explicit first, sweep as backstop" split the orphan
file sweep already uses.

**Capability.** `GET /v1/server-status` gains `max_blob_recipients`, and its
absence means **1**, not "unlimited" — a server that omits it predates this
document and would silently store the blob for the *first* recipient only
while answering `201`, which is exactly the silent failure our compatibility
rules forbid. A sender that reads `1` falls back to one upload per member on
that server: slower, correct, and visible in no way to the user. Discovered
per server, like `batch_messages`, because a federated group's members sit on
servers that will not upgrade together.

The value is bounded by `FREIZONE_MAX_BLOB_RECIPIENTS`, default **100** to
match `FREIZONE_MAX_BATCH_MESSAGES`: the recipients of one upload are the
members whose message copies that same fan-out will then batch to that same
server, so a different bound on the two would only ever be confusing.

## Heterogeneous servers

`blobs_enabled` and `max_blob_bytes` are the *recipient* server's, and in a
federated group they differ per member. **Encode once at the normal target
size, and re-encode only for a server whose limit is smaller.** The
alternative — one rendition at the smallest limit any member's server accepts
— lets a single member on a frugal server decide the picture quality for
everyone, which is the wrong party to hand that decision to. The cost is CPU
on the sender for the servers that need it, and it is paid only when they
exist.

Nothing else about this is new work: the attachment key is per attachment, not
per recipient (§10), and a re-encoded rendition is a different ciphertext
under that same key on a different server, referenced by a different
`blob_id` — and the reference is already built per recipient.

## Members whose server has blobs turned off

Never a silent failure and never a blocked send. The message goes out to
everyone as text, the attachment is marked undeliverable for the members whose
server reports `blobs_enabled: false` (or that answers the upload with a
`404`), and the sender is told plainly — "3 members cannot receive pictures" —
before or at send time. This is the same shape as partial delivery, which
[design/01-groups.md](01-groups.md) already establishes as the *normal* case in
a group rather than an error, so it needs no new concept in the outbox: those
recipients simply have a copy whose attachment never resolved.

## The metadata this costs

A multi-recipient upload tells the server "these N devices are getting the
same object" — a group-membership hint in plaintext, next to ciphertext it
cannot read. Named here rather than waved past, and accepted for one reason:
`POST /v1/messages/batch` already carries exactly that recipient set in a
single request, and the fan-out that follows this upload *is* such a batch.
The incremental disclosure over what the same send already reveals is nil.
What the server still never learns is what the attachment is, who sent it (no
sender column, deliberately — SRV-07), or which group it belongs to; the group
remains a client-side object the server has no representation of.

## Out of scope

- **Resumable uploads (SRV-11).** One upload per server instead of per member
  makes a failed upload proportionally more expensive — it now costs a whole
  server's copy. That argues for SRV-11, it does not block this.
- **A retry after the blob expired.** An outbox copy retried past the
  retention window references a blob that is gone. The window is long
  (`FREIZONE_BLOB_RETENTION_DAYS`, at least the message retention window) and
  the case is not new — it exists in one-to-one today. Recorded, not fixed.
- **Multi-device (SRV-02).** It needs nothing here: a member's several devices
  are simply more rows in `blob_recipients`, which is the shape this table has
  from the start.

## What shipped, and what the build changed

**Core shipped 2026-08-03**, as designed above, with three corrections the
implementation forced.

**The stream bound is the *largest* headroom, not the smallest.** The plan said
`maxThisBlob` should shrink to the smallest quota headroom among the accepted
recipients, "so no one of them can be pushed over their cap". That is exactly
backwards for a group: bounding the stream at the fullest member's remaining
bytes means a 3 MB photo dies with a `413` for *everyone* because one member
never emptied their storage — the precise failure this document says must not
happen. The bound is the largest headroom instead, and recipients the stored
size then does not fit are dropped afterwards with `quota_exceeded`, which is
a per-recipient failure like any other. Caught by writing the test for it, not
by reading the code.

**"Nothing fits anyone" cannot happen after the write.** With the bound above,
whoever had the largest headroom always fits whatever was written, so the
post-write check can never drop *all* recipients. A size that fits nobody is
refused as a `413` mid-stream instead — cheaper, since the body is never
written. The all-failed branch after the write was removed rather than left in
as an unreachable guard; `store.CreateBlob` rejecting an empty recipient list
is the remaining backstop.

**The migration's statement order is load-bearing.** `blob_recipients` carries
`ON DELETE CASCADE` from `blobs`, and SQLite's `DROP TABLE` performs an
implicit `DELETE` with foreign keys on. Creating the new table and filling it
*before* retiring the old one therefore has the drop cascade the migrated rows
straight back out — leaving every existing attachment unreachable, and
silently, since an empty `blob_recipients` is indistinguishable from a server
that never had one. The old table is renamed aside first and dropped only once
the recipient rows point at the new one. There is a test for the upgrade path
with populated tables, not only for a fresh install, because the fresh install
is the half that could not have caught this.

Also worth recording: `store.BlobUsage` and the admin activity aggregate
(SRV-09) both reach blobs through `blob_recipients` now, so a shared blob
counts once per recipient device. That keeps the number the admin list shows
identical to the number the quota is enforced on, which is the only reason to
show it.

### Verified end to end

Against both local Docker instances, federated, with `devclient blob` (which
grew a repeatable `-to` and a `-to-server` for the federated route):

- Three members on one server, one upload: **one** file of 300 000 bytes on
  disk, one `blobs` row, three `blob_recipients` rows, and all three fetch
  byte-identical content. A device that was not named gets `404`.
- The same from a *sender on the other server* over
  `POST /v1/federation/blobs` — the actual group case, since a federated
  group's members sit on servers the sender has no account on.
- One member deletes: the other two still fetch, the file stays. The last
  member deletes: rows and file both gone.
- One real and one non-existent recipient in the same upload: `stored` and
  `unknown_recipient` side by side, the real one served.
- A single non-existent recipient still answers `404 not_found`, not a `200`
  with an outcome an older client would never read.

## Client side (freizone-app, APP-16)

Both halves shipped 2026-08-04 — rendering through the same `ImageAttachment`
the one-to-one bubble uses, and a fan-out that resolves its recipients before
encrypting so it can upload once per distinct recipient server. Full reasoning
in that repo's `docs/design/16-groups.md`; two points belong here, because they
are about this document's decisions rather than the app's structure.

**The reference is keyed per member, not per server.** Sharing one blob id
across a server's members is the point of this document, and it is what happens
whenever `max_blob_recipients` is above 1 — but a server that states **1**,
which is also what silence means, stores a blob per device, so its members need
an upload and an id each. Keying the fan-out's result by member account id
covers both without a special case. Worth noting here because this document's
own summary above ("the reference is built per recipient") is the shape that
turned out to matter, not the per-server shortcut it might suggest.

**The re-encode rule was not built.** "Encode once at the normal target size,
re-encode only for a server with a smaller `max_blob_bytes`" needs a JPEG
encoder at send time: `dart:ui` can only encode PNG, which is *larger* for a
photo, and `image_picker` does its downscale natively at pick time, before the
group's servers are known. That means a new Dart dependency the app
deliberately avoids. Members on such a server are therefore treated exactly
like members whose server has blobs switched off — caption plus the stated note.
What was **not** done is shrink the picture for everybody, which is the one
option this document ruled out, so the decision stands even though half its
implementation does not exist yet. It needs an operator running
`FREIZONE_MAX_BLOB_BYTES` below roughly a megabyte (default 8 MiB) to be
reachable at all.
