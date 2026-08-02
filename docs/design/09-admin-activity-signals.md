# Design: Admin user-list activity signals

Status: **done** · Roadmap: [SRV-09](../ROADMAP.md)

The Server Admin Users list (`admin_screen.dart`) shows only role and blocked
status per account (`AdminAccountSummary`: id, role, status, created_at) —
nothing that distinguishes an active account from an abandoned one. Add, per
account: queued/pending message count and the age of its oldest pending
message (`store.ListPendingMessages` is per-*device* today; needs aggregating
across an account's devices), plus attachment/blob quota usage
(`store.BlobUsage`, also per-device, SRV-07) shown as e.g. "3.2/50 MB". The
goal is spotting unused accounts, not live monitoring, so this can ride the
same request that already lists accounts rather than need push updates.

**Shipped 2026-08-02.** `store.AccountActivityByAccount` (new
`internal/store/activity.go`) answers for the whole server in **two** aggregate
queries, not a pair per account — the list is unpaginated, so anything
per-account would have been an N+1 over however many accounts exist. It is
deliberately not built on `ListPendingMessages`: that one is per-device and
materializes every payload, the last thing a summary count should do. Messages
group straight by `recipient_account_id`; blobs need `devices LEFT JOIN blobs`,
with `COUNT(DISTINCT device_id)` so the fan-out doesn't multiply the device
count by each device's attachments.

The quota denominator was the one real decision. `MaxBlobBytesPerDevice` is
per *device*, but the list is per *account*, so `blob_bytes_limit` is the
per-device limit times the device count — the account's real ceiling, computed
server-side since the client has no business knowing the config. It moves as
devices come and go, which is accepted. Revoked devices count: a revoked device
keeps its blobs until its row is deleted, so excluding it could show usage
above its own limit.

`oldest_pending_at` is omitted for an empty queue (there is no such timestamp);
everything else is always present and zero, so a client can tell "nothing
queued" from an older server that doesn't report this at all — which
freizone-app detects via `device_count == 0`, the one field that cannot
legitimately be zero, since an account without a device could never have
registered. The app hides the whole line in that case, and hides each half when
it is empty: a row with no second line *is* the "abandoned" signal, and
printing "0 queued" on every row would bury the ones that mean something.

Moderators see the figures along with the rest of the list — the point is being
able to clean up a server without being an admin (SRV-08). They are aggregates
only: how much is waiting and how much is stored, never who an account talks to.
