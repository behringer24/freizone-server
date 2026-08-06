# Using `devclient` for Debugging & Diagnosis

[`cmd/devclient`](../cmd/devclient) is described in the [README](../README.md#trying-it-out-a-local-encrypted-chat)
as a way to try out encrypted chat locally. It's also the fastest way to
answer "is this the server or the app?" when something's misbehaving,
because it speaks the exact wire protocol
([docs/PROTOCOL.md](PROTOCOL.md)) with nothing else in the way — no UI, no
platform push, no local notification permissions, just the HTTP calls.

**Scope note:** this is a debugging tool, not an admin client. It implements
`bootstrap`/`register`/`upload-prekeys`/`chat`/`blob`/`group`/`loadtest` and
nothing under `/v1/admin/...` — no invites, no promoting a second admin, no
registration-policy or federation toggles. For actually administering a
server, use the [app](https://github.com/behringer24/freizone-app)'s admin
area; see [docs/INSTALL.md](INSTALL.md#5-claim-the-admin-account) for why
the app is the primary path even for the very first admin account.

```bash
go build -o devclient ./cmd/devclient
```

## The one flag that matters most: `-verbose`

Every subcommand accepts `-verbose`. It logs every request `devclient` makes
and every response it gets back — status code, body, the works. When
something behaves unexpectedly, reach for this before anything else: it
usually tells you immediately whether the server rejected the request (and
why) or `devclient` never sent what you expected.

```bash
./devclient chat -datadir ./alice -to BOBS_ACCOUNT_ID -verbose
```

## Safety first

`devclient` speaks the *real* protocol — pointed at a real server, it does
real things: claims real invite codes, sends real messages that count
against real queue caps, uploads real blobs that count against real quotas.

- Point `-server` at a local/dev instance unless you're deliberately
  diagnosing a specific production server.
- If you do need to test against production, use a **throwaway test
  account** (`register`, not `bootstrap`), never the real admin identity or
  an existing moderator's account.
- **Never run `loadtest` against a production server.** It's built to flood
  a server with messages to measure ingest throughput — exactly what you
  don't want happening to real users' queues. It's explicitly for
  local/dev servers only (see the comment at the top of
  [`cmd/devclient/loadtest.go`](../cmd/devclient/loadtest.go)).
- Each `-datadir` holds that identity's private keys in `state.json`. Treat
  it like a credential — don't commit it, don't paste its contents when
  asking for help.

## Diagnostic playbook

### Is the server reachable and configured as expected at all?

Not a `devclient` job — just:

```bash
curl https://chat.example.org/healthz
curl https://chat.example.org/v1/server-status
```

`server-status` is unauthenticated and advertises the running config that
matters to a client: registration policy, blob limits, batch limits,
federation on/off. Check this *first* — most "it doesn't work" reports turn
out to be a client hitting a limit the server is correctly advertising.

### Does bootstrap/registration behave as configured?

```bash
./devclient bootstrap -server https://chat.example.org -datadir ./test -token TOKEN -verbose
./devclient register  -server https://chat.example.org -datadir ./test -invite CODE -verbose
```

`-verbose` shows the exact rejection reason — an expired/wrong token, a
`closed` registration policy, an already-redeemed invite — rather than a
generic failure. See [Registration policy](../README.md#registration-policy-who-can-create-an-account)
for what each failure mode should look like.

### Is E2E session establishment (X3DH/ratchet) actually broken?

Reproduce with two disposable identities against the server in question
rather than guessing from app logs — one side can run unattended:

```bash
./devclient register -server https://chat.example.org -datadir ./probe-a
./devclient register -server https://chat.example.org -datadir ./probe-b

./devclient chat -datadir ./probe-b -to PROBE_A_ACCOUNT_ID -auto-reply -verbose &
./devclient chat -datadir ./probe-a -to PROBE_B_ACCOUNT_ID -verbose
```

`-auto-reply` makes the peer answer every message automatically (random
short text), so one human typing is enough to drive both sides. `-verbose`
on both shows the prekey claim, the first ratchet message, and every receipt
— usually enough to tell whether a stuck conversation is a session that
never established, a receipt that never got sent (`-receipts both|delivered|off`
controls that), or delivery that's actually fine and the problem is
elsewhere (e.g. push not waking the app).

### Is this a federation problem specifically?

Add `-to-server` to force cross-server delivery instead of relying on the
peer's account id already resolving there:

```bash
./devclient chat -datadir ./probe-a -to REMOTE_ACCOUNT_ID -to-server https://other.example.org -verbose
```

This posts directly to `/v1/federation/messages` on the remote server
(PROTOCOL §9) — `-verbose` shows you exactly what that server did with it,
which isolates "my server can't reach theirs" from "their server rejected
it" from "it worked and the problem is on their receiving end."

`blob` and `group send` accept the same `-to-server` flag for the same
reason, if the suspected problem is attachment or group federation instead
of plain messages.

### Is an attachment upload/download failing?

```bash
./devclient blob -datadir ./probe-a -upload ./test.jpg -verbose
./devclient blob -datadir ./probe-a -download BLOB_ID -out ./downloaded.jpg -verbose
./devclient blob -datadir ./probe-a -delete BLOB_ID -verbose
```

A `413` means `FREIZONE_MAX_BLOB_BYTES`; a `429` means the per-device count
or byte quota (`FREIZONE_MAX_BLOBS_PER_DEVICE` / `FREIZONE_MAX_BLOB_BYTES_PER_DEVICE`).
`-to` (repeatable) targets specific recipient devices for a multi-recipient
upload (PROTOCOL §10, SRV-18) instead of the uploader's own device.

### Is a group stuck in a diverged state (`state_hash` mismatch)?

```bash
./devclient group watch -datadir ./probe-a -id GROUP_ID -once -verbose
```

Groups have no server-side object — membership and roles converge from
signed events each member fans out to the others (PROTOCOL / `docs/design/01-groups.md`).
`-once` drains whatever's queued and exits instead of polling forever;
`-verbose` shows the raw events and any snapshot exchanged to resolve a
mismatch. `role` actions accept `moderator|admin` for `-role`.

### Measuring throughput (dev/local servers only)

```bash
./devclient loadtest -datadir ./sender -to PEER_ACCOUNT_ID -count 5000 -concurrency 16 -drain-datadir ./receiver -verbose=false
```

Creates no new accounts or devices — only transient message rows against
two accounts that already exist. `-drain-datadir` runs a receiver in
parallel so the recipient's queue doesn't hit `FREIZONE_MAX_QUEUED_MESSAGES_PER_DEVICE`
mid-run. Leave `-verbose` off here; at load, it's the bottleneck, not the
server.

## Subcommand reference

| Command | Purpose |
|---|---|
| `bootstrap` | Claim the first (admin) account with the one-time setup token. |
| `register` | Create an account normally (subject to the server's registration policy). |
| `upload-prekeys` | Top up this device's one-time X3DH prekeys (also runs automatically from `chat` when needed). |
| `chat` | Interactive encrypted 1:1 session with a peer, or `-auto-reply` for unattended use. |
| `blob` | Upload/download/delete an encrypted attachment. |
| `group` | Found/invite/moderate/send/watch a group — see `devclient group` with no action for the full list. |
| `loadtest` | Flood two existing accounts with messages to measure ingest throughput. **Dev/local only.** |

Every command's own `-h` lists its full flag set; this table and the
scenarios above are the "which command for which symptom" map, not a
replacement for that.
