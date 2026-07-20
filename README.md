# Freizone Server

A self-hostable, federated, end-to-end encrypted chat server (Go + SQLite) — modeled on email: you run your own small server under your own domain. Federation means a message to someone on a different server is still delivered directly — client to that recipient's server, not relayed through yours (see [docs/PROTOCOL.md §9](docs/PROTOCOL.md)) — no central provider, no server ever sees plaintext.

**Status:** identity, per-request signature authentication, account/device management, bootstrap, invites, and full X3DH + Double Ratchet end-to-end encrypted 1:1 messaging are implemented, including federation (see [docs/PROTOCOL.md §9](docs/PROTOCOL.md)). Server-side push-wake support is implemented for both UnifiedPush (Android, via `PUT /v1/devices/{device_id}/push-endpoint`) and a central FCM/APNs relay for devices without a UnifiedPush distributor (via `PUT /v1/devices/{device_id}/push-target` and a [freizone-gateway](https://github.com/behringer24/freizone-gateway) instance — see [docs/PROTOCOL.md §7](docs/PROTOCOL.md)); only groups/broadcast remain future work. The full wire protocol is documented in [docs/PROTOCOL.md](docs/PROTOCOL.md). A minimal reference client, [`cmd/devclient`](cmd/devclient), lets you try real encrypted chat locally — see [below](#trying-it-out-a-local-encrypted-chat).

This guide assumes no prior experience running a server. If you just want the quick reference, jump to [Configuration reference](#configuration-reference).

## What you need before you start

- A machine (VPS, home server, Raspberry Pi, ...) that can stay online and is reachable from the internet.
- A domain name (e.g. `chat.example.org`) with a DNS **A record** (and **AAAA record** if you have an IPv6 address) pointing at that machine's public IP address. A plain domain is enough — no special DNS entries (no SRV, no TXT records) are required.
- Ports **80** and **443** open and reachable from the internet (used for automatic TLS certificate issuance and for the API itself). If you're behind a home router, this means forwarding those two ports to the machine.
- Either **Docker**, or a **Go 1.26+** toolchain if you'd rather build from source.

If you're just trying this out locally and don't have a domain yet, skip straight to the [local trial run](#local-trial-run-no-domain-needed) below.

## Recommended setup: Docker with automatic TLS

This is the easiest way to run a real, internet-facing server. It uses [Let's Encrypt](https://letsencrypt.org/) to get and renew a TLS certificate automatically — you don't need to obtain or install a certificate yourself.

1. Build the image (or use a published one, once available):

   ```sh
   git clone https://github.com/behringer24/freizone-server.git
   cd freizone-server
   docker build -t freizone-server .
   ```

2. Create a persistent volume for the server's data (its database and TLS certificates live here — losing this means losing all accounts):

   ```sh
   docker volume create freizone-data
   ```

3. Start the server, replacing `chat.example.org` with your own domain:

   ```sh
   docker run -d \
     --name freizone-server \
     --restart unless-stopped \
     -p 80:80 -p 443:443 \
     -v freizone-data:/data \
     -e FREIZONE_DOMAIN=chat.example.org \
     -e FREIZONE_TLS_MODE=autocert \
     -e FREIZONE_REGISTRATION_POLICY=closed \
     freizone-server
   ```

   - `-d` runs it in the background; `--restart unless-stopped` brings it back up after a reboot or crash.
   - `FREIZONE_REGISTRATION_POLICY=closed` is the safe default: nobody can create an account except the admin you're about to bootstrap, who can then issue invite codes (see below).

4. Check that it's running and find your one-time setup token:

   ```sh
   docker logs freizone-server
   ```

   On the very first start, the server prints a block that looks like this:

   ```
   ================================================================
    Freizone setup token (save this now -- it will not be shown again):

    QWDX-7K2M

    Use it to claim the first admin account via POST /v1/bootstrap/claim.
    (Dashes are cosmetic -- enter it with or without them.)
   ================================================================
   ```

   **Copy this token somewhere safe right now.** It is only ever shown this one time — the server stores only a cryptographic fingerprint of it, not the token itself, so it cannot be recovered or displayed again later. If you lose it before using it, see [Lost your setup token?](#lost-your-setup-token) below.

   The token is short by design (8 characters, easy to type into a phone) — its safety against online guessing comes from a lockout (10 failed attempts permanently reject it) rather than raw length, since this endpoint deliberately has no other rate limiting.

5. Confirm the server is healthy:

   ```sh
   curl https://chat.example.org/healthz
   ```

   A working server replies `{"status":"ok"}`. If this fails, see [Troubleshooting](#troubleshooting) below.

### Claiming the admin account

The setup token proves *you* are allowed to create the first (admin) account — but actually creating one requires generating a cryptographic key pair and signing a certificate with it, which is a client's job, not something you type into a terminal by hand. **Until the Freizone mobile/desktop app exists**, use the bundled reference client to do this:

```sh
go build -o devclient ./cmd/devclient
./devclient bootstrap -server https://chat.example.org -datadir ./admin-identity -token YOUR_SETUP_TOKEN
```

This generates the admin's keys locally (under `-datadir`, on this machine only — nothing sensitive is ever sent to the server) and claims the account. See [Trying it out](#trying-it-out-a-local-encrypted-chat) below for the full rundown of what `devclient` can do, including actually exchanging encrypted messages.

Once your account is claimed, you (the admin) can issue invite codes for other people via `POST /v1/admin/invites` — the app will be able to turn a code into a scannable QR code. Invite codes only work while the registration policy is `invite`, though — switch to that policy first (see [below](#registration-policy-who-can-create-an-account)); `closed` blocks registration outright, invite code or not.

## Local trial run (no domain needed)

To just kick the tires on your own machine, without a domain or public IP, run without TLS:

```sh
go build -o freizone-server ./cmd/server

FREIZONE_TLS_MODE=off \
FREIZONE_HTTP_ADDR=127.0.0.1:8080 \
FREIZONE_DATA_DIR=./data \
FREIZONE_REGISTRATION_POLICY=closed \
./freizone-server
```

Then check `curl http://127.0.0.1:8080/healthz`. Do **not** use `FREIZONE_TLS_MODE=off` for anything reachable from the internet — it serves plain, unencrypted HTTP.

## Trying it out: a local encrypted chat

With the server above running locally, `cmd/devclient` lets you simulate two people chatting — with real X3DH + Double Ratchet end-to-end encryption, not a mock. Open two more terminals (one per "person"):

```sh
go build -o devclient ./cmd/devclient
```

**Terminal 1 (server):** already running from the [local trial run](#local-trial-run-no-domain-needed) above, with `FREIZONE_REGISTRATION_POLICY=open` so the second step below doesn't need an invite code.

**Terminal 2 ("Alice" — the admin):**
```sh
./devclient bootstrap -server http://127.0.0.1:8080 -datadir ./alice -token PASTE_THE_TOKEN_FROM_THE_SERVER_LOG
```
Note the account id it prints (a 21-character string).

**Terminal 3 ("Bob"):**
```sh
./devclient register -server http://127.0.0.1:8080 -datadir ./bob
```
Note Bob's account id too.

**Back in terminal 2, start chatting with Bob:**
```sh
./devclient chat -datadir ./alice -to BOBS_ACCOUNT_ID
```
**In terminal 3, chat back with Alice:**
```sh
./devclient chat -datadir ./bob -to ALICES_ACCOUNT_ID
```

Type a line and press enter in either terminal — it's encrypted on your machine, sent to the server as ciphertext the server can't read, and decrypted live in the other terminal over a Server-Sent Events stream. Each identity's keys and conversation state live under its own `-datadir` (`./alice`, `./bob`), so you can stop and restart either side without losing the session.

`devclient` also has an `upload-prekeys` subcommand (run automatically the first time `chat` needs it) and doubles as the reference implementation for anyone building a real client — see [docs/PROTOCOL.md](docs/PROTOCOL.md) for the exact wire format it speaks.

## Registration policy: who can create an account

Set via `FREIZONE_REGISTRATION_POLICY`, this controls how people other than the bootstrapped admin can join your server:

- **`closed`** (the default, and the safest choice): registration is fully blocked — nobody can self-register, and an existing invite code won't work either (the check for one is never reached). There is no "admin creates an account for someone else" flow — every account is always created by that person's own device generating its own keys, whether via self-registration (gated by this policy) or the one-off bootstrap flow. Use `closed` before you've decided on an ongoing policy, or to lock a server back down once everyone who should have an account already does.
- **`invite`**: people can register themselves, but only with a single-use invite code issued by the admin (`POST /v1/admin/invites`). Good middle ground — you control who joins, but don't have to do the technical work yourself for each person.
- **`open`**: anyone who can reach your server can create an account. Only use this if you deliberately want a public server.

`FREIZONE_REGISTRATION_POLICY` only **seeds** this on first boot (when the database has no policy stored yet). After that, the live policy — settable at runtime by an admin via `GET`/`PUT /v1/admin/registration-policy` (e.g. from the app's admin area) — is what's actually in effect and survives restarts; changing the env var later has no effect until the database is reset.

## Configuration reference

All configuration is via environment variables (there is no config file):

| Variable | Default | Description |
|---|---|---|
| `FREIZONE_DOMAIN` | – | Your domain name. **Required** when `FREIZONE_TLS_MODE=autocert`. |
| `FREIZONE_HTTP_ADDR` | `:80` | Bind address for plain HTTP — used for the ACME challenge and HTTPS redirect in `autocert` mode, or as the only listener in `off` mode. |
| `FREIZONE_HTTPS_ADDR` | `:443` | Bind address for TLS (`manual`/`autocert` modes). |
| `FREIZONE_TLS_MODE` | `off` | `off` (plain HTTP, local testing only) · `manual` (you supply your own certificate) · `autocert` (automatic Let's Encrypt certificate — recommended for real deployments) |
| `FREIZONE_TLS_CERT_FILE` | – | Path to your TLS certificate file. **Required** when `FREIZONE_TLS_MODE=manual`. |
| `FREIZONE_TLS_KEY_FILE` | – | Path to your TLS private key file. **Required** when `FREIZONE_TLS_MODE=manual`. |
| `FREIZONE_DATA_DIR` | `./data` | Directory holding the SQLite database and the Let's Encrypt certificate cache. Back this up; losing it means losing every account. |
| `FREIZONE_DB_PATH` | `<DATA_DIR>/freizone.db` | Override the exact SQLite file path, if you need it somewhere other than inside `FREIZONE_DATA_DIR`. |
| `FREIZONE_REGISTRATION_POLICY` | `closed` | `open` · `invite` · `closed` — see [above](#registration-policy-who-can-create-an-account). |
| `FREIZONE_MESSAGE_RETENTION_DAYS` | `14` | How long an undelivered message stays queued before being permanently discarded. There is no server-side message history beyond this — by design. |
| `FREIZONE_PUSH_GATEWAY_URL` | – | Base URL of a [freizone-gateway](https://github.com/behringer24/freizone-gateway) instance for relaying push wakes to devices that registered an FCM/APNs push target (`PUT /v1/devices/{device_id}/push-target`) instead of a UnifiedPush subscription. Unset disables that path entirely — UnifiedPush keeps working regardless. This server mints its own signing identity automatically; there's no separate registration step with the gateway. |
| `FREIZONE_FEDERATION_ENABLED` | `true` | Set to `false` to reject every inbound cross-server message (`POST /v1/federation/messages` returns `404`) — see [docs/PROTOCOL.md §9](docs/PROTOCOL.md) for how federation works. Outgoing federation (your own users messaging accounts on other servers) is a client-side capability and isn't gated by this. |
| `FREIZONE_MAX_REQUEST_BODY_BYTES` | `524288` (512 KiB) | Caps every incoming request body. Generous for a real E2E chat message, but bounds the cost of any single request regardless of who's sending it. |
| `FREIZONE_MAX_QUEUED_MESSAGES_PER_DEVICE` | `1000` | Caps how many undelivered messages may be queued for one recipient device at once (`POST /v1/messages` and `POST /v1/federation/messages` both return `429` once a device is at this limit) — a backstop against an unresponsive or malicious sender flooding a device's queue, far above what any real device should accumulate within the retention window. |

There are also two command-line flags: `--reset-setup-token` and `--reset-admin` (an alias for the same operation, named for the "lost the admin device" recovery scenario — see below).

## Lost your setup token?

If the server restarted before you could claim the admin account, or you lost the token from the logs, you don't need to reinstall anything. Stop the server, restart it with the extra flag, and it will print a brand-new token:

```sh
docker run --rm -v freizone-data:/data freizone-server --reset-setup-token
```

(or, if running from source: `./freizone-server --reset-setup-token`). This discards the old, unclaimed token and generates a fresh one on that same startup — it has no effect if the token was already claimed.

## Troubleshooting

- **`curl` to `/healthz` fails or times out:** check `docker logs freizone-server` for errors. Common causes: the domain's DNS A/AAAA record doesn't point at this machine yet (DNS changes can take time to propagate), or ports 80/443 aren't actually reachable from the internet (check your firewall/router port forwarding).
- **TLS certificate isn't issued (autocert mode):** Let's Encrypt needs to reach your server on port 80 over plain HTTP to verify domain ownership. If that port is blocked or misrouted, certificate issuance silently fails. Check that `curl http://chat.example.org/` (port 80, not 443) actually reaches your machine from outside your own network.
- **Server won't start, complains about `FREIZONE_REGISTRATION_POLICY` or `FREIZONE_TLS_MODE`:** these must be one of the exact values listed in the [configuration reference](#configuration-reference) above (typos are rejected rather than silently ignored).
- **You need to inspect the database directly:** it's a plain SQLite file at `FREIZONE_DATA_DIR/freizone.db` (or `FREIZONE_DB_PATH`) — you can open it with any standard SQLite tool while the server is stopped.

## Development

```sh
go build ./...
go vet ./...
go test ./...
```
