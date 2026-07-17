# Freizone Server

A self-hostable, federated, end-to-end encrypted chat server (Go + SQLite) — modeled on email: you run your own small server under your own domain, and servers deliver messages to each other directly. No central provider, no server ever sees plaintext.

**Status:** the foundation is implemented — identity, per-request signature authentication, account/device management, bootstrap, and invites. Message encryption (X3DH/Double Ratchet), federation, groups, and push notifications are future work. The full wire protocol is documented in [docs/PROTOCOL.md](docs/PROTOCOL.md).

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

    272235184eaa3b28b6d6751cc6871c261b8dcd7dd402f626d47ee8331c8424f4

    Use it to claim the first admin account via POST /v1/bootstrap/claim.
   ================================================================
   ```

   **Copy this token somewhere safe right now.** It is only ever shown this one time — the server stores only a cryptographic fingerprint of it, not the token itself, so it cannot be recovered or displayed again later. If you lose it before using it, see [Lost your setup token?](#lost-your-setup-token) below.

5. Confirm the server is healthy:

   ```sh
   curl https://chat.example.org/healthz
   ```

   A working server replies `{"status":"ok"}`. If this fails, see [Troubleshooting](#troubleshooting) below.

### Claiming the admin account

The setup token proves *you* are allowed to create the first (admin) account — but actually creating one requires generating a cryptographic key pair and signing a certificate with it, which is the companion app's job, not something you type into a terminal. **Until the Freizone mobile/desktop app is available, this last step needs a small companion tool**; the exact request shape it needs to send is documented in [docs/PROTOCOL.md](docs/PROTOCOL.md) under `POST /v1/bootstrap/claim`, for anyone who wants to script it in the meantime.

Once your account is claimed, you (the admin) can issue invite codes for other people via `POST /v1/admin/invites` — the app will be able to turn a code into a scannable QR code. This is how new users join a server whose registration policy is `closed` or `invite`.

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

## Registration policy: who can create an account

Set via `FREIZONE_REGISTRATION_POLICY`, this controls how people other than the bootstrapped admin can join your server:

- **`closed`** (the default, and the safest choice): nobody can self-register. The admin creates every account by hand (via the same bootstrap-style flow, without a token). Good for a private, invite-only community of a handful of people you personally onboard.
- **`invite`**: people can register themselves, but only with a single-use invite code issued by the admin (`POST /v1/admin/invites`). Good middle ground — you control who joins, but don't have to do the technical work yourself for each person.
- **`open`**: anyone who can reach your server can create an account. Only use this if you deliberately want a public server.

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

There is also one command-line flag: `--reset-setup-token` (see below).

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
