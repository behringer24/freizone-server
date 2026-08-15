# Install & Setup (Docker Compose)

This is the fast path to a running server: a `docker-compose.yml` using the
published image, no Go toolchain, no build step. If you'd rather build from
source or use plain `docker run`, see the [README](../README.md#recommended-setup-docker-with-automatic-tls)
instead — the environment variables are identical either way; the
[full reference](../README.md#configuration-reference) lives there and isn't
repeated here.

## Prerequisites

- A domain (e.g. `chat.example.org`) with a DNS **A** record (and **AAAA** if
  you have IPv6) pointing at this machine.
- Ports **80** and **443** reachable from the internet (Let's Encrypt uses 80
  for domain validation; the API itself is served on 443).
- Docker with the Compose plugin (`docker compose version`).

## 1. Pick an image tag

Published images live at
[ghcr.io/behringer24/freizone-server](https://github.com/behringer24/freizone-server/pkgs/container/freizone-server).
Pin an explicit version — **don't** use `:latest` in anything you plan to
leave running unattended. Check [docs/CHANGELOG.md](CHANGELOG.md) before
bumping the tag on an existing install; upgrades are just a new tag, but you
should know what changed first.

```
ghcr.io/behringer24/freizone-server:v0.13.1
```

## 2. Create the compose file and `.env`

`docker-compose.yml`:

```yaml
services:
  freizone-server:
    image: ghcr.io/behringer24/freizone-server:v0.13.1
    container_name: freizone-server
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - freizone-data:/data
    env_file: .env

volumes:
  freizone-data:
```

`.env` (next to the compose file — keep it out of git, it's config, not secret,
but there's no reason to publish it either):

```
FREIZONE_DOMAIN=chat.example.org
FREIZONE_TLS_MODE=autocert
FREIZONE_REGISTRATION_POLICY=closed
```

`closed` is the safe default: only the admin account you're about to bootstrap
can create accounts, via invite codes it issues afterwards. See
[Registration policy](../README.md#registration-policy-who-can-create-an-account)
in the README for `invite`/`open`.

Everything else — retention windows, blob limits, log level — has a working
default; add variables to `.env` only when you need to change one. The
complete list is in the README's
[configuration reference](../README.md#configuration-reference). The push
gateway URL gets its own section below, since it's worth understanding
before you set it rather than just copying a default.

## 3. Start it

```bash
docker compose up -d
docker compose logs freizone-server
```

The first-boot log contains a one-time setup token — copy it now, it is never
shown again (only its fingerprint is stored):

```
================================================================
 Freizone setup token (save this now -- it will not be shown again):

 QWDX-7K2M

 Use it to claim the first admin account via POST /v1/bootstrap/claim.
 (Dashes are cosmetic -- enter it with or without them.)
================================================================
```

Lost it before claiming? `docker compose run --rm freizone-server --reset-setup-token`
prints a fresh one — see [Lost your setup token?](../README.md#lost-your-setup-token)
in the README.

## 4. Confirm it's healthy

```bash
curl https://chat.example.org/healthz
```

Expect `{"status":"ok"}`. If it fails, see
[Troubleshooting](../README.md#troubleshooting) in the README — most first-run
failures are DNS not having propagated yet, or port 80/443 not actually being
forwarded to this machine.

## 5. Claim the admin account

**With the [Freizone Android app](https://github.com/behringer24/freizone-app)
— this is the normal, recommended path.** Its setup wizard takes the server
address and the setup token directly, generates the admin's keys on the
phone, and claims the account. It's also the *only* path to actually
**administer** the server afterwards: issuing invites, promoting other
accounts to admin/moderator, changing the registration policy, blocking a
sender — all of that lives in the app's admin area (`POST /v1/admin/...`,
see [docs/PROTOCOL.md](PROTOCOL.md)).

**Without the app** (standing a server up headlessly, or just trying it out
per the README's [local trial run](../README.md#local-trial-run-no-domain-needed)):
the bundled reference client, `cmd/devclient`, can claim the account instead —
but it's a protocol-level dev/test tool, not an admin client. It implements
only `bootstrap`/`register`/`chat`/`blob`/`group`/`loadtest` — nothing under
`/v1/admin/...` — so it can get you *an* admin account, and nothing further:
no inviting other people, no promoting a second admin, no policy changes. For
anything past the initial claim, you still need the app.

```bash
git clone https://github.com/behringer24/freizone-server.git
cd freizone-server
go build -o devclient ./cmd/devclient
./devclient bootstrap -server https://chat.example.org -datadir ./admin-identity -token YOUR_SETUP_TOKEN
```

See [docs/DEVCLIENT.md](DEVCLIENT.md) for what else `devclient` is good for —
it's primarily a debugging tool, useful well beyond first setup, but it
doesn't grow into an admin CLI no matter what you ask it to do.

## Push wake for devices without UnifiedPush

A device that has a UnifiedPush distributor installed (e.g. via `ntfy`) needs
none of this — it registers its own endpoint (`PUT /v1/devices/{device_id}/push-endpoint`)
and push-wake works fully decentralized, no gateway, no third party, nothing
to configure here at all.

A device *without* a distributor instead registers an FCM/APNs push target
(`PUT /v1/devices/{device_id}/push-target`), which needs a
[freizone-gateway](https://github.com/behringer24/freizone-gateway) instance
to relay the actual wake — set via `FREIZONE_PUSH_GATEWAY_URL`. This is
**not** something worth standing up yourself in the common case: an FCM
push token is scoped to the Firebase project baked into the app binary that
requested it, so a gateway running under your own Firebase project can only
ever wake a build of the app you compiled against that same project —
useless against the stock, officially distributed app. Running your own
only makes sense if you're also shipping your own app build; see
freizone-gateway's own README if that's actually your situation.

For everyone else, point at a shared instance instead:

```
FREIZONE_PUSH_GATEWAY_URL=https://fz-gateway.behringer24.de
```

No registration step needed on either side — this server mints its own
signing identity on first boot and starts calling the gateway the moment the
variable is set. Treat the choice of *which* gateway to trust the same way
you'd treat picking any other server your users' data passes through:
you're trusting that operator to relay honestly and keep the thing running,
same category of decision as federating with a server you don't run
yourself.

## Upgrading

```bash
# edit the image tag in docker-compose.yml, then:
docker compose pull
docker compose up -d
```

The container is stateless itself — everything that matters lives in the
`freizone-data` volume (SQLite database, blob files, TLS certificate cache) —
so an upgrade is just swapping the tag. Read the entry for the new version in
[docs/CHANGELOG.md](CHANGELOG.md) first; a version that changes on-disk format
says so there.

## Backup

Back up the whole `freizone-data` volume, not individual files inside it —
it holds the SQLite database (`freizone.db`) and, once anyone has sent an
attachment, the blob directory alongside it. Losing it means losing every
account.

```bash
docker run --rm -v freizone-data:/data -v "$(pwd)":/backup alpine \
  tar czf /backup/freizone-backup-$(date +%Y%m%d).tar.gz -C /data .
```

Stop the server first if you want a guaranteed-consistent snapshot (SQLite's
WAL mode means a live copy is *usually* fine, but "usually" isn't "always").
For always-consistent, low-lag backups without stopping anything, see
[docs/HIGH-AVAILABILITY.md](HIGH-AVAILABILITY.md) — the same replication
mechanism doubles as a proper backup strategy even if you never build a
standby.

## A note on the distroless image

The published image is built on `distroless/static` — no shell, no package
manager, no `curl`/`wget` inside it. That's deliberate (smaller attack
surface, nothing to exploit even if someone found a way in), but it means:

- `docker compose exec freizone-server sh` **will not work** — there is no
  `sh` to exec into.
- A Docker-native `HEALTHCHECK` (`CMD curl ...`) can't run inside the
  container either, for the same reason. Monitor `/healthz` from *outside*
  the container instead (your reverse proxy, an uptime checker, a cron job)
  — see [Further ideas](#further-ideas-to-shrink-the-setup-hurdle) below for
  where this could eventually move into the binary itself.
- To inspect the database directly, stop the container and open
  `freizone.db` from the volume with any SQLite tool — don't reach for a
  shell inside the container, there isn't one.

## Behind an nginx reverse proxy (with its own Let's Encrypt certificate)

If this machine already serves other domains on 80/443, you can't hand those
ports to `FREIZONE_TLS_MODE=autocert` — something else (nginx) has to own
them and terminate TLS itself. **If you don't already have that constraint,
skip this section** — the built-in `autocert` path above is simpler and has
one less moving part (no certbot, no renewal wiring, no reload trick).

Two things are easy to get wrong here, specifically for freizone-server:

1. **Leave `FREIZONE_DOMAIN` unset.** It's only consulted in `autocert` mode.
   Setting it anyway when nginx is terminating TLS makes the server compare
   its own [attestation](design/19-attested-servers.md), if any, against a
   domain it can't actually confirm from behind a proxy, which produces a
   spurious warning for no benefit. This project's own production
   deployments run exactly this shape (nginx/reverse proxy in front, no
   `FREIZONE_DOMAIN` set) — see the `SRV-19` log in
   [docs/ROADMAP.md](ROADMAP.md) for the false-positive that taught us this.
2. **Don't let nginx buffer the response.** Clients hold a long-lived
   Server-Sent Events connection open to receive messages live (the same
   stream the [local chat demo](../README.md#trying-it-out-a-local-encrypted-chat)
   uses) — nginx buffers proxied responses by default, which turns "live"
   into "arrives in delayed bursts, if at all." `proxy_buffering off` and a
   generous `proxy_read_timeout` are not optional for this specific proxy
   target.

### `docker-compose.yml`

```yaml
services:
  freizone-server:
    image: ghcr.io/behringer24/freizone-server:v0.13.1
    container_name: freizone-server
    restart: unless-stopped
    expose:
      - "80"
    volumes:
      - freizone-data:/data
    environment:
      FREIZONE_TLS_MODE: off
      FREIZONE_HTTP_ADDR: :80
      FREIZONE_REGISTRATION_POLICY: closed
    # no `ports:` -- only nginx is reachable from outside

  nginx:
    image: nginx:1.27-alpine
    container_name: nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - certbot-www:/var/www/certbot:ro
      - certbot-etc:/etc/letsencrypt:ro
    # periodic self-reload so a cert renewed by certbot (which runs in a
    # separate container with no way to signal this one) actually gets
    # picked up, without giving either container access to the Docker
    # socket. Well within Let's Encrypt's 90-day cert lifetime.
    command: /bin/sh -c "while :; do sleep 6h & wait $${!}; nginx -s reload; done & nginx -g 'daemon off;'"
    depends_on:
      - freizone-server

  certbot:
    image: certbot/certbot:latest
    container_name: certbot
    restart: unless-stopped
    volumes:
      - certbot-www:/var/www/certbot
      - certbot-etc:/etc/letsencrypt
    entrypoint: >
      sh -c 'trap exit TERM; while :; do certbot renew --webroot -w /var/www/certbot --quiet; sleep 12h & wait $${!}; done;'

volumes:
  freizone-data:
  certbot-www:
  certbot-etc:
```

### Getting the first certificate (chicken-and-egg)

nginx can't start an HTTPS server block for a certificate that doesn't exist
yet, so the first issuance is a two-step dance.

**Step 1 — HTTP only**, just enough to answer the ACME challenge.
`nginx/conf.d/freizone.conf`:

```nginx
server {
    listen 80;
    server_name chat.example.org;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 404;
    }
}
```

```bash
docker compose up -d freizone-server nginx
docker compose run --rm certbot certonly \
  --webroot -w /var/www/certbot \
  -d chat.example.org \
  --email you@example.org --agree-tos --no-eff-email
```

**Step 2 — replace the config** with the real HTTPS vhost, then reload:

```nginx
server {
    listen 80;
    server_name chat.example.org;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name chat.example.org;

    ssl_certificate     /etc/letsencrypt/live/chat.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.org/privkey.pem;

    location / {
        proxy_pass http://freizone-server:80;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # required for the SSE message stream -- see the note above
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1d;
    }
}
```

```bash
docker compose restart nginx
docker compose up -d certbot
curl https://chat.example.org/healthz
```

From here it's the same as the plain setup: find the setup token in
`docker compose logs freizone-server` and continue at
[step 3](#3-start-it) above.

## Traefik or Caddy instead

Same idea — that proxy terminates TLS and forwards plain HTTP to
`freizone-server:80` on the shared Docker network — but both handle
certificate issuance and renewal for you natively, without a separate
certbot container or the reload trick above. Whichever you use, the same two
points still apply: don't set `FREIZONE_DOMAIN`, and make sure the proxy
isn't buffering the response (Traefik's default is fine here; Caddy's
default is fine too — it's specifically nginx's default buffering that needs
turning off).

## Further ideas to shrink the setup hurdle

Not implemented yet — tracked here as candidates, not promises:

- **A pure-Go self-check flag** (e.g. `freizone-server --healthcheck`) that
  does a local HTTP GET to its own `/healthz` and exits `0`/`1` accordingly.
  Costs nothing at runtime, needs no shell or `curl`, and would let a
  `HEALTHCHECK` line work again despite the distroless base image — usable
  by `docker compose`'s `service_healthy` condition and by orchestrators
  that expect an exec-based check.
- **A `docker-compose.yml` shipped in the repo** (e.g. under
  `deploy/docker-compose.yml`) rather than only ever pasted into docs, so
  the quickest path is `curl`-ing one file down instead of copy-pasting a
  code block. Keeps this file itself as the explanation, the shipped file
  as the artifact.
- **A single bootstrap script** wrapping steps 1–5 above (write `.env` from
  prompted answers, `docker compose up -d`, poll `/healthz`, print the
  setup token) — optional, since it's one more thing to trust and audit,
  but would turn "read a page, run five commands" into "run one script".
- **A prebuilt `devclient` binary per release**, alongside the server image,
  so claiming the admin account doesn't require a Go toolchain on a machine
  that otherwise only needed Docker. Right now `devclient` is source-only.
