# High Availability: Failover, Not Scale-Out

For almost every freizone-server operator, the realistic failure mode isn't
"too much traffic" — a single small VM handles far more message throughput
than any friend group or small community will produce. The realistic failure
mode is **the box dies**: disk failure, host provider outage, a bad `apt
upgrade`, a landlord unplugging the wrong power strip.

This document covers a failover setup for that case: a warm standby that can
take over with a small, bounded amount of data loss (typically low seconds,
worst case whatever your replication interval allows), rather than a
horizontally-scaled cluster — freizone-server's storage (SQLite) and protocol
model (per-device state, no shared mutable session) don't lend themselves to
that shape of scaling, and essentially nobody self-hosting this needs it.

## What this buys you, and what it doesn't

- **Not** synchronous, zero-downtime failover. There is a real (short) window
  during which writes on the primary haven't yet reached the standby.
- **Not** automatic without you wiring up the trigger — this document shows
  the pieces, not a turnkey product.
- **Is** dramatically less operational burden than a real multi-node
  database cluster, appropriate for a single operator running this in their
  spare time.
- **Is** the same mechanism as a proper backup strategy — you get continuous,
  point-in-time-recoverable backups of the database as a side effect, even
  before you build a standby host.

## The building blocks

1. **[Litestream](https://litestream.io)** streams every new SQLite WAL
   frame to a replication target (S3-compatible object storage, in the setup
   below) continuously, not on a cron schedule. It is a **backup/restore**
   tool, not live multi-master replication — the standby's database is
   reconstructed from the replicated stream *at failover time*, it isn't
   sitting there already open and serving reads.
2. **Object storage** as the replication target — any S3-compatible service
   works (self-hosted MinIO, Hetzner Object Storage, Backblaze B2,
   Cloudflare R2, AWS S3, ...). This is also where your durable backup lives.
3. **DNS failover** — a low-TTL A/AAAA record you repoint at the standby's IP
   once it's confirmed up. There's no way around this being somewhat
   provider-specific; the example below uses a generic API call you'd swap
   for your registrar's.

One thing Litestream does **not** cover: `FREIZONE_BLOB_DIR` (attachment
ciphertext) is plain files on disk, not rows in the SQLite database — see
[the config reference](../README.md#configuration-reference). This setup
replicates the database in near-real-time and the blob directory on a
periodic sync (`rclone`/`rsync`), which is a real gap: a standby that takes
over seconds after a crash may be missing attachments uploaded in the last
sync interval, even though the database row referencing them survived. See
[Further ideas](#further-ideas) for closing this properly.

## Architecture

```
                    ┌─────────────────────┐
   DNS (low TTL) ───▶  PRIMARY host       │
   chat.example.org  │  freizone-server    │
                    │  + litestream sidecar│──── continuous WAL stream ────┐
                    └─────────────────────┘                               │
                                                                            ▼
                                                                 ┌──────────────────┐
                                                                 │  S3-compatible    │
                                                                 │  object storage   │
                                                                 │  (db + blob sync) │
                                                                 └──────────────────┘
                                                                            │
                    ┌─────────────────────┐                                │
                    │  STANDBY host        │◀──── restore on failover ─────┘
                    │  freizone-server      │
                    │  (stopped until      │
                    │   triggered)          │
                    └─────────────────────┘
```

## Primary: `docker-compose.yml`

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

  litestream:
    image: litestream/litestream:latest
    container_name: litestream
    restart: unless-stopped
    volumes:
      - freizone-data:/data
      - ./litestream.yml:/etc/litestream.yml:ro
    env_file: .env.litestream
    command: replicate
    depends_on:
      - freizone-server

volumes:
  freizone-data:
```

`litestream.yml`:

```yaml
dbs:
  - path: /data/freizone.db
    replica:
      type: s3
      bucket: freizone-ha-backup
      path: db
      endpoint: https://s3.your-provider.example  # omit for real AWS S3
      region: eu-central-1
```

`.env.litestream` (credentials only — keep it out of git):

```
LITESTREAM_ACCESS_KEY_ID=...
LITESTREAM_SECRET_ACCESS_KEY=...
```

Both the server and Litestream mount the **same named Docker volume** — that
has to be local disk on this one host (a bind mount works too). Litestream's
own docs are explicit that a network filesystem (NFS etc.) under the
database will cause corruption via SQLite's locking; don't try to make the
volume itself the "shared" part between primary and standby — the S3 bucket
is the shared part, by design.

Add a periodic blob sync alongside it (cron on the host, or another sidecar
container) — this is not continuous like the WAL stream:

```bash
# every few minutes, from the primary host
rclone sync /var/lib/docker/volumes/freizone-data/_data/blobs \
  remote:freizone-ha-backup/blobs
```

## Standby: same compose file, not started by default

Same `docker-compose.yml` on the second host, but gate the server service so
it isn't running (and fighting the primary over the domain) until you
actually fail over:

```yaml
services:
  freizone-server:
    image: ghcr.io/behringer24/freizone-server:v0.13.1
    profiles: ["standby"]   # docker compose up -d does NOT start this
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - freizone-data:/data
    env_file: .env
```

No Litestream service here — the standby is a *consumer* of the replica, not
a second producer.

## Failover procedure

A monitor on (or near) the standby host — cron, a small daemon, whatever you
already run — polls the primary's `/healthz` and, on sustained failure, runs
something like:

```bash
#!/bin/sh
set -e

# 1. Reconstruct the database from the latest replicated state.
docker run --rm \
  -v freizone-data:/data \
  -v "$(pwd)/litestream.yml:/etc/litestream.yml:ro" \
  --env-file .env.litestream \
  litestream/litestream:latest \
  restore -if-db-not-exists -o /data/freizone.db \
  s3://freizone-ha-backup/db

# 2. Pull the latest blob sync (best-effort -- see the gap noted above).
rclone sync remote:freizone-ha-backup/blobs /var/lib/docker/volumes/freizone-data/_data/blobs

# 3. Start the server on this host.
docker compose --profile standby up -d

# 4. Point DNS at this host. Example: generic REST call, swap for your
#    registrar's actual API (Cloudflare, Hetzner DNS, etc.).
curl -X PATCH "https://api.your-dns-provider.example/zones/$ZONE_ID/records/$RECORD_ID" \
  -H "Authorization: Bearer $DNS_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data "{\"content\":\"$(curl -s ifconfig.me)\"}"
```

Keep the DNS record's TTL low (60–300s) ahead of time — you can't shorten a
TTL retroactively at the moment you need it.

## After a failover: recovering the old primary

**Do not simply restart the old primary once it's reachable again.** The
standby has, by now, likely accepted messages the old primary never saw —
restarting it as-is risks two servers independently believing they're
authoritative for the same domain, with diverged databases.

Treat it as a rebuild: wipe its local `freizone-data` volume, point Litestream
at it in the *other* direction (new primary → this host as its new standby),
and let it `restore` from the current state before it rejoins as the standby.
It becomes the new standby, not an automatic return to being primary — moving
the "primary" role back is a deliberate, manual decision, not something to
automate the same way as failing over.

## Further ideas

- **Blob replication that isn't a separate periodic sync.** The real fix is
  architectural, not operational: an option to store `FREIZONE_BLOB_DIR`
  contents directly in an S3-compatible bucket instead of local disk would
  let one replication mechanism (the bucket) cover both the database and
  attachments, closing this document's biggest caveat. Worth a ROADMAP entry
  if this is a direction you want to take rather than something purely
  documented around.
- **A reference failover script/container** shipped alongside the project
  (rather than only ever pasted into this doc) — the shell snippet above is
  deliberately minimal and has no split-brain protection beyond "don't
  restart the old primary blindly"; a maintained version could do better
  (e.g. a fencing check before promoting the standby).
- **Litestream config validated in CI** against the actual schema, so this
  document's YAML doesn't silently drift out of sync with a future
  Litestream release.
