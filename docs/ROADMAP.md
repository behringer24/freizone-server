# Freizone Roadmap — freizone-server (core)

Planned changes whose **essential** work lands in this repo. freizone-server is
the project core, so cross-repo and protocol-level items live here by default.

Each item has a short **reference code** used to discuss it. Codes are
per-repo, so the prefix tells you which repo's `docs/ROADMAP.md` owns the item:

- `SRV-` — freizone-server (this file, core)
- `APP-` — freizone-app
- `GAW-`  — freizone-gateway

A change that spans several repos is listed **once**, in the repo where the
essential work happens; its entry names the other repos it touches.

Status values: `planned` · `in progress` · `done` · `deferred`.

## Planned

### SRV-01 — Groups / broadcast
Status: planned · Also affects: freizone-app
Group and broadcast messaging. Today none of it exists (no tables, no API, no
UI); a group send is conceptually just N direct sends. Needs protocol design
first (membership, key distribution, fan-out) before any implementation.

### SRV-02 — Multi-device linking
Status: planned · Also affects: freizone-app, shared Go core
Add a second device to an existing identity via a QR + Noise handshake, with
the server acting as a **blind relay** (it never sees the linking secrets).
Distinct from today's QR, which is only for registration invites — not device
linking. Prerequisite for SRV-03-style history transfer (see APP-02).

### SRV-03 — Session recovery on ratchet desync
Status: in progress · Also affects: freizone-app
The Double Ratchet had no self-healing: once `sessions[peer]` desynced, all
further messages from that peer stayed undecryptable and piled up in the
server queue. The desync *trigger* (cross-isolate push/foreground race) was
fixed 2026-07-22.

**Manual variant shipped 2026-07-26** (freizone-app): the receive path now
accepts an incoming X3DH `initial` as a re-key even when a session already
exists, replacing it only once it actually decrypts the envelope (a failed
attempt falls back safely, without burning a one-time prekey); an
undecryptable "poison" envelope is dropped from the server queue after a few
attempts instead of re-failing forever; and a user-triggered "Reset secure
session" action (peer profile + chat long-press) discards the local session
so the next outgoing message re-establishes X3DH, with a visible
"Secure session was reset" system-message marker on both sides. Recovers a
desynced conversation once **both** participants run a build with the
receive-path change — a one-sided reset alone did not work before this.

**Still open:** automatic detection (repeated decrypt failure → auto-discard
→ fresh X3DH) instead of requiring the user to notice and manually reset.

### SRV-04 — Authenticate the prekey-bundle claim
Status: planned
The prekey-bundle claim (`router.go`) is currently unauthenticated — a small
forward-secrecy risk, not a confidentiality problem. Harden it.

### SRV-05 — REST resource-model build-out
Status: planned
Incremental completeness of the REST surface. No concrete gap known; tracked so
detail work has a home.
