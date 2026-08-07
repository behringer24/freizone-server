# Design: Broadcast lists

Status: **planned** · Roadmap: [SRV-16](../ROADMAP.md) · Also affects: freizone-app

Split out of SRV-01 on 2026-08-02 because a broadcast's recipient list must
specifically **not** be shared with its recipients — which removes the whole
snapshot/`state_hash` convergence layer groups rely on and makes delivery
one-directional. Left undesigned until groups shipped (2026-08-05).

The requirement grew in the meantime: a broadcast list is also meant to carry
**notifications from future Freizone bots**, so the sender is not necessarily
the list's founder, and recipients may **subscribe** rather than always being
added by someone else. What follows assumes [01-groups.md](01-groups.md)
throughout — same key hierarchy, same event/fold pattern, same self-contained
authorization trick — and calls out only where broadcast differs.

## The one structural difference from groups

Groups have **symmetric** visibility: every member eventually knows every
other member, and that mutual knowledge is the entire convergence mechanism
(§B there). Broadcast needs **asymmetric** visibility: the people who may
send must know exactly who currently receives, so a message doesn't silently
miss someone — but a recipient must never learn who else receives, and
ideally not even the full roster of who may send.

That splits a broadcast list into two tiers instead of groups' one:

| Tier | Who | Sees each other? | Converges via |
|---|---|---|---|
| **Admin tier** | founder, admin, sender | yes, fully | fold + `state_hash` + snapshot, exactly like a group |
| **Subscribers** | everyone who receives | no — not each other, not necessarily the full admin roster | nothing; one-directional content only |

This is **not** groups' `State` with a redaction layer bolted on — `pkg/group`'s
fold, `state_hash`, and snapshot machinery has no per-audience scoping
anywhere; it was built on the opposite assumption, that every fact a member
holds is a fact every member may hold. A broadcast list needs a second,
sibling structure: an admin-tier fold that behaves exactly like a (very
small) group, plus a private fact namespace for subscribers that folds into
that *same* admin-tier convergence but is never disclosed past it.

## Roles and precedence

Three ranks, one fewer than groups' four — `moderator`/`member` don't apply
here, since there is no membership to moderate, only a send permission and a
subscriber list to manage:

| Action | Founder | Admin | Sender | Subscriber |
|---|:--:|:--:|:--:|:--:|
| Appoint / remove admin | ✔ | – | – | – |
| Appoint / remove sender | ✔ | ✔ | – | – |
| Approve a subscribe request | ✔ | ✔ | – | – |
| Remove a subscriber | ✔ | ✔ | – | – |
| Post to the list | ✔ | ✔ | ✔ | – |
| Set list name / topic | ✔ | ✔ | – | – |
| Leave (resign a role) | – | ✔ | ✔ | – |
| Unsubscribe | – | – | – | ✔ |
| Dissolve the list | ✔ | – | – | – |

Same rule as groups: **you may only act against strictly lower ranks**
([01-groups.md:333](01-groups.md)), with ranks ordered sender 1, admin 2,
founder 3. `sender` is deliberately not `grantable` by itself the way
groups' moderator/admin both are — a sender can never become an admin by
self-action, only by an admin's or the founder's grant, same as groups'
"granting role R requires a rank above R" rule.

**Why a `sender` rank at all, rather than reusing `admin` for everything:** a
notification bot should be able to post without also being trusted to decide
who else may subscribe or send. Collapsing the two would force every bot
account into full list administration just to let it post.

**The sender of a message stays identifiable.** Unlike the roster, *who
actually sent this one message* is not something to hide — a subscriber
sees which admin or sender posted, the same way a group member sees who
sent a group message. What must stay hidden is everyone else on either
side of the list, not the acting sender's own identity.

## List id and key hierarchy

A `broadcast_id` is derived exactly like a group id
([01-groups.md:192-201](01-groups.md)) — SHA-256 of the list's root public
key, bech32m, 21 characters — under its own version marker,
`VersionBroadcast`, next to `VersionGroup` in `pkg/address`. `DeriveIDVersion`/
`VerifyVersion`/`VersionOf` already take the marker as a parameter
(`pkg/address/address.go`), so this is one new constant and a two-function
wrapper package, `pkg/broadcast`, mirroring `pkg/group`'s
`DeriveID`/`VerifyID` (`pkg/group/group.go:132-145`) line for line. No change
to `pkg/address` itself.

```
List Root Key (Ed25519, one per list, created by the founder)
   │  signs
   ├─► Genesis                  (broadcast_id, founder_account_id, list_nonce, created_at)
   ├─► Role Grant: admin             ── founder only
   ├─► Role Revoke: admin            ── founder only
   └─► Dissolve
           │
           │  admins act with their ordinary device key
           ▼
       Role Grant/Revoke: sender        ── admin or founder
       Subscribe Accept / Subscriber Remove   ── admin or founder
       List Meta (name, topic)          ── admin or founder
       Subscribe / Subscribe Request / Unsubscribe   ── self-signed (subscriber)
       Leave                             ── self-signed (admin or sender resigning)
```

The founder is whoever holds the list root key, exactly as for a group and
an account. Every event below the root carries the same `signer` block
groups already use ([01-groups.md:223-230](01-groups.md)) — the verification
chain is the identical device key ← device cert ← root key ← `account_id` ←
role grant ← list root key ← `broadcast_id` chain, nothing new to implement
but the signing bytes.

**Genesis carries the founder's server and is the founder's own admin
membership** — same reasoning as groups ([01-groups.md:297-301](01-groups.md)):
without it the founder would be unreachable by their own list until they
first acted.

## Event encoding

Same length-prefixed, domain-tagged binary pattern as groups
([01-groups.md:241-276](01-groups.md)), own tags (`frz-broadcast-<type>-v1`):

| Event | Fields between list id and timestamp | Signed by |
|---|---|---|
| Genesis | `list_root_pubkey`, `list_nonce`, `founder_account_id`, `founder_server` | list root key |
| Role grant | `uint8(role)`, `subject_account_id` | list root key or device |
| Role revoke | `uint8(role)`, `subject_account_id` | list root key or device |
| Subscribe | `subject_account_id`, `subject_server` | subscriber's own device |
| Subscribe request | `subject_account_id`, `subject_server` | subscriber's own device |
| Subscribe accept | `subject_account_id` | device (admin or founder) |
| Unsubscribe | `subject_account_id` | subscriber's own device |
| Subscriber remove | `subject_account_id` | device (admin or founder) |
| List meta | `name`, `topic` | device |
| Leave | `subject_account_id` | subject's own device |
| Dissolve | *(none)* | list root key |

`Subscribe` and `subscribe_request` are mutually exclusive by policy (see
next section), not by anything the fold enforces structurally — a fold
running under the wrong policy simply never admits one of the two.

There is deliberately no `subscribe_reject` event: an unanswered request
just stays unanswered. No new state, no distinction between "not yet seen"
and "declined", and the requester may always ask again — the same stance
[15-community-policy.md](15-community-policy.md) already takes on invites
needing no justification to withhold.

## Subscribe policy — one enum, not two axes

A list has exactly one `subscribe_policy`, following
[15-community-policy.md:30-36](15-community-policy.md)'s own lesson that an
orthogonal second setting buys no expressiveness a single enum doesn't
already cover:

- **`open`** — a self-signed `subscribe` event is admitted unconditionally.
  Anyone who has the list's address (see "Discovery" below) can subscribe
  without anyone's approval.
- **`apply`** — a `subscribe_request` is only a proposal; a subscriber
  becomes real once some admin or the founder issues `subscribe_accept`.

**Not decided, flagged rather than specified:** a third value where an admin
adds a subscriber directly, without the subscriber asking first — the
natural shape for, say, an admin pre-populating a bot's notification list
from an existing contact set. This is deliberately left as a considered
extension rather than designed now, since it needs its own answer to "does
the added subscriber need to accept, the way a group's `member_add` requires
`join_accept`" and that answer changes the event table above.

## Admin-tier convergence

The admin tier — founder, admins, senders, *and* the subscriber facts below —
converges exactly the way a group does: fold over monotone signed facts,
`state_hash` as the SHA-256 of applied event ids, snapshot-on-mismatch,
loop avoidance by answering a given foreign `state_hash` once
([01-groups.md:425-450](01-groups.md)). The one rule that changes what
"admin tier" means in practice: **a `subscribe_request` is a fact in this
same fold**, not something routed only to the one admin who happened to
receive it. Every admin who has synced sees every open request and may act
independently; a double-decision on the same request resolves exactly like
groups' timestamp tie-break — the earlier `issued_at` wins, identical event
id as the final tie-break ([01-groups.md:369](01-groups.md)). This is the
direct application of groups' own lesson that the real failure mode is "I
fan out to the members I know" ([01-groups.md:427-429](01-groups.md)):
without admin-tier convergence on the subscriber set, one admin's send
silently drops whoever a slower-syncing admin already accepted.

**This convergence artifact — the fold, its `state_hash`, its snapshot — is
exchanged only within the admin tier.** That is the whole mechanism that
satisfies the constraint this item was split out for: a subscriber never
receives a snapshot, never learns another party's `state_hash`, and has
nothing to converge.

## Content delivery to subscribers

A message to a subscriber carries **no `state_hash` and no roster** — there
is nothing for the subscriber to converge against, and shipping one would
imply a synchronization the subscriber can never complete. What it carries
instead is the same self-contained authorization chain groups already use to
let a recipient verify an act without having synced the actor's appointment
first ([01-groups.md:392-409](01-groups.md)): device cert → root key →
`account_id` → the signer's role grant → list genesis. A subscriber checks
`broadcast_id == hash(list_root_pubkey)` and the chain, and now knows both
that the message is genuine and who — specifically — sent it, without ever
having seen the admin roster or the subscriber list.

## Discovery

No directory or registry — out-of-band link sharing only, the same as
groups' invite QR ([01-groups.md:621-624](01-groups.md)):

```
freizone://broadcast?id=<broadcast_id>&via=<admin id*server>
```

The named admin is who first receives a `subscribe`/`subscribe_request`; from
there it is an ordinary fact in the admin-tier fold and reaches the rest of
the admin tier through normal convergence, not through the `via` admin
relaying it by hand.

## Rejected / deferred

- **A directory or server-side listing of broadcast lists.** Out of scope for
  now; discovery stays link-only, as decided above.
- **The third `invite`-style subscribe policy** (admin adds directly). See
  "Subscribe policy" — considered, not specified.
- **Abuse-bounding for `open` policy** (a cap on unredeemed self-subscribes,
  a cooldown, a minimum account age) — the same candidate list
  [15-community-policy.md:43-54](15-community-policy.md) already worked out
  for invite-minting applies here nearly unchanged, but is a refinement for
  once this ships, not a blocker for the design.
- **Sender keys / MLS / a server-side relay** — same reasoning as groups
  (§A there); nothing about broadcast changes that calculus.

## Accepted weaknesses

- **Timestamps are self-asserted**, same residual risk as groups.
- **Equivocation is detectable, not preventable** — an admin showing
  different subscriber facts to different admins is caught by the next
  `state_hash` mismatch among admins, after the fact.
- **The admin tier can correlate who subscribed.** Unavoidable — admins must
  know the current subscriber set to deliver correctly at all. This is
  strictly less disclosure than a group (where every member learns every
  other), but it is not zero: a compromised admin account learns the full
  subscriber list, same as a compromised moderator learns a group's full
  member list today.
- **A bot's device key is an ordinary device key.** No new protocol category
  for automation — a bot is an account holding `sender` or `admin` rank like
  any other. Key custody for an unattended, always-on signer is an
  operational concern for whoever runs the bot, not something the protocol
  can enforce.

## Touch points

**freizone-server (this repo)**

- **`pkg/broadcast`** (new, sibling to `pkg/group`, not a parametrization of
  it — `pkg/group`'s `Role.grantable()`/`String()` and the hardcoded
  `RoleModerator` floors through its fold are group-specific literals, not a
  generic ordered-rank abstraction, so this gets its own 3-rank enum and its
  own fold thresholds rather than reusing `pkg/group.Role` in place):
  event types and signing bytes, verification, the admin-tier fold,
  `state_hash`, snapshot merge, and the separate subscriber-fact handling
  that never feeds a snapshot meant for a subscriber.
- `pkg/address`: one new constant, `VersionBroadcast`, next to
  `VersionGroup`.
- `pkg/wire`: new envelope versions (see "Wire additions" below).
- `internal/api`: no new endpoints expected beyond what groups already added
  — broadcast delivery reuses the existing batch endpoints
  (`POST /v1/messages/batch` and its federated twin) exactly as groups do.
- `cmd/devclient`: a `broadcast` subcommand mirroring the `group` one —
  create, grant/revoke, subscribe, request, accept, remove, meta, leave,
  dissolve, send, sync.
- `docs/PROTOCOL.md`: the new envelope versions. Note in passing: groups'
  own `v: 4`/`v: 5` were never actually added to `PROTOCOL.md`'s §6 table —
  they exist only in `01-groups.md`. That gap predates this document and is
  not something to fix silently as part of broadcast; it is a pre-existing
  inconsistency worth its own small follow-up.

**freizone-app** — designed separately once this is confirmed, following
the same pattern APP-16 used for groups.

## Wire additions

Per §6, `v: 1` is frozen and each control envelope gets its own version.
Two new ones, picking freshly unused numbers (groups claimed `4`/`5`,
whether or not `PROTOCOL.md` currently shows them):

| `v` | Content | Shown to the user |
|---|---|---|
| `6` | Broadcast content: `v: 1`'s fields, plus `broadcast_id` and the sender's authorization chain. No `state_hash`. | yes |
| `7` | Broadcast control: `kind: "events" \| "snapshot" \| "sync_request" \| "subscribe" \| "subscribe_request" \| "unsubscribe"`, `broadcast_id`, `events: [...]`. `state_hash` present only for the admin-tier kinds; absent for a subscriber-originated `subscribe`/`subscribe_request`/`unsubscribe`, which carries only one self-signed fact about the sender themself and has nothing to converge. | no |

## Phasing

Not started. Expected shape, following groups' own phasing
([01-groups.md:664-691](01-groups.md)):

1. `pkg/broadcast` with its own test suite — pure Go, no I/O, mirroring
   `pkg/group`'s coverage bar.
2. Wire additions (`v: 6`/`v: 7`) in `pkg/wire`; no new server endpoints,
   since delivery reuses the existing batch endpoints.
3. `cmd/devclient` `broadcast` subcommand, verified across the local Docker
   instances the way `group` was.
4. `docs/PROTOCOL.md` update — and, while there, close the pre-existing
   `v: 4`/`v: 5` documentation gap groups left open.
5. freizone-app.

## Out of scope

- Directory/registry of broadcast lists.
- The `invite`-style third subscribe policy.
- Bot key custody and operational hosting concerns.
- Sender keys / MLS / server-side relay (see groups' §A).
