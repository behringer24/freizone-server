# Design: Groups

Status: **planned** · Roadmap: [SRV-01](../ROADMAP.md) · Also affects: freizone-app

Group messaging with a founder/admin/moderator authority model. Nothing of it
exists today — no tables, no API, no UI. The decisive question is not the REST
surface but **where a group lives**, and the answer shapes everything else.

Broadcast, listed together with groups in SRV-01 today, is deliberately *not*
covered here — see "Out of scope".

## Where the group lives

**Nowhere on a server.** The moment a server holds membership, a federated
group needs a home server that *decides* who is a member — which contradicts §1
(self-certifying, host-independent identity) and creates exactly the trust
anchor the rest of the protocol avoids. §9 already assumes the opposite: "a
future group send is simply N parallel invocations of this same per-recipient
delivery, fanned out per member".

So a group is a **cryptographic object, not a server object** — precisely
analogous to an account. It has a self-certifying id, a root key, and a
certificate chain, and it exists only in its members' clients.

## Two problems, two answers

The common mistake is to force both into one group ratchet. They are separate
and take different solutions:

| | Problem | Solution |
|---|---|---|
| **A** | Confidentiality of messages | The existing pairwise Double Ratchets, N times over. **No group key at all.** |
| **B** | Who is a member, who may do what | Signed, monotone facts (certificates + revocations), the §2 pattern replicated |

---

# A. Message distribution

## Pairwise fan-out

A group message is N−1 ordinary `POST /v1/messages` (or
`POST /v1/federation/messages`) calls over the existing X3DH/Double Ratchet
sessions, one ciphertext per recipient *device*. New cryptography: **none**.

```
Clara sends "hello" to a group of Anna, Ben, Dora(2 devices):
  Clara → Anna's server   POST /v1/messages             Anna's device
  Clara → Ben's server    POST /v1/federation/messages  Ben's device
  Clara → Dora's server   POST /v1/messages             Dora's device 1
  Clara → Dora's server   POST /v1/messages             Dora's device 2
```

Every member fans out its own messages. **There is no relay through the founder
or through any other member.** The durable per-device queue on each recipient's
own server (§7) is the delivery guarantee, exactly as for a 1:1 message.

Why this rather than a shared group key:

- **Removal takes effect immediately and needs no re-key.** With sender keys,
  every remaining member must rotate after every removal, and a member that
  misses the rotation keeps handing its old key to the removed account. Since
  moderation is the *point* of this feature, that is the deciding argument.
- **Forward secrecy and post-compromise security hold per pair**, including
  SRV-03's self-healing. A group ratchet would have to re-earn both; sender keys
  have no PCS at all.
- **No per-message signature is needed.** Each member receives its own copy
  directly from the author, so nothing is relayed and the pair's AEAD
  authenticity suffices. Sender keys would additionally require an Ed25519
  signature per message, precisely because the ciphertext is forwarded.
- **The fan-out does not disappear anyway.** The server keeps one queue per
  device and federation targets several servers, so sender keys would save CPU,
  not requests — the actual benefit never materializes at this scale.

### Why not relay through the founder

- Founder offline ⇒ group dead. With pairwise fan-out it is enough that the
  *sender* is online.
- The founder could drop individual messages undetectably.
- A relay needs per-message signatures and a group key, because otherwise the
  founder would have to decrypt and re-encrypt every message. The entire benefit
  above would be gone, and the founder would see the full communication graph.

### Why not a server-side relay

A sending server forwarding to *other* servers would be a server-to-server
relay, which §9 deliberately does not have. It is technically possible — the
client pre-signs the N federated requests and hands them to its own server just
to be dispatched, since the server never has the device key — but it gives the
sender's server store-and-forward state, retry responsibility for foreign
delivery, and the complete recipient set including remote members. That trades
away a founding assumption of the protocol for a round-trip win.

## Costs, honestly

(N−1) × devices requests per message. Thirty members at ~1.5 devices ≈ 44
requests. Fine for a self-hosted community, wrong for 500 members.

- **Sizing guidance: up to ~50 members** pairwise fan-out is unremarkable. This
  is deliberately **not** a protocol limit — a `member_add` beyond it stays
  valid — because a number baked into the wire format can only be removed by a
  protocol change. The client warns above the threshold. The figure marks
  honestly where sender keys would become necessary.
- **Partial delivery is the normal case** (one server unreachable), so APP-08's
  outgoing queue becomes a hard prerequisite: retryable per recipient, not per
  message.
- **Receipts (`v: 2`) go to the message's author only** — not to all members.
  That keeps traffic linear (N per message) instead of quadratic (N² if everyone
  told everyone). The author sees "read by 12"; nobody else sees anything.
  **This needs no protocol change whatsoever**: a `v: 2` receipt already
  references a `message_id`, and the author resolves which group that message
  belonged to from its own local state. The receipt's sender is already known
  from the envelope. `v: 2` stays exactly as it is.
- **Attachments**: one blob key per attachment (§10 already keeps it
  non-ratchet-derived), uploaded **once per distinct recipient server**, not per
  recipient. The `blob_id` differs per server, so the reference is built per
  recipient — which the sender does anyway.
- **Message ordering** is not globally defined. A client orders a group
  transcript the same way it orders any other: by local receive order, using the
  sender's timestamp for display. Causal ordering across senders is not
  attempted; only *state* events are order-insensitive by construction (part B).

## Batch delivery (in v1)

A batch endpoint collapses the fan-out from one request per recipient device to
**one request per distinct recipient server**. In a non-federated community —
the common case — that is N→1; in a group spanning three servers, N→3.

Two variants are needed, since a federated send authenticates differently:

### `POST /v1/messages/batch` (signed)

```json
{ "messages": [
  { "message_id": "...", "recipient_device_id": "16hexchars", "payload": { } }
] }
```

All items are from the one signing device; §3's canonical string is unchanged
(the whole body is hashed as usual). Response `200`:

```json
{ "results": [ { "message_id": "...", "status": "queued" } ] }
```

with per-item `status` of `queued` · `duplicate` (§7's `message_id` idempotency)
· `unknown_recipient` · `queue_full`. **Failures are per item, never for the
batch**: one recipient at its queue cap must not cost the other members their
copy. The per-item statuses expose no more than `POST /v1/messages` already
does with its `404`/`409`/`429`.

### `POST /v1/federation/messages/batch` (public — self-describing key)

Same list, but the sender's identity block (`sender_account_id`,
`sender_root_pub_key`, `sender_device_cert`) appears **once at the top level**
instead of per message. That, not the round-trip count, is the larger saving
here: the certificate chain is verified once for the whole batch. Verification
is otherwise §9's, step for step, per item for the recipient checks.

### Discovery and limits

`GET /v1/server-status` gains `batch_messages: true` and `max_batch_messages`.
Per SRV-10 the capability is *discovered per server* and its absence means
"fall back" — a client sending into a group whose members sit on a mix of old
and new servers batches where it can and posts individually where it cannot.
Groups therefore work against every server that exists today; batch is an
optimization, never a prerequisite.

`FREIZONE_MAX_BATCH_MESSAGES` (default 100) caps the item count;
`FREIZONE_MAX_REQUEST_BODY_BYTES` (512 KiB) still caps the body, so a client
splits large batches itself.

**Accepted trade-off:** with a batch, the server sees the local recipient set as
an explicit set rather than having to correlate N separate posts by timing. This
is a real, if modest, metadata loss and the reason the endpoint is optional
rather than the only path.

## Rejected / deferred

- **Sender keys** — a later, additively negotiated envelope version if group
  sizes ever demand it. Costs PCS and makes removal a rotation problem.
- **MLS (RFC 9420)** — the technically superior answer for large groups, but it
  does not replace X3DH + Double Ratchet, it sits beside it. That is a project,
  not a feature.

---

# B. Group state

## Group id

A `group_id` is formed **exactly like an account id per §1** — SHA-256 of the
group root public key, bech32m, 21 characters, same checksum and charset — with
the 5-bit **version marker `1` instead of `0`**. Group and account ids are
therefore never confusable, at the cost of zero new encoding logic. There is no
`*server` part: a group has no server.

§1's id-prefix uniqueness rule does **not** apply — it is enforced by a server
over its own accounts, and no server holds groups.

## Key hierarchy

```
Group Root Key (Ed25519, one per group, created by the founder)
   │  signs
   ├─► Genesis           (group_id, founder_account_id, group_nonce, created_at)
   ├─► Role Grant: admin       ── founder only
   ├─► Role Revoke: admin      ── founder only
   └─► Dissolve
           │
           │  admins and moderators act with their ordinary device key
           ▼
       Role Grant/Revoke: moderator      ── admin only
       Member Add / Member Remove        ── admin or moderator
       Group Meta (name, topic)          ── admin or moderator
       Join Accept / Leave               ── self-signed
```

The founder is **whoever holds the group root key** — the same definition as
"account owner is whoever holds the root key". Everything below is signed with a
**device key** and carries the same `signer` block §9 already defines for
federated delivery:

```json
{ "account_id": "...", "root_pubkey": "base64",
  "device_cert": { "device_id": "...", "device_pub_key": "base64",
                   "issued_at": "...", "signature": "base64" } }
```

The verification chain is thus literally the existing one: device key ← device
cert ← root key ← `hash(root_pubkey) == account_id` ← named in the role grant ←
group root key ← `group_id`. Nothing new to implement but the signing bytes.

A device certificate is checked for **validity, not current activity**: a
revoked device's past acts stay valid. Cross-server device revocation is not
observable anyway (§9's known gap), so requiring it would be a check no
implementation could actually perform.

## Event encoding

Same deterministic length-prefixed binary pattern as §2/§5, with one deliberate
addition: **every event type begins with its own domain tag**, so a signature
over one event shape can never be reinterpreted as another. (§2 relies on its
two shapes having different lengths; with a dozen similar events that would stop
being safe.)

```
uint16BE(len(tag)) || tag (UTF-8)  ||  <type-specific fields>
```

| Event | Tag | Fields after the tag | Signed by |
|---|---|---|---|
| Genesis | `frz-group-genesis-v1` | `group_id`, `group_nonce` (16 raw bytes), `founder_account_id`, `created_at` | group root key |
| Role grant | `frz-group-role-grant-v1` | `group_id`, `uint8(role)`, `subject_account_id`, `issued_at` | group root key (admin) / admin's device (moderator) |
| Role revoke | `frz-group-role-revoke-v1` | `group_id`, `uint8(role)`, `subject_account_id`, `revoked_at` | as above |
| Member add | `frz-group-member-add-v1` | `group_id`, `subject_account_id`, `subject_server`, `added_at` | device |
| Member remove | `frz-group-member-remove-v1` | `group_id`, `subject_account_id`, `removed_at` | device |
| Join accept | `frz-group-join-accept-v1` | `group_id`, `subject_account_id`, `accepted_at` | subject's own device |
| Leave | `frz-group-leave-v1` | `group_id`, `subject_account_id`, `left_at` | subject's own device |
| Group meta | `frz-group-meta-v1` | `group_id`, `name`, `topic`, `set_at` | device |
| Dissolve | `frz-group-dissolve-v1` | `group_id`, `dissolved_at` | group root key |

Strings are `uint16BE(len) || UTF-8 bytes`; timestamps are UTC RFC 3339
(`2006-01-02T15:04:05Z07:00`), as in §2. `role` is `1` = admin, `2` = moderator.

**Event id** = `SHA-256(signing_bytes || signature)`, lowercase hex. It is what
deduplication and `state_hash` operate on.

**Name and topic in one event.** The stated requirement is only "set a topic",
but a group also needs a display name to be usable in a list, and two separate
last-writer-wins fields would produce a needless merge case. One record,
last-writer-wins as a whole. Flagged here because it is a small extension of the
requirement, not something to discover later in the code.

## Roles and precedence

| Action | Founder | Admin | Moderator | Member |
|---|:--:|:--:|:--:|:--:|
| Appoint / remove admin | ✔ | – | – | – |
| Appoint / remove moderator | ✔ | ✔ | – | – |
| Invite | ✔ | ✔ | ✔ | – |
| Remove a member | ✔ | ✔ | ✔ | – |
| Remove a moderator | ✔ | ✔ | – | – |
| Remove an admin | ✔ | – | – | – |
| Remove the founder | – | – | – | – |
| Set name / topic | ✔ | ✔ | ✔ | – |
| Leave | – | ✔ | ✔ | ✔ |
| Dissolve the group | ✔ | – | – | – |

The rule in one sentence: **you may only act against strictly lower ranks.** The
moderator limit mirrors SRV-08, where moderators may block regular members only,
because blocking staff would amount to removing them.

The founder is unremovable because "founder" is key possession, not an
assignment.

## State is a fold over monotone facts

There is no sequencer. Two moderators removing each other simultaneously is
unavoidable. So no event is a write; each is a **monotone statement**:

> "A appointed X moderator at T" · "A revoked X's moderator role at T′"

State is a **fold over the set of facts**, independent of arrival order:

- `role(X)` = the highest role R with a grant `(R, X, t)` for which no revoke
  `(R, X, t′)` with `t′ > t` exists. Re-appointment after revocation therefore
  works with no special case.
- `member(X)` iff an add exists with no later remove or leave, **and** a join
  accept exists (see below).
- An event `e` signed by S is valid iff `role(S)` at `e.issued_at` — computed
  from the facts timestamped before it — meets the requirement, and the target's
  role at that moment was strictly lower.
- Identical timestamps: the lower event id wins.

This is the certificate/revocation pattern §2 already uses for devices, merely
replicated. Mutual removal therefore ends with both parties out — it fails
closed, and an admin cleans up.

## Events are self-contained

A state event travels **together with the certificate chain that authorizes
it**, the way a TLS handshake ships its intermediates instead of expecting the
peer to fetch them:

```
Event:      "Clara removes Erik"     signed with Clara's device key
Enclosed:   Clara's device cert      ← root key ← account_id (§2)
            moderator grant for Clara, signed by Ben
            admin grant for Ben, signed by the group root key
            genesis, group_id == hash(group root pubkey)
```

Three small extra objects. A recipient can validate Clara's act **without ever
having seen Ben's appointment**, and learns Ben's admin status in the same step.
This removes the large majority of all synchronization rounds: **rights need not
be synchronous, they arrive with the action.**

## Revocations gossip

The one case self-containment cannot cover: **the absence of a revocation is not
provable.** A just-demoted moderator can attach its own still-plausible grant
and act; anyone who has not yet seen the revocation accepts it.

Therefore: grants travel with the action, **revocations flood** — whoever learns
a revocation forwards it to every member it knows. Monotone, idempotent, cheap.
When a revocation arrives late, the fold is recomputed and the act falls away
retroactively (the removed member is a member again).

This is inherent to a system without consensus — Matrix and Signal have the same
class of problem — and is carried deliberately, not solved.

## Convergence: `state_hash` and snapshots

The real failure mode is not "my state is wrong" but **"I fan out to the members
I know"**. If I do not know Dora, Dora does not get my message. State drives
delivery, so a missed membership event is not cosmetic.

Every group message (`v: 4`) carries

```
state_hash = SHA-256( concat of the applied event ids, sorted lexicographically )
```

If it differs from mine, one of us is missing something — and then I simply send
**my entire fact set** (`v: 5`, `kind: "snapshot"`). No delta protocol, no
version vectors:

- The state is a **grow-only set of signed facts**. Union is idempotent and
  commutative, so convergence is guaranteed regardless of order or repetition.
- It is small. An event with its signer block is ~200–300 bytes; 50 members and
  300 events ≈ 80 KB, well under the 512 KiB body limit. A delta sync only pays
  off far beyond that.
- It requires no trust. Every fact is individually signed, so a hostile snapshot
  can omit but never invent — and omission shows up at the next `state_hash`
  comparison with *anyone else*.

Loop avoidance: respond to any given foreign `state_hash` at most once.

A group message from an account I do not consider a member is **held briefly in
a small bounded buffer, not discarded**, and re-evaluated after the snapshot
exchange. Symmetrically, a sender attaches its snapshot proactively to the first
group message it sends to a peer whose `state_hash` it has not yet seen agree.

### Worked example: Dora joins

| # | Who | What |
|---|---|---|
| 1 | Clara (mod) | creates `member_add(Dora)`, signs it with her device key |
| 2 | Clara → Dora | `v: 5` **snapshot**: genesis, all grants/revocations, member list, meta |
| 3 | Clara → all | `v: 5` the `member_add` **plus Clara's authorization path** |
| 4 | Dora | checks `group_id == hash(pubkey)` and Clara's chain, then builds pairwise sessions to everyone via the public prekey bundles (§4, cross-server included) |
| 5 | Dora → all | `join_accept`, self-signed |

Two independent paths carry Dora's existence: Clara's broadcast (3) and Dora's
own accept (5). The latter matters more — Dora has the strongest interest in
being known, and she has the full list from (2).

If Ben was offline and missed both, he later sends to everyone *except* Dora.
Anna and Clara see his stale `state_hash` and push him the snapshot. Exactly one
message is lost, and Ben's client can say so, because it learns afterwards that
its fan-out was incomplete.

## Accepted weaknesses

Worth writing down rather than discovering:

1. **Timestamps are self-asserted.** A hostile admin can backdate. Within its
   own authority that gains little; the bounds are that an event may not predate
   the genesis or the signer's own grant. Residual risk accepted, like §9's
   cross-server revocation gap.
2. **A late-arriving fact can retroactively invalidate an event.** Not a bug but
   eventual consistency: given the same fact set every member folds to the same
   state deterministically.
3. **Equivocation is detectable, not preventable.** An admin showing different
   histories to different members is caught by the `state_hash` comparison —
   after the fact.
4. **Membership mutually discloses identities.** Every member must be able to
   send to every other, so every member learns every other's `account_id` and
   home server. This is forced by pairwise fan-out and cannot be designed away;
   the UI must say so at join time.
5. **Servers can correlate.** A recipient's server sees N deliveries from one
   sender at one moment. Neither sender keys nor a group host would fix this.
6. **A removed member keeps its history.** Unavoidable under end-to-end
   encryption.
7. **No client capability discovery exists.** SRV-10 covers server capabilities
   only. A member on an older app build sees the §6 "newer feature" placeholder
   for group messages, and no one can know in advance. Tolerable — it is exactly
   the behaviour §6 prescribes for an unknown `v` — but a conscious choice.

---

# Membership lifecycle

**Creation.** The founder derives the group root key, emits genesis, and adds
itself. No server is contacted.

**Recovering the group root key from the seed.**

```
group_root_seed = HKDF-SHA256(ikm  = account_root_seed,
                              info = "Freizone-Group-Root-v1" || group_nonce)
```

`group_nonce` (16 random bytes) lives **in the genesis event**, i.e. in public
group state. So: the founder loses every device → restores the account from the
APP-01 seed → receives the group state from *any* member → reads the nonce from
genesis → re-derives the group root key. **No additional backup material and no
new way to lose the group.** That is the reason to derive the key rather than
generate a fresh one.

**Invitation requires acceptance.** A `member_add` is a proposal. Until the
invitee sends a signed `join_accept`, they show as "invited" everywhere and
receive no messages. Being added to a group discloses your account id to every
member, and that disclosure must not be someone else's decision. The cost is one
round trip and one extra UI state.

**Founder loss ossifies the group.** With no emergency exit in v1, admins keep
moderating, inviting and removing; only new admins can no longer be appointed.
That follows the requirement exactly and needs no additional cryptography. The
practical remedy is founding a new group. A founder handover and a k-of-n admin
quorum were both considered: the handover helps only against a planned exit, and
the quorum is the single place in this whole design that would need real
consensus between members. Neither earns its complexity in v1.

**The founder cannot leave.** Leaving would produce an authority that is not in
the member list — cryptographically honest, but unexplainable in a UI. Instead
the founder can **dissolve** the group: a signed `dissolve` event after which
every client archives the conversation locally and refuses to send.

---

# Wire additions

Per §6, `v: 1` is frozen and each control envelope gets its own version. A
`group_id` field added to `v: 1` would make an older client file a group message
silently into a 1:1 conversation, which is worse than a placeholder.

| `v` | Content | Shown to the user |
|---|---|---|
| `4` | Group chat content: `v: 1`'s fields unchanged, plus `group_id` and `state_hash` | yes |
| `5` | Group control: `kind: "events" \| "snapshot" \| "sync_request"`, `group_id`, `events: [...]`, `state_hash` | no |

`v: 2` (receipts) and `v: 3` (re-key) are unchanged and need no group awareness —
see the receipts note in part A, and note that re-keying is per pair and knows
nothing about groups by construction.

An `events` list carries objects of `{ type, fields, signer, signature }`, where
`signer` is omitted for group-root-signed events (the group root public key is
in genesis) and otherwise is §9's identity block verbatim.

A group invitation QR follows §11's pattern:
`freizone://group?id=<group_id>&via=<inviter id*server>`. It carries no secret —
joining still requires a `member_add` from someone authorized — so, like §11,
there is nothing here to expire or revoke.

---

# Touch points

**freizone-server (this repo)**

- **`pkg/group`** (new, public like `pkg/ratchet` and `pkg/wire`, so the app's
  shared core imports it rather than reimplementing it): event types, signing
  bytes, signature verification, the fold, `state_hash`, snapshot merge. Pure
  Go, fully testable without any I/O — and the bulk of the actual work.
- `pkg/wire`: `v: 4` / `v: 5` payload shapes.
- `internal/api/messages.go`, `federation.go`, `router.go`: the two batch
  endpoints; `config.go` for `FREIZONE_MAX_BATCH_MESSAGES`; the server-status
  handler for `batch_messages` / `max_batch_messages`.
- `cmd/devclient`: create, invite, accept, send, sync — the reference path that
  proves the design end-to-end before any UI exists.
- `docs/PROTOCOL.md`: a new §12 for groups, the two new rows in §6's table, the
  batch endpoints in §7/§9, the capability in §4's server-status.

No schema migration and no new table: the server stores group traffic as the
ordinary per-device message queue it already has.

**freizone-app** — designed separately as
[APP-16](https://github.com/behringer24/freizone-app/blob/master/docs/design/16-groups.md):
a `ChatTarget` base under `Conversation` plus a new `GroupConversation`, one
state file per group, fan-out over APP-08's outbox, and the group UI. `pkg/group`
is reached over four FFI exports with the state blob opaque to Dart, so the
convergence rules exist once.

Two constraints that document establishes and that belong here too:

- **APP-08 step 2 (a durable outbox) is a hard prerequisite.** A fan-out that
  dies partway currently loses the remainder for good.
- **A group message must be encrypted once per recipient**, which settles APP-08
  step 2's own open fork in favour of queueing *plaintext* and encrypting at send
  time. Queued ciphertext would commit N copies to N specific session states that
  any re-key invalidates.

# Phasing

1. `pkg/group` with its test suite — events, verification, fold, convergence.
2. Batch endpoints and the capability flag.
3. `cmd/devclient`: a full group between two local instances plus one federated,
   without UI.
4. App (APP-16), which begins with its own two prerequisites: the `ChatTarget`
   refactor and APP-08 step 2.

# Out of scope

- **Broadcast**, despite sharing SRV-01's title today, becomes its own roadmap
  item citing this design. The difference is not a flag: the recipient list must
  specifically *not* be shared, which removes the entire snapshot/`state_hash`
  layer and makes the fan-out one-directional.
- **Sender keys / MLS** — see part A.
- **Server-to-server relay** — see part A.
- **Group history for a newly linked device** belongs to SRV-02/APP-02; here a
  new device gets current *state* from any peer's snapshot, not past messages.
