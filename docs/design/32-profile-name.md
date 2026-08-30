# Design: Self-asserted profile name

Status: **planned** · Roadmap: [SRV-32](../ROADMAP.md) · Client half: freizone-app APP-27

An address is `id*server` and the id says nothing about the person behind it,
which is correct — it is self-certifying and unsquattable, and that is worth
more than legibility. But every address people are used to carries a name:
an e-mail address usually spells one out, a phone gets one from the address
book. A newcomer who sees `qk5x9-p2qan-7f3xy-zqeh8-m` and nothing else has no
way to tell two contacts apart, and that is the first minute of using Freizone.

This gives an account one optional, self-asserted name that travels **inside
the encrypted channel**, so it reaches exactly the people it already talks to
and nobody else — the server included.

## What was rejected: a server-side directory

The obvious shape is a directory on the home server: an optional entry per
account, one name visible to fellow members and one visible to federated
lookups, served from `GET /v1/accounts/{id}` alongside the key material.
It was worked through and dropped, for reasons worth recording because they
will be re-proposed otherwise:

- **The prefix form makes it enumerable.** §4 lets `GET /v1/accounts/{id}`
  be called with the 5-character prefix, which is 2^20 possibilities. Today
  that only yields ids and public keys, which is harmless. Put a name in the
  same response and roughly a million requests harvest a server's entire
  member list, with no browse endpoint anywhere in sight.
- **The endpoint cannot tell who is asking.** "Visible to members of this
  server" needs a caller identity, and that route is deliberately anonymous
  (a keyserver). It would have needed the prekey-bundle claim's three-tier
  treatment purely to hold one string back — and the tier is only politeness
  anyway, since any member can copy the name and repeat it.
- **It is the first thing a server could lie about.** Everything else in the
  protocol is verifiable against `hash(root_pubkey) == id`. An unsigned name
  in a server response is a claim the operator can forge; signing it costs a
  format, signing bytes and a verification path in every client.
- **Signing bytes collide with SRV-24.** A directory entry signed over the
  full address would be invalidated for the entire population when a server
  moves house, and the mistake would only surface at the worst moment.
- **It makes the operator responsible for every name.** A directory is
  published data, so somebody has to moderate it, and somebody has to answer
  for what stands in it.

None of that buys anything the encrypted channel does not already give. The
one case a directory covers and this does not — looking up a name for an
address obtained third-hand, before any contact — is also precisely the
impersonation case, so losing it is not obviously a loss.

## The claim

A `profile` object is carried as an **optional field on envelopes that
already fly** — `v: 1` (chat), `v: 2` (receipt) and `v: 4` (group chat) —
not as a control envelope of its own.

```json
{
  "profile": {
    "name": "Anna",
    "device_id": "16hexchars",
    "issued_at": "2026-09-01T10:00:00Z",
    "signature": "base64"
  }
}
```

**Why a field and not a `v: 6` envelope.** §6's rule is that an unknown `v`
renders as a neutral "newer feature" placeholder. A dedicated envelope would
therefore paint a visible ghost message into the transcript of every peer on
an older app, every time somebody changes their name — for a payload whose
whole point is to be invisible. An unknown *field* is ignored instead, which
is what `contentWire`'s "every field any version uses, in one struct" already
does and what §10's attachments established when they were added to `v: 1`.
The "`v: 1` is frozen" rule is about its role, not about additive fields.

Riding on receipts is what makes it work in practice: receipts fly on their
own, so a peer who only ever reads learns the name of a peer who only ever
writes, with no fan-out job and no extra delivery. A name change reaches a
contact the next time anything passes between them, and a contact nothing
passes to needs no update.

**Signing bytes**, in §2's pattern — deterministic binary, not JSON:

```
uint16BE(len(account_id)) || account_id (UTF-8)
|| device_id (8 raw bytes, decoded from hex)
|| uint16BE(len(name))    || name (UTF-8)
|| uint16BE(len(issued_at_str)) || issued_at_str
```

No Unicode normalization, deliberately: the signature covers the exact bytes,
so normalizing would have to happen identically in every client *before*
signing or the signature simply stops verifying. `issued_at` is RFC 3339 to
second precision on the wire and in the signing bytes both, so the two cannot
disagree.

`name` is bounded at **64 bytes** and must carry no control characters, line
breaks, or Unicode bidirectional formatting characters. The last of those is
the one with teeth: an override renders a name as something other than what it
says, which would defeat the point of showing an asserted name to a moderator
at all. Zero-width joiners stay allowed — composed emoji need them and they
reorder nothing. The rule is enforced *before* the signature is checked, so a
hostile client cannot sign its way past it.

`signature = Ed25519.Sign(device_identity_private_key, signing_bytes)`.

- **`account_id` is in there** so the blob cannot be lifted and replayed under
  another identity; **the server part is not**, so SRV-24 leaves it intact.
- **Signed by the device key, not the root key** — deliberately the opposite
  choice from the rejected directory entry. The root key never leaves the
  primary device (§2), and a name people want to correct from whichever phone
  is in their hand must not require it. The chain root → device certificate →
  claim is fully verifiable by any recipient from `GET /v1/accounts/{id}`,
  which they fetch anyway, so nothing is given up. A revoked device does not
  retroactively unmake the claim: `issued_at` against `revoked_at` says
  whether the device was live when it spoke, which is the question that
  matters for SRV-33's evidence.

**An empty `name` is a withdrawal**, not an empty name: a fresh `issued_at`
with `""` retracts the suggestion. Without it there is no way back out.

## Receiving

1. Verify the signature against the device certificate for `device_id` on the
   sender's account, and that `account_id` in the signing bytes is the sender.
   A claim that does not verify is **dropped silently** — the surrounding
   message is still delivered normally. Nothing about a bad name is worth
   failing a message over.
2. Ignore a claim whose `issued_at` is not newer than the newest already
   stored for that account. Replay protection and last-writer-wins in one
   rule; no clock comparison against local time, since only the ordering
   between one account's own claims matters.
3. Store it **as received, with its signature**, alongside the previous ones.
   The history is what SRV-33 forwards as evidence and what APP-27 renders as
   a "now calls themselves …" transcript line. Bound it — the ten most recent
   claims, or those from the retention window, whichever is smaller — so a
   peer renaming itself in a loop cannot grow a store without limit.

## Where this lives

**The server changes nothing.** No endpoint, no column, no capability flag: a
field inside ciphertext needs no server-side support at all, so there is
nothing for an old server to be missing and nothing to discover per §10.

In this repo the work is `pkg/client` plus PROTOCOL §6: a `profileWire` field
on `contentWire`, a `ProfileClaim` type on `Content`, the sign and verify
helpers, the "is it newer" rule, and the send-side decision of when to attach
one. The claim store belongs to the core's per-account state and not to
freizone-app's `ContactStore` — see APP-27 for why, and note the practical
half of it here: the receive path runs in the push isolate, where the Dart
contact store must not be touched, while the core already owns an exclusive
lock on the account directory (SRV-30) and writes from both isolates as a
matter of course.

## What it is not

It is not verification, and the UI must never let it read as such. Anyone may
call themselves anything; the claim proves only that this account said it,
which is exactly enough to act on when somebody reports it (SRV-33) and not
one bit more. Key verification stays what it is.
