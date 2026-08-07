# Freizone Server — Commercial License

> **Draft — not yet in effect.** This document has not been legally reviewed
> and is not an offer capable of acceptance. It exists to settle the shape of
> the eventual terms before they are drafted for real. Do not rely on it, and
> do not treat anything below as binding.

## How this relates to the AGPL

Freizone Server is, and remains, licensed to everyone under the
[GNU Affero General Public License v3 or later](LICENSE) — including for
commercial use, without a size limit, without payment. Nothing in this
document takes that away or contradicts it. Anyone is entitled to run, study,
modify and self-host Freizone Server under the AGPL alone, for free, forever,
subject only to the AGPL's own terms (chiefly: if you modify it and offer it
as a network service, you must offer that service's users the modified source
— see AGPL §13).

This document describes something offered *in addition* to that: a separate
agreement, for organisations that would rather have it, covering the two
things the AGPL cannot itself provide —

- **freedom from the AGPL's own copyleft obligations**, and
- **an explicit, on-the-record licence to point to**, which is the thing an
  organisation's own legal or compliance function generally needs before it
  will treat continued use as settled, whether or not the AGPL alone would
  have technically sufficed.

## Who this is for

A for-profit organisation (any legal or natural person acting in the course
of a commercial or independent professional activity — see BGB §14) running
a Freizone server for its own staff, with **more than 10 accounts registered
on that server at the same time** (every account, including any used by
bots or integrations — see [CONTRIBUTING.md](CONTRIBUTING.md)).

Below that threshold, and for any non-commercial operator — families, clubs,
non-profits, personal use — nothing here applies. The AGPL is the only
licence such an operator will ever need, and this document changes nothing
for them.

**Out of scope, at any size:** operating a Freizone server that end users pay
for access to. That is not offered under any terms, commercial or otherwise —
see [CONTRIBUTING.md](CONTRIBUTING.md) on why.

## Why an organisation above the threshold would actually want this

Not only "because you are expected to." Buying this licence is meant to be
worth it on its own terms:

- **Relief from AGPL §13.** If your deployment is modified in any way — even
  a small internal patch — the AGPL requires offering that modified source to
  everyone who interacts with it over the network, which for an internal
  deployment usually just means your own staff, but which some organisations
  still cannot accept as a matter of policy (e.g. where an internal
  modification embeds something the organisation is not free to disclose,
  such as an integration with other internal systems). This licence removes
  that obligation for the licensed deployment.
- **A `commercial`-tier attestation** (see `pkg/attest`, SRV-19): a signed
  token your server can present, which your own IT/security function can
  point to in an internal audit or a vendor review as evidence the deployment
  is licensed — the badge is not just cosmetic for you, it is your own
  compliance artefact.
- **A named point of contact and a real agreement**, rather than "we run
  AGPL software and hope that is enough" — the thing a compliance review
  usually actually wants to see.
- *(Reserved for the real terms once drafted: support response times,
  security-advisory notice, anything else worth bundling in.)*

## What this is not

This is not a technical restriction and nothing about Freizone Server checks
or enforces it. An organisation that qualifies and does not buy this licence
does not lose access to anything, is not locked out of any feature, and
commits no crime — it operates outside the terms this project asks
commercial operators to observe, which is a different thing from operating
outside what the AGPL permits. See [CONTRIBUTING.md](CONTRIBUTING.md) for why
that gap is accepted rather than closed by a code-level lock.

## Terms (placeholders — none of this is decided)

| | |
|---|---|
| Threshold | More than 10 accounts registered at the same time, per organisation (not per server instance) |
| Price | `TBD` |
| Term | `TBD` — likely annual, renewable |
| Audit | The licensor may request, on reasonable notice and under NDA, confirmation of the account count in scope |
| Scope | Internal use by the licensed organisation's own staff and integrations only — does not extend to operating a server for third parties, paid or not |
| Governing law | `TBD` (German law is the working assumption, to be confirmed with counsel) |

## Getting one

Contact <info@behringer24.de>. Nothing above is a price list or an offer —
it is the starting point for an actual conversation.
