# Contributing to Freizone Server

Bug reports, protocol questions and pull requests are all welcome. This file
covers the practical side, plus one thing unusual enough to state up front:
contributions to this repository require a contributor licence agreement, and
the reason for it is spelled out [below](#contributor-licence-agreement)
rather than left to be discovered.

## Before you open a pull request

- **Open an issue first for anything non-trivial.** A server change often
  implies a client change, and the protocol is spoken by more than one
  implementation — it's cheaper to agree on the shape before the code exists.
- **The protocol is a contract.** Anything in [`docs/PROTOCOL.md`](docs/PROTOCOL.md)
  is binding on every client. A change there needs the document updated in the
  same pull request, and — if it touches the wire format — an explicit note on
  how old clients and old servers behave against the new one (see SRV-10 in
  [`docs/ROADMAP.md`](docs/ROADMAP.md)).
- **Keep the build clean:**

  ```sh
  go build ./...
  go vet ./...
  go test ./...
  ```

  All three should pass before you push. There is no CI yet, so these are run
  by hand.

- **Match the surrounding code.** Comment density, naming and idiom in this
  repository are fairly consistent; comments explain *why* an approach was
  chosen, not what the line does. A patch that reads like the code around it
  needs no style discussion.
- **Non-obvious decisions belong in [`docs/design/`](docs/design/)** — one file
  per topic, covering what was chosen, what was rejected, and which trade-offs
  were accepted, linked from the roadmap entry.
- **Security.** Please do not open a public issue for a vulnerability in the
  cryptography, the authentication scheme, or federation. Report it privately
  to <info@behringer24.de> first.

## Contributor licence agreement

Every non-trivial contribution to this repository requires that you accept the
agreement below. It is short, and it does one thing that the AGPL alone does
not: it lets the copyright in the codebase stay undivided, so the licence can
still be changed later without having to track down and ask every person who
ever contributed.

### Why this project asks for it

Freizone Server is AGPL-3.0 today, and the intention is that it stays free —
permanently and without conditions — for anyone running it for themselves,
their family, a club, or a non-profit organisation.

What is deliberately being kept open is the possibility of different terms for
**commercial deployments**. The shape that is currently intended:

- Running a server for yourself, your family, a club, a non-profit
  organisation, or any other non-commercial purpose stays free — no threshold,
  no conditions beyond the AGPL.
- A for-profit organisation running a server for its own staff would need a
  paid commercial licence above 10 accounts registered at the same time —
  every account, including any used by bots or integrations, since the server
  has no way to tell those apart. Below that it stays free as well.
- Operating a server that end users pay for access to would not be permitted at
  all — that is an exclusion rather than a price.

Nothing here has been decided or drafted yet, and any actual licence text would
be considerably more precise than that summary. But it is the shape this is
meant to take, and it is written down so you can weigh it before contributing
rather than afterwards. Deciding it later is only possible while the rights in
the whole codebase are held in one place — accept a single contribution without
this agreement, and that option is gone for good, because relicensing would
then need the agreement of every contributor individually.

So this is not a formality. If that intent is not something you want to
contribute to, that is an entirely reasonable position, and it is better that
you know it before writing the patch than after.

### What you keep

You keep the copyright in your own work, and an unrestricted right to use it
however you like, including in other projects and under other licences. This
agreement takes nothing away from you; it adds a permission for the maintainer.

### The agreement

By submitting a contribution to this repository, you agree to the following,
for that contribution and for any future contribution you make here:

1. **Grant of rights.** You grant Andreas Behringer an exclusive, worldwide,
   perpetual, irrevocable, transferable and sublicensable right to use,
   reproduce, modify, adapt, translate, publish, distribute, and otherwise
   exploit your contribution, in whole or in part, alone or combined with other
   work, in any form and by any means whether known today or developed later,
   and to license it to third parties under any terms — including terms
   differing from the licence this project uses at the time you contribute.
   Where the applicable law does not permit copyright itself to be transferred
   (as under German law, § 29 UrhG), this is a grant of exclusive rights of use
   to the fullest extent that law permits.
2. **Licence back to you.** You retain a non-exclusive, worldwide, perpetual,
   irrevocable right to use, publish and license your own contribution for any
   purpose, under any terms, without restriction and without needing anyone's
   permission.
3. **You are entitled to grant this.** You confirm that the contribution is
   your own work, that you have the right to grant the rights above, and that
   it does not knowingly infringe anyone else's rights. If you wrote it in the
   course of employment or under a contract that might assign rights to someone
   else, you confirm that your employer or client has agreed to this, or that
   the contribution falls unambiguously outside that scope. (Under German law,
   rights in software written by an employee in the course of their duties pass
   to the employer automatically — § 69b UrhG — so this matters more often than
   people expect.)
4. **Patents.** To the extent your contribution is covered by a patent you own
   or control, you grant a perpetual, worldwide, non-exclusive, royalty-free
   licence to that patent, as far as is necessary to use, distribute and
   sublicense your contribution as part of this project.
5. **No warranty.** Your contribution is provided as-is. Except where the law
   provides otherwise, you give no warranty and accept no liability for it.

### Small changes

Fixing a typo, rewording a comment, correcting a broken link or reformatting
existing code does not need this. There is no original creative content in such
a change, so there is nothing to license.

### How to accept it

Include this line in the description of your pull request:

> I have read CONTRIBUTING.md and I accept the Contributor Licence Agreement in
> it, for this and all my future contributions to this repository.

Your GitHub account and the pull request itself are the record. If a signing
bot is set up later, it will replace this step; anything accepted this way
stays valid.

If you are contributing on behalf of a company, or anything above does not fit
your situation, get in touch before you start — open an issue, or write to
<info@behringer24.de>. It is far easier to sort out beforehand.
