# Security Policy

Freizone is an end-to-end-encrypted messenger, so a vulnerability in the
cryptography, the authentication scheme, or federation can have real
consequences for the people running and using a server. Reports are taken
seriously and are welcome.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.** Public
disclosure before a fix exists puts every operator running the affected code at
risk.

Instead, report it privately:

- Email **<info@behringer24.de>**, or
- Use GitHub's **“Report a vulnerability”** button under this repository's
  **Security** tab (Privately report a vulnerability), which opens a private
  advisory visible only to the maintainer.

This is the same private channel described in
[`CONTRIBUTING.md`](CONTRIBUTING.md); it applies with particular force to the
cryptography, the authentication scheme, and federation.

### What to include

The more of this you can provide, the faster a report can be confirmed:

- A description of the issue and why you believe it is a security problem.
- The affected version or, better, the exact commit (`git rev-parse HEAD`).
- Steps to reproduce, or a proof of concept, if you have one.
- The impact you think it has, and any conditions required to trigger it
  (for example: requires a registered account, requires federation enabled).

If you are unsure whether something is a real vulnerability, report it anyway
and let it be assessed — a false alarm costs far less than a missed one.

## What to expect

This is a small project without a dedicated security team, so responses are
best-effort rather than bound by a formal timeline. A report sent to the
address above will be acknowledged and investigated, and you will be kept
informed as it is confirmed and fixed.

Freizone does not run a paid bug bounty program and cannot offer monetary
rewards. What a valid report earns instead is credit in the fix or release
notes, if you would like it — the recognition, not a transaction. If you would
rather stay anonymous, that is respected too.

Please give a reasonable window for a fix to be prepared and released before
disclosing an issue publicly.

## Supported versions

Freizone Server is pre-1.0 and moves in a single release line; there are no
long-term-support branches. Security fixes land on the latest release, so the
supported version is always the **most recent release** (see
[`docs/CHANGELOG.md`](docs/CHANGELOG.md)). Running an older build means running
without later security fixes — upgrade to pick them up.

## Scope

This repository is the **server**. The Android app and the push gateway live in
their own repositories; a vulnerability specific to one of those is best
reported there, though when in doubt the contact above will route it.
