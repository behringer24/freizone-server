# Design: Attested servers

Status: **planned** · Roadmap: [SRV-19](../ROADMAP.md) · Client side: freizone-app
[APP-22](https://github.com/behringer24/freizone-app/blob/master/docs/ROADMAP.md)

Some servers are run in agreement with the project. Users should be able to see
that, and — the part that makes it a design problem rather than a settings
toggle — the signal must not be forgeable by whoever operates the server being
described. So it is a signed statement about a server, not a flag the server
sets:

| Field | Meaning |
| --- | --- |
| `v` | format version |
| `domain` | the server this is about |
| `tier` | `community` · `commercial`, open-ended (below) |
| `subject` | display name |
| `seats` | advisory account-count ceiling, `0` = unspecified/unlimited (Version2) |
| `issued` / `expires` | validity window |
| `issuer_key` | which issuer public key signed this |

plus an Ed25519 signature over a canonical encoding of exactly those fields.
An operator configures the resulting token via `FREIZONE_ATTESTATION`; the
server serves it verbatim on `GET /v1/server-status`; the client verifies it.

**Nothing is online, and that is the central property.** Verification is a
signature check against issuer public keys compiled into `pkg/attest`. There is
no revocation list and no status endpoint to consult, because either would
reveal to a third party which user contacted which server and when — in a
project built on metadata avoidance that is disqualifying regardless of how
convenient it would be. Withdrawal is therefore expiry and nothing else, which
makes the lifetime the only lever there is. It also means an issuer key can stay
on offline media rather than on a machine that answers requests, which is a
security property, not just an operational one.

**The attestation binds the domain, not the server's identity key.** Binding
`store.InitRelayIdentity`'s key was the first sketch, on the reasoning that a
token would then be uncopyable. It buys almost nothing: the client already
checks the domain against the host it is talking to, so a stolen attestation is
useless elsewhere, and an attacker holding TLS for the right domain can simply
run their own server there. What it costs is concrete — that key lives in the
data directory, so a restore onto new hardware, a lost volume or a reset path
would invalidate the attestation and force a reissue. The domain is the stable
identifier and TLS carries the burden of proof, exactly as in the web PKI.

**The trust anchor is a set.** Each attestation names the issuer key that signed
it, and several issuer public keys ship from the first release even though only
one signs. Adding one later requires a release that reaches every user, which is
precisely what cannot be relied on at the moment that would make it necessary.
The accepted trade-off: with no revocation, a compromised key stays usable until
the attestations it signed expire — bounded by lifetime rather than by release
cadence, with a spare promotable immediately.

**`tier` is an open string.** A client meeting a tier it does not recognise
shows the neutral label rather than nothing: the signature is valid, so
"attested, kind unknown to this version" is the truthful rendering. Falling
silent would make an older app contradict a newer one about the same server,
which a user reads as the badge being unreliable rather than as the app being
old — the standing constraint from [SRV-10](10-compatibility.md).

**`pkg/attest` carries its own permissive licence** inside this AGPL
repository. Third-party clients have to be able to verify a badge without taking
on copyleft, and a verification rule only one implementation may use is not a
verification rule. The secret here is a private key, never the procedure.

Server-side behaviour is deliberately unassertive. The start-up check validates
signature, domain against `FREIZONE_DOMAIN`, and expiry, then **warns** — a
server whose attestation is malformed, foreign or lapsed still starts and still
serves chat, because refusing to boot would turn a cosmetic credential into an
outage. The token itself is not a secret: it is handed to anyone who asks for
server-status, and its safety comes from the domain binding, not from being
hidden.

On the landing page the badge is **presentation only** and cannot be otherwise:
the page is served by the very server it describes, and no visitor verifies an
Ed25519 signature by eye. A public register of attested domains would turn it
into a checkable claim; that is a later question, and the badge is useful in the
app without one.

**Seats (Version2) is advisory, and deliberately never public.** An
attestation can carry an account-count ceiling, shown to the operator's own
admins via `GET /v1/admin/license` alongside the server's actual active-account
count, with a warning once the count passes it. Nothing enforces it — no
registration is rejected, no account blocked — the same "warn, never refuse"
posture the expiry check already takes. It is absent from `GET
/v1/server-status`, the landing page, and any future public register
(freizone-licensing's own roadmap tracks that side): how many accounts a
server has is exactly the kind of fact that turns "a server exists" into "a
server worth attacking", and it tells a visitor nothing about whether to trust
the operator, unlike the attestation itself. `0` means "unspecified" on
purpose rather than getting a separate flag -- a Version1 token (issued before
this field existed) and a deliberately unlimited Version2 one are the same
case for every consumer that only wants to know whether there is a ceiling to
warn about.

Adding it cost a format version, which is the one lesson worth keeping for
whatever gets added after Seats: `pkg/attest`'s wire format is a fixed byte
layout signed as a whole, not a self-describing structure, and `Decode`
rejects any version number it doesn't recognise outright rather than skipping
unknown fields. A field that turns out to matter later is cheap to add only
before real adoption exists to break -- while there are still a handful of
issued tokens and few or no third-party verifiers, not after. Version2 stays
compatible the other direction, though: it can still decode a Version1 token,
reading `Seats` back as `0`.

**What the attestation claims stays narrow.** It says the operator is known to
the project. It says nothing about message security — end-to-end encryption is
identical on every Freizone server, and an attested operator observes no less
metadata than any other. A badge implying otherwise would be actively harmful
here, which is why the client side treats the explanation as part of the feature
rather than as a tooltip.

Considered and not done:

- **A licence service the server queries for its state.** Makes the issuer a
  single point of failure for something visible on every screen, and the
  deployments most likely to want an attestation — a company's internal server —
  frequently have no outbound internet at all.
- **X.509 or a JWT library.** The project already has Ed25519 and its own wire
  formats; a self-describing struct with a detached signature is the whole
  mechanism and stays readable to anyone writing a third-party client.
- **Refusing to start on an invalid attestation.** Fails the wrong way for a
  credential that is decorative by design.
