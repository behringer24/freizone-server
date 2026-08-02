# Design: Authenticating the prekey-bundle claim

Status: **done** · Roadmap: [SRV-04](../ROADMAP.md)

The prekey-bundle claim (`router.go`) was unauthenticated — a small
forward-secrecy risk, not a confidentiality problem: anyone could drain a
device's one-time-prekey pool by claiming repeatedly, after which every new
session with that device started without one until it next topped up.

**Shipped 2026-08-02**, in the two stages that made it non-breaking.

**Stage 1, server.** `authenticateBundleClaimant` (`internal/api/prekeys.go`)
accepts either credential the protocol already has, and treats their absence as
a legitimate anonymous request:

- a body carrying the claimant's own self-certifying chain, verified by the
  existing `verifyFederatedSender` — the only form available to a claimant whose
  account lives on **another** server, which has no local row to look up;
- an ordinary §3 device signature for a claimant registered here;
- neither → anonymous.

An anonymous claim still gets `200` and the full bundle, just **without** the
one-time prekey. That is the shape an empty pool already produced, and every
client — app, devclient, the responder side of X3DH — already handled it, which
is exactly why this could ship before any client change: an old client keeps
working at precisely the forward-secrecy level it had before, while the pool it
could have drained is protected. Requiring authentication outright would have
stopped every deployed client from starting new conversations.

Credentials that are *present but invalid* are refused, never downgraded to
anonymous — that would turn a client bug or a skewed clock into a silent,
months-long loss of forward secrecy that nothing reports. `one_time_prekey_omitted`
(`"pool_empty"` / `"unauthenticated"`) makes the two cases distinguishable;
older clients ignore it.

The **federation switch** governs the foreign form: with federation off the
inline claim is `404`, like a federated message, since that sender could not
deliver the message the bundle is for anyway. A local claim is unaffected —
turning federation off must not stop a server's own users talking to each other.
Blocklisted senders are refused too, inherited from `verifyFederatedSender`.

Closes a second hole not in the original entry: a claim that dropped the pool
below the low-water mark fired a push wake, so *anyone* could make this server
wake an arbitrary device on demand. Only an identified claimant consumes a key
now, so only they can trigger it.

**Stage 2, clients.** freizone-app signs same-server claims with its device key
and presents the inline chain for federated ones (`claimFederatedPrekeyBundle`),
deciding between them exactly as the send path does. It logs loudly if a server
ever answers `"unauthenticated"`, since that can only mean its own credentials
were refused. `cmd/devclient` does the same. `auth.Middleware.TryAuthenticate`
was exported for this — the non-writing variant of `Require`, deliberately
documented as being for this one route.

Verified live against the local two-server stack: an anonymous claim returns a
usable bundle with `one_time_prekey_omitted: "unauthenticated"`; a signed
same-server claim gets a key and the resulting envelope carries its
`one_time_prekey_id`; a federated first contact across servers does the same
with the inline chain (never-registered sender, `200`). The federation-off case
is covered by test rather than live, since flipping it on the local instance
would have meant resetting its setup token.

**Not done, and deliberately:** no third stage that rejects unauthenticated
claims outright. It buys nothing over withholding the key — the pool is already
safe — and would break old clients for symbolism. Also no per-claimant rate
limit: identifying the claimant makes drain attributable and bounded by the cost
of holding an account, which is the point; a limit would add state for a much
smaller marginal gain. `bundleClaimant.AccountID` is carried anyway, since that
is what such a limit (or a log line naming who drained a pool) would need.
