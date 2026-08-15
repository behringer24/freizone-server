# Design: Forward/backward compatibility as a standing constraint

Status: **ongoing policy** · Roadmap: [SRV-10](../ROADMAP.md)

(Renumbered from SRV-12 on 2026-07-30 to close an accidental gap in the
codes; SRV-10 and SRV-11 had never been issued. Older notes or commit
messages may still say SRV-12.)
Federation means any app-version/server-version combination is permanently
in the field — a new feature must degrade gracefully rather than assume the
peer app, the user's own server, or a remote federated server already knows
about it. Policy (see also `freizone-claude/freizone-shared.md`): capability
is *discovered*, never assumed, via explicit status fields (`GET
/v1/server-status`'s `federation_enabled`, `blobs_enabled`, `max_blob_bytes`)
or by whether an optional response field is present at all — an absent
field falls back to its documented default (precedent: a pre-federation-flag
server omits `federation_enabled`, treated as `true`) rather than crashing
or silently misbehaving. When a feature genuinely isn't available on the
other side, either hide the affected UI or tell the user plainly why (e.g.
"this contact's app can't receive images yet") — never fail silently.

A **baseline feature set needs no per-call capability check**: everything
already shipped and in the field, only newer features need a discovery step.
Attachments are the deliberate exception to that, even though they have
shipped — not because they are new, but because the server that has to
support them is the *recipient's*, which this client never controls and
whose operator may have them switched off or capped differently (see the
`blobs_enabled` discussion below). "Already shipped" only makes something
baseline when it is a property of *our* side.

Already following this pattern: `federation_enabled`'s absence-means-true
default (consumed in `app_session.dart`); and the `attachments` list in
`MessageContent` (freizone-app), which was carried as a reserved, always-empty
field from the day the v1 envelope was introduced — so when APP-04 finally
filled it, no format change was needed and builds predating it still render
the caption instead of failing to parse.

`blobs_enabled`/`max_blob_bytes` were the first test of this pattern for a
capability that isn't just on/off but carries a numeric limit, and they went
unconsumed for a while after SRV-07 shipped: APP-04's first version simply
assumed attachments worked. Now closed — the app reads both, and does so
from the **recipient's** server rather than its own, since that is where a
blob is stored. A peer whose server has attachments off gets no picture
button at all, and one over the size cap is refused with the actual limit
named instead of a bare `413`. An unreachable or erroring status call means
*unknown*, never *unsupported*, so the feature isn't hidden by a hiccup.

Note the default differs from `federation_enabled` on purpose: an absent
`blobs_enabled` means **off**, because a server that doesn't advertise the
field predates SRV-07 and has no blob endpoints — whereas absent
`federation_enabled` means on, because federation predates its own flag.
The rule is "fall back to what that specific field's absence actually
implies", not one global default.

**Still worth doing:** a pass over existing endpoints/UI to check none of
them silently assume a capability instead of checking for it — overdue now
that groups (SRV-01) already shipped without one, and worth finishing before
multi-device (SRV-02) grows the surface further still.
