# Design: Shared protocol client core

Status: **planned** · Roadmap: [SRV-23](../ROADMAP.md) · Also affects:
freizone-app, future freizone-bot

Freizone has **two client implementations of the same protocol today**, and
nothing forces them to agree. `cmd/devclient` is 3,236 lines of Go
(`chat.go`, `session.go`, `prekeys.go`, `message.go`, `group.go`,
`group_send.go`, `group_watch.go`, `blob.go`, `state.go`, `client.go`);
freizone-app carries roughly 12,400 lines of non-UI Dart, of which
`lib/state/app_session.dart` alone is 4,461 — send/receive pipeline, ratchet
session persistence, group snapshot debt, receipt retry, prekey lifecycle, SSE
reconnect, federation locks. Both sit on the same primitives (`pkg/ratchet`,
`pkg/group`, `pkg/wire`, `pkg/httpsig`, `pkg/address`, `pkg/attest`,
`pkg/devicecert`, `pkg/mnemonic`), so the cryptography is shared. The
*orchestration around it* is written twice.

That is the defect this item fixes: **`pkg/client`, one protocol client
implementation, consumed by every shell.** (Measurements taken 2026-08-07,
app at 0.19.0+23, server after 0.15.0.)

**The question that surfaced it was about UI frameworks, and the answer turned
out not to be about UI frameworks.** Asked whether to drop Flutter and build
two genuinely native apps — Kotlin and Swift — the honest blocker is not
Flutter's overhead. It is that half the protocol lives in Dart, so "two native
apps" would mean hand-writing the session lifecycle a second and third time.
Divergence there does not produce cosmetic bugs; it produces undecryptable
messages and broken sessions, in a place where the project has exactly one
Android test device and no iOS device at all. Once the core owns the state
machine, each additional UI is view code over a single implementation, and the
question becomes cheap to answer either way. The sequencing is therefore: core
first, UI decision after. Flutter stays in the meantime because it exists and
keeps a working Android build in front of testers throughout.

## What the core owns

```
pkg/{ratchet,group,wire,httpsig,address,attest,devicecert,mnemonic}
        ↑ primitives — unchanged
pkg/client/                          ← protocol orchestration
        ↑                ↑                       ↑
   cmd/<cli>      freizone-app/native      freizone-bot
   (dev/test)      (cgo shell)              (own repo, later)
                        ↓ libfreizonecore.so / .xcframework
                 freizone-app/lib  ← UI + platform shell
```

`pkg/client` owns state, persistence, network and every protocol decision. A
shell owns what is irreducibly local to it: filesystem location, notifications,
foreground signalling and UI in the app; external control channels in the bot.

**Network ownership comes early rather than last** — deliberately. The moment
the core holds HTTP and the SSE stream, everything above it is thin, and the
later native-UI question loses its main risk at the earliest possible point
rather than the latest.

## Three consumers, and what they force

The third consumer is not hypothetical: a Go-based **freizone-bot** is planned,
letting other tools push messages into Freizone or take part in chats via AI or
commands — an IoT bridge, driven over external channels. `cmd/devclient` is the
seed of it, so it stops being a developer tool and becomes a product; the name
goes with that change. [16-broadcast.md](16-broadcast.md) already assumes it,
since a broadcast list is meant to carry notifications from exactly such bots.

Three consumers with different needs are the standard route to an API that
suits none of them, so the constraints are stated up front rather than
discovered:

**`pkg/client` is idiomatic Go.** Channels, `context.Context`, Go types, Go
errors. No JSON envelope, no handle integers, no FFI residue — those belong
exclusively to `freizone-app/native`, which adapts the core's event channel into
the blocking `CorePoll` call Dart needs. This ordering matters and is easy to
get backwards: the FFI boundary already exists and is the loudest caller, so
shaping the core around it is the tempting move. It would hand the bot a
contorted API for the convenience of a wrapper that is supposed to absorb
exactly that awkwardness.

**Goroutine-safe, with real concurrency.** The app is effectively single-user
and serialised; a bridge relaying for many devices sends concurrently. That is a
requirement on the core, not something a shell can add afterwards.

**Several identities per process.** One `*client.Client` per account, no package
globals, no implicit "current account". The app uses one, the bot uses many.

**No mobile lifecycle vocabulary in the core.** No foreground/background, no
notification concepts. The bot has neither, and encoding them would bake in
assumptions that are simply false for it.

**Nothing bot-specific in the core either.** Command parsing, AI integration,
IoT protocol adapters, webhooks, bot configuration — all of that is
freizone-bot's. The core knows the Freizone protocol: nothing above it, nothing
below it. The boundary is written down here because the bot work will
inevitably lean on it.

## Persistence is replaced, not inherited

Local state today is a single indented JSON file, rewritten in full on every
change, with no partial reads — `lib/state/app_session.dart`'s store mirrors
`cmd/devclient/state.go`. Keeping that format was previously mandatory. It is
not any more: the app is in closed beta with a small tester circle, and a
one-time reset is acceptable. That removes the most expensive and riskiest part
of the migration — no format compatibility, no migration path, no golden-file
gate — and it is the only reason the persistence layer can be chosen on merit.

**SQLite via `modernc.org/sqlite` (pure Go).** Partial reads, indexes and
transactions are the point: a chat list must not load the entire history to show
a last-message preview. Pure Go rather than `mattn/go-sqlite3` because the
c-shared build already cross-compiles to `android/arm64` and `android/amd64` and
will have to reach `ios/arm64` — a second C dependency inside the NDK build, and
then inside Xcode, is precisely the friction that makes the iOS step expensive.
The server already runs on SQLite, so the pattern is familiar in-house.

**The accepted cost is binary size,** which sits in tension with the project's
preference for compact builds. It is therefore measured rather than estimated:
reporting the per-ABI growth of `libfreizonecore.so` is part of accepting the
first stage. The decision stays reversible until the reset release ships, and
not cheaply afterwards — a later change of format would cost testers a second
reset.

**The wire protocol does not change.** [`PROTOCOL.md`](../PROTOCOL.md) is
untouched: this is a rearrangement of client-side implementation, nothing more.
The local storage format is not a wire format and is free to change. Every
stage is still exercised against an older counterpart, per the standing
constraint in [10-compatibility.md](10-compatibility.md) — an arbitrary mix of
app and server versions is in the field permanently.

## Sequence

`cmd/devclient` is the foundation, not a drop-in. It knows re-keying, receipts,
snapshots, the outgoing queue and federation; it has almost nothing for session
recovery, locally blocked peers or attachments, all of which the Dart side
implements. Each stage is *extract, then raise to the app's level*.

| Stage | Content |
| --- | --- |
| 0 | Conformance fixtures: recorded envelope sequences (first contact, re-key, out-of-order, snapshot mismatch, attachment) both sides must answer identically |
| 1 | `pkg/client` with state and the new persistence |
| 2 | Core takes over HTTP and SSE |
| 3 | Receive pipeline, including the re-key/recovery decision ([03-session-recovery.md](03-session-recovery.md)) |
| 4 | Send pipeline, outgoing queue, prekey lifecycle |
| 5 | Group orchestration: fan-out, snapshot debt, reconciliation, receipts ([01-groups.md](01-groups.md)) |
| 6 | iOS: core as an xcframework, `ios/` set up — needs a Mac, blocks nothing before it (freizone-app `APP-03`) |

**Stage 0 comes first and alone.** Without recorded protocol behaviour, every
behavioural change in the stages after it is invisible. Note what these fixtures
are and are not: they pin *protocol* behaviour, not the old storage format,
which is being discarded on purpose.

Each stage ships on its own. The app has real testers and feature work cannot
stall for the length of a rewrite. The CLI shell stays green throughout as the
second consumer — a core that only works with Flutter next to it has missed the
point — and the bot, being headless and scriptable, will make a better
end-to-end harness for federation and group tests than driving a Flutter app
ever did.

Considered and not done:

- **Two native apps now (Kotlin + Swift), dropping Flutter.** The obstacle is
  not the discarded Dart, which the beta status makes affordable. It is that
  reimplementing the session lifecycle per platform puts semantic divergence in
  the one place where it silently destroys messages, with no iOS device to catch
  it. Revisit once the core owns the state machine — the cost then is view code,
  not protocol.
- **Keeping the monolithic JSON store and merely moving it to Go.** Cheapest
  first stage, and it preserves the O(n) rewrite per message plus the inability
  to read part of the state. With compatibility no longer binding, carrying the
  format forward would be paying its cost for none of its benefit — and swapping
  it later would cost a second reset.
- **Shaping `pkg/client` around the existing FFI JSON envelope.** It is the
  loudest caller and the shape is already proven for the primitives, but the
  wrapper exists to absorb that awkwardness, not to spread it into the library
  every other consumer links against.
- **Go→Dart callbacks (`NativeCallable`) for stream events.** A blocking
  `CorePoll` driven from a Dart isolate gets the same result with the existing
  synchronous marshaling (`jsonCall` / `toCResult` in the app's `native/`) and
  no new machinery on the boundary.
- **A separate repository for `pkg/client`.** The protocol belongs in the core
  repo, and cross-repo module versioning would be ceremony for a single
  maintainer. freizone-bot does get its own repo — a product with external
  control channels has no business under `cmd/` here — and consumes this as an
  ordinary Go module.
- **Renaming `cmd/devclient` as part of the extraction.** Correct eventually,
  and part of the bot work; doing it in the same change as the extraction makes
  the diff unreadable.
