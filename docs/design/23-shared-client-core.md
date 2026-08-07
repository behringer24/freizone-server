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
preference for compact builds. Measured rather than estimated, on
`android/arm64` with `-buildmode=c-shared`, by building the same probe with and
without `pkg/client`:

| | size | |
| --- | --- | --- |
| probe without `pkg/client` | 2.59 MB | |
| probe with `pkg/client` | 9.63 MB | **+7.04 MB** |
| the real core as shipped today | 5.96 MB | |
| projected with `pkg/client` | ~13 MB | +118% |
| release APK today | 78.1 MB | |
| projected | ~85 MB | **+9%** |

The honest headline is the last row, not the first: the core more than doubles,
but what a user downloads grows by about a tenth, once, and Play ships per-ABI
splits so it is not paid twice. Notable, not disqualifying.

Two corrections this measurement forces:

- **The "pure Go avoids C friction" argument above is weaker than it reads.**
  The core is already cgo — it cannot be built without a C toolchain on any
  platform — so compiling one more C library is the same class of problem, not
  a new one. Pure Go still avoids a second thing that can break per platform,
  which is worth something, but it is not the decisive argument it was written
  as. `mattn/go-sqlite3` links the real SQLite and is materially smaller; it has
  not been measured here.
- **The decision is cheap to defer and cheap to reverse.** Both drivers sit
  behind `database/sql`, so swapping is the import, the driver name and the
  pragma syntax in one DSN string — a single function in `store.go`, not a
  rewrite. The format on disk is plain SQLite either way. So this does not have
  to be settled before the reset release after all; only before anyone relies
  on the file being readable by a specific driver, which nothing does.

**The wire protocol does not change.** [`PROTOCOL.md`](../PROTOCOL.md) is
untouched: this is a rearrangement of client-side implementation, nothing more.
The local storage format is not a wire format and is free to change. Every
stage is still exercised against an older counterpart, per the standing
constraint in [10-compatibility.md](10-compatibility.md) — an arbitrary mix of
app and server versions is in the field permanently.

## Three rules the transcript turned up

Modelling the history layer surfaced decisions that look like details and are
not, each one a place where a reasonable-looking schema diverges from the app.

**Arrival order, not time order.** The app appends to a list and never sorts it
— the only `sort` calls in the codebase order chat *lists* by activity, not
lines within a transcript. So a message decrypted late, carrying an older
timestamp, belongs where it arrived rather than where its clock says. The table
therefore has an explicit `seq` and is only ever read by it. Ordering by
`timestamp` would have looked more natural, quietly rearranged exactly the
transcripts that had something go wrong, and given system lines — which have no
sender clock at all — nowhere sensible to sit.

**A pending send is settled when the database is opened, not when it is read.**
The app's rule is that a message written while in flight loads back as failed,
because nothing is in flight in a process that no longer exists. Transcribing
that as "read `pending` as `failed`" is the obvious move and is wrong: a send
that is genuinely running *in this process* would report as already failed the
moment anything drew the bubble. The transformation belongs at `Open`, which is
where "a process that no longer exists" is actually established, and where the
app's own load-from-file happens to do it too.

**`chat_id` is one namespace for peers and groups.** Not a shortcut: the app
says both ids are 21-character bech32m strings differing only in a version
marker, "so anything keyed by this needs no second form". Following it means the
transcript, its attachments, its pins and its per-recipient deliveries all work
for a group already, and stage 5 has only the group's signed fact set left to
add rather than a parallel set of tables.

With that, `local_state.dart` is covered except for three maps —
`pendingGroupEvents`, `groupSnapshotDebts`, `groupPeerStateHashes` — which are
group *coordination* rather than storage and belong with the rest of the group
orchestration in stage 5.

## Where the compatibility rule actually lives

[10-compatibility.md](10-compatibility.md) says availability is discovered,
never assumed. Moving `GET /v1/server-status` into the core turns that from a
principle into a decoding problem, because **two of its silences mean the
opposite of Go's zero value**:

- `federation_enabled` absent means **true**. A server predating the switch
  federates, and reading silence as "off" strands every conversation with one.
- `max_blob_recipients` absent means **1**, not unlimited. An older server
  ignores the extra recipients, stores the blob for the first one and still
  answers `201` — so a sender that assumed otherwise would deliver a group
  picture to exactly one member and report success.

Decoding straight into a plain struct gets both wrong, silently, and only
against servers nobody is testing on. `ServerStatus` therefore decodes through a
wire type with pointers wherever absent and false differ, and applies each
documented default explicitly. The tests assert the older-server case as its own
scenario rather than as an afterthought — an explicit `federation_enabled:false`
from an operator who switched it off has to survive too, which is what makes the
pointer necessary rather than a default value sufficient.

The same care goes into telling two failures apart that a single "request
failed" would merge: a Freizone server refusing something answers JSON and
becomes an `APIError` carrying its own code, while a host answering HTML or
nothing becomes a `NotFreizoneServerError`. That distinction is not tidiness —
"the server said no" and "you typed the wrong address" need different words in
front of a user, and the second is what a mistyped domain or a parked page
actually produces.

## The stream, and why it is one channel

`Client.Stream` returns a single channel of a tagged union — connected,
message, disconnected, failed — rather than one channel per concern. In Go that
is merely fine; the reason it is *right* is the FFI wrapper, which can only
offer a blocking "give me the next event" call across the boundary. Several
channels would have to be multiplexed back into one there, putting the
multiplexing on the side least able to test it.

Events are dropped when the buffer is full rather than blocking the reader.
A consumer that has gone away must not be able to stall the connection, because
a stalled connection is indistinguishable, from the server's side, from a client
that is still listening.

The reconnect policy is the app's, including the part that only gets written
after real failures: **two distinct regimes**, not one backoff. A stream that
came up and then ended is a resume from background or a brief blip, so it
reconnects after ~500ms *with the backoff reset* — the difference between a
resume feeling instant and feeling broken. A stream that never came up backs off
exponentially from 3s to 30s with ±20% jitter, so an offline home server is
probed ever less aggressively instead of hammered, and several sessions against
one server do not return as a thundering herd.

One detail transcribes rather than translates. The app closes its per-attempt
HTTP client in a `finally` because otherwise every backoff retry against a
dead-but-routed host leaves another dial in SYN-SENT, clearing only on the
OS-level TCP timeout minutes later. The Go equivalent is a cancellable context
per attempt, cancelled on every exit path, with the connect deadline driven by a
timer that cancels it. Note what the deadline covers: *reaching* the stream, not
reading from it. A healthy stream is idle for as long as nobody writes to the
account, with only a heartbeat comment every 25 seconds — a read deadline would
kill exactly the connections that are working.

On the FFI side of that channel, four choices are worth recording. The bridge
lives in a **cgo-free** file next to `logic.go` for the reason that file already
gives — only the `//export` wrappers need cgo, so the handle lifecycle and the
poll semantics stay coverable by ordinary `go test` instead of only by running
the app. `CorePoll` returns a **batch**, because one crossing per event is pure
overhead exactly when a reconnect has just delivered a backlog. Event kinds cross
as **strings**, not the core's integer enum, so a Dart build and a core build
that disagree about the set fail visibly on an unknown name rather than silently
reinterpreting a number. And `disconnected` deliberately carries **no error
text** even when the core has one: only a failed connect attempt is meant to
reach the user, and a clean end just reconnects.

Two behaviours on the message endpoints are worth stating because the naive
reading of each is wrong. `SendMessage` treats **409 as delivered**: the server
de-duplicates by message id, so a retry's second copy being refused is the retry
working, and reading it as failure is how a client ends up either sending twice
or reporting a delivered message as failed. `AckMessage` treats **404 as
success**, because something already deleted is deleted, and the acknowledgement
is best-effort by design — a lost one means redelivery, which the duplicate
check absorbs.

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

## What stage 0 found

The vectors live in `pkg/conformance` (schema and loader in `vector.go`,
authored cases in `generator.go`, committed data under `testdata/`). Both
clients run them: `cmd/devclient/conformance_test.go` here, and
freizone-app's `test/receive_path_conformance_test.dart` there.

Nine vectors. **The app passes all nine. This client passes four.** That is the
measurement the item was worth doing for, and it points the migration in a
direction the LOC counts alone did not: `pkg/client` is not "extract devclient
and tidy it up". On every rule where the two disagree, the Dart implementation
is the correct one, so the app is the specification and this client is the
thing being brought up to it.

Passing, and worth stating because they are the parts that did *not* drift: first
contact, the simultaneous-establishment tie-break in both directions, and the
SRV-17 deliberate-re-key override. The hard, recently-designed rules are
consistent across both implementations.

Failing, each a real defect in this client rather than a stylistic difference:

| Vector | What this client does |
| --- | --- |
| `redelivered-initial-must-not-reset-session` | No processed-message-id tracking at all, so a redelivered first envelope is processed again: the responder step re-runs and the rewound session replaces the advanced one |
| `duplicate-ordinary-message-is-not-desync-evidence` | The ratchet *does* reject the duplicate, but `decryptIncoming` discards that error for a generic "no session decrypts this message" |
| `authentication-failure-is-desync-evidence` | Same cause: `pkg/ratchet` classifies it and `SuggestsDesync` reports true, but the error is wrapped with `fmt.Errorf` and no `%w`, so the code is lost — and there is no desync accounting to feed it into (SRV-03 is app-only) |
| `failed-responder-attempt-must-not-burn-prekey` | `respondToNewSession` deletes the one-time prekey *before* `RespondToSession` is called, so any initial that fails to decrypt still costs a prekey |
| `legacy-rekey-inferred-from-plaintext` | A prekey block without the SRV-17 field is always treated as the racing case; the app additionally infers a re-key from the content being a `v:3` re-key signal, a plaintext version this client does not model at all |

The two failures sharing a cause are the sharpest evidence for this item.
`pkg/ratchet` already exports `FailureCode` and `SuggestsDesync` precisely so a
caller can tell a harmless redelivery from a broken session — and one of the two
callers throws that away. Nothing about the primitives caused it; it is a
decision made in the orchestration layer, in the copy that nobody was testing.

**Known failures are recorded rather than left red.** `knownDivergences` in the
test names each one with its cause, so `go test ./...` stays green while the
defects stay visible. The list is self-cleaning in both directions: a listed step
that starts conforming fails with "remove it from the list", and a listed key no
vector produces fails too. Emptying it is therefore a green signal that
`pkg/client` has taken over, not a judgement call.

Two honest limits of what was built:

- **One claim did not survive contact with the vector.** The redelivery case was
  expected to break the conversation permanently. It does not: X3DH is
  deterministic, so the rebuilt session derives the same chain, and with the
  receiver having sent nothing in between there is no DH ratchet step to lose.
  The redelivery is a real defect — a message re-decrypted and re-shown, skipped
  keys discarded — but recoverable in this scenario. Proving worse needs
  send-side modelling, which the receive-only format cannot express. The vector
  says so in its own description rather than overclaiming.
- **Not every rule is observable where the vectors look.** The app satisfies the
  desync-evidence assertions because `CoreErrorCode.suggestsDesync` carries the
  ratchet's classification through — but the act of *recording* that evidence
  lives in `AppSession._giveUpOnEnvelope`, one layer above the extracted
  `processIncomingMessage` the vectors drive. So the vectors pin the
  classification, not the accounting built on it. Worth knowing when `pkg/client`
  draws its own boundary: the pure function that exists today is not yet the
  whole decision surface.

Getting the app half running needed a host build of the core, which is worth
recording as a result of its own. `FreizoneCoreBindings.open()` loaded the
shared library only on Android and fell back to `DynamicLibrary.process()`
elsewhere, which finds nothing in a test process — so **every one of the 8,700
lines in the app's `lib/state/` was untestable on a development host**, and
`processIncomingMessage`, its most protocol-critical function, had no coverage
at all while 5,000 lines of Dart tests covered everything that needs no core.
The fix was small: a C toolchain (mingw-w64 on Windows, since the core is cgo
and the Android NDK's clang only targets Android), a `native/build_desktop.ps1`
beside the existing Android one, and a test-only `libraryPath` parameter that
leaves the production loader untouched. The vectors were the occasion, but the
capability outlasts them — that layer can now be tested at all.

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
