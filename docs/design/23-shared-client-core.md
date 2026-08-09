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

**Plain files — and it was SQLite first.** That reversal is worth recording in
full, because the reasoning that led to SQLite was wrong in a way that is easy
to repeat.

The original argument was: partial reads, indexes and transactions, plus "the
server already runs on SQLite, so the pattern is familiar in-house". The last
clause is where it went astray. The server has relational, queried,
multi-tenant data. A client has one account, a handful of chats, and an
append-only transcript each — no query has ever been needed. Carrying the
server's answer across to a different problem is what bought a SQL engine to
store a list.

Two measurements ended it. `modernc.org/sqlite`, the pure-Go driver, **cannot
run on android/amd64 at all**: its libc emulation calls the `lstat` syscall,
Android's seccomp filter kills the process, and the app died at startup on every
x86_64 device and emulator. The newest upstream release still does it, and every
other pure-Go driver — `zombiezen.com/go/sqlite`, `github.com/glebarez/go-sqlite`
— is modernc underneath. The cgo driver works and is 2.2 MB smaller, but makes
cgo mandatory for every consumer of this package, which a planned Flutter
desktop client turns from an inconvenience into a cross-compilation matrix.

Worth noting what the market comparison does *not* say. Signal, WhatsApp,
Telegram and Element all use SQLite, and they are right to: they are native apps
whose operating system hands it to them for nothing. The 7–9 MB only existed
because this storage lives in a Go core that has to bring its own.

The store that replaced it keeps one rule, which is the actual defect being
fixed: **nothing costs more as history grows**. The old Dart store rewrote one
JSON file in full per message, and per-chat files rewritten in full would have
been the same defect with more filenames.

| what | shape | what one message costs |
| --- | --- | --- |
| transcript | append-only log per chat | one appended line |
| ratchet session | one small file per peer and kind | that file |
| conversation metadata | one small file per chat | that file |
| handled message ids | in memory, appended to a log | one appended line |
| identity, prekeys, blocks | small files | nothing — they change rarely |

Deletions and send-state changes are appended as their own records naming the
message they refer to, never edited into the line holding it: editing a line in
a text file means rewriting everything after it. That shape also makes a record
arriving long after its message harmless, since it carries an id rather than a
position — and compaction happens on a threshold, never on a write path.

The read side needed the same discipline. A chat list draws one preview per
conversation, and replaying a whole transcript for each would have moved the
same O(n) from the write path to the read path; the preview reads a bounded
window from the end of the log instead.

Crash safety is the pattern the app already relies on: write to a temporary
name, fsync, rename. Its single JSON file has never corrupted anyone's
sessions — the trouble was always the rewriting.

**The accepted cost is binary size,** which sits in tension with the project's
preference for compact builds. Measured rather than estimated, on
`android/arm64` with `-buildmode=c-shared`, by building the same probe with and
without `pkg/client`:

First estimated with a probe, then measured on the real core once it actually
linked `pkg/client`. The estimate was low, which is the reason the acceptance
criterion said *measure*:

| | before | after | |
| --- | --- | --- | --- |
| probe (three packages) | 2.59 MB | 9.63 MB | +7.04 MB, the estimate |
| **real core, arm64-v8a** | 5.96 MB | **15.07 MB** | **+9.11 MB** |
| **real core, x86_64** | 6.40 MB | **15.83 MB** | **+9.43 MB** |
| release APK | 78.1 MB | ~87 MB | ~+12% |

The honest headline is the last row, not the first: the core more than doubles,
but what a user downloads grows by about an eighth, once, and Play ships
per-ABI splits so it is not paid twice. Notable, not disqualifying.

Worth keeping in mind for any future estimate of this kind: a probe that links
fewer packages than the real thing understates the delta rather than matching
it, because what the new dependency shares with what was already there differs
between the two.

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
timer that cancels it. That deadline covers *reaching* the stream, not reading
from it.

**A silence timeout, though, is a different thing, and not having one was a
gap.** A connection can die without saying so — a half-open socket, a network
handover, a proxy dropping it mid-flight — and then nothing notices: the connect
deadline is long over, and a read that will never return does not fail on its
own. The symptom is the worst kind, "messages sometimes just don't arrive", with
nothing in any log to attach it to. `sse_client.dart` had the same gap and it
was inherited faithfully; it is closed here because the reconnect now lives
somewhere it can be tested.

The server makes it safe: it sends a heartbeat comment every 25 seconds, so a
healthy stream is never quiet for longer than that however idle the account is.
An idle timeout of a little over twice that detects a dead connection in about a
minute and cannot fire on a working one. Every line resets it, heartbeats
included — which is the half worth testing, since the fix without that reset
looks perfectly reasonable and tears down every idle stream on a schedule.

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

## What stage 3 settled

`pkg/client` now decrypts. **It passes all nine vectors** — the number that
matters is the comparison: the app nine, this repo's older client four, and the
new implementation nine on its first run. That is not a claim that it is
finished; it is a claim that the four decisions `cmd/devclient` gets wrong are
not inherited, which was the whole risk of "extract the Go one".

Passing on the first run is also the least trustworthy kind of green, so each of
those four was re-broken deliberately to check the vectors bite here rather than
merely load: burning the one-time prekey at lookup time fails
`failed-responder-attempt-must-not-burn-prekey`, dropping the processed-id check
fails `redelivered-initial-must-not-reset-session`, and wrapping the ratchet
error with `%v` instead of `%w` fails `authentication-failure-is-desync-evidence`
on both the code and the evidence assertion at once.

Deliberately **no `knownDivergences` list beside this runner**, unlike
`cmd/devclient`'s. That list exists there to keep a defect visible without
keeping the suite red; here a failure has nowhere to go but a fix, because this
implementation has no history to stay compatible with.

Four decisions the port had to make rather than copy:

- **Failures carry their consequence, not just their cause.** A failed decrypt
  returns a `*DecryptError` holding whether it counts as desync evidence,
  whether this envelope has now been given up on, and whether the evidence
  justifies re-keying — wrapping the ratchet error so `FailureCode` and
  `SuggestsDesync` still work through it. The Dart original spreads those three
  answers across the caller; putting them on the error is what lets the shell
  stay a shell.
- **The evidence is counted per envelope, not per attempt.** One broken message
  retried three times is one broken message. Counting attempts would reach any
  threshold on a single envelope, which is the difference between recovering a
  session and re-keying on every reconnect.
- **`ErrNoSessionMaterial` is desync evidence even though nothing failed.** An
  envelope with no session and no prekey block produces no cryptographic error
  at all — this side's session is simply gone while the peer keeps sending into
  the one they still hold. It is the one desync shape that announces itself
  only by absence, and the case automatic recovery exists for.
- **Group envelopes are decrypted and handed back undigested.** Stage 5 owns
  group state. Until then the ratchet has already advanced and the id is
  already marked, so the caller *must* act on what comes back: dropping it
  loses the facts for good. That is a temporary seam, and it is the only one —
  the one-to-one path is complete here, transcript and all.

The recovery policy moved across as a pure function (`shouldAutoRekey`): the
tie-break on account id, the five-minute grace for the higher id, the
fifteen-minute spacing between attempts. Thresholds and tie-breaks are the part
that is wrong in ways nothing notices, so it stays testable without a session, a
server or a clock to wait for.

What the vectors do **not** cover is the larger half of this stage, and it has
its own tests: the notification rules (a stranger's first message interrupts
once, their follow-ups do not, an open chat is silent), a blocked peer's message
being decrypted and then dropped without a trace while still counting as
processed, receipts as monotonic watermarks in the sender's clock domain that
never create a conversation, and the transcript marker for an accepted re-key —
which must not touch last-activity, because recovering a session is maintenance
and must not jump the chat to the top of the list. Those rules are the quiet
kind: nothing fails when they are wrong, a message simply never appears, or
interrupts someone it should not have.

## What stage 4 settled

The core can now hold a conversation on its own: resolve an address, publish
and claim prekeys, establish a session, send, retry, confirm, and re-key.
`send.go`, `prekeys_api.go` and `peers_resolve.go`, and a stub server the tests
run two real clients through.

**Sending is not receiving with the arrows reversed, and that asymmetry drives
the file.** Receiving is forgiving: an envelope that will not open can be
retried, and the ratchet refuses to move until one does. Sending is not —
encrypting *advances* the ratchet, and an advance committed for a message the
peer never received burns a message number they will never see used. They
observe a gap, which their ratchet bridges only so far before it counts as a
desync. So: no advance is kept unless the envelope carrying it left the
building.

That rule also makes retrying safe in the case that looks worst. A POST can
fail *after* the server stored the message — a response lost on the way back is
indistinguishable from a send that never landed. Because the failure rolled the
ratchet back, the retry re-encrypts under the same message number, and if the
first copy did arrive the peer's ratchet rejects the second as the duplicate it
is. The de-duplication that makes a retry safe is therefore the rollback, not
the wire id, which is fresh on every attempt.

**The test caught a real defect in that rule, and it was mine.** `Session`
unmarshals a fresh value on every call, so reading it once and handing the same
value to both the rollback copy and the encryption meant `Encrypt` advanced the
very object kept to undo it — the rollback dutifully restored the advance it
existed to prevent. Nothing failed; the send worked, the retry worked, and the
peer accumulated a gap per failed attempt. It is exactly the class of bug that
argued for moving this into one implementation, and it was found because the
test drives a real send through a real receive rather than asserting on a
request body.

Three more decisions worth recording:

- **Topping up is not rotating.** The upload endpoint always replaces the
  signed prekey on file, so a top-up has to send one — but it re-signs the
  *same* key material. `cmd/devclient` mints a new one on every upload, which
  would replace the key peers are mid-establishment against several times a
  day, for nothing. Two calls, `RotatePrekeys` and `TopUpOneTimePrekeys`, so
  the difference cannot be made by accident.
- **A weakened session is reported, not refused.** A bundle can arrive without
  a one-time prekey because the peer's pool ran dry, or because the server
  refused our claim's credentials and answered anyway. The session still works
  and its first message has no forward secrecy. Refusing would cost a working
  conversation for one message's property; saying nothing would let it degrade
  silently forever. So `SendResult.WithoutOneTimePrekey`.
- **The stale-device rule heals at the point it hurts.** Nothing propagates a
  device being replaced or an account re-created across servers, and the cached
  device id never expires on its own. The send that trips over the dead id is
  the one that forgets it — id and session together, because a session bound to
  a device that no longer exists would otherwise encrypt to a stranger's
  ratchet after the next re-resolve.

Recovery is now closed end to end. Stage 3 could only *report* that the
evidence justified a re-key, because acting on it means sending; `ResetSession`
and `RecoverDesyncedSessions` do the acting, and a test watches the peer adopt
it and the conversation work again in both directions. The eligibility rules —
not blocked, not an unaccepted request, not across a border with federation off
— stay separate from `ShouldAutoRekey`, because only one of those questions is
about the ratchet.

Deliberately still out: attachments. The blob upload lives elsewhere and this
package does not hold the bytes, so `RetryMessage` refuses a message with one
rather than quietly re-sending the caption alone as something the user never
composed.

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
