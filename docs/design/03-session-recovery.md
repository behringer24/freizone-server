# Design: Session recovery on ratchet desync

Status: **in progress** · Roadmap: [SRV-03](../ROADMAP.md)

The Double Ratchet had no self-healing: once `sessions[peer]` desynced, all
further messages from that peer stayed undecryptable and piled up in the
server queue. The desync *trigger* (cross-isolate push/foreground race) was
fixed 2026-07-22.

**Manual variant shipped 2026-07-26** (freizone-app): the receive path now
accepts an incoming X3DH `initial` as a re-key even when a session already
exists, replacing it only once it actually decrypts the envelope (a failed
attempt falls back safely, without burning a one-time prekey); an
undecryptable "poison" envelope is dropped from the server queue after a few
attempts instead of re-failing forever; and a user-triggered "Reset secure
session" action (peer profile + chat long-press) discards the local session
so the next outgoing message re-establishes X3DH, with a visible
"Secure session was reset" system-message marker on both sides. Recovers a
desynced conversation once **both** participants run a build with the
receive-path change — a one-sided reset alone did not work before this.

**Root causes of *permanent* desync closed 2026-07-28**, found while chasing
a "no background push notifications" report back to its actual source (the
messages simply never decrypted): (1) `pkg/ratchet.Session.Decrypt` mutated
the session step-by-step with no rollback, so a single undecryptable message
(a duplicate, a stale straggler, a corrupted envelope) left it permanently
wedged — `Decrypt` now works on a clone and commits only once the message
authenticates, and rejects an outright duplicate before it can consume the
next message key; (2) freizone-app's background push isolate and foreground
session both applied a whole-profile last-writer-wins save, so a resume that
raced a push-driven decrypt silently rolled the ratchet back by however many
messages the wake had just processed — an exclusive cross-isolate lock now
serializes each account's load-decrypt-save sequence; (3) redelivered
messages (delivery is at-least-once) were processed a second time, which for
a redelivered X3DH initial meant rebuilding and overwriting the already-
advanced session — freizone-app now tracks processed message ids and skips
a repeat. Verified end-to-end on real devices after resetting two sessions
this had already broken.

**Automatic detection + re-key implemented 2026-08-01** — no manual "Reset
secure session" needed, and no waiting for the user to type something. Four
pieces:

1. **A failure taxonomy** (`pkg/ratchet/failure.go`): `Session.Decrypt`'s
   errors are now sentinels behind an exported `FailureCode` /
   `SuggestsDesync`, so a caller can tell a routine redelivery
   (`duplicate_message`) from diverged keys (`authentication_failed`,
   `too_many_skipped`, `no_receiving_chain`) without matching error text.
   Carried across freizone-app's cgo boundary as a `code` field on the core's
   JSON result envelope (an `error` value can't cross it) and surfaced in Dart
   as `FreizoneCoreException.code`.
2. **Per-peer evidence** (freizone-app `AppState.peerSessionHealth`, persisted):
   an envelope counts once, only after it has exhausted its retries *and* only
   if its code meant desync -- plus the one desync shape that produces no error
   at all, a non-`initial` envelope from a sender we have no session for (our
   own state lost/rolled back). Any successful decrypt clears the evidence. A
   background push wake can only *detect* (it has no sending machinery), which
   is why this lives in the profile rather than in memory: the next live session
   acts on what a wake recorded.
3. **The invisible re-key envelope** (PROTOCOL §6, `v: 3 / kind: rekey`): a
   control payload alongside receipts, never stored or notified. A desync breaks
   *receiving*, so the peer keeps sending into a session we can't read and
   nothing they do fixes it -- only a fresh `prekey` block from our side does,
   and it needs a message to ride on. The manual reset now sends one too, so it
   finally works one-sided. Cost of the format choice: a build predating `v: 3`
   shows the generic "newer app feature" placeholder for what should have been
   invisible.
4. **Two rules against making it worse** (`session_recovery.dart`, pure and
   unit-tested): both sides re-keying at once leaves both broken again round
   after round, so the **lower** `account_id` goes first and the higher one only
   after a grace period; and since each re-key burns one of the peer's one-time
   prekeys, attempts per peer are spaced. Ineligible peers are skipped entirely
   (blocked, an unaccepted message request -- answering one invisibly would tell
   a stranger we're there -- or federation switched off).

Tested at every layer that can be: the failure taxonomy and the envelope shape
directly, the policy as a pure function (`test/session_recovery_test.dart`), and
the whole crypto loop in `pkg/ratchet/rekey_test.go` -- a deliberately desynced
pair, the repeated identical `authentication_failed` a client detects it by, the
re-key that heals it in both directions, and the guard that a stale `prekey`
block cannot break a healthy session.

**Still open:** the same loop end-to-end through two real app instances,
including across a background push wake (where detection and recovery happen in
different isolates). Worth an explicit desync injector in a debug build: with the
2026-07-28 root causes closed, a desync should now be *rare* rather than merely
recoverable, so this path will seldom run in the field -- which is exactly why it
needs a way to exercise it on purpose to stay trustworthy.

Two adjacent gaps found while building this, both pre-existing and both left
alone: `_getOrCreateCryptoSession` stores a fresh initiator session before the
send that carries its `initial` succeeds, so a failed first send loses the
handshake material (the recovery loop above now papers over it for existing
conversations, but not for genuine first contact); and `cmd/devclient` never
accepts a re-key over an existing session, so it cannot participate in recovery
at all.
