# Design: Short, hand-typeable invite codes

Status: **done** · Roadmap: [SRV-12](../ROADMAP.md)

Invite codes were 32 hex characters (16 random bytes) — fine to scan, awful
to read aloud or type. Now 12 symbols of Crockford Base32 grouped in fours,
`ABCD-EFGH-JKMN`, the same alphabet and normalization the setup token already
used, extracted into `pkg/humancode` so both share one implementation.

Input is deliberately forgiving, because every variation is the same code to
the person entering it: case is ignored, `-`/`_`/whitespace are stripped (so
the grouped display form and the compact form in a QR are interchangeable),
and `I`/`L` read as `1`, `O` as `0` — unambiguous precisely because the
alphabet cannot produce those letters. `U` is left alone, since no digit it
plausibly stands for. Normalization happens server-side in `store`, so the
typed path and the QR path cannot diverge.

**12 symbols, not the token's 8** — 60 bits rather than 40. The token's
shortness is bought by `MaxSetupTokenAttempts`: it is a singleton, so a
failed guess identifies the one thing to lock out. Invite codes break both
halves of that. Many are outstanding at once and *any* unused one grants
registration, so a guesser need not target a particular code (each extra
outstanding code shaves a bit off), and a failed guess names no code to lock.
With no rate limiting on registration either, the length has to do the work
the lockout does. Shipped alongside:

- **Only the code's SHA-256 hash is stored**, as for the setup token — a
  leaked database yields no working invites. Possible because no endpoint
  lists codes; the cost is that a lost code cannot be re-shown and must be
  reissued.
- **A default expiry** (`FREIZONE_INVITE_EXPIRY_DAYS`, 14 days; `0` opts
  out). An unbounded window is what makes guessing worth attempting at any
  length. The app now shows "Valid until …" next to a freshly issued code,
  since otherwise someone hands one out unaware it has a deadline.

**Migration note:** migrations here are plain SQL and SQLite has no
`sha256()`, so existing plaintext codes could not be hashed in place.
`0012_hash_invite_codes.sql` therefore **drops unredeemed codes** — any
invite handed out but not yet used stops working and has to be reissued —
while keeping already-used rows as history behind a placeholder that no
lookup can match. Leaving old codes un-hashed would have defeated the point.

Considered and not done: a global rate limit / attempt counter on the
registration path. It would be the real backstop and would make even 8
symbols defensible, but at 60 bits the length already carries it, and this
was not the moment to add a new failure mode to the registration flow.
