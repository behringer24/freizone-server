# Design: The "community" registration policy

Status: **planned** · Roadmap: [SRV-15](../ROADMAP.md)

A fourth `registration_policy` value between `open` and `invite`: **nobody joins
without an invite, but any existing user can issue one** — not just admins and
moderators. The point is a server that grows by its members vouching for people,
without either letting strangers walk in (`open`) or funnelling every new
account through staff (`invite`).

**Registration itself needs no change.** Under `community` an invite code is
required exactly as under `invite` — `handleRegisterAccount`
(`internal/api/accounts.go`) can treat the two identically. What differs is
authorization on **`POST /v1/admin/invites`**, which is gated
admin-or-moderator inline today (`handleCreateInvite`, `internal/api/invites.go`)
and would consult the policy instead: any active account may create a code when
the policy is `community`.

Touch points: `config.RegistrationPolicy` and its validation (`config.go`, two
places), the runtime policy is already DB-backed and admin-settable so
`store.{Init,Get,Set}RegistrationPolicy` need nothing, `handleCreateInvite`'s
gate, PROTOCOL §4's registration-policy and invite entries, and the policy
selector in `admin_screen.dart`. App-side the real work is
`chat_list_screen.dart`'s `_canInvite` (a `community` case returning true for
everyone) and `invite_screen.dart`, which currently only mints a code when the
policy is exactly `"invite"` — under `community` a plain user reaching that
screen must get a real code, which is a path that screen has never taken for a
non-staff account.

**Model it as a fourth policy value, not a second axis.** The tempting
alternative is an orthogonal "who may invite" setting (staff / everyone). It is
conceptually cleaner but adds no expressiveness: with `open` invites are
irrelevant and with `closed` nothing works, so the only combination a second
axis buys is precisely `invite` + everyone. One enum keeps it to one knob in the
UI and one value to reason about. Worth writing down, because the two-axis
refactor looks like an improvement until you enumerate the cells.

**The real question is abuse, not authorization.** Today the invite surface is
bounded by trust: only staff can mint codes, so a spam wave needs a compromised
staff account. Under `community` every member is a registration vector, and one
malicious or compromised account can mint codes without limit and onboard as
many accounts as it likes — each of which can then do the same. Before this
ships, at least one bound is needed. Candidates, roughly in order of appeal:

- **A cap on unredeemed codes per account** (e.g. 5 outstanding). Cheap to
  enforce with a `COUNT` on `invite_codes`, self-cleaning via SRV-13's sweep of
  expired unredeemed rows, and it maps to the honest use case: you invite the
  people you actually know, a few at a time.
- **A cooldown** between codes from the same account. Bounds rate rather than
  depth; composes with the cap.
- **A minimum account age** before a new member may invite, so an onboarded
  spam account cannot immediately extend the chain.
- Staff exempt from all of the above, since the `invite` policy's behaviour
  should not get worse.

**Moderation follow-through** matters more here than under `invite`:

- SRV-14's `invited_by` becomes the main tool — the invite chain is how an
  operator finds who let a problem account in. Under `community` it is also
  worth reconsidering whether *moderators* should see it (SRV-14 deliberately
  restricted it to admins), since they are the ones doing this work.
- Blocking an account does **not** currently touch its unredeemed codes
  (deleting one cascades them, blocking does not). Blocking a spam inviter while
  leaving their outstanding codes live is a hole this policy creates; the fix is
  either revoking them on block or refusing to redeem a code whose creator is
  disabled. The latter is one `JOIN` in `ConsumeInviteCode` and needs no new
  state.
- An admin-side view of "codes this account issued, and who redeemed them"
  would follow naturally, and is the reverse direction SRV-14 deliberately did
  not expose. Worth deciding on purpose rather than drifting into it.

Naming: `community` reads well next to `open`/`invite`/`closed` and says what it
is about. The UI copy needs to make the distinction from `invite` unmissable,
since "Invite" and "Community" both require a code and the difference is only
*who* can hand one out.
