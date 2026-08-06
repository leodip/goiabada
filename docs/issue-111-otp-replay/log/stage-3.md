# Stage 3: enforcement in the browser flow

Landed 2026-08-06, commit `cc208c5`, on tree `56e3b6ce57f1`. Two review rounds, the second clean.

## As built

The first stage where a real request consumes a step. Both browser sites claim; the account API and
the two disable sites are stage 4, so one-time use does not yet hold across all three call sites,
which is why the `security.mdx` bullet is still not written.

**The audit event.** `constants.AuditOTPCodeReplayDetected = "otp_code_replay_detected"`, declared
beside `AuditRefreshTokenReplayDetected` and following its doc-comment shape: what the event records,
that it does **not** assert malicious intent and is not proof of replay (the claim is a
compare-and-set, so a false has the three causes `TryConsumeUserOTPStep` enumerates), and the payload,
`userId` plus the matched step, never the code. Added to `AuditEventTypes` between `AuditLogout` and
`AuditRefreshTokenReplayDetected`: `TestAuditEventTypes_Alphabetical` sorts by **value**, not by
constant name, and `otp_code_replay_detected` sits there. Two drift guards moved with it,
`allAuditConstants` and `expectedCount` 95 to 96. Not added to `criticalEvents`, because #128 did not
add its own replay event there and step 1 said to follow it; the argument for adding it is real, and
it is left as a question the reviewer can raise rather than a silent divergence.

**The two call sites**, each `totp.Validate` replaced by `otp.MatchStep(...)` then
`TryConsumeUserOTPStep`. The `totp` import is gone from the handler: neither branch validates
directly any more, which is the property that makes the guard unskippable rather than merely present.

- `otp/verify-enabled` passes `requireOTPEnabled` **true**. A verification claim asserts a factor and
  that assertion is only true of an enrolled authenticator (decision 10).
- `otp/verify-enrolling` passes **false**, and claims **before** `otp/enroll-write`. Both carry the
  reason inline: enrolment establishes the authenticator rather than asserting it, and a burned code
  with a retry beats OTP left enabled on a request that was refused.
- A claim error is a 500 at both. A refused claim emits `AuditOTPCodeReplayDetected` and then takes
  the existing `AuditAuthFailedOtp` plus `otp/incorrect-error` path unchanged, so the caller cannot
  tell a replay from a typo.

The match-then-claim block is written out in both branches rather than hoisted above them. Decision 7
rejected a shared helper and §4 specifies the replacement per call site; the two branches also differ
in the secret they check, the flag they pass and the reason each comment gives, so the shared part is
smaller than it looks.

**Seam 5**, `handler_auth_otp_test.go`. The three subtests reaching a successful validation gained the
claim stub, and each **matches `requireOTPEnabled` exactly** rather than with `mock.Anything`:
`test/unit-otp-success` with `true`, the two enrolment subtests with `false`. That is where decision
10's flag is pinned, and passing the wrong value would otherwise go unnoticed. Two new subtests on the
verification branch, deliberately thin because seams 1 and 2 own the tables: a refused claim asserting
both audit events, that the payload carries `userId` and a step within one of the current one, that it
carries no code, and that the rendered error is the **same value** the wrong-code branch renders; and
an erroring claim asserting `InternalServerError`.

**Seam 3**, new `src/authserver/tests/integration/auth_otp_replay_test.go`, named after
`token_refresh_replay_test.go`. Nothing in it reads `users.last_otp_step`. Two cases, each with the
later-step control §5 requires:

1. **Replay refused.** Enrolled user, code C authenticates, then C in a new ceremony draws the generic
   incorrect-code page. The refusal is attributable to the claim and nothing else: C still validates
   against the secret, so the matcher accepts it and only the consumed-step guard can reject it.
2. **Enrolment code refused at verification**, pinning decision 3. Enrol in the browser flow with C,
   assert the user is now enrolled (or the second ceremony would not be a verification), then present
   C against the stored secret. Without the enrolment claim an enrolment code is usable exactly twice.

`nextStepCode` builds each control and **skips** unless the step `MatchStep` reports for it is
strictly above the step it reports for the consumed code, which is the guard's own predicate: a
control the guard is entitled to refuse cannot separate the guard from a broken ceremony, which is
the one thing it exists to do. It first compared the two codes' digits instead; round 1 below shows
why that was not enough.

**Decision 8's repair.** `ResetUserOTPStep` beside the direct disable in `test/reenroll-same-window`,
with the comment that decision requires, saying it stands in for the disable handlers and why the
whole-user write above it cannot do the job.

## Tiers

Three trees, all green, and each delta between them is named.

**`44f1bd176635`**, what round 1 read. Unit and integration green (893 pass per engine, 5m52s).

**`3df0300e8ed7`**, after round 1's control fix, what round 2 read (`tree-hash.sh`).

| Tier | Command | Engines | Result | Time |
|---|---|---|---|---|
| unit | `where.sh test --type modules` | n/a | 44 packages `ok`, 2764 pass, 0 fail, 0 skip | 4s |
| integration | `where.sh test --type integration` | mysql, postgres, mssql, sqlite | 893 pass per engine, 0 fail, 0 skip, one `ok ... integration` each (74s / 98s / 131s / 44s) | 6m05s |

**`56e3b6ce57f1`**, the tree this stage commits. Delta from the above is round 2's bookkeeping fix and
nothing else: two doc comments, in `src/core/otp/verifier.go` and `auth_otp_replay_test.go`.

| Tier | Command | Engines | Result | Time |
|---|---|---|---|---|
| unit | `where.sh test --type modules` | n/a | 44 packages `ok`, 2764 pass, 0 fail, 0 skip | 4s |
| data | `where.sh test --type data` | mysql, postgres, mssql, sqlite | 391 pass per engine, 0 fail, one `ok ... tests/data` each; 4 pre-existing engine skips (sqlite skips both single-writer concurrency cases, one of them stage 2's `TestTryConsumeUserOTPStep_ConcurrentCallersProduceOneWinner`; mssql skips `TestTransaction_UncommittedWriteIsNotVisibleOutside`) | 32s |

Integration was **not** re-run on the committed tree, deliberately. The delta is two comments, and
unit plus data recompile every package a comment edit could have broken in 36 seconds against
integration's six minutes. Data is not otherwise applicable to this stage, no query, interface
method, migration or schema change, and seam 2 owns the two methods on four engines already; it ran
here purely as that recompilation check.

Logs on the host: `/tmp/leo111-s3r1-modules.log`, `/tmp/leo111-s3r1-int-final.log`,
`/tmp/leo111-s3r2-modules.log`, `/tmp/leo111-s3r2-data.log`.

**One recorded count was wrong and is corrected above.** The unit tier was written down as 2694 pass,
a transposition of 2764. Round 1's own log reproduces the real figure
(`grep -cE '^\s*--- PASS' /tmp/leo111-s3r1-modules.log` returns 2764), so nothing about the tree
moved, only the number written beside it.

`check-anchors.sh`: 24 of 24. Two rows were re-swept, `otp/verify-enabled` and `otp/verify-enrolling`,
whose locators were the `totp.Validate` lines this stage deleted. Both now point at their `MatchStep`
line, with the Note recording what they used to be.

## The tests earn their rows: three mutations, run and reverted

1. **Neutralise the guard at both sites** (`if false && !consumed`). Both new integration cases fail on
   sqlite, each at the replay submission: "got status 302 redirecting to .../auth/completed: the
   submission was accepted". Nothing else in the suite notices, which is the point: before this stage
   that acceptance was the shipped behaviour.
2. **Remove decision 8's reset** from `test/reenroll-same-window`. That test fails, "Expected status
   code 302, got 200", the re-enrolment refused because the session helper had already consumed that
   step. It confirms the repair is load-bearing rather than defensive, and that the enrolment claim
   bites through a test that existed before this change.
3. Mutation 1 was run twice. The first time both cases failed at `getCsrfValue`, "expecting to find
   'gorilla.csrf.Token'", which is true and useless: an accepted submission redirects with an empty
   body and every later read of that body reports something unrelated. `assertOtpRefused` now checks
   the status first and fatally, naming the redirect target, and the CSRF token is read afterwards.
   Recorded because the fix is the difference between a test that catches a regression and one that
   catches it unreadably.

Reverted from a copy taken before the first mutation; `tree-hash.sh` returns `44f1bd176635`
afterwards, and both tiers above were run after the revert.

## Deviations from the plan

1. **The second ceremony is a fresh cookie jar, not `prompt=login`.** §5 named `prompt=login`, and it
   does not produce a second OTP prompt here. `prompt=login` skips the session only at
   `/auth/authorize`; `HandleAuthLevel1CompletedGet` then loads the session the cookie still names and
   steps up to level 2 only when `targetAcrLevel.IsHigherThan(session ACR)`, which is false for a
   `level2_mandatory` session meeting a `level2_mandatory` request. `handler_auth_pwd.go` touches no
   session row, so the ceremony would redirect straight to `/auth/completed` and never reach
   `/auth/otp`, and the case would prove nothing while passing.

   §5's reason for demanding a fresh ceremony is untouched and still honoured: resubmitting inside the
   first ceremony 500s at the `requiredState` check before the guard is consulted. A fresh cookie jar
   is also the more faithful threat model, an attacker holding the level 1 credential and a stolen
   code, in their own browser. Recorded in the plan step as well as here, since it is the sort of
   detail a later reader would otherwise "correct" back.

2. **The `criticalEvents` list in `constants_test.go` was not extended**, per step 1. `AuditAuthFailedOtp`
   is on that list and a replay is a stronger signal than the typo it accompanies, so there is a case
   for adding it; #128 set the precedent the step names, and following the neighbour beat improvising.

3. **The recount in step 6 held.** `test/reenroll-same-window` is still the only test submitting two
   codes for one user, checked by mapping every `authenticateWithOtp`, `createSessionWithAcrLevel2Mandatory`
   and `navigateToOtpScreen` call to its enclosing test function across
   `src/authserver/tests/integration/*.go`, rather than by trusting §1's sentence.

## Not done, deliberately

- **`api-otp/verify` still accepts a code without claiming it**, and neither disable site resets. Both
  are stage 4, and until they land a code accepted at the account API remains presentable at the
  browser prompt.
- **No `docs/security-2fa` bullet**, for the reason the stage's Docs line gives: after this stage the
  guarantee it would state is broader than the code gives.
- **No unit test file for `handler_api_account_otp.go`**, which §5 records as absent infrastructure
  rather than an oversight, and which stage 4 observes end to end at seam 4 instead.

## Decisions

None raised. Nothing here contradicted one: decision 10's flag landed at both sites with the values
its answer specified, decision 3's enrolment claim is pinned end to end, and decision 8's repair
behaves exactly as that decision predicted, confirmed by mutation 2.

### Round 1, 2026-08-06

`gpt-5.6-sol`, effort xhigh, fresh Codex session (`.review/reviewer.env`). All three axes `reviewed`,
`unchecked` empty, one minor finding. What it ran: `tree-hash.sh` and `check-anchors.sh` against the
record, a Go program of its own (`issue111_control_collision.go`), `TestHandleAuthOtpPost`, both new
integration cases on sqlite, `git diff --check`, and `gofmt -d` on every changed file. It took the
recorded four-engine run and the three mutations as read because the hash matched, which is what the
hash is for.

Found sound, with those checks behind it: both browser branches reach the claim through `MatchStep`
with no `totp.Validate` left in the handler; decision 10's two flag values; the claim before the
enable write, with no ordering that leaves OTP enabled on a refused request; the audit pair, with a
payload carrying `userId` and the step and no code; every refusal returning before AMR, session or
token issuance can advance; and deviation 1, which it checked independently by reading the level 1
session path and judged to strengthen seam 3 rather than weaken it. Deviations 2 and 3 it examined
and let stand.

1. **The later-step control can canonicalize below the step it must sit above.** `Raised by: reviewer`,
   quality, minor, confidence high, `needs_human: false`. Status: **Resolved**

   Confirmed by running the reviewer's own program before changing anything. At current step 818666
   with the seam 1 secret, the consumed code `706873` reports step 818666; the control built from the
   next nominal step is `475244`, which differs, so the old digit-equality skip stayed silent, but
   that passcode is also produced by 818665 and the walk reports 818665 for it. The guard then
   refuses the control correctly (`818666 < 818665` is false) and the test fails as though the
   ceremony were broken. Digit comparison only ever covered a collision with the immediately
   preceding step and left the other two lookback steps, about 2 in a million per control, the same
   order as the case it did cover rather than an orders-smaller residual.

   Fixed at the cause rather than by widening the digit comparison: the skip is now
   `controlStep > consumedStep` over the steps `MatchStep` reports, which is the guard's own
   predicate. Recomputing those steps in the test is sound precisely because decision 12 makes the
   reported step constant across every presentation of an accepted passcode. A code that has fallen
   out of the acceptance window before the control is built also skips, naming which of the two it
   was.

   **Half the recommendation was declined, deliberately.** No new test pins the skip.
   `TestMatchStepWithCollidingSteps` already pins this exact mechanism at seam 1, with this pair:
   818665 and 818667 produce one passcode and `MatchStep` reports 818665 at every accepting current
   step. That is the seam §5 gives the step-reporting table to, and a rival case in the integration
   package would test a test helper at the most expensive tier and need a pure predicate extracted
   for it first. The helper's comment names the pair and that test instead, so a later
   simplification back to comparing digits reads as the divergence it is.

   Re-ran after the fix: both cases pass on sqlite, and mutation 1 (the guard neutralised at both
   sites) still fails both at the replay submission rather than skipping, so the control fix did not
   move where the test bites. Then both tiers on the committed tree, above.

**The response's follow-up, not a finding.** The reviewer asked to widen closing follow-up 2 to cover
stale enrolment replacement, and the mechanism holds against the code: `otp/verify-enrolling` passes
`requireOTPEnabled` false, so the claim binds nothing about *which* authenticator is being
established, and the enable is a whole-user write of this request's session secret. Two overlapping
enrolment ceremonies both succeed and the later write replaces the earlier secret. It predates this
change and each ceremony spends its own code, so #111's one-time-use contract is untouched, which is
why it is a follow-up rather than a gate finding. Recorded as follow-up 2's second shape, with a
fresh duplicate search that found nothing.

### Round 2, 2026-08-06

`gpt-5.6-sol`, effort xhigh, resumed Codex session (`.review/reviewer.env`, `GATE=stage-3 ROUND=2`).
**Clean: zero findings**, all three axes `reviewed`, `unchecked` empty.

What it ran: `tree-hash.sh` and `check-anchors.sh` against the record, its own program against the
real matcher (`.review/scratch/issue111_round2_invariance.go`), `git diff --check`, and `gofmt -d` on
the changed integration file. It did not repeat the unit or four-engine integration tiers, saying the
recorded hash is the tree in front of it, which is what the hash is for.

What it checked is the assumption round 1's fix rests on, and that is what earns the round. It
reproduced round 1's pair through the real matcher, at current 818666 the consumed code reports
818666 while the next nominal code reports 818665, so the new comparison rejects that control, and
then confirmed the reported step is invariant across a continuously accepted chain, including when
the chain's bottom already sits below the live window and when the cap refuses instead. It also
checked that consulting `MatchStep` in the test does not make the replay assertion circular: both
cases assert the refusal before `nextStepCode` is reached, and the recorded neutralised-guard
mutation still fails there before the helper can skip. It accepted the declined half of round 1's
recommendation for the reason the log gave, that the mechanism is already pinned at seam 1 and a
rival case would test test code at the most expensive tier.

**One bookkeeping note, fixed in passing rather than spent as a round.** `MatchStep`'s doc comment
said the reported step is "the same at every current step from which the passcode is accepted". That
holds within one unbroken run of accepting steps, not across a refused gap: a pair spread wider than
`lookbackSteps` has a separate answer either side, which is exactly the residual decisions 11 and 12
accept knowingly and which `lookbackSteps`' own comment already states correctly. Corrected at the
source and in the helper comment that inherited the phrase. Comments only, so unit and data were
re-run and integration was not, per the tiers above.

Nothing else moved: no decision raised, and no production behaviour changed since round 1.
