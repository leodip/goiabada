# 6. Plan

Four stages. Stage 1 is the pure matcher, stage 2 the column and its two narrow writes, stage 3
enforcement in the browser flow, stage 4 enforcement in the account API plus the reset on disable.
Sections 0 to 5 are in `agreement.md` and every stage builds from them, not from this file alone.

Stage order is forced by dependency: stage 3 cannot claim a counter that stage 2 has not created, and
the repair of `test/reenroll-same-window` (decision 8) needs `ResetUserOTPStep`, so it lands in
stage 3 against stage 2's method.

### Stage 1: the step matcher
Status: **Done**
Seams: 1. Tiers: unit (core module). Docs: none, internals only.

1. **`src/core/otp/verifier.go`**, new file in the existing `package otp` beside `generator.go`.
   Holds `const StepSeconds = 30` and
   `MatchStep(passcode string, secret string, now time.Time) (int64, bool)`: empty secret returns
   `(0, false)` per decision 9, then the window over `hotp.ValidateCustom` with `Digits: DigitsSix`
   and `Algorithm: AlgorithmSHA1`. An error from the library collapses to `(0, false)`, which is what
   `totp.Validate` does today (`rv, _ := ValidateCustom(...)`), so a 5-digit passcode stays a generic
   incorrect-OTP response rather than becoming a 500.

   **Per decision 11, answered B**, the step reported is not the one that matched inside the window
   but the lowest within `lookbackSteps` below it that produces the same passcode, so that a passcode
   two steps can produce reports one answer at every current step that accepts it. Two unexported
   constants, `skewSteps = 1` and `lookbackSteps = 2*skewSteps + 1`, the second derived from the first
   so #142 narrowing the window narrows the lookback with it. Acceptance is unchanged and is still
   decided by the window alone; the search below it moves the answer only.

   Import `github.com/pquerna/otp/hotp` plus the root package aliased,
   `pquernaotp "github.com/pquerna/otp"`, for the two enum values. The alias is not required by the
   compiler, since a package's own name is not an identifier in its own file scope, but `otp.DigitsSix`
   inside `package otp` reads as a self-reference and is worth avoiding.

   **Per decision 12, answered A**, that lookback is walked down transitively rather than applied
   once: from the matched step, scan the `lookbackSteps` below it, and repeat from whatever that
   finds. Applied once it reports the bottom of one fixed interval, which is the bottom of an
   isolated pair but not of a chain of three, whose lowest step falls out of the interval while the
   passcode is still continuously acceptable. Each scan takes the lowest step it finds, which is
   enough to reach the bottom in one pass down, and the walk costs exactly what the single interval
   cost whenever nothing collides, since it stops the moment a scan finds nothing.

   A third unexported constant, `maxLookbackScans = 5`, bounds the walk, **with its derivation
   stated where it is written** as the answer asks: read off the sweep's measured link rate against
   a stated criterion, not rounded to a comfortable number, and refusing rather than answering when
   it fires. The probe prints the ladder it comes off.

   The walk moves behind an unexported step predicate, `producesPasscode`, called through
   `matchStepWith(produces, current)`, because a chain cannot be exhibited with any real secret.
   That is a boundary below the seam the interview sealed and it is recorded as a **named amendment
   to §5**, per the answer, rather than as a detail of this step.

   Carry §4's doc comment, extended with decisions 11 and 12: why `now` is a parameter, why an empty
   secret matches nothing, and why the reported step is the bottom of a chain rather than the step
   that matched.
   Status: **Done** (`src/core/otp/verifier.go`, `StepSeconds`, `skewSteps`, `lookbackSteps`,
   `maxLookbackScans`, `producesPasscode`, `MatchStep`, `matchStepWith` and the `lowestMatch` helper)

2. **`src/core/otp/verifier_test.go`**, new file, testify `assert`/`require` with `t.Run` subtests to
   match `generator_test.go`. **Seam 1's exhaustive table**, at the pinned instant
   `time.Unix(1700000000, 0).UTC()`, which is 20 seconds into step `56666666` and so straddles no
   period boundary.

   Codes are derived through `totp.GenerateCode(secret, time.Unix(step*StepSeconds+15, 0).UTC())`,
   the library's TOTP generator with the same defaults `otp/secret-generator` relies on. Generating
   through TOTP and validating through HOTP is **not** two independent cryptographic
   implementations, and the plan review corrected an earlier wording here that implied it was:
   `totp.GenerateCode` delegates to `hotp.GenerateCodeCustom`, so both sides share one HMAC. What the
   table does pin is the part that is genuinely ours and genuinely independent: TOTP maps a chosen
   *timestamp* to a counter, while `MatchStep` must derive the correct counter and window from `now`.
   The step arithmetic is the thing under test; the HMAC is the library's and seam 1 does not retest
   it (§5, rejected seams).

   Base secret `JBSWY3DPEHPK3PXP` (16 characters, valid base32). Every case varies exactly one thing
   from the accepted case at delta 0.

   | Case | Passcode | Secret | Expected |
   |---|---|---|---|
   | window -2 | code(step-2) | valid | `(0, false)` |
   | window -1 | code(step-1) | valid | `(step-1, true)` |
   | window 0 | code(step) | valid | `(step, true)` |
   | window +1 | code(step+1) | valid | `(step+1, true)` |
   | window +2 | code(step+2) | valid | `(0, false)` |
   | empty passcode | `""` | valid | `(0, false)` |
   | 5 digits | code(step) minus its last character | valid | `(0, false)` |
   | 7 digits | code(step) plus `"0"` | valid | `(0, false)` |
   | non-numeric | `"abcdef"` | valid | `(0, false)` |
   | whitespace-padded passcode | `" " + code(step) + " "` | valid | `(step, true)` |
   | lowercase secret | code(step) | `strings.ToLower(valid)` | `(step, true)` |
   | interior-space secret | code(step) | `"JBSW Y3DP EHPK 3PXP"` | `(0, false)` |
   | surrounding-space secret | code(step) | `" JBSWY3DPEHPK3PXP "` | `(step, true)` |
   | invalid base32 secret | code(step) | `"INVALID!SECRET!!"` | `(0, false)` |
   | empty secret | the code the library derives from `""` at the pinned step | `""` | `(0, false)` |

   The accepted rows assert the returned step, not just the boolean, or the table would pass with the
   step arithmetic wrong.

   Three rows carry a "keep this" comment:
   - **empty secret.** The one row that deliberately diverges from `totp.Validate`, which accepts it.
     The passcode must be the code actually derived from the empty secret at the pinned instant
     (`totp.GenerateCode("", pinned)`), never arbitrary digits, or it passes with the guard deleted.
     Pins decision 9.
   - **lowercase secret.** Asserts acceptance, which reads like a laxity to tighten. The library
     upper-cases, so refusing it would be a silent behaviour change.
   - **interior-space and surrounding-space secrets together.** They look contradictory. The library
     trims the outside of a secret and then base32-decodes it, so interior spaces fail the decode and
     surrounding ones do not. Both directions are stated so a later reader does not "fix" one of them.

   Each negative row names the mechanism that rejects it in a comment: outside the window, wrong
   passcode length (`ErrValidateInputInvalidLength` on the first iteration), unparseable base32
   secret, or the decision 9 guard.

   **Plus decision 11's cases, which the pinned table cannot reach**: nothing collides within eight
   steps of the pinned instant, so all 15 rows above pass under every rule decision 11 rejected. A
   second function sweeps the three located colliding pairs, spreads 1, 2 and 3, over every current
   step from two below the lower to two above the upper, asserting the same reported step wherever the
   passcode is accepted and a refusal either side. Steps and expectations are transcribed from
   `probe/step-collisions`, whose output is committed beside it, not reasoned out here. The spreads
   are written as literals because they are claims about a skew of 1, so #142 has to revisit them.

   **Plus decision 12's cases, which no real secret can reach**, at the boundary §5's amendment names:
   three functions over `matchStepWith` and a synthetic match set. One replays decision 2's high-water
   claim across **every continuously live shape**, the 5 pairs and all 9 chains of three, asserting
   that no presentation leaves a later one acceptable, with the two inherent spreads asserting the
   opposite and carrying the "keep this" note saying why. One pins the cap, where a chain of
   `maxLookbackScans` steps resolves to its bottom and one step further is refused, both written in
   terms of the constants. One pins the two error branches, including the walk's, which is unreachable
   through `MatchStep` and must refuse rather than answer with the match.
   Status: **Done** (`src/core/otp/verifier_test.go`, `TestMatchStep`, 15 rows,
   `TestMatchStepWithCollidingSteps`, 3 pairs sweeping 21 current steps,
   `TestMatchStepWithChainsOfCollidingSteps`, 14 shapes, `TestMatchStepWithAChainLongerThanTheWalk`
   and `TestMatchStepWithAFailingStepPredicate`, plus the `codeAtStep` and `stepMidpoint` helpers and
   the pinned constants)

3. Run the unit tier: `where.sh test --type core`. Nothing outside `src/core/otp/` is touched, so no
   other module can be affected, and nothing calls `MatchStep` yet.
   Status: **Done** (core tier green, `ok github.com/leodip/goiabada/core/otp`, no FAIL anywhere,
   re-run after decision 12)

### Stage 2: the column and its two narrow writes
Status: **Not started**
Detail: **sketch**

Pre-flight first, per §4: confirm version 000027 is not already recorded in `schema_migrations` in
the long-lived `goiabada_data` and `goiabada_integration` databases on mysql, postgres and mssql
(sqlite gets a fresh file per run and cannot carry a stale version). No SQL client exists in the
container, so this is a throwaway Go program run there against the same DSNs `run-tests.sh` uses. A
recorded 000027 is skipped silently and the whole suite then runs against the wrong schema.

Then migration `000027_add_last_otp_step` up and down on all four engines, following
`migration/generation-sqlite` for shape and `migration/generation-mssql` for the named default
constraint the down migration needs; the four `schema.sql` snapshots updated in the same stage.
`models.User` gains `LastOTPStep int64` tagged `dont-update`, with the reasoning
`model/generation-field` records. `TryConsumeUserOTPStep` and `ResetUserOTPStep` declared next to
`data/interface-generation` with §4's doc comments, implemented once in `commondb/user.go` on the
`data/mark-code-used` template, and delegated from each of the four engine packages the way
`IncrementUserAuthStateGeneration` is. The `data.Database` mock is regenerated (mockery lives at
`/usr/local/go-tools/bin/mockery` in the container, driven by `src/core/.mockery.yaml`).

Seams: 2. Tiers: unit (all three modules, since the interface and its mock change), data (four
engines): seam 2's claim table plus a `migration_000027_*` test in the shape of
`migration_000026_code_revoked_test.go`. Docs: none, internals only. Expand when stage 1 lands.

**Amended per decision 10, answered option A on 2026-08-05.** The signature is
`TryConsumeUserOTPStep(tx *sql.Tx, userId int64, step int64, requireOTPEnabled bool) (bool, error)`,
which supersedes §4's three-argument declaration; the doc comment follows §4's otherwise and gains
the flag's reasoning plus the second cause of a false at a verification site. When the flag is set the
builder adds `ub.Equal("otp_enabled", true)` to the `WHERE`, alongside `id` and `last_otp_step < step`;
when it is not, the predicate is §4's unchanged. `TrySetUserEnabled` is the precedent for the bound
bool, and `users.otp_enabled` carries the same type as `users.enabled` on all four engines, so nothing
here is engine-specific. `ResetUserOTPStep`, the migration, the column and the tag are exactly as
sealed: the answer changed no schema.

**Two more data cases, from decision 10.** Both at seam 2, which owns the column, and neither is
observable from an endpoint, because the interleaving they pin needs a request holding state loaded
before a disable:

- **A verification claim is refused once the authenticator is gone.** Claim step S with
  `requireOTPEnabled` true against an enrolled user, which succeeds; disable OTP; then claim S+1 with
  the flag true, which must be refused with no error, and the same claim with the flag false, which
  must succeed. Pins both directions of the flag, so deleting the term or hard-wiring it fails.
- **A reset does not reopen a consumed step to a verification claim.** Consume S with the flag true,
  disable, `ResetUserOTPStep`, then claim S again: refused with the flag true, accepted with it false.
  This is decision 10's hole and decision 4's remedy in one case, and it fails if the flag's term is
  dropped or if the reset is made unconditional on enrolment state.

**Two coverage cases the first plan draft was missing**, both added by the plan review and both
pinning a §2 goal that no other planned case could fail on. Neither is affected by decision 10's
answer, beyond passing the flag:

- **Concurrent single-winner** (§2 goal 3, "two concurrent submissions of one code yield at most one
  success"). The sequential claim table cannot tell a conditional `UPDATE` from a read-then-write,
  because a non-atomic implementation passes first/same/lower/higher rows perfectly and still lets two
  concurrent callers both win. Follows `cleanup_claim_test.go:TestTryClaimCleanupRun_ConcurrentCallersProduceOneWinner`
  exactly: N callers released together on one barrier against one user and one step, assert exactly
  one `true`, treat a lock-wait timeout or deadlock as a legitimate "did not claim", and repeat over
  several rounds since overlap can only be made likely rather than forced. **Skips sqlite**, which is
  held to one connection (`SetMaxOpenConns(1)`) so callers queue instead of contending and the test
  would pass without ever creating overlap. Carries that precedent's honesty note: a green run detects
  a broken implementation probabilistically, it does not certify atomicity.
- **Stale whole-user write** (§2 goal 4, "the counter cannot be regressed by an ordinary whole-user
  write"). Decision 2 assigns the `dont-update` tag, and dropping or misspelling it still compiles and
  leaves every claim and migration case green. Follows
  `user_test.go:TestUpdateUser_DoesNotClobberAuthStateGeneration`, which exists for this exact
  invisible failure: claim a nonzero step, then change an unrelated field on a model loaded before the
  claim, `UpdateUser` it, reload, and assert both that the unrelated change applied and that the
  claimed step survived. The claimed step must be nonzero, since 0 is the column default and a case
  written with 0 passes with the field never assigned at all.

### Stage 3: enforcement in the browser flow
Status: **Not started**
Detail: **sketch**

`constants.AuditOTPCodeReplayDetected = "otp_code_replay_detected"`, added to the event list the way
`AuditRefreshTokenReplayDetected` was. Both browser call sites (`otp/verify-enabled` and
`otp/verify-enrolling`) become match-then-claim per §4, with the claim placed **before**
`otp/enroll-write` so a failed enable cannot leave OTP on for a refused request. **Per decision 10**
`otp/verify-enabled` passes `requireOTPEnabled` true and `otp/verify-enrolling` passes false, each with
a short comment saying why: the first asserts a factor, the second is establishing one and runs while
`otp_enabled` is still false. The replay branch
reuses `otp/incorrect-error` and emits `AuditAuthFailedOtp` alongside the new event, so the caller
cannot tell a replay from a typo. `test/reenroll-same-window` is repaired per decision 8 by calling
`ResetUserOTPStep` beside the direct disable it already performs, with the comment that decision
requires.

Seams: 3, 5. Tiers: unit (authserver internal), integration. Seam 5 is deliberately thin: one refused
claim, one erroring claim, plus the new stub on the three existing subtests that reach a successful
validation. Seam 3 is a new `auth_otp_replay_test.go` with both cases and their controls, each second
submission in a fresh `prompt=login` ceremony for the reason §5 gives.

Docs: **none. The `docs/security-2fa` bullet moved to stage 4**, reversing this plan's first draft.
The draft put it here, arguing that stage 3 is where the claim becomes true of authentication, that
stage 3 introduces the audit event the bullet names, and that a docs line attached to the last stage
is the first thing an early stop loses. The plan review disproved the first of those, which was the
one carrying the argument: after stage 3 the account API still accepts a code without claiming it, so
a code accepted at `api-otp/verify` remains replayable at browser verification until stage 4 lands.
§2's goal is one-time use "on any of the three call sites", and stage 3 enforces two of three, so the
bullet would state a guarantee broader than the code gives. An early stop is a reason to lose a docs
line, never a reason to publish an untrue security claim. Expand when stage 2 lands.

### Stage 4: the account API, and reset on disable
Status: **Not started**
Detail: **sketch**

`api-otp/verify` becomes match-then-claim in the same shape, reusing the existing `INVALID_OTP_CODE`
JSON error so the API caller learns nothing either. It passes `requireOTPEnabled` **false** per
decision 10: the handler refuses an enable with `OTP_ALREADY_ENABLED` when OTP is already on, so this
site only ever runs with `otp_enabled` false. `api-otp/disable` and `admin-otp/disable` call
`ResetUserOTPStep` alongside their existing `ClearOTPSecret` plus `UpdateUser`, which cannot carry the
column because it is `dont-update`.

**Amended per decision 10: the reset goes after the `UpdateUser` that clears `otp_enabled`, at both
sites, with a comment saying why.** No transaction is needed, but the order is load-bearing: reset
first and there is a window where the marker reads 0 while the authenticator still reads enabled, and a
verification request that loaded the old state claims a consumed step through it, which is exactly the
hole decision 10's flag closes. Placing it after means the flag has already refused that claim. The
residual decision 10 leaves open, a re-enrolment landing while a stale request is in flight, is a
drafted follow-up in `closing.md` and is not built here.

Seams: 4. Tiers: unit (modules, for the build and the existing API tests), integration: extend
`api_account_otp_test.go` at `test/api-otp-enable` with the enable, disable, re-enable-with-the-same-code
case that pins decision 4, carrying the "keep this" note §5 asks for, since it asserts a success where
a replay reading expects a refusal. No unit test file is created for `handler_api_account_otp.go`: §5
records that absence as a stated choice.

**Two more coverage cases the first plan draft was missing**, both added by the plan review. The
enable/disable/re-enable case above is a *reset* test that silently assumes the enable path already
claims: with the whole of stage 4's claim change reverted, today's handler accepts all three
operations, so on its own it proves nothing about the third call site. And decision 4 names two
disable sites while seam 4 exercised only one.

- **API enrolment claims, observed at browser verification** (pins decision 3's third call site).
  Enable OTP through `PUT /api/v1/account/otp` with code C, then start a fresh browser level 2
  ceremony for that same user and submit C: it must draw the generic incorrect-code response. Seam 3's
  enrolment-to-verification case enrols *in the browser flow*, so no planned case crossed the API
  boundary, and omitting `TryConsumeUserOTPStep` from `api-otp/verify` alone left the whole suite
  green. The attack that makes this worth a case: a user enables OTP through the API and consumes C
  there, and anyone holding C plus the level 1 credential presents C at the browser prompt and reaches
  level 2 because the API acceptance was never recorded. **Needs the later-step control** in the same
  test, per §5, so the refusal is attributable to the claim and not to a broken ceremony.
- **Admin disable resets too** (pins decision 4's second site). Consume C for a user, disable that
  user through the admin endpoint `PUT /api/v1/admin/users/{id}/otp`, then re-enable through the
  account API with the same secret and C, which must succeed. `api_users_auth_test.go:TestAPIUserOTPPut_DisableSuccess`
  already owns that endpoint and is the place to extend. Endpoint-observable throughout: it never
  asserts `users.last_otp_step`, which §5 rejects as a side channel that passes with the endpoint
  broken. Forgetting the reset call in the admin handler previously left the complete suite green.

Docs: **`docs/security-2fa` gains its bullet here**, moved from stage 3, because this is the first
stage at which one-time use holds at all three call sites and so the first at which the bullet is
true. Shape and content unchanged from §2's "documentation owed": one bullet in the shape of the
neighbouring "Refresh token rotation" and "Replay containment" bullets, naming
`otp_code_replay_detected` and linking to `/concepts/audit-log/` exactly as those two do.

Expand when stage 3 lands.
