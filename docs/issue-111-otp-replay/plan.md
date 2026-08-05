# 6. Plan

Four stages. Stage 1 is the pure matcher, stage 2 the column and its two narrow writes, stage 3
enforcement in the browser flow, stage 4 enforcement in the account API plus the reset on disable.
Sections 0 to 5 are in `agreement.md` and every stage builds from them, not from this file alone.

Stage order is forced by dependency: stage 3 cannot claim a counter that stage 2 has not created, and
the repair of `test/reenroll-same-window` (decision 8) needs `ResetUserOTPStep`, so it lands in
stage 3 against stage 2's method.

### Stage 1: the step matcher
Status: **Not started**
Seams: 1. Tiers: unit (core module). Docs: none, internals only.

1. **`src/core/otp/verifier.go`**, new file in the existing `package otp` beside `generator.go`.
   Holds `const StepSeconds = 30` and
   `MatchStep(passcode string, secret string, now time.Time) (int64, bool)`, exactly as §4 sketches
   it: empty secret returns `(0, false)` per decision 9, then the deltas `0, -1, 1` over
   `hotp.ValidateCustom` with `Digits: DigitsSix` and `Algorithm: AlgorithmSHA1`, returning the
   matched step. An error from the library collapses to `(0, false)`, which is what `totp.Validate`
   does today (`rv, _ := ValidateCustom(...)`), so a 5-digit passcode stays a generic incorrect-OTP
   response rather than becoming a 500.

   Import `github.com/pquerna/otp/hotp` plus the root package aliased,
   `pquernaotp "github.com/pquerna/otp"`, for the two enum values. The alias is not required by the
   compiler, since a package's own name is not an identifier in its own file scope, but `otp.DigitsSix`
   inside `package otp` reads as a self-reference and is worth avoiding.

   Carry §4's doc comment verbatim: why `now` is a parameter, and why an empty secret matches nothing.
   Status: **Not started**

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
   Status: **Not started**

3. Run the unit tier: `where.sh test --type core`. Nothing outside `src/core/otp/` is touched, so no
   other module can be affected, and nothing calls `MatchStep` yet.
   Status: **Not started**

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

**Blocked on decision 10.** The plan review found that the claim predicate as designed (`id` plus
`last_otp_step < step`, with disable and reset as separate writes) lets a reset reopen a consumed
step to a verification request that loaded the old enabled authenticator. Answering it may change
`TryConsumeUserOTPStep`'s signature, so the method is not written until decision 10 is `Decided`.
Everything else in this stage, the migration, the column, the tag and `ResetUserOTPStep`, is
unaffected by the answer.

**Two coverage cases the first plan draft was missing**, both added by the plan review and both
pinning a §2 goal that no other planned case could fail on. Neither depends on decision 10:

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
`otp/enroll-write` so a failed enable cannot leave OTP on for a refused request. The replay branch
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
JSON error so the API caller learns nothing either. `api-otp/disable` and `admin-otp/disable` call
`ResetUserOTPStep` alongside their existing `ClearOTPSecret` plus `UpdateUser`, which cannot carry the
column because it is `dont-update`.

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

**Blocked on decision 10** for the disable resets specifically: the answer decides whether disable and
reset must be one atomic transition, and whether the claim binds to enrolment state. The
`api-otp/verify` claim and its two coverage cases above are unaffected. Expand when stage 3 lands.
