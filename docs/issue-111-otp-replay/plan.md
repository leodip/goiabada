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
   through TOTP and validating through HOTP is deliberate: it is the path a real authenticator takes,
   so the table pins parity with what `totp.Validate` accepts today rather than checking `MatchStep`
   against itself.

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

Docs: `docs/security-2fa` gains its bullet here rather than in stage 4. This is the stage that makes
the claim true of authentication and that introduces the audit event the bullet names, and a docs
line attached to the last stage is the first thing an early stop loses. Expand when stage 2 lands.

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

Docs: none, stage 3 carries the bullet. Expand when stage 3 lands.
