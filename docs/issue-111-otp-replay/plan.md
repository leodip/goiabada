# 6. Plan

Four stages. Stage 1 is the pure matcher, stage 2 the column and its two narrow writes, stage 3
enforcement in the browser flow, stage 4 enforcement in the account API plus the reset on disable.
Sections 0 to 5 are in `agreement.md` and every stage builds from them, not from this file alone.

Stage order is forced by dependency: stage 3 cannot claim a counter that stage 2 has not created, and
the repair of `test/reenroll-same-window` (decision 8) needs `ResetUserOTPStep`, so it lands in
stage 3 against stage 2's method.

### Stage 1: the step matcher
Status: **Done**
Landed 2026-08-06, code at `01a186c`, closed at `7841920`. Account in `log/stage-1.md`.

### Stage 2: the column and its two narrow writes
Status: **Done**
Landed 2026-08-06, commit `21cdef8`. Account in `log/stage-2.md`.

### Stage 3: enforcement in the browser flow
Status: **Done**
Seams: 3, 5. Tiers: unit (modules), integration.

Docs: **none. The `docs/security-2fa` bullet moved to stage 4**, reversing this plan's first draft.
The draft put it here, arguing that stage 3 is where the claim becomes true of authentication, that
stage 3 introduces the audit event the bullet names, and that a docs line attached to the last stage
is the first thing an early stop loses. The plan review disproved the first of those, which was the
one carrying the argument: after stage 3 the account API still accepts a code without claiming it, so
a code accepted at `api-otp/verify` remains replayable at browser verification until stage 4 lands.
§2's goal is one-time use "on any of the three call sites", and stage 3 enforces two of three, so the
bullet would state a guarantee broader than the code gives. An early stop is a reason to lose a docs
line, never a reason to publish an untrue security claim.

1. `constants.AuditOTPCodeReplayDetected = "otp_code_replay_detected"` in
   `src/core/constants/constants.go`, declared beside `AuditRefreshTokenReplayDetected` with a doc
   comment in its shape, saying what a `false` claim does and does not prove (decision 5, and the
   three-way false `TryConsumeUserOTPStep` documents). Added to `AuditEventTypes`, which
   `TestAuditEventTypes_Alphabetical` sorts by **value**, so it lands between `AuditLogout` and
   `AuditRefreshTokenReplayDetected`. Two drift guards in `constants_test.go` move with it:
   `allAuditConstants` in `TestAuditEventTypes_MatchesConstants`, and `expectedCount` in
   `TestAuditEventTypes_Count`, 95 to 96 (`grep -c "^	Audit" src/core/constants/constants.go` over
   the slice). Not added to `criticalEvents`: #128 did not add its own replay event there and the
   sketch says to follow it. Status: **Done**

2. `otp/verify-enabled` becomes match-then-claim per §4: `otp.MatchStep(otpCode, otpSecret,
   time.Now().UTC())` in place of `totp.Validate`, then `TryConsumeUserOTPStep(nil, user.Id, step,
   true)`. `requireOTPEnabled` is **true** here with a comment saying why (a verification claim
   asserts a factor, decision 10). A claim error is a 500; a refused claim emits
   `AuditOTPCodeReplayDetected` with `userId` and `step`, then takes the existing
   `AuditAuthFailedOtp` plus `otp/incorrect-error` path unchanged. The `totp` import goes, since
   neither branch validates directly any more. Status: **Done**

3. `otp/verify-enrolling` the same, against `secretKey` and with `requireOTPEnabled` **false**
   (enrolment establishes the authenticator and runs while `otp_enabled` is still off), the claim
   placed **before** `otp/enroll-write` so a failed enable cannot leave OTP on for a refused request.
   Status: **Done**

4. Seam 5, `handler_auth_otp_test.go`, deliberately thin. The new stub on the three subtests that
   reach a successful validation, each pinning its flag by matching the argument exactly:
   `test/unit-otp-success` with `true`, "Successful OTP validation for disabled OTP (enrollment)" and
   "Error updating user during OTP enrollment" with `false`. Two new subtests on the verification
   branch: a refused claim asserting both audit events and that the rendered error is the **same
   value** the wrong-code path renders, and an erroring claim asserting `InternalServerError`.
   Status: **Done**

5. Seam 3, new `src/authserver/tests/integration/auth_otp_replay_test.go`, named after
   `token_refresh_replay_test.go`. Two cases, each with the later-step control §5 requires, and each
   second submission in a genuinely fresh ceremony: **replay refused** (enrolled user, submit C,
   complete, then submit C again) and **enrolment code refused at verification** (enrol at step N in
   the browser flow, then submit the same C against the now-stored secret, pinning decision 3).
   Local setup helpers create a `level2_mandatory` client and user without completing a ceremony, so
   the marker is 0 and the test owns every code submitted.

   **Deviation from §5, verified: the fresh ceremony is a fresh cookie jar, not `prompt=login`.**
   `prompt=login` re-runs level 1 only. `HandleAuthLevel1CompletedGet` then loads the session the
   cookie still names and steps up only when `targetAcrLevel.IsHigherThan(session ACR)`, which is
   false for a `level2_mandatory` session meeting a `level2_mandatory` request, so the ceremony
   redirects straight to `/auth/completed` and never reaches `/auth/otp`. A new `createHttpClient`
   has no session cookie, so the target beats level 1 and the OTP form is shown. §5's actual reason
   for demanding a fresh ceremony is untouched and still honoured: resubmitting inside the first one
   500s at the `requiredState` check before the guard is consulted. Status: **Done**

6. `test/reenroll-same-window` repaired per decision 8: `ResetUserOTPStep` beside the direct disable
   it already performs, with the comment that decision requires. Recounted, and the count holds: it
   is still the only test submitting two codes for one user
   (`awk` over `authenticateWithOtp`, `createSessionWithAcrLevel2Mandatory` and `navigateToOtpScreen`
   across `src/authserver/tests/integration/*.go`, mapping each call to its enclosing function).
   Status: **Done**

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
