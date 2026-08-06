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
