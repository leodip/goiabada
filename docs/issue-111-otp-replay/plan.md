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
Landed 2026-08-06, commit `a856e4b`. Account in `log/stage-3.md`.

### Stage 4: the account API, and reset on disable
Status: **Done**
Seams: 3, 4. Tiers: unit (modules), integration (four engines). Data: not applicable, stage 2 owns
both methods and their four-engine table and this stage adds no query, interface or migration.
Docs: `docs/security-2fa`.

`api-otp/verify` becomes match-then-claim in the same shape stage 3 landed at the two browser sites,
reusing the existing `INVALID_OTP_CODE` JSON error so the API caller learns nothing either. It passes
`requireOTPEnabled` **false** per decision 10: the handler refuses an enable with
`OTP_ALREADY_ENABLED` when OTP is already on, so this site only ever runs with `otp_enabled` false.
`api-otp/disable` and `admin-otp/disable` call `ResetUserOTPStep` alongside their existing
`ClearOTPSecret` plus `UpdateUser`, which cannot carry the column because it is `dont-update`.

**Amended per decision 10: the reset goes after the `UpdateUser` that clears `otp_enabled`, at both
sites, with a comment saying why.** No transaction is needed, but the order is load-bearing: reset
first and there is a window where the marker reads 0 while the authenticator still reads enabled, and
a verification request that loaded the old state claims a consumed step through it, which is exactly
the hole decision 10's flag closes. Placing it after means the flag has already refused that claim.
The residual decision 10 leaves open, a re-enrolment landing while a stale request is in flight, is
follow-up 2 in `closing.md` and is not built here.

**Amended again per decision 13, raised by this stage's own code review and answered "A": the two
writes commit together.** Ordering is not enough on its own. Between them the row reads
`otp_enabled = false` with the old marker still standing, and an enrolment landing in that window
claims a step which the reset then erases, settling at `otp_enabled = 1, last_otp_step = 0` with a
code already consumed. One transaction removes the window: a concurrent enrolment sees the pre-disable
state, where it is refused, or the fully committed post-disable state, where its claim stands. The
order inside the transaction stays decision 10's. Steps 2 and 3 are rewritten below and step 9 is new.

1. `api-otp/verify`: replace `totp.Validate` with `otp.MatchStep` plus
   `TryConsumeUserOTPStep(nil, user.Id, step, false)`, in `handler_api_account_otp.go`. The wrong-code
   and replay branches write the identical `INVALID_OTP_CODE` body, hoisted into one local so they
   cannot drift apart. Drops the now-unused `pquerna/otp/totp` import and adds `core/otp` plus `time`.
   Status: **Done**
2. `api-otp/disable`: clear the secret, clear `otp_enabled` and reset the marker as one committed
   transaction, per decision 13. `ResetUserOTPStep` still runs after the `UpdateUser` that clears
   `otp_enabled`, decision 10's order. Failure at any statement is a 500 and rolls the whole disable
   back, as every other write on that path is a 500. Status: **Done**
3. `admin-otp/disable`: the same operation in `handler_api_users_crud.go`, decision 4's second site.
   Both sites run the identical five statements and the reasoning is a paragraph, so it is one shared
   unexported function, `otp/disable-writes`, rather than written out twice; a `defer`-scoped rollback
   wants a function of its own in any case. Each site keeps its own 500 response. Status: **Done**
4. Seam 4's pin for decision 4, in `api_account_otp_test.go`: enable with code C, disable, enable
   again with the same secret and the same C, which must succeed. Endpoint-observable throughout, and
   carrying the "keep this" note §5 asks for, since it asserts a success where a replay reading
   expects a refusal. Plus a shared skip guard for a code that has fallen out of the acceptance
   window mid-test, so a period boundary crossing cannot make either re-enable case fail for a reason
   unrelated to the reset. Status: **Done**
5. Decision 3's third call site, in `auth_otp_replay_test.go` beside the browser sibling it mirrors:
   enable through `PUT /api/v1/account/otp` with code C, then a fresh browser level 2 ceremony for
   that same user submitting C, which must draw the generic incorrect-code page, with the later-step
   control §5 requires so the refusal is attributable to the claim and not to a broken ceremony.
   Extracts `createLevel2MandatoryClient` out of stage 3's `createLevel2MandatoryUser` so the client
   fixture serves a user the account API created. Status: **Done**
6. Decision 4's second site, in `api_users_auth_test.go`: consume C through the account API, disable
   that user through `PUT /api/v1/admin/users/{id}/otp`, then enable again through the account API
   with the same secret and C, which must succeed. A new function rather than an extension of
   `TestAPIUserOTPPut_DisableSuccess`, which owns the admin response shape and has no account token.
   Status: **Done**
7. `docs/security-2fa` gains its bullet, moved from stage 3 because this is the first stage at which
   one-time use holds at all three call sites and so the first at which the bullet is true. One
   bullet in the shape of the neighbouring "Refresh token rotation" and "Replay containment" bullets,
   naming `otp_code_replay_detected` and linking to `/concepts/audit-log/` exactly as those two do.
   Status: **Done**
8. Re-point §0's `api-otp/verify` row, whose locator step 1 deletes, plus the two disable rows steps 2
   and 3 move, add a row for `otp/disable-writes`, and re-run `check-anchors.sh`. Status: **Done**
9. Decision 13's atomicity pins, at the unit tier, because no sequential caller can see them: the
   integration reset cases observe the same end state whether or not the two writes share a
   transaction, so only the call shape distinguishes them. Three cases against a mocked
   `data.Database`: both writes and the commit in order at `api-otp/disable`, the same at
   `admin-otp/disable` so the second site is pinned to the shared function rather than assumed, and a
   failing reset at `api-otp/disable` that must roll back, not commit, and not audit a disable that
   did not happen. Status: **Done**

**Why the two extra cases**, both added by the plan review. Step 4 is a *reset* test that silently
assumes the enable path already claims: with the whole of stage 4's claim change reverted, today's
handler accepts all three operations, so on its own it proves nothing about the third call site. And
decision 4 names two disable sites while seam 4 exercised only one. Omitting `TryConsumeUserOTPStep`
from `api-otp/verify` alone, or the reset from the admin handler alone, each previously left the
complete suite green.

**§5's rejected unit file for `handler_api_account_otp.go` was created after all**, by round 1's
finding 2. §5 rejected it because "the claim logic there is identical to seam 5's", and this stage
deliberately made the audit behaviour diverge from seam 5, so the premise stopped holding. The file's
own header comment records that, and step 9's two account-site cases land in it.
