# Issue 111: TOTP codes are replayable, RFC 6238 5.2 requires one-time use

**Issue:** [#111](https://github.com/leodip/goiabada/issues/111)
**Issue state:** open (labels: bug, security)
**Written:** 2026-08-05
**Last synced:** 2026-08-05 (no comments on the issue)
**Agreement sealed:** not yet
**Run state:** not started
**PR:** none
**Related:** #106 (closed) established the `dont-update` + narrow-write pattern this reuses. #128 (closed) established the replay audit event this may follow. Neither blocks; no shared call sites.

---

## 0. Code anchors

| Label | File | Function | Locate by | Note |
|---|---|---|---|---|
| `otp/verify-enabled` | `src/authserver/internal/handlers/handler_auth_otp.go` | `HandleAuthOtpPost` | `otpValid := totp.Validate(otpCode, otpSecret)` | call site 1: browser login, user already enrolled |
| `otp/verify-enrolling` | `src/authserver/internal/handlers/handler_auth_otp.go` | `HandleAuthOtpPost` | `otpValid := totp.Validate(otpCode, secretKey)` | call site 2: browser login, enrolling now |
| `otp/enroll-write` | `src/authserver/internal/handlers/handler_auth_otp.go` | `HandleAuthOtpPost` | `if err := user.SetOTPSecret(secretKey); err != nil {` | the enable write that follows call site 2 |
| `otp/incorrect-error` | `src/authserver/internal/handlers/handler_auth_otp.go` | `HandleAuthOtpPost` | `incorrectOtpError := i18n.NewLocalizedError(i18n.ErrCodeOtpIncorrectCode, nil).Localize(r.Context())` | the generic error a replay must reuse |
| `api-otp/verify` | `src/authserver/internal/handlers/apihandlers/handler_api_account_otp.go` | `HandleAPIAccountOTPPut` | `if !totp.Validate(req.OtpCode, normalizedSecret) {` | call site 3: self-service enable |
| `api-otp/disable` | `src/authserver/internal/handlers/apihandlers/handler_api_account_otp.go` | `HandleAPIAccountOTPPut` | `user.ClearOTPSecret()` | self-service disable |
| `admin-otp/disable` | `src/authserver/internal/handlers/apihandlers/handler_api_users_crud.go` | `HandleAPIUserOTPPut` | `user.ClearOTPSecret()` | admin disable, the only other place OTP is turned off |
| `model/generation-field` | `src/core/models/user.go` | `n/a` | `// AuthStateGeneration is the authoritative per-user authentication generation:` | the `dont-update` precedent, verbatim reasoning |
| `model/get-otp-secret` | `src/core/models/user.go` | `GetOTPSecret` | `if len(u.OTPSecretEncrypted) == 0 {` | how a stored secret is read |
| `data/mark-code-used` | `src/core/data/commondb/code.go` | `MarkCodeAsUsed` | `ub.Equal("used", false),` | the compare-and-set template |
| `data/increment-generation` | `src/core/data/commondb/user.go` | `IncrementUserAuthStateGeneration` | `auth_state_generation = auth_state_generation + 1` | narrow-write template |
| `data/update-user-tags` | `src/core/data/commondb/user.go` | `UpdateUser` | `WithoutTag("dont-update").Update("users", user)` | what excludes a column from the ordinary update |
| `data/insert-user-tags` | `src/core/data/commondb/user.go` | `CreateUser` | `insertBuilder := userStruct.WithoutTag("pk").InsertInto("users", user)` | `dont-update` columns are still in the insert |
| `data/interface-generation` | `src/core/data/database.go` | `n/a` | `IncrementUserAuthStateGeneration(tx *sql.Tx, userId int64) (int64, error)` | where a new method is declared |
| `otp/secret-generator` | `src/core/otp/generator.go` | `GenerateOTPSecret` | `key, err := totp.Generate(totp.GenerateOpts{` | period/digits/algorithm are all library defaults |
| `migration/generation-sqlite` | `src/core/data/sqlitedb/migrations/000024_add_auth_state_generation.up.sql` | `n/a` | `ALTER TABLE users ADD COLUMN auth_state_generation INTEGER NOT NULL DEFAULT 0;` | shape to copy |
| `migration/generation-mssql` | `src/core/data/mssqldb/migrations/000024_add_auth_state_generation.up.sql` | `n/a` | `CONSTRAINT [df_users_auth_state_generation] DEFAULT 0;` | mssql needs a NAMED default or the down migration cannot drop the column |
| `ratelimit/otp-route` | `src/authserver/internal/server/routes.go` | `n/a` | `r.With(rateLimiter.LimitOtp).Post("/otp"` | the only OTP route that is rate limited |
| `catalog/incorrect-otp` | `src/core/i18n/catalogs/active.en.toml` | `n/a` | `handler.otp.incorrect_code` | the existing generic message |
| `docs/security-2fa` | `site/src/content/docs/reference/security.mdx` | `n/a` | `**Two-factor authentication** - Optional or mandatory 2FA using TOTP` | where a one-line claim belongs |
| `test/reenroll-same-window` | `src/authserver/tests/integration/authorize_existing_session_test.go` | `TestAuthorize_ExistingAcrLevel2MandatorySession_AcrLevel2MandatoryRequest_OtpDisabled` | `otpSecret := getOtpSecretFromEnrollmentPage(t, resp)` | the one test this change breaks |
| `test/session-l2m-helper` | `src/authserver/tests/integration/utils_test.go` | `n/a` | `func createSessionWithAcrLevel2Mandatory` | fresh user per call, so tests do not collide |
| `test/unit-otp-success` | `src/authserver/internal/handlers/handler_auth_otp_test.go` | `TestHandleAuthOtpPost` | `t.Run("Successful OTP validation for enabled OTP"` | one of three subtests needing a new stub |
| `test/api-otp-enable` | `src/authserver/tests/integration/api_account_otp_test.go` | `n/a` | `func TestAPIAccountOTPPut_Enable_Success` | the API enrollment seam |

## 1. Context

### What the code does today

Three call sites validate a TOTP code, all through the library's zero-configuration entry point
(`grep -rn "totp\." --include=*.go src/ | grep -v _test.go` returns exactly these three plus the
generator): `otp/verify-enabled`, `otp/verify-enrolling` and `api-otp/verify`. The issue's list is
correct and complete. The admin console has no fourth site; its OTP page posts to the account API
(`src/adminconsole/internal/handlers/accounthandlers/handler_account_otp.go` calls
`apiClient.UpdateAccountOTP`).

`totp.Validate` carries no notion of a consumed code, and nothing in the schema records one. Verified:
`grep -rn "last_otp\|otp_counter\|otp_used" src/` returns nothing outside this document.

Parameters are all library defaults, confirmed by reading `otp/secret-generator`, which passes no
`Period`, `Digits` or `Algorithm`: period 30, six digits, SHA1, skew 1. Skew 1 accepts the previous,
current and next step, so the acceptance window is roughly 90 seconds.

`ratelimit/otp-route` caps the browser OTP endpoint at 10 attempts per minute per user. As the issue
says, that bounds guessing and does nothing about replay, which needs one attempt.

### Confirmed by execution

A throwaway probe against `pquerna/otp v1.5.0`, pinned to a fixed instant so nothing straddles a period
boundary, checked a candidate matcher against the library's own accept/reject set:

- Codes from steps -1, 0 and +1 are accepted; -2 and +2 are rejected. The matcher names the correct
  step in all three accepted cases.
- All nine degenerate inputs agree with today's behaviour: empty passcode, 5-digit, 7-digit,
  non-numeric, whitespace-padded (accepted, the library trims), lowercase secret (accepted, the
  library upper-cases), space-padded secret (rejected), invalid base32 secret, empty secret.
- Claiming the matched step and refusing anything at or below it gives: first submit accepted, second
  and third refused, previous-step code refused, next-step code accepted then refused on resubmit.

### Where verification contradicts the issue

1. **The issue's proposed loop is unnecessary.** It hand-rolls `totp.GenerateCode` plus
   `subtle.ConstantTimeCompare`, and warns not to regress the constant-time comparison.
   `hotp.ValidateCustom(passcode, counter, secret, opts)` is public, takes an explicit counter, and
   already does exactly that comparison (`crypto/subtle` is imported by `hotp.go` for this). Iterating
   the skew window over `hotp.ValidateCustom` gets the matched step with no cryptographic code of our
   own. This is a departure and decision 7 records it.

2. **The issue's nullable column disagrees with the repo's precedent.** It proposes
   `last_otp_counter BIGINT` nullable with `sql.NullInt64`. `migration/generation-sqlite` and
   `model/generation-field` show the established shape is `NOT NULL DEFAULT 0` with a plain `int64`,
   which works here because any real step is around 1.8e9, so 0 is unambiguously "never used".
   Decision 2.

3. **The issue does not mention that `UpdateUser` would regress the counter.** `model/generation-field`
   records why `auth_state_generation` is tagged `dont-update`: every credential handler loads the
   whole user and writes it back, so a request holding a stale model silently regresses the column.
   A monotonic replay counter has exactly that hazard, and the enrollment path
   (`otp/enroll-write`) is itself one of those whole-user writes. Decision 2.

4. **Enrolment is not merely "lower risk", it is a second use of the same code.** The issue argues the
   enrolment sites should share the mechanism "for consistency". Verified stronger: at
   `otp/verify-enrolling` a successful enrolment sets `OTPEnabled = true`, so resubmitting the same
   code takes the `otp/verify-enabled` branch on the next request and validates against the now-stored
   secret. Without a claim at enrolment, an enrolment code is usable exactly twice. Decision 3.

5. **One integration test breaks.** `test/reenroll-same-window` calls `test/session-l2m-helper`, which
   authenticates with OTP, then disables OTP, sleeps 200ms, and enrols a fresh secret submitting a
   code from the same time step. A per-user counter refuses the second submission. Every other OTP
   test submits at most one code per user (`awk` over `authenticateWithOtp`,
   `createSessionWithAcrLevel2Mandatory` and `navigateToOtpScreen` across
   `src/authserver/tests/integration/*.go`), and `test/session-l2m-helper` creates a fresh user per
   call, so no other test collides. Decision 8.

6. **Three unit subtests need a new stub.** `test/unit-otp-success`, "Successful OTP validation for
   disabled OTP (enrollment)" and "Error updating user during OTP enrollment" all reach a successful
   validation against a mocked `data.Database`.

### The consequences worth knowing before deciding

- **A legitimate user is refused a code they just used.** Enable OTP on the account page, then hit a
  level2 client: `Level2AuthConfigHasChanged` forces an OTP prompt, and the authenticator may still be
  showing the code just consumed. They wait for the next one. This is what RFC 6238 5.2 asks for, and
  `catalog/incorrect-otp` already tells them codes change every 30 seconds.
- **A strictly monotonic counter with no reset is a lockout trap.** If the clock steps far forward and
  then back, the stored counter is in the future and every code is refused until wall time catches up.
  With no reset there is no operator remedy: admin-disabling OTP and re-enrolling also fails, because
  re-enrolment claims against the same poisoned counter. Decision 4.

> **Assumption.** Migration number 000027 is free. `ls src/core/data/sqlitedb/migrations | tail`
> shows 000026 as the highest, and 000026 (`add_code_revoked`, #129) is merged to main. Not verified
> against `schema_migrations` in the long-lived `goiabada_data` and `goiabada_integration` databases,
> which no repo file records and which the container has no SQL client to query. The run must confirm
> the number is not already recorded there before writing the migration: a version recorded by a
> discarded attempt is skipped silently and the tests then run against the wrong schema.

## 2. Goal

A TOTP code that has been accepted once is never accepted again, on any of the three call sites, and
the refusal is indistinguishable from a wrong code to the caller.

Checkable:

1. Submitting the same code twice to the browser OTP endpoint succeeds once and fails once, with the
   same rendered error as a wrong code.
2. A code accepted during enrolment is refused when replayed at verification.
3. Two concurrent submissions of one code yield at most one success.
4. The counter cannot be regressed by an ordinary whole-user write.
5. The four engines agree, proven at the data tier.

### Out of scope

- **Narrowing the skew window** (issue recommendation 3). Independent of replay, changes behaviour for
  users with fast clocks, and the issue itself calls it optional and separate. Decision 6; drafted as a
  follow-up in `closing.md` so it is not lost when #111 closes.
- **The empty-secret enrolment defect** found while grounding (see `closing.md`). Real and verified,
  but a different bug.
- **Rate limiting `PUT /api/v1/account/otp`**, already tracked as #113.
- **`LimitOtp` returning a blank 200 on an unreadable auth context**, already tracked as #114.
- **Dropping the plaintext `users.otp_secret` column**, already tracked as #98.
- Any change to how OTP secrets are generated, stored or encrypted.
- Any change to ACR/AMR, session or step-up logic.

### Documentation owed

- `docs/security-2fa`: the "Authentication security" list says two-factor auth exists but nothing about
  one-time use. One bullet, in the stage that lands enforcement, in the shape of the neighbouring
  "Refresh token rotation" and "Replay containment" bullets.
- `site/src/content/docs/concepts/acr-amr.mdx` describes the OTP prompt but makes no claim about code
  reuse, so it is not falsified. No change unless decision 5 adds an audit event, which would also
  touch `site/src/content/docs/concepts/audit-log.mdx`.
- **No new user-facing string.** `catalog/incorrect-otp` already carries the generic message a replay
  must reuse, so neither `active.en.toml` nor `active.pt-BR.toml` changes. If decision 5 adds an audit
  event that is a server-side event name, not a catalog entry.
- `CLAUDE.md` gains nothing: no new directory, tier or flow. The migration number is not recorded there.

## 3. Decisions

Eight, provisionally. Answering one routinely exposes another.

1. **Where does the consumed-code state live?**
   Status: **Open** · Raised by: user

   A column on `users`, a separate consumed-codes table, or an in-process cache. What hangs on it:
   everything downstream, including whether this needs a migration at all.

2. **What shape is the column and how is it written?**
   Status: **Open** · Raised by: user

   Nullable `BIGINT` with `sql.NullInt64` as the issue proposes, or `NOT NULL DEFAULT 0` with a plain
   `int64` as `model/generation-field` does. And whether it rides in `UpdateUser` or is tagged
   `dont-update` with a narrow compare-and-set method. Depends on 1.

3. **Do all three call sites claim the counter, or only verification?**
   Status: **Open** · Raised by: user

   Context item 4 shows enrolment leaves a code usable twice if it does not claim. Claiming everywhere
   costs the friction in context, plus the test repair in decision 8.

4. **Does disabling OTP reset the counter?**
   Status: **Open** · Raised by: user

   Resets at `api-otp/disable` and `admin-otp/disable` are the only operator remedy for the clock-jump
   lockout in context. Costs a second narrow data method and touches the admin path. Depends on 2.

5. **Does a detected replay get its own audit event?**
   Status: **Open** · Raised by: user

   The issue says reuse `AuditAuthFailedOtp`. #128 set the opposite precedent with
   `refresh_token_replay_detected`. The audit log is server side, so a distinct event leaks nothing to
   the caller. Adds a constant and a line to `concepts/audit-log.mdx`.

6. **Is narrowing the skew window part of this change?**
   Status: **Open** · Raised by: user

   Provisionally out of scope per section 2. Confirm, and confirm the follow-up draft.

7. **Where does the step matcher live, and do the three sites share a helper?**
   Status: **Open** · Raised by: user

   A pure function in `src/core/otp/` iterating the skew window over `hotp.ValidateCustom`, versus the
   issue's hand-rolled compare. And whether the match-then-claim pair is inlined at each site or
   extracted. Determines the seams in section 5.

8. **How is `test/reenroll-same-window` repaired?**
   Status: **Open** · Raised by: user

   It already reaches into the database to disable OTP, so clearing the counter there is consistent,
   but only if decision 4 makes that production behaviour. The alternative is waiting out a period,
   which adds up to 30 seconds to the suite. Depends on 3 and 4.
