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
- **Any empty-secret or malformed-secret hardening beyond `otp/verify-enrolling`.** Decision 9 guards
  the one site this change rewrites and nothing else.
- **Rate limiting `PUT /api/v1/account/otp`**, already tracked as #113.
- **`LimitOtp` returning a blank 200 on an unreadable auth context**, already tracked as #114.
- **Dropping the plaintext `users.otp_secret` column**, already tracked as #98.
- Any change to how OTP secrets are generated, stored or encrypted.
- Any change to ACR/AMR, session or step-up logic.

### Documentation owed

- `docs/security-2fa`: the "Authentication security" list says two-factor auth exists but nothing about
  one-time use. One bullet, in the stage that lands enforcement, in the shape of the neighbouring
  "Refresh token rotation" and "Replay containment" bullets, naming `otp_code_replay_detected` and
  linking to `/concepts/audit-log/` exactly as those two do.
- **`concepts/audit-log.mdx` is not touched.** Verified: it does not enumerate events, it states that
  the full set is defined in `src/core/constants/constants.go`. New events are documented where the
  behaviour is, which for both #128 and #129 was `security.mdx` plus the concepts page owning that
  behaviour.
- **No new concepts page or section.** `concepts/acr-amr.mdx` owns ACR and AMR levels, not TOTP
  mechanics, and makes no claim about code reuse, so nothing there is falsified. No page owns TOTP
  mechanics today, and one-time use is a single sentence, so the `security.mdx` bullet carries it
  rather than inventing a section structure for it.
- **No new user-facing string.** `catalog/incorrect-otp` already carries the generic message a replay
  must reuse, so neither `active.en.toml` nor `active.pt-BR.toml` changes. The audit event is a
  server-side identifier, not a catalog entry.
- `CLAUDE.md` gains nothing: no new directory, tier or flow. The migration number is not recorded there.

## 3. Decisions

Nine. Announced as eight; sweeping the design for what the run would otherwise have to escalate added
decision 9.

1. **Where does the consumed-code state live?**
   Status: **Decided** · Raised by: user

   **A single last-consumed time-step counter per user, as a column on `users`.** One row per user,
   nothing to grow, nothing to sweep, and the shared database is the arbiter so it holds across
   multiple server instances. Matches the issue's proposal.

   **Rejected:** a consumed-codes table, one row per burned (user, step) pair. More precise, since a
   high-water mark also refuses codes below it that were never actually used, but that over-rejection
   only spans the 90-second acceptance window and it costs a table, an index and a cleanup sweep.
   **Rejected:** an in-process cache, which forgets on restart and does not hold across instances, so
   a replay right after a deploy succeeds.

2. **What shape is the column and how is it written?**
   Status: **Decided** · Raised by: user

   **`users.last_otp_step`, `NOT NULL DEFAULT 0`, a plain `int64` on the model tagged
   `dont-update`, written only by a narrow compare-and-set.** 0 means never used, unambiguously: any
   real step is around 1.8e9. The same shape as `model/generation-field`, for the same reason spelled
   out there. The only write is

   ```sql
   UPDATE users SET last_otp_step = ?, updated_at = ? WHERE id = ? AND last_otp_step < ?
   ```

   which is both the claim and the replay check, so a second submission of one code matches no row.
   `data/insert-user-tags` shows `dont-update` columns are still in the insert, so a new user lands at
   the Go zero value 0, which is the correct starting state.

   **Rejected:** nullable with `sql.NullInt64`, as the issue proposes. It distinguishes never-used
   from used, nothing needs that distinction, and it puts `.Valid` handling at every read site.
   **Rejected:** an ordinary field carried by `UpdateUser`. `otp/enroll-write` is a whole-user write
   on the very path that claims a counter, so a model loaded before a concurrent verification would
   write the old counter back and reopen the replay window.

3. **Do all three call sites claim the counter, or only verification?**
   Status: **Decided** · Raised by: user

   **All three.** `otp/verify-enabled`, `otp/verify-enrolling` and `api-otp/verify`. Enrolment claims
   because it is not merely lower risk: it sets `OTPEnabled = true`, so the same code resubmitted takes
   the verification branch against the now-stored secret and is accepted a second time. Claiming makes
   one-time use hold across that boundary.

   Accepted costs: the repair in decision 8, and a user who enrols and immediately meets a level2
   prompt (via `Level2AuthConfigHasChanged`) waits for the next code.

   **Rejected:** verification only. Cheaper, and it leaves an enrolment code usable exactly twice,
   which is the property this change exists to remove.

4. **Does disabling OTP reset the counter?**
   Status: **Decided** · Raised by: user

   **Yes, at `api-otp/disable` and `admin-otp/disable`, via a second narrow method.** The counter
   belongs to the enrolled authenticator; removing the authenticator clears it. It is also the only
   in-product remedy for the clock-jump lockout in section 1: with no reset, admin-disabling and
   re-enrolling claims against the same poisoned counter and fails too.

   Not a bypass. Self-service disable requires the password (`api-otp/disable` verifies it before
   branching), admin disable requires `authserver:manage`, and re-enrolling requires possession of a
   fresh secret. Nothing here lets a replayed code buy anything.

   **Rejected:** strictly monotonic with no reset. One method instead of two and a simpler invariant,
   at the price of a permanent per-user OTP lockout that no operator can clear from the product.

5. **Does a detected replay get its own audit event?**
   Status: **Decided** · Raised by: user

   **Yes, `otp_code_replay_detected`, emitted alongside the existing `AuditAuthFailedOtp`.** A
   replayed code is a far stronger signal than a mistyped one, usually a real-time phishing proxy, and
   it deserves to be alertable on its own. Follows #128's `refresh_token_replay_detected` rather than
   the issue's suggestion. The audit log is server side, so the caller still sees only
   `catalog/incorrect-otp` and learns nothing.

   Payload follows the neighbours: `userId`, and the matched step so an operator can see which code
   was replayed. Never the code itself.

   **Rejected:** reusing `AuditAuthFailedOtp` alone, as the issue asks. Nothing new to add, and it
   makes the one failure mode that indicates an active attack indistinguishable from a typo.

6. **Is narrowing the skew window part of this change?**
   Status: **Decided** · Raised by: user

   **No. Skew stays at 1, and the question is drafted as a follow-up in `closing.md`.** It is
   independent: the counter guard behaves identically at any skew. Narrowing it starts refusing users
   whose device clock runs fast, which is a user-visible change that should not ride along inside a
   security fix nobody is reading for UX.

   **Rejected:** narrowing here, which is cheap once the matcher iterates the window explicitly and
   is exactly why it would go unnoticed. **Rejected:** dropping it, since the issue raised it and
   closing #111 would lose it.

7. **Where does the step matcher live, and do the three sites share a helper?**
   Status: **Decided** · Raised by: user

   **`otp.MatchStep(passcode, secret string, now time.Time) (int64, bool)` in `src/core/otp/`, pure,
   with match-then-claim inlined at each of the three sites.** It iterates the skew window over
   `hotp.ValidateCustom`, so the constant-time comparison stays the library's. No database dependency
   in `core/otp`, and the six inlined lines respect that the three sites' failure handling genuinely
   differs: two rerender a template, one writes JSON.

   `now` is a parameter rather than read inside, which is what makes the exhaustive table testable at
   a pinned instant instead of racing period boundaries.

   **Rejected:** a shared verify-and-consume helper. It removes little, since it must return a
   three-way result each site translates back into its own branches, and it pulls `data.Database` into
   whichever package holds it. **Rejected:** the issue's hand-rolled `GenerateCode` plus
   `subtle.ConstantTimeCompare`, which writes cryptographic comparison code that
   `hotp.ValidateCustom` already provides.

8. **How is `test/reenroll-same-window` repaired?**
   Status: **Decided** · Raised by: user

   **The test resets the step alongside the direct disable it already performs.** It bypasses the
   handlers to disable OTP (`user.OTPEnabled = false` then `UpdateUser`), and `last_otp_step` is
   `dont-update` so that write cannot reach it. Adding the reset call there reproduces exactly what
   `api-otp/disable` and `admin-otp/disable` do under decision 4. One line, no wall clock.

   **Requires a comment** saying the test is standing in for the disable handler, or it reads as a
   test helping itself past the guard under review.

   **Rejected:** disabling through the admin API, which is more faithful but rewrites setup in a test
   about ACR step-up and needs an admin token it does not have. **Rejected:** sleeping past the period
   boundary, which adds up to 30 seconds of wall clock to the integration suite for one test.

9. **Is the empty-secret enrolment gap fixed here?**
   Status: **Decided** · Raised by: user

   **Yes, a guard at `otp/verify-enrolling` refusing an empty candidate secret before matching.**
   Confirmed by execution: `totp` computes a real six-digit code for the empty secret and accepts it,
   so an enrolment reached with an empty session secret enrols a secret anyone can derive. That line
   is being rewritten by this change, so leaving the path in it is a review objection waiting to
   happen, and the guard is two lines. The follow-up is still drafted in `closing.md`, recorded as
   fixed here.

   Scope stays honest: the guard is at the one site being rewritten, not a general hardening pass.

   **Rejected:** follow-up only, which is the tidier scope boundary but knowingly ships the gap on a
   line we touched. **Rejected:** guarding all three sites; `api-otp/verify` already rejects a secret
   outside 16 to 64 base32 characters, and `otp/verify-enabled` reads its secret from the database, so
   the extra checks would be redundant.

## 4. Design

**The property that makes this safe:** a code is accepted only by the statement that consumes it. The
compare-and-set is the claim and the replay check at once, so there is no window between deciding a
code is good and recording that it was used. Two requests presenting one code contend on a single
`UPDATE`, and at most one row transitions.

### The matcher, `src/core/otp/verifier.go`

```go
const StepSeconds = 30

// MatchStep reports which time step produced passcode, within the accepted skew
// window, so the caller can record that step as consumed. now is a parameter rather
// than read here so the window can be tested at a pinned instant.
func MatchStep(passcode string, secret string, now time.Time) (int64, bool) {
	current := now.Unix() / StepSeconds
	for _, delta := range []int64{0, -1, 1} {
		step := current + delta
		ok, err := hotp.ValidateCustom(passcode, uint64(step), secret, hotp.ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, false
		}
		if ok {
			return step, true
		}
	}
	return 0, false
}
```

Digits, algorithm and the 30 second step are the library defaults `otp/secret-generator` relies on, so
this accepts exactly what `totp.Validate` accepts today. Verified by execution against
`pquerna/otp v1.5.0`, per section 1.

Errors collapse to "no match" rather than propagating, which preserves today's behaviour: `totp.Validate`
discards the same errors (`rv, _ := ValidateCustom(...)`). A wrong-length passcode and an unparseable
secret both produce the generic incorrect-OTP response, not a 500. This is deliberate and not an
oversight to be tidied later.

### The column and its two writes

`users.last_otp_step`, `NOT NULL DEFAULT 0`, `int64` on the model tagged `dont-update` per decision 2.
Migration 000027 on all four engines, following `migration/generation-sqlite` for shape and
`migration/generation-mssql` for the named default constraint the down migration needs. The four
`schema.sql` snapshots are updated in the same stage; they are documentation, but 000024's columns are
in all four, so leaving them out is drift.

Two methods on `data.Database`, declared next to `data/interface-generation`:

```go
// TryConsumeUserOTPStep records step as the user's most recently consumed TOTP time
// step, but only if it is strictly newer than what is stored, and reports whether
// this call is the one that made the transition. Compare-and-set for the same reason
// MarkCodeAsUsed is: validating a code and recording it as used must not be separable,
// or two concurrent submissions of one code both pass.
TryConsumeUserOTPStep(tx *sql.Tx, userId int64, step int64) (bool, error)

// ResetUserOTPStep returns the user's consumed-step marker to 0, meaning no code has
// been consumed. Called when OTP is disabled: the marker belongs to the enrolled
// authenticator, and it is the only remedy if a clock jump strands the marker in the
// future (#111 decision 4).
ResetUserOTPStep(tx *sql.Tx, userId int64) error
```

`tx` is optional on both, as on `MarkCodeAsUsed`, because each is a single statement. Neither reads
back, so the transaction requirement `data/increment-generation` documents does not apply.

The claim is:

```sql
UPDATE users SET last_otp_step = ?, updated_at = ? WHERE id = ? AND last_otp_step < ?
```

with the same value bound to both `?` for the step. `rowsAffected == 1` means this call transitioned
the row, on all four engines: matching the `WHERE` implies the assigned step is strictly greater, so
the row genuinely changes and MySQL's changed-rows accounting agrees with matched-rows. That is the
trap `RevokeCodesBySessionIdentifier` documents, and it does not bite here.

**A `false` return is not proof of replay.** It means no row transitioned, which is either a step at or
below the stored one, or a user row that vanished. The caller loaded the user moments earlier, so
replay is overwhelmingly the cause, and the response is identical either way. The audit event in
decision 5 is named for the likely cause and the doc comment records the imprecision, as
`data/mark-code-used` does for its own.

**Failure is not benign.** A query error returns `(false, err)` and the caller responds 500. Collapsing
a database fault into "not consumed" would refuse valid codes; collapsing it into "consumed" would
accept replays for the duration of the fault. Neither is acceptable, and the data tier proves the
error path with a rolled-back transaction.

### The three call sites

Each becomes, in place of the single `totp.Validate` call:

```go
step, matched := otp.MatchStep(code, secret, time.Now().UTC())
if !matched {
    // existing AuditAuthFailedOtp path, unchanged
}
consumed, err := database.TryConsumeUserOTPStep(nil, user.Id, step)
if err != nil {
    // 500
}
if !consumed {
    auditLogger.Log(constants.AuditOTPCodeReplayDetected, map[string]interface{}{
        "userId": user.Id, "step": step,
    })
    // the same AuditAuthFailedOtp path as a wrong code
}
```

The replay branch reuses `otp/incorrect-error` at the two browser sites and the existing
`INVALID_OTP_CODE` JSON error at `api-otp/verify`. A replay is indistinguishable from a wrong code to
the caller, and both emit `AuditAuthFailedOtp`; the new event is additional, not a substitute.

**At `otp/verify-enrolling`, the claim comes before `otp/enroll-write`.** If the enable write then
fails, a code is burned and the user retries with the next one. The reverse order would leave OTP
enabled on a request that was refused.

**At `otp/verify-enrolling`, an empty `secretKey` is refused before matching** (decision 9), with the
generic incorrect-OTP error.

### Disable resets

`api-otp/disable` and `admin-otp/disable` call `ResetUserOTPStep` alongside their existing
`ClearOTPSecret` and `UpdateUser`. `UpdateUser` cannot do it: the column is `dont-update`, which is the
whole point.

### Not part of this

`last_otp_step` is internal state and is not added to `api.ToUserResponse`, which maps fields
explicitly, so nothing exposes it over the API. No settings key, no per-client configuration: one-time
use is unconditional.

### Pre-flight the run owes

Confirm migration version 000027 is not already recorded in `schema_migrations` in the long-lived
`goiabada_data` and `goiabada_integration` databases before writing it, per the assumption in section 1.
A version recorded by a discarded attempt is skipped silently and the suite then runs against the wrong
schema. The `migration_000024_*` and `migration_000026_*` data tests are the pattern for reading it.
