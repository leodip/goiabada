# Issue 111: TOTP codes are replayable, RFC 6238 5.2 requires one-time use

**Issue:** [#111](https://github.com/leodip/goiabada/issues/111)
**Issue state:** open (labels: bug, security)
**Written:** 2026-08-05
**Last synced:** 2026-08-05 (no comments on the issue)
**Agreement sealed:** 2026-08-05
**Run state:** stage 2 done at `a10c6bb`, unit/data/integration green on tree `f53d3b9a0856`, review clean in one round. Stage 3 next, enforcement in the browser flow. All twelve decisions decided, none raised this stage. Account in `log/stage-2.md`
**PR:** [#143](https://github.com/leodip/goiabada/pull/143) (draft)
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
  library upper-cases), space-padded secret (rejected), invalid base32 secret, empty secret. The
  shipped matcher then diverges on exactly one of these, the empty secret, by decision 9.
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
  users with fast clocks, and the issue itself calls it optional and separate. Decision 6; filed as
  #142 so it is not lost when #111 closes.
- **Malformed-secret hardening beyond the empty case, and repairing rows the empty-secret bug already
  created.** Decision 9 refuses an empty secret in `MatchStep`, which makes such a row inert; it does
  not detect or repair one, and it does not touch the other secret-format checks.
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

Twelve, all decided. Announced as eight; sweeping the design for what the run would otherwise have to
escalate added decision 9, and three more were raised during stage 1: decision 10 from the plan review,
decision 11 from the code review and decision 12 from its third round, all three answered by the user
on PR #143.

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

   Filed as #142 on 2026-08-05.

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

9. **Is the empty-secret gap fixed here, and where does the guard go?**
   Status: **Decided** · Raised by: user

   **Yes. `MatchStep` returns `(0, false)` for an empty secret**, which covers all three call sites
   from one place. Confirmed by execution: `totp` computes a real six-digit code for the empty secret
   and accepts it, and the code depends only on the time step, so it is the same for every deployment.

   **First answered as a guard at `otp/verify-enrolling` alone, then revised.** That reading rested on
   the claim that `otp/verify-enabled` is safe because its secret comes from the database. It is not.
   `SetOTPSecret("")` stores the ciphertext of an empty string, so `model/get-otp-secret` returns `""`
   for such a row, and a user enrolled through this very bug ends up with `OTPEnabled = true` and an
   empty secret. For that user `otp/verify-enabled` accepts the computable empty-secret code, so an
   enrolment-site-only guard would stop new poisoned rows and leave existing ones exploitable by
   anyone holding the password. The guard belongs where every site passes through.

   **Consequence, accepted:** an existing poisoned row becomes inert rather than exploitable. That user
   cannot pass level2 until an admin disables OTP and they re-enrol, which is the same operator remedy
   decision 4 provides for a stranded counter.

   **Rejected:** follow-up only, which knowingly ships the gap on a line this change rewrites.
   **Rejected:** the enrolment-site guard, for the reason above. **Rejected:** adding a startup sweep
   that disables OTP on rows with an unusable secret, which is correct but introduces a data-repair
   path to a change that otherwise has none, for a population that may well be empty.

10. **The claim binds to enrolment state. `TryConsumeUserOTPStep` takes a `requireOTPEnabled` flag.**
    Status: **Decided** · Raised by: run (raised during stage 1, at the plan-review gate, before any
    stage started)

    Answered by the user on PR #143, 2026-08-05, in full: "A. Bind the claim to enrolment state."
    That is option A below, the recommended one, taken over B, C and D with no amendment.

    **What the answer settles.** The method becomes
    `TryConsumeUserOTPStep(tx *sql.Tx, userId int64, step int64, requireOTPEnabled bool) (bool, error)`,
    superseding the three-argument declaration in §4 and its doc comment. With the flag set the
    predicate gains `AND otp_enabled = ?` bound true; without it the predicate is §4's.
    `otp/verify-enabled` passes true, because a verification claim asserts a factor and that assertion
    is only true of an enrolled authenticator. `otp/verify-enrolling` and `api-otp/verify` pass false,
    because §4 puts the claim before the enable write deliberately and `otp_enabled` is still false
    there. Verified for the third site: `api-otp/verify` refuses an enable with `OTP_ALREADY_ENABLED`
    when `user.OTPEnabled`, so it is only ever reached with OTP off.

    **The predicate is portable, checked rather than assumed.** `users.otp_enabled` carries the same
    type as `users.enabled` on all four engines (`numeric`, `tinyint(1)`, `boolean`, `BIT`), and
    `TrySetUserEnabled` already binds a Go bool against `users.enabled` in exactly this position, so
    `ub.Equal("otp_enabled", true)` needs nothing engine-specific.

    **The two writes need no transaction, but their order is load-bearing**, which is the half of the
    question the plan review left open. A disable must write `otp_enabled = false` before it resets the
    marker, the order §4 already describes. Reversed, there is a window where the marker reads 0 while
    the authenticator still reads enabled, and an in-flight verification claims a consumed step through
    it, reintroducing by ordering the hole the flag closes. Both disable sites carry a comment saying
    so; neither needs `tx`.

    **Accepted cost, and it is not only the parameter.** A verification claim now returns false for a
    second reason: the authenticator was removed under this request. So `otp_code_replay_detected`
    fires on that rare interleaving too, naming the likely cause rather than the certain one, which is
    what `data/mark-code-used` already documents about its own three-way false. The caller sees
    `catalog/incorrect-otp` either way.

    **Not closed, and knowingly.** A disable immediately followed by a re-enrolment, while a stale
    verification request is still in flight, has `otp_enabled` true again by the time the claim lands.
    Closing that needs an enrolment-generation column. Narrower than option A's text below says: the
    re-enrolment must also claim a step strictly below the replayed one, so the replayed code has to
    come from the +1 window and the re-enrolment from the current one or earlier. Drafted as a
    follow-up in `closing.md`.

    **What lost.** B, resetting to the current step, on its 30 second re-enrolment delay and because it
    bounds the blast radius instead of fixing the cause, weakening seam 4's pinned case in the process.
    C, accepting the false factor assertion, which the run declined to judge on the user's behalf. D,
    dropping the reset, which was not recommended.

    The question as escalated is kept below, because the reasoning is what makes the answer reviewable.

    ---

    **The original question.** The plan review found an interleaving that decision 4's "Not a bypass.
    ... Nothing here lets a replayed code buy anything" does not cover. Both mechanism claims verified
    against the code:

    1. A browser request at `otp/verify-enabled` loads the user (`GetUserById`), then decrypts the
       stored secret and validates, holding both in memory for the rest of the request.
    2. A disable (`api-otp/disable` or `admin-otp/disable`) commits `ClearOTPSecret` plus
       `UpdateUser`, then `ResetUserOTPStep` sets the marker to 0, as two separate writes.
    3. The designed claim predicate is `id` plus `last_otp_step < step` and binds nothing about
       enrolment, so the in-flight request then claims an already-consumed step successfully.
    4. `handler_auth_completed.go:HandleAuthCompletedGet` reloads the user but checks only
       `user.Enabled`, never `user.OTPEnabled`, so nothing downstream catches it.

    The race is required: after a disable commits, a *fresh* request takes the enrolling branch and
    validates against the session secret, not the stored one, so only a request that loaded the old
    enabled state can do this.

    **The impact is narrower than the review states, and this is what the answer should turn on.**
    The review concludes the attacker "obtains level 2". Verified otherwise: once OTP is disabled, a
    holder of the level 1 credential already reaches level 2 more cheaply.
    `handler_auth_level2.go:HandleAuthLevel2Get` sends `AcrLevel2Optional` with `!user.OTPEnabled`
    straight to `/auth/completed`, skipping OTP entirely, and `AcrLevel2Mandatory` to the enrolment
    form where the attacker can enrol their own secret. So the replay buys no access that the disable
    did not already grant. What it does buy is a token asserting `amr: ["pwd","otp"]` for an
    authenticator that has just been removed, obtained without the `AuditEnabledOTP` event and the
    visible new authenticator that self-enrolment would leave. A false factor assertion and a stealth
    gain, not an access gain.

    **Why this is the user's call rather than the run's:** it is a security property, it touches
    authentication, and the leading options change `TryConsumeUserOTPStep`'s signature or decision 4's
    observable behaviour, which stage 2 fixes and stage 4 depends on. The reviewer returned it with an
    empty `forced_answer`, so it is a choice, not a mechanical repair.

    **Option A, bind the claim to enrolment state.** Add `AND otp_enabled = 1` to the claim, which
    cannot be unconditional because the two enrolment sites claim while `otp_enabled` is still false
    (§4 puts the claim before `otp/enroll-write` deliberately). So the method takes a flag:
    `TryConsumeUserOTPStep(tx, userId, step, requireOTPEnabled bool)`. Closes the hole at its cause,
    costs a signature change and one more branch at three call sites. Does not close the narrower
    variant where a disable is immediately followed by a re-enrolment with a new secret while the
    stale request is still in flight, since `otp_enabled` is true again by then; closing that needs an
    enrolment generation column, which is a second column and a larger change.

    **Option B, reset to the current step rather than to 0.** `last_otp_step = now/30` on disable. A
    code consumed in the current window stays refused, and a marker stranded in the future by a clock
    jump still comes back to now, so decision 4's operator remedy survives. No signature change, no
    new column, one line different in `ResetUserOTPStep`. Cost: after a disable, re-enrolling with a
    code from the current window is refused and the user waits up to 30 seconds, and seam 4's pinned
    "enable, disable, re-enable with the same C succeeds" case has to become a later-step code, which
    weakens what that case proves about the reset.

    **Option C, accept and document it.** Given the corrected impact above, record the false AMR
    assertion as a known narrow window and proceed with the design as sealed. Costs nothing now and
    leaves an authentication surface where a token can name a factor that no longer exists.

    **Option D, drop the reset entirely**, reversing decision 4. Removes the reopening completely and
    reinstates the permanent clock-jump lockout with no in-product remedy, which decision 4 rejected
    for good reason. Recorded for completeness; not recommended.

    **Recommendation: A.** It is the only option that fixes the cause rather than the blast radius,
    the signature change is cheap because it lands in stage 2 before any caller exists, and the flag
    reads honestly at each site (verification requires enrolment, enrolment does not). B is the
    fallback if the signature change is unwelcome, and its 30 second re-enrolment delay is the thing
    to weigh. C is defensible only if the false AMR assertion is judged acceptable, which is a
    judgement about what the tokens this server issues are allowed to claim, and that is not the run's
    to make.

    Getting it wrong either way: choosing C and later reversing means revisiting stage 2's interface
    and stage 4's tests after both have landed. Choosing A when C would have done costs one boolean
    parameter and a little noise at three call sites.

11. **One passcode can be produced by two steps in the window. Which step does `MatchStep` return?**
    Status: **Decided** · Raised by: run (raised during stage 1, at the code-review gate, after the
    matcher landed)

    Answered by the user on PR #143, 2026-08-06, in full: "B". That is option B below, the
    recommended one, taken over A, B2, C and D with no amendment.

    **What the answer settles**, superseding §4's `MatchStep` sketch and its doc comment. `MatchStep`
    keeps `(int64, bool)` and accepts exactly what §4 accepted, a match at
    `current-skew .. current+skew`, so nothing in stages 2 to 4 moves. What changes is the step it
    reports:
    the lowest one within `lookbackSteps` below the window that produces the same passcode, where
    `lookbackSteps = 2*skewSteps + 1`, derived from the window rather than written as a literal so
    that #142 narrowing the skew narrows this with it. Costs at most three further HMAC computations,
    and only on a successful match: the failure path still computes the window and stops.

    That value is the same at every current step from which a continuously acceptable passcode is
    accepted, which is what makes the first claim of it refuse all the rest. Verified by executing the
    sweep rather than by argument: `probe/step-collisions` reports, for each of the three located
    pairs, the same step at every accepting current step and a refusal either side, and confirms no
    third step within eight either side produces those passcodes. `probe/step-collisions/output.txt`
    is that run. `TestMatchStepWithCollidingSteps` asserts exactly the sweep's last section.

    **What lost, and why the reviewer's own answer was not taken.** A, the greatest match inside the
    window, is the `forced_answer`, and the probe shows it leaves the spread 1 pair replayable from a
    step-early presentation and does not touch spreads 2 and 3 at all. B2 buys only the inherent
    spread 5 case and costs two signature changes in stage 2. C is strictly worse than B on both
    failure modes, accepting a second presentation 30 seconds later and burning up to three of the
    user's upcoming codes. D ships #111 with a reachable instance of the defect #111 exists to close.

    **Accepted cost, unchanged from the escalation.** In the same 3-in-a-million case the marker sits
    up to three steps below the code's own step, which shrinks the incidental refusal of lower unused
    codes that decision 1 calls the counter's imprecision, and which nothing depends on. It can refuse
    one legitimate code, when a collision coincides with a consumption in the previous four steps: the
    user's next code works, so it fails toward a retry rather than a lockout.

    **Still inherent, and knowingly.** Pairs spread 4 or more apart have a gap in which the passcode is
    refused, so by the time it is accepted again the authenticator is legitimately displaying those
    digits for a new step. No marker recording a step can refuse that, and refusing it means storing
    the code itself, which is stronger than the consumed-codes table decision 1 already rejected. The
    probe shows B accepting such a pair a second time at `A+5`, from three presentations.

    The question as escalated is kept below, because the reasoning is what makes the answer reviewable.

    ---

    **The original question.** Stage 1's code review found the shipped matcher replayable and returned a populated
    `forced_answer`, which is normally a repair the run applies rather than a question it escalates.
    This one is escalated because the answer is **demonstrably insufficient**: applying it verbatim
    leaves the invariant broken in cases the probe pins. What to do instead is a choice, and it is a
    choice about the matcher's contract, so it belongs here.

    **The mechanism, reproduced.** A six-digit passcode does not name a time step. `MatchStep` returns
    the first step in delta order `0, -1, 1` that produces the passcode, and decision 2's marker
    records exactly that step. When two steps that are both live for one passcode produce the same six
    digits, the lower is claimed first and the higher is still claimable once the window slides, so the
    same passcode is accepted twice. Verified: steps 3710568 and 3710569 both yield `874294`, and steps
    818665 and 818667 both yield `475244`, for the secret seam 1 pins its table on.

    **How often.** `probe/step-collisions` swept 600,000 consecutive steps, 208 days of one secret, and
    found 5 same-passcode pairs within a spread of 5 steps, against 5 expected: one pair spread 1
    apart, one spread 3, three spread 5. So roughly 8 authentications in a million meet one at all, and
    roughly 3 in a million meet one that matters, for the reason in the next paragraph. Meeting one is
    not yet an exploit: an attacker still needs the code, which is the same precondition #111 already
    assumes.

    **The boundary this should be decided against.** Step A is acceptable while the current step is
    `A-1`, `A` or `A+1`, so two matching steps are *continuously* acceptable only when they are at most
    3 apart, which is `2 * skew + 1` at today's skew of 1. A wider pair has a gap in which the passcode
    is refused, and by the time it is accepted again the authenticator is legitimately displaying those
    same six digits for a new step. No marker that records a *step* can refuse that; refusing it means
    storing the code itself, a stronger thing than the consumed-codes table decision 1 already rejected.
    **Continuously live pairs, spread 1 to 3, are the target. Wider ones are inherent.**

    **What each candidate does**, from the probe. A trace reads "first accepted at current `c1`,
    accepted again at `c2`", and a rule is safe for a pair when no presentation leaves a later one
    acceptable. Every rule below accepts exactly the codes `totp.Validate` accepts today, the empty
    secret aside; they differ only in what they record as consumed.

    | Rule | spread 1 | spread 2 | spread 3 | spread 5 (inherent) |
    |---|---|---|---|---|
    | shipped, first match | replayable from 2 presentations | 3 | 3 | 3, again at `A+4` |
    | A, greatest inside the window | 1, only from `A-1` | 2 | 3 | 3, again at `A+4` |
    | B, lowest within 3 below the window | safe | safe | safe | 4, again at `A+5` |
    | B2, as B but claiming the greatest inside the window | safe | safe | safe | 3, again at `A+5` |
    | C, greatest within 3 above the window | safe | safe | safe | 2, again at `A+1` |

    **Option A, the reviewer's answer as given.** Return the greatest match inside the window, one line,
    reverse the delta order. It closes the trace the reviewer demonstrated and nothing else: the spread
    1 pair survives when the code is presented a step early, which is what the `+1` window exists to
    allow, and spreads 2 and 3 survive from an ordinary presentation because the colliding step is not
    in the window yet when the claim is made.

    **Option B, return the lowest step within three below the window that produces the passcode.**
    Acceptance still requires a match in `c-1 .. c+1`; on a match, walk down to `c-4` and return the
    lowest step there that produces the same code. That value is constant across every presentation of
    a continuously live passcode, which is what makes the first claim block the rest. **No signature
    moves:** `MatchStep` keeps `(int64, bool)` and `TryConsumeUserOTPStep` keeps decision 10's shape,
    so stages 2 to 4 are untouched. Costs: up to four extra HMAC computations on a successful match,
    microseconds; and in the same 3-in-a-million case the marker sits up to three steps below the
    code's own step, which shrinks the incidental refusal of lower unused codes that decision 1
    describes as the counter's imprecision, and which nothing depends on. It can refuse one legitimate
    code, when a collision coincides with a consumption in the previous four steps: the user's next
    code works, so it fails toward a retry rather than a lockout. The `3` should be derived from the
    window rather than written as a literal, so #142 narrowing the skew narrows it too.

    **Option B2, as B but returning two values**, the lowest for the guard and the greatest inside the
    window for the claim, so the marker keeps sitting at the top of the window. The claim stays a single
    statement, `SET last_otp_step = <claim> WHERE id = ? AND last_otp_step < <guard>`. Marginally
    stronger on the inherent wide pairs. Costs a wider `MatchStep` return and a wider
    `TryConsumeUserOTPStep`, both in stage 2, which has no callers yet.

    **Option C, claim upward instead**, the greatest match within three steps above the window. Equal
    on the continuously live cases and no signature change, but the guard rises with the claim, so on a
    wide pair it accepts the second presentation 30 seconds later rather than after a refused gap, the
    worst second-acceptance timing of any candidate. When it fires it also burns up to three of the
    user's upcoming codes, up to 90 seconds of refusals, so it fails toward a lockout.

    **Option D, take A and record the remainder as a known limitation** with a drafted follow-up. It is
    the cheapest, and it ships #111 with a reachable instance of the exact defect #111 exists to close.

    **Recommendation: B.** It is the only candidate that closes every continuously live case, changes
    no signature and no later stage, and fails toward a retry. B2 is the answer if the marker sitting
    below the current step is judged to matter, and the two extra signatures are the price. C is
    strictly worse than B on both failure modes. D is defensible only if 3 in a million is judged
    acceptable for this property, which is a judgement about how literally RFC 6238 5.2 binds here, and
    that is not the run's to make.

    Getting it wrong either way: choosing A or D and later reversing means revisiting the matcher and
    its table after stages 2 to 4 have built on the returned step, and it means the release notes for
    this fix are wrong. Choosing B when A would have done costs four HMAC computations, one test row
    and a longer doc comment.

    **State at the time of asking.** Stage 1's two files were written and its tiers green, but the
    returned step is what this question is about, so nothing was committed and stage 1 stayed
    `In progress`. Seam 1's existing 15 rows survive every option unchanged: the probe confirms
    nothing collides within eight steps of the instant they pin, for both the valid secret and the
    empty one. Whichever rule wins, the table gains collision rows pinned at their own instants, and
    the pairs above are already located for them.

12. **A fixed lookback closes colliding pairs but not chains of three. Closed, or accepted?**
    Status: **Decided** · Raised by: run (raised during stage 1, at the code-review gate, round 3)

    Answered by the user on PR #143, 2026-08-06, in full: "A. Walk the lookback down transitively."
    That is option A below, the recommended one, taken over B, C and D, with three amendments the
    answer attaches and one instruction about what it settles.

    **What the answer settles**, superseding decision 11's single lookback interval and §4's
    `MatchStep` sketch with it. `MatchStep` still accepts exactly a match at
    `current-skew .. current+skew` and still returns `(int64, bool)`, so nothing in stages 2 to 4
    moves. What changes is how the reported step is found: from the matched step, scan the
    `lookbackSteps` below it, and repeat from whatever that finds, until a scan finds nothing. The
    answer is then the bottom of the whole backward-connected chain rather than the bottom of one
    fixed interval, which is what makes it constant across every current step from which the passcode
    is accepted. Each scan takes the lowest step it finds, which reaches at least as far down as any
    higher step in the same scan could, so one pass down is enough.

    Executed rather than argued: `probe/step-collisions` replays both rules against every
    continuously live shape, and the walk is safe from every presentation for all 9 chains of three
    and all 3 continuously live pairs, where the fixed interval leaves 6 of the 9 chains replayable.

    **Amendment 1, the seam, recorded in §5 rather than inside a step.** The walk cannot be exercised
    at seam 1: no secret anyone can enrol exhibits a chain, so the scan moves behind a step predicate
    and is pinned with a synthetic match set, one boundary below the seam the interview sealed. §5
    carries that as a named amendment with its reason, per the answer.

    **Amendment 2, the cap, with its reasoning where the cap is written.** `maxLookbackScans = 5`,
    read off the sweep rather than rounded to a comfortable number. Every further scan that finds
    something needs one more step producing the same six digits within `lookbackSteps` below the last,
    and the sweep measured that link rate instead of assuming it: 55 links in 20,000,000 steps over 4
    secrets, 2.75e-06 per step against the 3.0e-06 an independent-uniform model predicts. Links are
    independent, so a chain of n steps is `(3e-06)^(n-1)` per presentation. The stated criterion is
    that the cap must first refuse at a chain whose expected count stays under one in a billion across
    1e18 presentations, an absurdly generous bound on every authentication every deployment of this
    server will ever perform; 5 scans is the first value that clears it, refusing at a chain of 6 at
    2.4e-28 per presentation. The probe prints that ladder, so the number is checkable rather than
    asserted. Hitting the cap refuses the passcode, which fails in the same direction as the error
    branches: a refusal costs one code and the next one works, while claiming a step above the bottom
    of a chain is a replay.

    The cap is not what makes the walk terminate. Each scan searches strictly below the step it last
    found, so the loop is already a total function; what the cap bounds is work per request, turning
    a bound of the whole step axis into `maxLookbackScans * lookbackSteps` HMAC computations.

    **Amendment 3, this settles the class and not just this shape.** The walk canonicalises a chain of
    any length within the cap, so no further escalation about colliding steps is wanted. A fourth shape,
    if one turns up, gets the same rule applied and a line in the log entry.

    **Accepted costs, as the answer states them.** On the inherent span 4 pair the walk re-accepts at
    `A+3` rather than `A+5`, 60 seconds sooner, from 3 presentations rather than 5. That whole class,
    pairs spread 4 or more apart, stays replayable at roughly a millionth per presentation and decision
    11 accepted it knowingly; the answer restates that it is about a hundred thousand times more likely
    than the chain case closed here, that option A is worth taking because it is nearly free rather
    than because chains are a threat, and that no further rounds should be spent narrowing this class,
    since closing the residual that dominates needs the consumed-codes table decision 1 rejected.

    **What lost.** B, accepting the residual and narrowing the claim, because it ships #111 with an
    instance of exactly the defect #111 exists to close. C, binding consumption to the passcode,
    because it reopens decision 1 for a rate five orders of magnitude below what decision 11 already
    accepted as inherent. D, a wider fixed lookback, which does not work at any fixed value.

    The question as escalated is kept below, because the reasoning is what makes the answer reviewable.

    ---

    **The original question.** Escalated on PR #143, 2026-08-06. Nothing rested on it in the tree:
    stage 1's two files stayed uncommitted and stage 1 stayed `In progress`.

    **The defect, confirmed and then widened.** Decision 11's answer reports the lowest match in
    `current-4 .. current+1`. Three steps producing one passcode chain their acceptance ranges into
    one unbroken run when each adjacent gap is at most 3, and the lowest of them then falls out of
    that fixed interval while the run is still live. For steps 100, 103 and 106 the passcode is
    accepted continuously from current 99 through 107, but the reported step advances from 100 to 103
    at current 105, so a marker holding 100 accepts 103 and the same passcode is consumed twice.
    Executed: the reviewer's `.review/scratch/issue111_decision11_model.go`, reproduced and extended
    in `probe/step-collisions`.

    Wider than the review found. **6 of the 9 continuously live chains of three are replayable**,
    every one whose total span exceeds the lookback of 3; `{A, A+1, A+2}`, `{A, A+1, A+3}` and
    `{A, A+2, A+3}` are safe. The span 4 pair also leaks from 5 presentations rather than 3.

    **How often, measured rather than argued.** The probe swept 20,000,000 steps over 4 secrets, 19
    years of one authenticator: 55 colliding pairs at most 3 apart, 2.75e-06 per step against 3.0e-06
    expected, which is what validates the 1e-06 per-pair model everything else here rests on. Chains
    of three: **0**, against 1.8e-04 expected. A presented code sits in a chain about **2.7e-11** of
    the time, roughly 3 in 100 billion authentications, five orders of magnitude below the 8.3e-06
    pair rate decision 11 was answered against.

    **Why this is the user's call rather than the run's.** It is a security property in
    authentication, which `decisions.md` never auto-resolves, and the reviewer returned it
    `needs_human: true` with an empty `forced_answer`, naming three resolutions. Decision 11 chose to
    close a rate five orders of magnitude higher; whether that choice carries down to this one is the
    same judgement decision 11 recorded as not the run's, about how literally RFC 6238 5.2 binds.

    **Option A, walk the lookback down transitively** instead of applying it once: from the matched
    step, look for a match in the 3 steps below it, and repeat from whatever it finds. Closes all 9
    chain shapes and all 3 continuously live pairs, executed in the probe. Acceptance is untouched,
    `MatchStep` keeps `(int64, bool)`, and nothing in stages 2 to 4 moves. **Costs exactly what the
    current code costs whenever nothing collides**, one lookback scan of 3 steps, because the walk
    stops the moment a scan finds nothing; 2 scans on a pair, 3 on a chain of three. Needs a cap to
    stay a total function, at a chain length nothing can reach. Two real costs. On the inherent span 4
    pair it re-accepts at `A+3` rather than `A+5`, 60 seconds sooner, though from 3 presentations
    rather than 5, and that whole class is what decision 11 already accepted as inherent. And it
    **cannot be tested at seam 1**: no reachable secret exhibits a chain, so the scan has to move
    behind a step predicate and be pinned with a synthetic match set, which is a boundary below the
    seam sealed in §5. The three located pairs report identically under both rules at every current
    step, executed in the probe, so `TestMatchStepWithCollidingSteps` and the 15-row table are
    unaffected either way.

    **Option B, accept the residual and narrow the claim.** One sentence in `MatchStep`'s doc comment
    and in decision 11 saying the constant answer holds for a pair and for a chain spanning at most 3,
    and not beyond. Costs nothing and ships #111 with a 3-in-100-billion instance of the defect #111
    exists to close.

    **Option C, bind consumption to the passcode** rather than to the step, storing the consumed code
    or its hash. Closes the chains and the inherent wide pairs with them. Reopens decision 1, which
    rejected a consumed-codes table as too expensive for a 90-second window, and costs a second column
    in stage 2.

    **Option D, widen the lookback to a larger fixed number.** Recorded because it is the obvious first
    thought and it does not work: any fixed `L` fails for a chain spanning more than `L`. Strictly
    dominated by A, which is D taken to its limit at lower cost.

    **Recommendation: A.** It is the only candidate that makes the invariant decision 11 chose actually
    hold, it is free in the case every real authentication takes, and no signature or later stage
    moves. Its honest price is the test boundary, not the code. B is defensible if 3 in 100 billion is
    judged acceptable, which is the same question decision 11 answered at 3 in a million and is why
    this is being asked rather than applied. C is a larger change than #111 has called for anywhere
    else.

    Getting it wrong either way: choosing B and later reversing costs the matcher and one test
    function, both still uncommitted, so it is cheap now and less so once stages 2 to 4 have built on
    the returned step. Choosing A when B would have done costs a loop, a cap and a test at a lower
    boundary than §5 sealed.

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
//
// An empty secret matches nothing (#111 decision 9). The library happily derives a
// code from the empty key, and that code depends only on the time step, so it is the
// same everywhere and anyone can compute it. Refusing here covers every call site at
// once, including a stored secret that decrypts to empty.
func MatchStep(passcode string, secret string, now time.Time) (int64, bool) {
	if secret == "" {
		return 0, false
	}
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
this accepts exactly what `totp.Validate` accepts today, with the single deliberate exception of the
empty secret. Verified by execution against `pquerna/otp v1.5.0`, per section 1.

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

**No per-site empty-secret check.** `MatchStep` refuses an empty secret (decision 9), so all three
sites get the generic incorrect-OTP response without repeating the guard.

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

## 5. Seams

1. **`otp.MatchStep`** (`src/core/otp/verifier.go`), new unit file `src/core/otp/verifier_test.go`
   beside the existing `generator_test.go`. **Owns the exhaustive matcher table**, at a pinned instant
   so nothing races a period boundary: window positions -2, -1, 0, +1, +2 with the accepted ones
   asserting the returned step; passcodes empty, 5-digit, 7-digit, non-numeric, whitespace-padded;
   secrets lowercase, space-padded, invalid base32, empty. Every row was executed against
   `pquerna/otp v1.5.0` before being written down (section 1).

   **Two rows deserve a "keep this" note.** The empty-secret row asserts a refusal where today's
   library accepts, so it is the one row that deliberately diverges from `totp.Validate` and pins
   decision 9; it must use the code actually derived from the empty secret at the pinned instant, not
   an arbitrary six digits, or it passes with the guard deleted. The lowercase-secret row asserts
   acceptance, which reads like a laxity to be tightened; it is there because the library upper-cases
   and dropping it would be a silent behaviour change.

   **Amendment, decision 12: seam 1 also owns one boundary below itself, the walk over a step
   predicate.** The interview sealed this seam at `otp.MatchStep`, which takes a passcode and a secret,
   and every case above reaches the step arithmetic through real HMAC output. Decision 12's answer
   cannot be tested that way. It makes the reported step the bottom of a chain of colliding steps, and
   **no secret anyone can enrol exhibits a chain**: the sweep in `probe/step-collisions` found 0 chains
   of three in 20,000,000 steps over 4 secrets, against 1.8e-04 expected, because each further link is
   another factor of about 3e-06. A test that only drives `MatchStep` therefore passes with the walk
   deleted, which is the one thing this seam must not allow.

   So the walk moves behind an unexported step predicate, `matchStepWith(produces, current)`, and is
   pinned with a **synthetic match set**: an explicit set of steps standing in for the HMAC, over which
   the chain shapes are reachable. That is a boundary below the sealed seam, named here rather than
   left as an implementation detail inside a plan step, because it is a change to what this seam covers
   and not a choice about how a step is written.

   **What it owns**, all three over the predicate, all three transcribed from or replaying the probe:
   every continuously live shape (pairs spread 1 to 5, and all 9 chains of three whose adjacent gaps
   are at most 3), asserted by replaying decision 2's high-water claim over every presentation rather
   than by transcribing constants; the cap, where a chain of `maxLookbackScans` steps resolves to its
   bottom and one step further is refused; and the walk's **error branch**, which is unreachable
   through `MatchStep` and must refuse rather than answer with a step whose chain was not fully walked.

   **What it does not move.** Acceptance, the 15 rows above and `TestMatchStepWithCollidingSteps` all
   still run through `MatchStep` against real HMAC output. The probe confirms the three located pairs
   report identically under both rules at every current step, so the transcribed rows are unaffected by
   the amendment.

   **The inherent pairs are pinned as replayable, deliberately.** Two of the shapes above, spreads 4
   and 5, assert that a second acceptance is still possible, which reads like a test of a bug. It is
   the residual decisions 11 and 12 both accepted knowingly: a pair spread wider than `2*skew+1` has a
   refused gap, so the authenticator is legitimately redisplaying those digits, and refusing it needs
   the consumed-codes table decision 1 rejected. Pinning it is what makes the safe rows mean something.

2. **`TryConsumeUserOTPStep` and `ResetUserOTPStep`** at the data tier, appended as new functions to
   `src/authserver/tests/data/user_test.go`, where #106's narrow user methods are already tested.
   **Owns the claim table**, on all four engines: first claim from 0 succeeds; the same step again is
   refused; a lower step is refused; a higher step is accepted; an unknown user id returns false with
   no error; reset returns the marker to 0 and a previously consumed step is then accepted again.
   Plus the two questions testing against a mock cannot answer: the **failure path** returns
   `(false, err)` rather than a benign false, and the methods **enlist in the caller's transaction**.
   A rolled-back transaction forces both.

3. **`POST /auth/otp`** (browser flow), new integration file
   `src/authserver/tests/integration/auth_otp_replay_test.go`, named after the existing
   `token_refresh_replay_test.go`. **Owns the end-to-end proof** that a code accepted once is refused
   afterwards, without reaching into storage.

   **The second submission must happen in a fresh ceremony**, driven by a new authorize with
   `prompt=login`. Resubmitting inside the same ceremony proves nothing: the first success moves the
   auth context to `AuthStateAuthenticationCompleted`, so the handler's `requiredState` check rejects
   the second POST with a 500 before the replay guard is ever consulted. That is a negative case
   failing for the wrong reason, and the ordering here is load-bearing rather than incidental.

   Two cases:
   - **Replay refused.** Enrolled user, submit code C, complete. New ceremony with `prompt=login`,
     submit C again: the same rendered incorrect-OTP error as a wrong code.
   - **Enrolment code refused at verification** (pins decision 3). Enrol at step N in the browser flow,
     then in a fresh ceremony submit the same code, now against the stored secret. Fails if enrolment
     does not claim, which is the hole decision 3 exists to close.

   Each needs a control in the same test: a code from a later step is accepted in that fresh ceremony,
   so the refusal is attributable to the replay guard and not to the ceremony being broken.

4. **`PUT /api/v1/account/otp`**, extending `src/authserver/tests/integration/api_account_otp_test.go`
   at `test/api-otp-enable`. **Owns the pin for decision 4**: enable with code C, disable, enable again
   with the same C, which succeeds. It fails if reset-on-disable is removed.

   **Keep this case.** It asserts a success where a replay-guard reading expects a refusal, so it looks
   like a mistake. It is the only test that breaks if the reset is dropped.

5. **`HandleAuthOtpPost` with a mocked `data.Database`**, extending the existing
   `handler_auth_otp_test.go`. **Deliberately thin**, because seams 1 and 2 own the tables: one subtest
   where the claim is refused, asserting the generic error plus both `AuditAuthFailedOtp` and
   `AuditOTPCodeReplayDetected`, and one where the claim errors, asserting 500. Plus the new stub on
   the three existing subtests that reach a successful validation (`test/unit-otp-success`,
   "Successful OTP validation for disabled OTP (enrollment)", "Error updating user during OTP
   enrollment"). The empty-secret guard is seam 1's, not this one's: it lives in `MatchStep` now, so a
   handler-level case would only re-test seam 1 through a mock.

**Rejected seams**

- **Asserting `users.last_otp_step` from handler or integration tests.** A side channel into storage
  that passes with the endpoint broken. Seam 2 owns the column; everything above it observes refusals.
- **A unit test file for `handler_api_account_otp.go`.** None exists today (the package has only
  `handler_api_account_password_test.go`), the claim logic there is identical to seam 5's, and seam 4
  observes it end to end. Recorded as absent infrastructure rather than built, so the gap is a stated
  choice rather than an oversight.
- **Testing `hotp.ValidateCustom` itself.** Library behaviour. Seam 1 tests our window and our step
  arithmetic, not the HMAC.
- **Reading the real clock in seam 1.** A table built on `time.Now()` straddles a period boundary a few
  times a day and fails for a reason unrelated to the change.
