# Plan gate

## Round 1

Reviewer: codex, model `gpt-5.6-sol`, effort `xhigh`, fresh session, gate `stage-1`, round 1
(`.review/reviewer.env`). Request `111-20260805T231624Z`, `type: plan-review`, raised
2026-08-05T23:16:24Z, verdict returned 23:25:57Z. Verdict: `findings`, six of them, five `blocking`.
All three axes `reviewed`.

The review ran, per its own account: `check-anchors.sh` (24 of 24 green), `agreement.sh entry`, a read
of the request, agreement, plan and `closing.md`, an inspection of `pquerna/otp` v1.5.0's HOTP and
TOTP implementations, the 15 row matcher probe re-run in `goiabada-devcontainer-1`, and a read of the
OTP handlers, completion flow, data patterns and the relevant unit, data, integration and
documentation files. No Go tier ran, correctly: this was a plan gate with no implementation to test.

### The three questions the request asked

1. **Is the stage 1 table sound, and is the interior versus surrounding space split right?** Yes to
   both, and this was the row most likely to be wrong. The probe reproduced all 15 rows in the
   container. The pinned instant `time.Unix(1700000000, 0).UTC()` has remainder 20 modulo 30, so it
   straddles no period boundary at any delta from -2 to +2, and each delta produced a distinct code
   with the expected step returned. The library trims the outside of a secret and then base32 decodes
   it, so surrounding spaces are accepted and interior spaces fail the decode: the plan's split stands
   as written. The empty secret derives `501315` at the pinned instant and matched with the decision 9
   guard removed, so that row genuinely pins the guard rather than passing for an unrelated reason.
   Each negative row fails for the mechanism the plan names (length, comparison, base32 decode, or the
   guard).

   **One correction absorbed into the plan.** The plan's rationale for generating through
   `totp.GenerateCode` and validating through `hotp.ValidateCustom` implied the two were independent
   cryptographic implementations. They are not: `totp.GenerateCode` delegates to
   `hotp.GenerateCodeCustom`, so both sides share one HMAC. What is independent, and what the table
   actually pins, is the timestamp to counter mapping, which is the part `MatchStep` owns. Reworded in
   stage 1 step 2. Bookkeeping grade, fixed in passing.

2. **Is the decomposition sound, and is anything unassigned?** Sound, and the dependency order holds.
   Every decision has a landing stage and the review enumerated them. Four coverage gaps found, below.

3. **Is the `security.mdx` bullet in the right stage?** No. Moved to stage 4. Finding 5.

### Findings

**1. No test of the concurrent single-winner property.** Axis security, blocking, confidence high.
Upheld. §2 goal 3 requires two concurrent submissions to yield at most one success, and seam 2's table
was entirely sequential. A read-then-write implementation passes the first, same, lower and higher step
rows and still lets two concurrent callers both return true, so the planned table could not tell the
required conditional `UPDATE` from the shape decision 2 rejected. The repository already guards this
defect class three times over: verified
`cleanup_claim_test.go:TestTryClaimCleanupRun_ConcurrentCallersProduceOneWinner`,
`token_authcode_concurrent_test.go:TestToken_AuthCode_ConcurrentDoubleSpend_IssuesOnlyOnce` and
`token_refresh_concurrent_test.go:TestToken_Refresh_ConcurrentDoubleSpend_IssuesOnlyOnce` all exist.
**Disposition: resolved in the plan.** Stage 2 gains the case, on the cleanup-claim precedent's shape
including its sqlite skip (that database is held to one connection, so callers queue instead of
contending) and its honesty note that a green run detects a broken implementation probabilistically
rather than certifying atomicity. Not an escalation: §2 asked for this and a stage now owns it.

**2. No test pins `last_otp_step` against a stale `UpdateUser`.** Axis security, blocking, confidence
high. Upheld. §2 goal 4 requires it, decision 2 assigns the `dont-update` tag, and dropping or
misspelling that tag still compiles and leaves every planned claim and migration case green. Verified
`user_test.go:TestUpdateUser_DoesNotClobberAuthStateGeneration` exists for exactly this invisible
failure, and read its shape: it re-creates the user so the nonzero value arrives through an insert,
then writes back a stale model and asserts both the unrelated change and the protected field.
**Disposition: resolved in the plan.** Stage 2 gains the analogous case, with the note that the
claimed step must be nonzero because 0 is the column default.

**3. Stage 4's only new account API case passes with the account API claim removed.** Axis security,
blocking, confidence high. Upheld, and this was the sharpest finding. Enable C, disable, enable C again
is a *reset* test that assumes the enable path already claims: with stage 4's claim change reverted
entirely, today's handler accepts all three operations. Seam 3's enrolment-to-verification case enrols
in the browser flow, so no planned case crossed the API boundary, and omitting
`TryConsumeUserOTPStep` from `api-otp/verify` alone would have left the complete suite green while
decision 3's third call site went unimplemented. **Disposition: resolved in the plan.** Stage 4 gains
an API-enrol-then-browser-verify case with the later-step control §5 requires.

**4. Reset through the admin disable endpoint has no owner in coverage.** Axis conformance, blocking,
confidence high. Upheld. Decision 4 names `api-otp/disable` and `admin-otp/disable` separately and
seam 4 exercised only the first. Verified `api_users_auth_test.go:TestAPIUserOTPPut_DisableSuccess`
already owns the admin endpoint. **Disposition: resolved in the plan.** Stage 4 extends it: consume C,
disable through the admin endpoint, re-enable through the account API with the same C. Endpoint
observable throughout, so §5's rejection of asserting the storage column still holds.

**5. The security documentation would claim one-time use one stage too early.** Axis conformance,
significant, confidence high. Upheld, reversing this plan's own first draft. The draft's argument had
three parts and the review disproved the load-bearing one: stage 3 is *not* where the claim becomes
true of authentication, because after stage 3 the account API still accepts a code without claiming
it, so a code accepted at `api-otp/verify` stays replayable at browser verification. §2's goal is
one-time use "on any of the three call sites", and stage 3 enforces two of three. **Disposition:
resolved in the plan.** Bullet moved to stage 4. An early stop is a reason to lose a docs line, never a
reason to publish a security claim broader than the code.

**6. A disable reset can reopen a consumed step to a verification request already in flight.** Axis
security, blocking, confidence high, `forced_answer` **empty**. Upheld on mechanism, corrected on
impact, and **escalated as decision 10**.

Mechanism verified against the code, all four steps: `HandleAuthOtpPost` loads the user then decrypts
and validates, holding both in memory; the disable handlers commit `ClearOTPSecret` plus `UpdateUser`
and then reset the marker as two separate writes; the designed predicate is `id` plus
`last_otp_step < step` and binds nothing about enrolment; and `HandleAuthCompletedGet` reloads the user
but checks only `user.Enabled`, never `user.OTPEnabled`. The race is genuinely required, since a fresh
request after the disable takes the enrolling branch and validates against the session secret.

**Impact corrected, and the correction matters to the answer.** The review concludes the attacker
"obtains level 2". Verified otherwise: once OTP is disabled a holder of the level 1 credential already
reaches level 2 more cheaply, because `handler_auth_level2.go:HandleAuthLevel2Get` sends
`AcrLevel2Optional` with `!user.OTPEnabled` straight to `/auth/completed`, skipping OTP altogether, and
sends `AcrLevel2Mandatory` to the enrolment form where an attacker enrols their own secret. The replay
buys no access the disable did not already grant. It buys a token asserting `amr: ["pwd","otp"]` for an
authenticator just removed, without the `AuditEnabledOTP` event and visible new authenticator that
self-enrolment leaves. A false factor assertion and a stealth gain, not an access gain.

**Disposition: blocking decision, not resolved by the run.** It is a security property on an
authentication surface, the empty `forced_answer` marks it a choice rather than a mechanical repair,
and the leading options change `TryConsumeUserOTPStep`'s signature or decision 4's observable
behaviour. Both of those are things stage 2 fixes and stage 4 depends on, so deferring would mean
rewriting work not yet done. Four options recorded in decision 10 with the recommendation (A, bind the
claim to enrolment state through a `requireOTPEnabled` flag) and what reversing each costs.

### Follow-ups and bookkeeping

The response reported none of either. Nothing added to `closing.md` this round.

### Round productivity

Productive. It moved plan coverage in four places, reversed a docs placement, corrected a rationale,
and raised the question that halts the run. Stall count stays 0.

### Run state at exit

Decision 10 is `Open`, so the guard stops the run and no code has been written. Nothing is
implemented; the only commit from this round is the agreement and plan amendment. Stage 1 itself is
**unaffected** by decision 10, since `MatchStep` is pure and binds no storage, so the answer unblocks
stage 2's method signature and stage 4's disable resets rather than the whole plan. Escalation budget:
one, at the plan gate, which is the cheapest place in the run to spend one.

Waiting on: the user's answer to decision 10 on PR #143.

## Decision 10 answered, 2026-08-05

The user replied on PR #143 at 23:39Z, four minutes after the escalation: "A. Bind the claim to
enrolment state." Option A, the recommendation, with no amendment. One session applied it; no code was
written, and stage 1 is still `Not started`.

Verified before writing anything down, since option A rests on two mechanism claims the escalation had
not checked:

- **`api-otp/verify` is only ever reached with OTP off**, so `requireOTPEnabled` false is honest there
  rather than merely convenient: the enable branch refuses with `OTP_ALREADY_ENABLED` when
  `user.OTPEnabled`. Read in `handler_api_account_otp.go`. Same for `otp/verify-enrolling`, which is the
  `else` of `if user.OTPEnabled` in `handler_auth_otp.go`.
- **The bound bool predicate is portable.** `users.otp_enabled` has the same column type as
  `users.enabled` on all four engines (`numeric`, `tinyint(1)`, `boolean`, `BIT`), and
  `TrySetUserEnabled` already binds a Go bool against `users.enabled` in this exact position, so
  `ub.Equal("otp_enabled", true)` needs nothing engine-specific. Checked against the four `schema.sql`
  snapshots, not inferred from one.

**Two things the answer settled that the escalation had left implicit**, both now in decision 10 and in
the plan:

1. **The disable writes need no transaction, but their order is load-bearing.** The reset must follow
   the `otp_enabled = false` write. Reversed, there is a window where the marker reads 0 while the
   authenticator still reads enabled, and an in-flight verification claims a consumed step through it,
   reintroducing the hole by ordering. §4's order is already the correct one; stage 4 adds the comment.
2. **A false at a verification site now has a second cause**, the authenticator being removed under the
   request, so `otp_code_replay_detected` is named for the likely cause rather than the certain one.
   `data/mark-code-used` documents the same imprecision about its own three-way false, so this follows
   existing precedent rather than inventing a convention.

Applied to: decision 10 (flipped to `Decided`, the question kept below the answer), the header's run
state, stage 2 (signature, predicate, and two data cases at seam 2 pinning both directions of the flag),
stage 3 (which site passes which value, and why), stage 4 (the write order, and `api-otp/verify` passing
false). §4 and §5 are frozen at seal and were not rewritten; decision 10 names what it supersedes, which
is how issue 129 handled the same situation with its decision 15.

Not closed by option A, and drafted as follow-up 2 in `closing.md`: a re-enrolment landing while a stale
verification request is in flight. Narrower than option A's text said, worked out while applying it, and
the narrowing is what makes it a follow-up rather than a second escalation: the re-enrolment must claim a
step strictly below the replayed one, so the replayed code has to come from the +1 window.

Escalation budget: one, spent at the plan gate and answered in four minutes. Nothing else is open.

Waiting on: nothing. Stage 1 is next.
