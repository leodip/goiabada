# Stage 4: the account API, and reset on disable

### Stage 4, 2026-08-06

**Landed.** The third call site, `api-otp/verify`, becomes match-then-claim with
`requireOTPEnabled` false. `ResetUserOTPStep` at both disable sites, `api-otp/disable` and
`admin-otp/disable`, after the `UpdateUser` that clears `otp_enabled`. Three integration cases:
seam 4's reset pin, the admin reset pin, and the API-enrolment-refused-at-browser-verification case
that pins decision 3's third site. The `docs/security-2fa` bullet. All eight steps done.

**Not committed, and the stage is not closed.** Round 1 of the code review raised a blocking security
finding, now **decision 13**, `Open`. The whole diff stays in the working tree, which is the same state
stage 1 held while decisions 11 and 12 were open.

One-time use now holds at all three call sites on the sequential paths, which is what makes §2's
checkable goals 1 and 2 true and what makes the docs bullet true. Decision 13 is about an interleaving,
not about those paths.

**Tiers**, against tree `a6eaa147c727` (`tree-hash.sh`), the tree the review read.

- Unit, green, 2694 ok 0 fail, ~8s (`where.sh test --type modules`), all three modules.
- Data, green on sqlite, mysql, postgres and mssql, 0 fail, ~26s (`where.sh test --type data`). Not
  strictly owed by this stage, which adds no query, interface or migration, but it is 26 seconds and
  it recompiles everything the handler edits could have broken.
- Integration, green on all four engines, 0 fail (`where.sh test --type integration`): sqlite 45s,
  mysql 75s, postgres 104s, mssql 140s.
- All of the above in one `where.sh test --type all`, 6m47s, 5636 ok 0 fail 4 skip. The four skips
  are the pre-existing engine-capability skips (three sqlite single-connection contention cases and
  one mssql READ COMMITTED case), none of them from this stage and none of them the
  `skipIfOtpCodeOutsideWindow` guard, so every new case genuinely ran on every engine: 4 passes each
  for `TestAPIAccountOTPPut_Disable_ResetsConsumedStep`,
  `TestAPIUserOTPPut_DisableResetsConsumedStep` and
  `TestAuthOtp_APIEnrolmentCodeIsRefusedAtVerification`.

**Each new case was mutation-checked, because each of the three pins something whose absence
previously left the whole suite green.** Both runs on sqlite, both reverted afterwards, and the tree
hash above is the unmutated tree.

1. Claim removed from `api-otp/verify` (the call deleted, not neutralised, so the marker never
   advances): `TestAuthOtp_APIEnrolmentCodeIsRefusedAtVerification` FAIL, its two browser siblings
   still PASS, which is what makes the failure attributable to the third site.
2. `ResetUserOTPStep` removed from both disable sites: `TestAPIAccountOTPPut_Disable_ResetsConsumedStep`
   and `TestAPIUserOTPPut_DisableResetsConsumedStep` both FAIL, each on its own site's re-enable
   returning 400 `INVALID_OTP_CODE`, with `otp_code_replay_detected` in the server log naming the
   step. Removing both at once stays attributable: neither test touches the other's endpoint.

**As-built.** Six things worth recording, one of them a question the stage resolved.

1. **The API replay branch emits `otp_code_replay_detected` and no `AuditAuthFailedOtp`**, unlike
   the two browser sites. Resolved rather than escalated, on a derivation: decision 5 says the new
   event is emitted "alongside the existing `AuditAuthFailedOtp`", and at this site there is no
   existing one. `grep -rn "AuditAuthFailedOtp" --include=*.go src/ | grep -v _test.go` returns four
   call sites, all in `handler_auth_otp.go`, so a wrong code at `api-otp/verify` audits nothing
   today. Adding a failure event this endpoint has never emitted would be a behaviour change §2 did
   not ask for, and `auth_failed_otp` would be the wrong name for it: enabling OTP is not an
   authentication ceremony. Recorded in a comment at the branch. The caller is unaffected either
   way, which is the property decision 5 actually constrains. **Round 1 accepted this reasoning**
   and its finding 2 then pinned the asymmetry with a test, since it was previously unproved.
2. **Both wrong-code and replay branches write one hoisted `incorrectOtpCode` string**, rather than
   repeating the literal. The two responses have to be byte-identical or the API caller can tell a
   replay from a typo, and two copies of a 180-character sentence are a drift waiting to happen.
3. **Step 5's case lives in `auth_otp_replay_test.go`, not with the account API cases.** It is
   `TestAuthOtp_EnrolmentCodeIsRefusedAtVerification` with the enrolment moved to the API, and it
   needs that file's ceremony helpers, so it reads best beside the sibling it mirrors.
4. **`createLevel2MandatoryClient` extracted** out of stage 3's `createLevel2MandatoryUser`, so a
   user the account API enrolled can be driven through the browser flow with the same fixture. Pure
   extraction, no behaviour change; stage 3's two cases still pass.
5. **Step 6 is a new function rather than an extension of `TestAPIUserOTPPut_DisableSuccess`**, as
   the plan said. That test owns the admin response shape and holds no account token, and consuming
   a step endpoint-observably needs one.
6. **Two new test helpers.** `putAccountOTP` returns status and body so the reset cases can drive
   several enables and disables without repeating the request shape.
   `skipIfOtpCodeOutsideWindow` skips a reset case whose code left the acceptance window mid-test,
   which a period boundary crossing can do: that enable would fail because the matcher refused the
   code, not because the marker was never reset, and a positive case failing for an unrelated reason
   is a flake that reads as a regression. It fired on none of the four engines.

**No adminconsole change, verified rather than assumed.** Its OTP page posts to this very endpoint
and already renders `INVALID_OTP_CODE`'s message on both the enable and disable branches
(`handler_account_otp.go`, the two `apiErr.Code` switches), so a replay through the console UI draws
the same generic incorrect-code error a wrong code draws. That is decision 5's indistinguishability
on the third site's user-visible path.

**§0 swept.** `api-otp/verify`'s locator was the `totp.Validate` line this stage deletes, so the row
now names the `MatchStep` call and its Note says so, matching how stage 3 re-pointed the two browser
rows. `check-anchors.sh`: 24 of 24 resolve, re-run after round 1 and still 24 of 24.

---

## Review round 1, ingested 2026-08-06

Reviewer `codex`, model `gpt-5.6-sol`, effort `xhigh`, session fresh, from `.review/reviewer.env`.
Request `111-20260806T134226Z`. All three axes `reviewed`. Three findings, two `blocking` and one
`minor`, all three `needs_human: true`.

The review did not re-run the tiers, on the ground that the recorded tree hash matched the tree it
read, and it said so explicitly. It spent that budget on a program of its own instead, which is what
found finding 1. Its `ran` list: the full agreement, stage 4's plan, this log entry and `closing.md`,
the changed code, tests and docs; `tree-hash.sh` returning `a6eaa147c727`; `check-anchors.sh` 24 of 24;
`git diff --check`; a SQLite reproduction in `.review/scratch/issue111_stage4_disable_race.sql`; and
call-site, authorization, audit, docs and coverage searches.

### Finding 1, security, blocking. A stale disable reset can erase a newer enrolment's claim

**Disposition: raised as decision 13, `Open`.** Escalated on PR #143 as comment 5205689887.

Confirmed at the code level, not merely accepted: both disable sites run `UpdateUser` then
`ResetUserOTPStep` as two unconditional statements with no transaction, and `ResetUserOTPStep`'s
predicate in `commondb/user.go` is `id` alone, so the reset is bound to nothing the disable observed.
An enrolment that loads the user after the disable's first write, claims its step, and finishes after
the disable's reset leaves `otp_enabled = 1`, `last_otp_step = 0` with a code already consumed. The
reviewer's SQL demonstrates that the database permits the state; that the code permits the schedule was
established by reading it.

**Widened while verifying, and this is the part that changes the feasibility argument.** The reviewer
reasoned about the account API as the racing enrolment, which verifies the password between loading the
user and claiming, so the disable would have to stall for a whole bcrypt to lose the race, which is not
plausible. The browser enrolment site is also an enrolment claim with `requireOTPEnabled` false and has
**no password verify in that gap**: `handler_auth_otp.go` loads the user at the top of
`HandleAuthOtpPost` and claims a few lines later, with a client fetch and a few HMAC computations
between. The racing request therefore needs microseconds inside the disable's inter-statement gap
rather than tens of milliseconds. This is recorded in decision 13 and in the escalation, because it is
the difference between "not plausible" and "a coin flip, repeatable at will".

**Why it blocked rather than resolving under §1b.** The attacker chooses the timing, supplies both
requests, and can repeat without limit, since rate limiting this endpoint is out of scope (#113).
§1b's rarity carve-out is available only when the attacker cannot influence the residual, and there is
no plain statement here of why they cannot. No meaningful rate could be produced for a probe either:
it depends on deployment load and connection-pool behaviour, not on arithmetic. The reviewer also
returned it with an **empty `forced_answer`** naming more than one sound repair, which is the
definition of a choice under `decisions.md` §1.

**Why the escalation asks a wider question than the finding.** Decision 10 already answered one member
of this family and knowingly left another open as follow-up 2. Per `decisions.md` §3, the class was
escalated rather than the instance: all three shapes are named, and a single answer settles them.
`decisions.md` §5's note is recorded in decision 13 itself, since this is the fifth escalation on #111
and the second in decision 10's family.

### Finding 2, quality, blocking. No test reached the account API's replay or claim-error branches

**Disposition: applied**, `forced_answer` populated, and the demonstration is below.

Verified before acting, because it asks for a seam §5 positively **rejected** ("a unit test file for
`handler_api_account_otp.go`"). §5's stated reason was that the claim logic there is "identical to seam
5's". That reason stopped being true in this stage: as-built item 1 made the audit behaviour
*deliberately diverge* from seam 5, and the JSON response shape was never seam 5's either. So the
rejection's premise no longer held, and the coverage was owed. Two incidental corrections to §5's
parenthetical: the package has nine test files today, not only
`handler_api_account_password_test.go`.

`handler_api_account_otp_test.go` is new, three cases, all on the enable branch from the claim onwards:
the replay refusal, the claim-error 500, and a wrong-code control proving the first two are
attributable. The replay case asserts 400, `INVALID_OTP_CODE`, the description **read out of the
handler's own wrong-code branch** rather than compared against a copied literal, `userId` and the
matched step in the `otp_code_replay_detected` payload, and no enable write. It asserts the absence of
`AuditAuthFailedOtp` structurally: the audit mock fails an unexpected call, so registering only the
replay event is the assertion.

**Six mutations, each reverted, the handler restored byte-identical (verified by sha256):**

| Mutation | Result |
|---|---|
| replay branch returns `OTP_CODE_REPLAYED` instead of `INVALID_OTP_CODE` | FAIL, as intended |
| `otp_code_replay_detected` dropped | FAIL, as intended |
| replay branch writes a distinct description | FAIL on the indistinguishability assertion |
| claim error treated as consumed instead of 500 | **PASS at first**, see below |
| replay branch does not `return`, so OTP is enabled anyway | FAIL, as intended |
| claim passes `requireOTPEnabled` true instead of false | FAIL, as intended |

**The fourth mutation passing was a real defect in the new test, found by running the mutations rather
than by trusting them, and it is the more useful half of this finding.** The `apihandlers` package's
`TestMain` never called `encryption.InitDataCipher`, unlike its two sibling handler packages
`handlers` and `accounthandlers`. So every `models.SetOTPSecret` in that package fails, the handler
returns 500 from the encryption error a few lines below the claim, and a test asserting 500 on the
claim-error branch passed with that branch deleted. That is exactly the "passes for a different wrong
reason" the review request asked about, on the very case added to answer it. Fixed by initialising the
cipher in `TestMain` with the same fixed key the two sibling packages use, with a comment saying why.
The whole `apihandlers` package is green with the cipher initialised, and mutation 4 now fails by
reaching an unregistered `UpdateUser`.

### Finding 3, conformance, minor. The security page promised permanence that reset-on-disable does not give

**Disposition: applied**, `forced_answer` populated and correct. The bullet said "A code that has been
accepted is refused everywhere afterwards", which decision 4 deliberately contradicts across an
authenticator removal, and `TestAPIAccountOTPPut_Disable_ResetsConsumedStep` and
`TestAPIUserOTPPut_DisableResetsConsumedStep` both pin that contradiction. Qualified to the
authenticator currently enrolled, with an explicit sentence that removing an authenticator clears the
history, and the audit event reworded to record a refused replay. The atomic
simultaneous-submission claim is kept, which the compare-and-set does support. Independent of decision
13's answer either way: the exception is forced by decision 4, not by the interleaving.

### The review's `unchecked` list, and whether the gate depended on it

Four entries, none load-bearing for this gate. It did not run finding 1's interleaving on mysql,
postgres or mssql, which the chosen repair will determine the shape of, so it belongs to decision 13's
answer rather than to this round. It did not benchmark timing equality between a wrong code and a
replay; the two write one hoisted string, which is stronger than a benchmark. It did not re-review the
settled matcher, PKCE, token internals or session lifetimes, none of which this stage touches. It
inspected the audit backend statically rather than executing it, which the integration cases cover
end to end.

### Follow-up the review raised, drafted not filed

**Redact credentials and OTP material from API debug request logging.**
`middleware/api_debug_middleware.go:debugLog` writes the whole JSON request body when
`GOIABADA_AUTHSERVER_DEBUG_API_REQUESTS` is enabled, and this endpoint's body carries `Password`,
`OtpCode` and `SecretKey`. Predates stage 4 and belongs to a logging-hardening change, so it is drafted
into `closing.md` rather than fixed here, per `reviewer.md` §3. Checked against the agreement first:
§2 asks for nothing about debug logging, so this is genuinely out of scope rather than a missing
requirement in disguise.

### Tiers after the round

Round 1 changed **no production code**: the two production files are byte-identical to the reviewed
tree, verified by `git hash-object` returning `d406f23486be8eec` and `3822f842d074fc66`, which match
the `index` lines of the diff the reviewer read. The delta is one new unit test file, one `TestMain`
line, and one prose sentence in `security.mdx`.

Tree after the round: `d0aaf085d9a2`.

- Unit, green, 2767 PASS 0 FAIL 0 SKIP, ~8s (`where.sh test --type modules`), counting `--- PASS`
  lines. Includes the three new `TestHandleAPIAccountOTPPut_*` cases.
- Data, green on sqlite, mysql, postgres and mssql, 1564 PASS 0 FAIL 4 SKIP, 29s
  (`where.sh test --type data`). The 4 skips are the pre-existing engine-capability skips.
- **Integration deliberately not re-run**, per the tier discipline: production code is byte-identical
  to the tree on which it was green on all four engines, so the 5m26s would re-establish a claim the
  blob hashes already settle. Unit and data were re-run in full because they are 37 seconds together
  and they recompile everything a test-only edit could have broken.
- `check-anchors.sh`: 24 of 24.

### State at the point of stopping

Decision 13 is `Open` and posted. Nothing is committed: stage 4's diff, the new test file, the
`TestMain` line, the docs edit, the decision and this entry are all in the working tree, and the stage
stays `In progress`. Nothing here rests on decision 13's answer except the two disable sites, which is
what the answer decides. When it arrives, apply it inside stage 4, re-run all three tiers on four
engines because the repair touches production code, and then close the gate.

---

## Decision 13 answered and applied, 2026-08-06

The user answered on PR #143 with a single character, "A", the recommended option and the one the
escalation asked for last. No amendment attached, so the answer settles exactly the question asked and
nothing beyond it: the two disable sites bind their writes, and members (a) and (b) of the class stay
where decision 10 knowingly left them, as follow-up 2.

**What landed.** Both disable sites now commit `ClearOTPSecret` plus `otp_enabled = false` plus the
marker reset as one transaction. Nothing else about the stage moved: no interface, no column, no
migration, no user-visible behaviour, and the two enrolment claim sites are untouched.

**One thing option A did not prescribe, and the reason for it.** The five statements are a shared
unexported function, `otp/disable-writes`, rather than written out at both sites. Three reasons, in
order of weight. The rollback belongs in a `defer`, and deferring at handler scope would hold the
transaction handle across the session write, the reload and the response encoding, which is a wider
scope than the operation; a function of its own is what makes the `defer` correct. Both sites run the
identical sequence, so a repair to one that misses the other is the failure mode this stage has already
met twice, at step 6 and at round 1's finding 1. And the reasoning is a paragraph that would otherwise
be duplicated and drift. The account file is its home because it is the package's OTP file; each site
keeps its own 500 response, which is the only part that differs.

**The comment at `otp/disable-writes` says the commit boundary now closes the window rather than the
ordering.** Decision 10 required `otp_enabled` cleared before the marker, and that order is kept, but
inside a transaction no reader outside it observes either write until both have landed, so the ordering
is no longer what carries the safety. Recording that rather than leaving decision 10's original claim
in place matters: a comment asserting that reset-first "opens a window" is false once the pair is
atomic, and a false reason is worse than no reason for the next person deciding whether the order can
move.

**Three new cases, at the unit tier, and why not integration.** The four-engine reset cases
(`TestAPIAccountOTPPut_Disable_ResetsConsumedStep`, `TestAPIUserOTPPut_DisableResetsConsumedStep`)
already run this code on every engine, and they still pass, but they cannot see the repair: a
sequential caller observes the identical end state whether or not the two writes share a transaction.
Only the call shape distinguishes them, so the pins go against a mocked `data.Database`.

- `TestHandleAPIAccountOTPPut_Disable_CommitsBothWritesAtomically`, and its admin twin
  `TestHandleAPIUserOTPPut_DisableCommitsBothWritesAtomically` in `handler_api_users_crud_test.go`.
  Each registers every write against one opaque non-nil handle, so a write that slipped back to the
  pool arrives with a nil tx and fails as an unexpected call, and each asserts the call order
  `begin, update, reset, commit`. The admin twin exists because decision 4 names two sites and step 6
  already established that omitting one of them leaves the whole suite green.
- `TestHandleAPIAccountOTPPut_Disable_ResetFailureRollsBack`, the other half: a failing reset must
  take the `otp_enabled` write down with it rather than leaving the authenticator half-removed at
  `otp_enabled = false` with a live marker, which would be a lockout on re-enrolment until that step
  passed. It asserts 500, no commit, and no `disabled_otp` audit event for a disable that did not
  happen.

**Three mutations, run and reverted, the handler restored byte-identical (`sha256sum -c`).**

| Mutation | Result |
|---|---|
| both writes unbound again, the pre-decision-13 shape | FAIL, all three cases; the admin twin's stack named `HandleAPIUserOTPPut`'s own call into the shared function, which is what makes that failure attributable to the second site rather than to the first |
| commit moved before the reset, so the reset lands outside the transaction | FAIL, all three cases |
| reset error swallowed and the transaction committed anyway | FAIL, **only** `..._ResetFailureRollsBack`, so that case is attributable to the rollback path alone |

**Tiers**, against tree `6de62e71d30b` (`tree-hash.sh`), the tree the review will read. All three, on
four engines, because the repair touched production code. One `where.sh test --type all`, 7m06s,
`All tests completed successfully`, 0 FAIL.

- Unit, 2770 PASS 0 FAIL 0 SKIP, all three modules, counting `--- PASS` lines. 2767 before, plus the
  three new cases.
- Data, 1564 PASS 0 FAIL 4 SKIP on sqlite, mysql, postgres and mssql: 14.7s, 2.1s, 6.1s, 2.5s of
  `go test`. The 4 skips are the pre-existing engine-capability skips, three sqlite
  single-connection contention cases and one mssql `READ COMMITTED` case, none of them from this
  stage. Not strictly owed, since this stage still adds no query, interface or migration, but the
  repair puts two existing methods inside a transaction and this is the tier that proves they enlist.
- Integration, 0 FAIL 0 SKIP on all four engines: mysql 74.6s, postgres 110.2s, mssql 146.0s,
  sqlite 47.3s. The three OTP cases stage 4 added each ran 4 times, once per engine, and
  `skipIfOtpCodeOutsideWindow` fired on none of them.
- `check-anchors.sh`: 25 of 25.
- `gofmt -l` and `go vet ./...` clean in all three modules.

**§0 swept again, three rows.** The repair moved `user.ClearOTPSecret()` out of both handlers, which
was the locator for `api-otp/disable` and `admin-otp/disable`; both now name their `disableUserOTP`
call. A new row, `otp/disable-writes`, names the shared function, because decision 13 and this entry
both cite it and a cited symbol with no row is exactly what the sweep exists to catch. 24 rows became
25.

**The agreement.** Decision 13 is `Decided` with the user's answer quoted, recording what it
supersedes (§4's "Disable resets" paragraph, and the half of decision 10 that said no transaction was
needed), what it does not move, and what lost. §3's preamble now reads "Thirteen, all decided". Stage
4 gains an amendment paragraph, rewritten steps 2 and 3, and step 9 for the atomicity pins; its
closing paragraph about the rejected unit file was false after round 1 created that file, so it now
records why the rejection's premise stopped holding.

### State at the point of stopping

Round 2 is requested at this gate, because the repair is production code the reviewer has not seen.
Nothing is committed: the whole stage, the decision, the plan amendment and this entry are in the
working tree, and stage 4 stays `In progress`.

---

## Review round 2, ingested 2026-08-06

Reviewer `codex`, model `gpt-5.6-sol`, effort `xhigh`, session resumed, from `.review/reviewer.env`.
Request `111-20260806T163000Z`, matching `verdict.json`. All three axes `reviewed`. One finding,
`minor`, `needs_human: true` with a **populated `forced_answer`**, which `reviewer.md` §1b makes a
finding the code settles rather than a choice: nothing is chosen, so it was applied here.

`reviewer.env` reads `ROUND=1` while the request it answers is round 2. Recorded rather than
normalised, since the file is meant to be quoted and not inferred from; the `request_id` match is what
identifies the verdict, and it is exact. Its `STARTED` also precedes the request's `created` by six
minutes, so the round counter and the timestamps in that file both look written for the gate's first
round rather than for this one.

**The review answered the question round 1 left open, and did it without a stress harness.** Round 1
could not check whether the repair closed member (c) on four engines because the repair's shape was
undecided. This round queried each live engine's actual isolation instead of trying to race it: MySQL
`REPEATABLE-READ`, PostgreSQL `read committed`, SQL Server locking `READ COMMITTED` with
`is_read_committed_snapshot_on = 0`, and SQLite serialised by `MaxOpenConns(1)`. None exposes an
uncommitted write to an outside reader, so on every supported engine a concurrent enrolment sees the
pre-disable state or the fully committed post-disable state and nothing between. It also read the lock
order and found no second resource taken inside the transaction, so the new write lock cannot form a
deadlock cycle, and confirmed the audit, session and reload work all happens after the commit.

It did not re-run the tiers, on the ground that `tree-hash.sh` returned `6de62e71d30b`, the recorded
tree. That is the fifth gate on this issue at which the re-run was skipped in favour of a program of
the reviewer's own, and the fifth at which it found something the run had not.

### Finding 1, quality, minor. Three comments said the opposite of the code beside them

**Disposition: applied.** The `forced_answer` was correct on both comments it named, and sweeping for
the same defect class found a third the review did not name.

The false claim was the word "uncommitted". `disableUserOTP`'s doc comment said the two writes,
"uncommitted, leave a window in which the row reads `otp_enabled = false` with the old marker still
standing". That is not the defect decision 13 closed. The pre-decision-13 shape passed `nil` for `tx`
at both writes, so each autocommitted, and the window was **between two committed statements**. An
uncommitted intermediate state is the one thing no supported engine exposes, which the review had just
established engine by engine. So the comment named a transaction as the hazard when a transaction is
the remedy, and a reader deciding whether the two writes could be split again would have been reasoning
from a false premise.

Corrected to "committed separately, which is how they were written before that decision", with the
distinction stated explicitly: the window is between two commits, not inside one.

**The third occurrence, found by sweeping rather than by the review.** `testing.md` §7 asks for the
sibling branch of any defect to be audited for the same class, and
`grep -rn "Uncommitted\|uncommitted" --include=*.go src/` returned a third instance the review missed:
`TestHandleAPIAccountOTPPut_Disable_CommitsBothWritesAtomically`'s own doc comment repeated the same
framing. Fixed in the same pass. The other four hits are `tests/data/transaction_test.go`, where
"uncommitted" is used correctly about the isolation property that file tests.

The second comment the review named was the new test file's header, which still read "Only the enable
branch is covered" after round 2 added two disable-branch cases to that same file. Rewritten to say
what each branch is actually covered for: the enable branch from the claim onwards, the disable branch
for decision 13's transaction shape alone, with the endpoint-observable proof that the marker is really
reset left where it lives, in `TestAPIAccountOTPPut_Disable_ResetsConsumedStep` on four engines.

Status: **Resolved**

### Why no round 3

`reviewer.md` §5 puts prose disagreeing with the code it sits beside under bookkeeping, which is fixed
in passing and never earns a round of its own, and it says a round producing only bookkeeping means the
gate is passed. Round 2 produced exactly that: zero blocking findings, zero security findings, all
three axes `reviewed`. Nothing in the `unchecked` list is load-bearing for this gate. The stress
harness was replaced by the per-engine isolation check, which is a stronger answer to the same
question; lock-wait latency is performance and the transaction adds one same-row update; the settled
matcher, PKCE, token and session surfaces are untouched by round 2; and the audit backend is exercised
end to end by the integration cases.

### Tiers after the round

The delta is three comment blocks in two files, `handler_api_account_otp.go` and
`handler_api_account_otp_test.go`. Every changed line is a `//` line, so no statement moved.

Tree `6de62e71d30b` before, `a260b415eee3` after (`tree-hash.sh`).

- Unit, green, **2770 PASS 0 FAIL 0 SKIP**, ~29s (`where.sh test --type modules`), all three modules,
  `All tests completed successfully`. Identical to the counts on the reviewed tree.
- Data, green on sqlite, mysql, postgres and mssql, **1564 PASS 0 FAIL 4 SKIP**, 28.8s
  (`where.sh test --type data`): 11.9s, 2.1s, 6.3s, 2.5s of `go test`. Identical counts again. The 4
  skips are the pre-existing engine-capability skips, three on sqlite
  (`TestTransaction_UncommittedWriteIsNotVisibleOutside`,
  `TestTryClaimCleanupRun_ConcurrentCallersProduceOneWinner`,
  `TestTryConsumeUserOTPStep_ConcurrentCallersProduceOneWinner`) and one on mssql
  (`TestTransaction_UncommittedWriteIsNotVisibleOutside`).
- **Integration deliberately not re-run**, per the tier discipline for a round that changed only
  comments. It was green on all four engines on tree `6de62e71d30b`, and unit plus data at 58 seconds
  recompile everything a comment edit could have broken.
- `check-anchors.sh`: 25 of 25.
- `go vet ./...` clean in all three modules.

**One correction to this entry's own earlier tier record.** The decision 13 section above claims
"`gofmt -l` ... clean in all three modules". Re-run from each module root, `gofmt -l` in `src/core`
lists `i18n/error_codes.go` and `i18n/middleware_test.go`, comment-alignment drift in two files this
issue never touches. Both are byte-identical to `main` (`git diff main -- src/core/i18n/` is empty and
neither is in `git status`), so the branch introduces no formatting deviation, and the changed package
is clean (`gofmt -l internal/handlers/apihandlers/` empty). The earlier claim was measured too
narrowly to support the words it used. Not drafted as a follow-up: it is cosmetic, pre-existing on
`main`, and in files unrelated to #111.

### Gate

Stage 4 closes here. All nine steps `Done`, the review clean of anything blocking after two rounds,
five run-raised decisions all answered by the user and applied, and §2's five checkable goals hold:
one-time use at all three call sites (goals 1 and 2, integration), at most one success from concurrent
submissions (goal 3, the compare-and-set plus its four-engine contention case), no regression through
an ordinary whole-user write (goal 4, `dont-update`), and the four engines agreeing at the data tier
(goal 5).
