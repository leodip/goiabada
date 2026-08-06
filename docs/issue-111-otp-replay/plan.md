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
Landed 2026-08-06, code at `a10c6bb`, on tree `f53d3b9a0856`. One clean review round. Account in
`log/stage-2.md`.

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
`migration_000026_code_revoked_test.go`. Docs: none, internals only.

#### Steps

1. **Pre-flight the migration number.** Status: **Done**

   `probe/preflight-migration-version/` reads `schema_migrations` on mysql, postgres and mssql for
   both `goiabada_data` and `goiabada_integration`, opening each with the driver directly rather than
   through the repo constructors, which create an absent database and would make the check
   self-fulfilling. All six report highest 26 and no row at 27, so 000027 is free;
   `output.txt` beside it is that run. sqlite is out of scope for the reason above.

2. **The migration, all four engines.** Status: **Done**

   `000027_add_last_otp_step.{up,down}.sql` in each of the four `migrations/` directories. One column,
   `users.last_otp_step`, `NOT NULL DEFAULT 0`, typed per engine as `data/mark-code-used`'s neighbours
   are: `INTEGER` on sqlite, `bigint` on mysql and postgres, `BIGINT` with a **named** default
   constraint `df_users_last_otp_step` on mssql, which is what lets the down migration drop the column
   at all (`migration/generation-mssql`). The sqlite up migration carries the reasoning; the other
   three point at it, exactly as the 000024 set does. No index: every read and write is by `id`.

   Existing rows land at 0, which is "no code consumed" per decision 2, so no user is locked out by
   the deployment.

3. **The model field.** Status: **Done**

   `models.User` gains `LastOTPStep int64` with `db:"last_otp_step" fieldtag:"dont-update"`, beside
   `AuthStateGeneration`, carrying the reasoning `model/generation-field` records in its own terms: a
   monotonic marker in the ordinary update set is regressed by any whole-user write holding a stale
   model, and `otp/enroll-write` is exactly such a write on the path that claims it.

4. **The two interface methods.** Status: **Done**

   Declared in `src/core/data/database.go` in the user block, next to
   `data/interface-generation`, with the short summaries that file uses; the full reasoning goes on the
   implementations. `TryConsumeUserOTPStep` carries decision 10's signature, four arguments including
   `requireOTPEnabled`.

5. **The commondb implementations.** Status: **Done**

   In `src/core/data/commondb/user.go`, on the `data/mark-code-used` template: a single conditional
   `UPDATE` built with the flavour's update builder, `rowsAffected == 1` as the return, a wrapped error
   on failure and a rejected `userId == 0`. `TryConsumeUserOTPStep` adds `ub.Equal("otp_enabled", true)`
   to the predicate only when the flag is set, `TrySetUserEnabled` being the precedent for the bound
   bool. `ResetUserOTPStep` assigns 0 unconditionally and returns only an error, so a reset of an
   already-reset user is not a failure.

   The doc comments carry §4's text plus what decision 10 added: why the flag exists, why a false at a
   verification site now has two causes, and why the reset must not be reordered before the
   `otp_enabled` write at either disable site.

6. **The four engine delegations.** Status: **Done**

   Two forwarding methods in each of `sqlitedb/user.go`, `mysqldb/user.go`, `postgresdb/user.go` and
   `mssqldb/user.go`, in the shape `IncrementUserAuthStateGeneration` uses. **As built: no comments.**
   This step's draft said "each with the one-line comment those neighbours carry", and the neighbours
   carry none: every delegation in those four files is a bare forward. The code won.

7. **Regenerate the `data.Database` mock.** Status: **Done**

   `mockery` in the container against `src/core/.mockery.yaml`. Skipping this is the classic way a
   stage lands broken: every `mocks_data.Database` user in all three modules stops satisfying the
   interface, so the unit tier fails to compile rather than fail a test.

8. **The four `schema.sql` snapshots.** Status: **Done**

   Documentation-only, but 000024's and 000026's columns are in all four, so leaving this out is drift.
   The column is added to the `users` block of each, in the position and spelling that engine's snapshot
   uses.

9. **Seam 2's data tests.** Status: **Done**

   Appended to `src/authserver/tests/data/user_test.go`, where #106's narrow user methods already live:
   the claim table (first claim from 0, same step refused, lower refused, higher accepted, unknown user
   id false with no error, reset returns to 0 and reopens a consumed step), the `requireOTPEnabled`
   cases from decision 10 in both directions, the failure path returning `(false, err)` and the
   transaction enlistment, both forced by a rolled-back transaction, the concurrent single-winner case
   following `cleanup_claim_test.go` and skipping sqlite, and the stale whole-user write case following
   `TestUpdateUser_DoesNotClobberAuthStateGeneration` with a nonzero step.

10. **The migration test.** Status: **Done**

    `migration_000027_last_otp_step_test.go`, in the shape of `migration_000026_code_revoked_test.go`:
    absent at 000026, present and `NOT NULL DEFAULT 0` after, a row that predates the column reads 0,
    and the down/up round trip is clean, which is what exercises mssql's named-constraint drop.

11. **Repair `TestMigration000026_CodeRevoked`, which this stage breaks.** Status: **Done**
    Not in the plan; found by running the data tier.

    That test seeds a client, a user and a code **through the ORM while the schema is at 000026**, and
    the ORM writes every column the Go models carry, so the insert began naming `last_otp_step` at a
    version that does not have it. It failed on all four engines at `seed user`. The seed now runs at
    the head migration (`Migrator.Up()`) before the down/up round trip that restores 000026, which is
    the fix `migration_000021_countries_test.go` already made for the same reason, in its own words:
    "This used to be a plain `Migrate(20)`". The comment there records why, so the next column does not
    reopen it.

    In scope rather than a follow-up: this stage broke it, and a stage that leaves the suite red has
    not landed.

**Amended per decision 10, answered option A on 2026-08-05.** The signature is
`TryConsumeUserOTPStep(tx *sql.Tx, userId int64, step int64, requireOTPEnabled bool) (bool, error)`,
which supersedes §4's three-argument declaration; the doc comment follows §4's otherwise and gains
the flag's reasoning plus the second cause of a false at a verification site. When the flag is set the
builder adds `ub.Equal("otp_enabled", true)` to the `WHERE`, alongside `id` and `last_otp_step < step`;
when it is not, the predicate is §4's unchanged. `TrySetUserEnabled` is the precedent for the bound
bool, and `users.otp_enabled` carries the same type as `users.enabled` on all four engines, so nothing
here is engine-specific. `ResetUserOTPStep`, the migration, the column and the tag are exactly as
sealed: the answer changed no schema.

**Two more data cases, from decision 10.** Both at seam 2, which owns the column, and neither is
observable from an endpoint, because the interleaving they pin needs a request holding state loaded
before a disable:

- **A verification claim is refused once the authenticator is gone.** Claim step S with
  `requireOTPEnabled` true against an enrolled user, which succeeds; disable OTP; then claim S+1 with
  the flag true, which must be refused with no error, and the same claim with the flag false, which
  must succeed. Pins both directions of the flag, so deleting the term or hard-wiring it fails.
- **A reset does not reopen a consumed step to a verification claim.** Consume S with the flag true,
  disable, `ResetUserOTPStep`, then claim S again: refused with the flag true, accepted with it false.
  This is decision 10's hole and decision 4's remedy in one case, and it fails if the flag's term is
  dropped or if the reset is made unconditional on enrolment state.

**Two coverage cases the first plan draft was missing**, both added by the plan review and both
pinning a §2 goal that no other planned case could fail on. Neither is affected by decision 10's
answer, beyond passing the flag:

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
