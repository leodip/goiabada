# Stage 2: the column and its two narrow writes

## As built

Storage only. Nothing calls either new method yet, by design: stage 3 claims at the two browser sites
and stage 4 at the account API plus the two disable sites.

**The migration.** `000027_add_last_otp_step` up and down in all four `migrations/` directories, one
column `users.last_otp_step`, `NOT NULL DEFAULT 0`, typed per engine as the 000024 set types
`auth_state_generation`: `INTEGER` on sqlite, `bigint` on mysql and postgres, `BIGINT` with the named
default constraint `df_users_last_otp_step` on mssql, which is what lets the down migration drop the
column at all (`migration/generation-mssql`). The sqlite up migration carries the reasoning and the
other three point at it, which is the convention 000024 and 000026 both follow. No index: every read
and write is by primary key.

**The model.** `models.User.LastOTPStep int64`, `db:"last_otp_step" fieldtag:"dont-update"`, directly
below `AuthStateGeneration`, with the reasoning restated in its own terms rather than cross-referenced.
The hazard is more direct than #106's: the OTP enrollment handler claims a step and then writes the
whole user back **in the same request**, so without the tag it would write its own pre-claim value over
its own claim, which is a replay hole rather than a stale-model race. Two `db:` tag conversions in the
struct were reflowed by gofmt when the field landed, which is why `Groups`, `Permissions` and
`Attributes` show in the diff.

**The two methods**, declared in `data/database.go` in the user block after `TrySetUserEnabled` with
short summaries, implemented once in `commondb/user.go`, forwarded from each of the four engine
packages.

`TryConsumeUserOTPStep(tx, userId, step, requireOTPEnabled)` carries decision 10's four-argument
signature. One conditional `UPDATE` on the `data/mark-code-used` template: assign the step and
`updated_at`, `WHERE id = ? AND last_otp_step < ?`, plus `AND otp_enabled = ?` bound true when the flag
is set. The predicates are built as a `[]string` and appended to rather than branching over two
`ub.Where` calls, because sqlbuilder's `Where` replaces rather than accumulates. `rowsAffected == 1` is
the return.

`ResetUserOTPStep(tx, userId)` assigns 0 unconditionally and returns only an error, since nothing gates
on whether it transitioned, unlike `TrySetUserEnabled`'s disable direction.

**The doc comments carry three things beyond §4's sketch**, all of which a later reader needs and none
of which is inferable from the SQL: why the flag exists and which sites pass which value; that a false
now has a third cause at a verification site, in the shape `data/mark-code-used` documents its own
three-way false; and, on `ResetUserOTPStep`, that callers must reset **after** the write clearing
`otp_enabled`, which is decision 10's ordering constraint recorded where stages 3 and 4 will read it.

**The `data.Database` mock** was regenerated with the container's mockery against `src/core/.mockery.yaml`.
Skipping it would have failed the unit tier at compile time in all three modules, which is the cheap
failure; the expensive one is forgetting the four engine delegations, and the interface catches that too.

**The four `schema.sql` snapshots** each gained the column in the `users` block, in that engine's own
spelling, including the named constraint on mssql. Documentation only, never loaded by Go, but 000024's
and 000026's columns are in all four, so omitting it is drift.

## Tiers

All three tiers were run twice: once before the review against tree `734aa2315304`, and again after
the review's two comment corrections moved the tree to **`f53d3b9a0856`**, which is the tree this stage
commits and the hash every claim below is against. The re-run was not optional bookkeeping: a claim
pinned to a hash the tree no longer has is exactly the stale-but-plausible claim the hash exists to
expose, and comment text sits in the same `.go` files the tiers compile.

| Tier | Command | Engines | Result | Time |
|---|---|---|---|---|
| unit | `where.sh test --type modules` | n/a | green, `All tests completed successfully`, 0 fail | 8s |
| data | `where.sh test --type data` | sqlite, mysql, postgres, mssql | 284 / 287 / 287 / 286 pass, 0 fail, 3 / 0 / 0 / 1 skip | 26s |
| integration | `where.sh test --type integration` | sqlite, mysql, postgres, mssql | 891 pass per engine, 0 fail, one `ok ... integration` each (43s / 71s / 85s / 112s) | 5m26s |

Logs: `/tmp/goiabada-tests-20260806-120354-1247474` (modules),
`/tmp/goiabada-tests-20260806-120408-1248170` (data),
`/tmp/goiabada-tests-20260806-120453-1248971` (integration).

**The counts are identical to the pre-review run**, per engine and per tier, which is the evidence that
the corrections were comment-only: the same 284 / 287 / 287 / 286 and the same 891, with the same
single sqlite skip on the concurrency case. All eight of this stage's cases pass on all four engines
except `TestTryConsumeUserOTPStep_ConcurrentCallersProduceOneWinner`, which skips on sqlite as designed
and says so in the skip message.

One incident in the re-run, recorded because it wasted a suite and would waste another: the first
attempt piped `where.sh test` into `head -40`, which closed the reader, and `run-tests.sh` then died of
`SIGPIPE` **part-way through the integration tier** having already written four green data logs. It
looked like a finished run: the process was gone and the earlier logs were complete. Only
`integration-mysql.log` existed of four, and nothing wrote a failure. A truncated pipe produces a
partial suite that reads as a whole one, so the tiers above were re-run with output redirected to a
file and read afterwards.

The seven new data tests pass on all four engines, except
`TestTryConsumeUserOTPStep_ConcurrentCallersProduceOneWinner`, which skips on sqlite as designed and
says so in the skip message.

**Integration was run although the plan claimed only unit and data.** Stage 2 changes no behaviour any
endpoint reaches, so on the plan's reasoning it was unnecessary. It is here because the migration is
this stage's riskiest artifact and the data tier exercises it only against isolated databases created
at version 0: the integration tier is what applies 000027 to the long-lived, populated
`goiabada_integration` databases, which is the deployment path. It found nothing, and that is the
claim worth having on record rather than an assumption.

`check-anchors.sh`: 24 of 24 rows resolve. This stage added code and touched `models/user.go`,
`data/database.go` and `commondb/user.go` below every cited line, so no cited code moved.

## Pre-flight: 000027 is free, confirmed rather than assumed

§4 owed this, and the assumption in §1 named the failure mode: a version recorded by a discarded
attempt is skipped silently by golang-migrate and the suite then runs against a schema that never
received the migration.

`probe/preflight-migration-version/` reads `schema_migrations` on mysql, postgres and mssql for both
`goiabada_data` and `goiabada_integration`, using the credentials `run-tests.sh` exports. All six report
highest 26 and no row at 27. `output.txt` beside it is that run.

Two things about how it reads, both deliberate. It opens each database **with the driver directly**
rather than through `NewMySQLDatabase` and friends, because those create the database when it is
absent, and a pre-flight that creates what it is inspecting proves nothing. And it queries
`MAX(version)` plus a `COUNT(*) WHERE version = 27` rather than reading the single row golang-migrate
maintains, so a hand-edited multi-row table cannot hide a recorded 27 behind a lower current version.
sqlite is not checked: `run-tests.sh` points it at `/tmp/goiabada_<suffix>.db` per run.

## The tests earn their rows: six mutations, run and reverted

Seven passing tests prove nothing about what they would catch, and three of these cases are the kind
that stay green while a security property quietly stops holding. So each load-bearing property was
broken on purpose, the data tier run on sqlite, and the failure set recorded. The tree was restored from
copies taken before the first mutation, and `tree-hash.sh` reports `734aa2315304` afterwards, the tree
the pre-review tier run used and the one the reviewer verified. The committed tree `f53d3b9a0856`
differs from it only in the two comments under Review below, so each mutation result still describes
the code as committed.

1. **Drop `ub.LessThan("last_otp_step", step)`.** Only `TestTryConsumeUserOTPStep` fails, on exactly
   two assertions: "claiming the same step twice must report false; that is a replay" and "a step below
   the stored one must be refused". This is the whole issue in one predicate, and the first/higher rows
   cannot see its absence.
2. **Never apply the flag** (`if false && requireOTPEnabled`). Both flag tests fail:
   `TestTryConsumeUserOTPStep_RequireOTPEnabled` at "a verification claim must be refused once OTP is
   disabled", and `TestResetUserOTPStep_DoesNotReopenConsumedStepToVerification` at "a reset must not
   reopen a consumed step to a verification claim". Each also trips its second assertion as a knock-on,
   because the claim that should have been refused consumed the step the next assertion uses.
3. **Hard-wire the flag on** (`if true || requireOTPEnabled`). The other direction, and the one a
   reader "simplifying" the signature would reach for: the same two tests fail, now at "an enrollment
   claim must succeed with OTP disabled (is the flag hard-wired on?)" and "a reset must let
   re-enrolment claim a previously consumed step". Nothing else moves, which is what makes the pair of
   mutations meaningful: 2 and 3 fail on different assertions of the same two tests.
4. **Delete `fieldtag:"dont-update"` from `LastOTPStep`.** Only
   `TestUpdateUser_DoesNotClobberLastOTPStep` fails: "UpdateUser regressed last_otp_step to 0, want
   59533904". Every claim, flag and migration case stays green, which is exactly why the case exists.
5. **Collapse a query error into a benign false** (`return false, nil`). Only
   `TestTryConsumeUserOTPStep_EnlistsInTransactionAndFailsClosed` fails, at "a claim through a finished
   transaction must return an error, not a benign false". The fault path is unreachable from the other
   six cases.
6. **Change the sqlite migration to `DEFAULT 1`.** Only `TestMigration000027_LastOTPStep` fails, on
   three assertions: the declared default after apply, the pre-existing row's value, and the declared
   default after the round trip. A wrong default is a marker in the future for every existing user,
   refusing every code until wall time catches up, and no behavioural test would notice because the
   claim always writes the column explicitly.

## Deviations from the plan

1. **Step 6's delegations carry no comments.** The step said "each with the one-line comment those
   neighbours carry"; the neighbours carry none, every delegation in those four files being a bare
   forward. The code won, and the step now records that.
2. **`TestMigration000026_CodeRevoked` had to be repaired**, which the plan did not foresee. It seeds a
   client, a user and a code **through the ORM while the schema is at 000026**, and the ORM writes
   every column the Go models carry, so the insert began naming `last_otp_step` at a version that does
   not have it. It failed on all four engines at `seed user`, before any of this stage's own tests ran.
   The seed now happens at the head migration (`Migrator.Up()`) before the down/up round trip that
   restores 000026 for the assertions.

   Not an invention: `migration_000021_countries_test.go` already made this exact change for this exact
   reason, and says so in its own words, "This used to be a plain `Migrate(20)`". The comment added here
   names #111's column, so the next column does not reopen it.

   In scope rather than a follow-up: this stage broke it, and a stage that leaves the suite red has not
   landed. Recorded as step 11.
3. **The predicates are a `[]string`, not two `ub.Where` calls.** §4 sketches one `WHERE`; the flag
   makes it conditional, and sqlbuilder's `Where` replaces the clause rather than appending to it, so
   branching over two calls would silently drop the first set. This is a mechanical consequence of
   decision 10 rather than a design choice.
4. **Integration was run beyond the plan's declared tiers**, for the reason under Tiers above.

## Not done, deliberately

- **No call site claims anything.** Stages 3 and 4 own that, and the plan's ordering is what makes the
  signature change land before any caller exists.
- **No `last_otp_step` in `api.ToUserResponse`.** §4 says so: the field maps explicitly, so internal
  state stays internal.
- **No repair of the residual decision 10 left open**, a re-enrolment landing while a stale
  verification request is in flight. It needs an enrolment-generation column and is drafted as a
  follow-up in `closing.md`.

## One incident worth recording

The first mutation was reverted with `git checkout -- src/core/data/commondb/user.go`, which restored
the file to `HEAD` and so deleted both new methods, all of it uncommitted work. Restored from context
and verified two ways: the module builds and vets, and `tree-hash.sh` reports `734aa2315304`, byte
identical to the tree the tiers had already run against. Later mutations were reverted from copies
taken in `/tmp` instead. Nothing was lost and no tier claim above rests on a tree the restore changed.

## Decisions

None raised. All twelve were already decided when this stage started, and nothing here contradicted
one: decision 10's amendments landed as written, and the pre-flight confirmed §1's stated assumption
rather than overturning it.

## Review

**One round, clean.** Codex, `gpt-5.6-sol` at `xhigh` effort, fresh session, taken from
`.review/reviewer.env` rather than inferred. Request `111-20260806T115500Z`, round 1, all three axes
`reviewed`, zero findings, nothing left `unchecked` within the gate. Verbatim in `.review/response.md`
and `.review/verdict.json`.

A clean verdict is worth only as much as what it covered, so what it actually reproduced rather than
took on trust:

- `tree-hash.sh` returned the recorded `734aa2315304`, which is what let it accept the unit, data,
  integration and vet claims, and the six mutation results, as evidence about the tree in front of it
  instead of re-running them. That is the trade the hash discipline is for, and this gate is the first
  on this issue where the reviewer spent the saved budget rather than the suite.
- It ran this stage's new cases on **sqlite** itself, all passing, with the concurrency case skipping
  for its stated single-connection reason, then ran
  `TestTryConsumeUserOTPStep_ConcurrentCallersProduceOneWinner` on **postgres**, where it executed five
  rounds and passed. So the one case sqlite cannot exercise was independently confirmed on an engine
  that can.
- `check-anchors.sh` resolves all 24 rows; `git diff --check` clean.

Its conformance read reached decision 10 in both directions independently, confirmed
`api.ToUserResponse` still maps explicitly and does not leak `last_otp_step`, and agreed the
`TestMigration000026_CodeRevoked` repair is in scope because this stage's model field is what broke it.
On quality it verified the point that is easy to get wrong on MySQL: the assigned step and the strict
upper bound are the same value, so every matching row genuinely changes and `rowsAffected == 1` keeps
its meaning on an engine that reports matched rather than changed rows. On security it confirmed the
claim fails closed on database errors, is atomic at the row, and that the three predicates together
stop both a replay and a stale verification claiming after the authenticator is removed.

### Two bookkeeping items, fixed in passing

Neither is a finding and neither justified a second round, but both were wrong on the page and would
have misled the next reader, so both are fixed rather than noted:

1. **The step magnitude was wrong by a factor of 30**, in `models/user.go`'s `LastOTPStep` comment and
   in `user_test.go`'s `nowStep`. Both said "any real step is around 1.8e9", which is the Unix
   timestamp; a step is that divided by 30, so a real one is around **6e7**, about 59.5 million today.
   The argument the comments make is unaffected, 0 is still unambiguous, but a reader checking the
   claim against `TestUpdateUser_DoesNotClobberLastOTPStep`'s expected `59533904` would have found the
   comment contradicting the test. Both now say Unix seconds divided by 30, which makes the magnitude
   derivable instead of asserted.
2. **`TestTryConsumeUserOTPStep_EnlistsInTransactionAndFailsClosed` justified itself with a call site
   that will not exist.** Its comment said the browser handler claims inside the same transaction as
   the enrollment write, but §4 is explicit that `tx` is optional on both methods because each is a
   single statement, and `otp/enroll-write` calls `UpdateUser(nil, user)` today. The test is still
   right to exist: honouring a supplied `tx` is the interface contract every write in this layer keeps,
   and it is the precondition for a later change wrapping the claim and the enable together. The
   comment now says that, rather than describing a transaction no planned caller opens.

Both edits are comment text only, which is why the re-run under Tiers returned identical counts. They
are recorded here rather than passed over because a comment that misdescribes the design is how the
next stage inherits a wrong assumption.

## Where this stops

Stage 2 closed. Eleven steps `Done`, three tiers green on the committed tree `f53d3b9a0856`, one clean
review round, no decisions raised and none left open. Stage 3 takes enforcement to the two browser
sites and is the first stage where a real request consumes a step.
