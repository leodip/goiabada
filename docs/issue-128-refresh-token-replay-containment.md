# Issue 128: refresh token single-use is not atomic, and detected replay does not revoke the token family

**Issue:** [#128](https://github.com/leodip/goiabada/issues/128)
**Issue state:** open (labels: bug, security)
**Spec written:** 2026-07-31
**Last synced:** 2026-07-31 (no comments on the issue)
**Plan approved:** 2026-07-31 (through finding 8)
**Related:** #132 (open) tracks the containment residual decision 7 accepts. #77 (closed) is the pattern for defect 1 and the cautionary precedent for defect 2. #106 (closed 2026-07-31, after this issue was filed) landed the authentication-generation machinery this spec must not fight. #131 (open) is a sibling concurrency defect that explicitly states #128 does not subsume it. #127 (closed, not planned) surfaced the unused family columns. #129 (open) covers session termination and is untouched here.

## 0. Code anchors

| Label | File | Function | Locate by | Note |
|---|---|---|---|---|
| `token/refresh-revoked-check` | `src/authserver/internal/handlers/handler_token.go` | `HandleTokenPost` | `if refreshToken.Revoked {` | the validation-time read; the replay branch hangs off it |
| `token/refresh-claim` | `src/authserver/internal/handlers/handler_token.go` | `HandleTokenPost` | `claimed, err := database.MarkRefreshTokenAsRevoked(nil, refreshToken.Id)` | stage 3 replaced the unconditional write here |
| `token/refresh-loser-no-cascade` | `src/authserver/internal/handlers/handler_token.go` | `HandleTokenPost` | `// It does not protect EVERY concurrent duplicate. One whose lookup lands` | the recorded rationale for refusing a lost claim without cascading |
| `token/authcode-claim` | `src/authserver/internal/handlers/handler_token.go` | `HandleTokenPost` | `claimed, err := database.MarkCodeAsUsed(nil, validateResult.CodeEntity.Id)` | the #77 compare-and-set call site |
| `token/authcode-loser-no-cascade` | `src/authserver/internal/handlers/handler_token.go` | `HandleTokenPost` | `// Lost the race: another request concurrently redeemed this same code` | the loser branch that deliberately skips the cascade |
| `token/authcode-reuse-dispatch` | `src/authserver/internal/handlers/handler_token.go` | `HandleTokenPost` | `if reused, ok := err.(*customerrors.AuthCodeReusedError); ok {` | the sequential-reuse branch that does cascade |
| `token/reuse-audit` | `src/authserver/internal/handlers/handler_token.go` | `revokeAndAuditAuthCodeReuse` | `revokedJtis, err := revokeOnAuthCodeReuse(database, code)` | audit payload shape to mirror |
| `token/reuse-conditional-teardown` | `src/authserver/internal/handlers/handler_token.go` | `revokeOnAuthCodeReuse` | `// what makes concurrent redemption safe: a losing racer's cascade finds no` | the recorded rationale for the conditional teardown |
| `data/mark-code-as-used` | `src/core/data/commondb/code.go` | `MarkCodeAsUsed` | `// MarkCodeAsUsed atomically transitions a code from unused to used via a` | the compare-and-set to copy |
| `data/update-refresh-token` | `src/core/data/commondb/refresh_token.go` | `UpdateRefreshToken` | `can't update refreshToken with id 0` | unconditional full-row update |
| `data/refresh-tokens-by-session` | `src/core/data/commondb/refresh_token.go` | `GetRefreshTokensBySessionIdentifier` | `// GetRefreshTokensBySessionIdentifier returns every refresh token whose` | joins codes, so it needs a join the family query will not |
| `data/refresh-tokens-by-user` | `src/core/data/commondb/refresh_token.go` | `GetRefreshTokensByUserId` | `// ROPC: the user is on the token itself and there is no code at all.` | the two-linkage-shape precedent |
| `data/promote-generations` | `src/core/data/commondb/refresh_token.go` | `PromoteRefreshTokenGenerations` | `// An empty id list is a no-op. That is not a formality: an empty IN () is a syntax` | narrow writer of `auth_state_generation` |
| `data/delete-expired-or-revoked` | `src/core/data/commondb/refresh_token.go` | `DeleteExpiredOrRevokedRefreshTokens` | `unable to delete expired/revoked refresh tokens` | deletes every revoked row with no grace |
| `data/iface-mark-code-as-used` | `src/core/data/database.go` | `n/a` | `MarkCodeAsUsed(tx *sql.Tx, codeId int64) (bool, error)` | interface declaration to mirror |
| `data/iface-refresh-by-code` | `src/core/data/database.go` | `n/a` | `GetRefreshTokensByCodeId(tx *sql.Tx, codeId int64) ([]*models.RefreshToken, error)` | where a family query would be declared |
| `data/mark-refresh-token-revoked` | `src/core/data/commondb/refresh_token.go` | `MarkRefreshTokenAsRevoked` | `// MarkRefreshTokenAsRevoked atomically transitions a refresh token from live to` | added by stage 2; the defect 1 compare-and-set |
| `data/revoke-refresh-token-family` | `src/core/data/commondb/refresh_token.go` | `RevokeRefreshTokenFamily` | `// RevokeRefreshTokenFamily revokes every currently live member of one rotation family` | added by stage 2; the defect 2 cascade |
| `data/iface-refresh-family` | `src/core/data/database.go` | `n/a` | `RevokeRefreshTokenFamily(tx *sql.Tx, firstRefreshTokenJti string) (int64, error)` | added by stage 2; its sibling sits directly above |
| `test/data-mark-refresh-revoked` | `src/authserver/tests/data/refresh_token_test.go` | `TestMarkRefreshTokenAsRevoked` | `MarkRefreshTokenAsRevoked(0) must return an error` | added by stage 2 |
| `test/data-revoke-family` | `src/authserver/tests/data/refresh_token_test.go` | `TestRevokeRefreshTokenFamily` | `two families on one browser session` | added by stage 2 |
| `model/refresh-token-family-jti` | `src/core/models/refresh_token.go` | `n/a` | `FirstRefreshTokenJti` | the family identity, written but never read |
| `model/refresh-token-generation` | `src/core/models/refresh_token.go` | `n/a` | `// AuthStateGeneration records the generation this token's grant was authenticated` | the #106 column and its dont-update tag |
| `issuer/refresh-family-carry` | `src/core/oauth/token_issuer.go` | `generateRefreshToken` | `refreshTokenEntity.FirstRefreshTokenJti = refreshToken.FirstRefreshTokenJti` | family carried forward on auth-code rotation |
| `issuer/refresh-insert` | `src/core/oauth/token_issuer.go` | `generateRefreshToken` | `err := t.database.CreateRefreshToken(nil, refreshTokenEntity)` | child inserted outside any transaction |
| `issuer/ropc-family-carry` | `src/core/oauth/token_issuer.go` | `generateRefreshTokenForROPC` | `refreshTokenEntity.FirstRefreshTokenJti = previousRefreshToken.FirstRefreshTokenJti` | family carried forward on ROPC rotation |
| `validator/refresh-lookup` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `refreshToken, err := val.database.GetRefreshTokenByJti(nil, jti)` | the read whose `revoked` value the handler later trusts |
| `validator/refresh-missing-row` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `the refresh token is invalid because it does not exist in the database` | what a swept-away row produces |
| `validator/refresh-generation-authcode` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `if refreshToken.AuthStateGeneration != refreshToken.Code.User.AuthStateGeneration {` | fires before the handler's revoked check |
| `validator/refresh-generation-ropc` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `if refreshToken.AuthStateGeneration != refreshToken.User.AuthStateGeneration {` | same, ROPC branch |
| `validator/refresh-session-check` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `userSession, err := val.database.GetUserSessionBySessionIdentifier(nil, refreshToken.SessionIdentifier)` | session-bound tokens only, not offline |
| `handlers/revoke-refresh-tokens` | `src/authserver/internal/handlers/revocation.go` | `revokeRefreshTokens` | `revokedJtis := make([]string, 0, len(tokens))` | shared revoker, skips already-revoked rows |
| `handlers/revoke-user-auth-state` | `src/authserver/internal/handlers/revocation.go` | `RevokeUserAuthState` | `newGeneration, err := db.IncrementUserAuthStateGeneration(tx, userId)` | the #106 user-scoped sweep |
| `worker/cleanup-interval` | `src/authserver/internal/workers/background_worker.go` | `n/a` | `cleanupInterval = 12 * time.Hour` | how often revoked rows are reaped |
| `worker/used-code-grace` | `src/authserver/internal/workers/background_worker.go` | `n/a` | `usedCodeCleanupGrace = 5 * time.Minute` | the only cleanup grace that exists today |
| `worker/refresh-token-sweep` | `src/authserver/internal/workers/background_worker.go` | `performTask` | `err := w.database.DeleteExpiredOrRevokedRefreshTokens(nil)` | the call that erases the replay signal |
| `constants/authcode-reuse-event` | `src/core/constants/constants.go` | `n/a` | `// AuditAuthCodeReuseDetected is logged when an authorization code is replayed` | naming and doc-comment precedent |
| `constants/event-type-list` | `src/core/constants/constants.go` | `n/a` | `var AuditEventTypes = []string{` | a new event must be appended here too |
| `constants/replay-event` | `src/core/constants/constants.go` | `n/a` | `AuditRefreshTokenReplayDetected = "refresh_token_replay_detected"` | added by stage 4 |
| `token/replay-containment` | `src/authserver/internal/handlers/handler_token.go` | `HandleTokenPost` | `revokedCount, err := database.RevokeRefreshTokenFamily(nil, refreshToken.FirstRefreshTokenJti)` | added by stage 4; the cascade behind the revoked read |
| `token/replay-audit` | `src/authserver/internal/handlers/handler_token.go` | `HandleTokenPost` | `auditLogger.Log(constants.AuditRefreshTokenReplayDetected, map[string]interface{}{` | added by stage 4; gated on a positive count |
| `test/handler-replay-payload` | `src/authserver/internal/handlers/handler_token_test.go` | `TestHandleTokenPost_Refresh_Replay_AuditsContainment` | `the replay payload must carry exactly these six fields` | added by stage 4; the only tier that can see the payload |
| `test/replay-family-scope` | `src/authserver/tests/integration/token_refresh_replay_test.go` | `TestToken_Refresh_Replay_DoesNotContainOtherFamilies` | `family B shares the browser session but not the family: it must stay live` | added by stage 4; the assertion that pins decision 3 |
| `test/replay-ropc` | `src/authserver/tests/integration/token_refresh_replay_test.go` | `TestToken_Refresh_Replay_ContainsROPCFamily` | `a ROPC refresh token must have no code_id` | added by stage 4 |
| `test/authcode-concurrent` | `src/authserver/tests/integration/token_authcode_concurrent_test.go` | `TestToken_AuthCode_ConcurrentDoubleSpend_IssuesOnlyOnce` | `const concurrency = 8` | the integration shape to mirror |
| `test/concurrent-post-helper` | `src/authserver/tests/integration/token_authcode_concurrent_test.go` | `concurrentTokenPost` | `// multiple goroutines. Unlike postToTokenEndpoint it never touches *testing.T` | reusable, already goroutine-safe |
| `test/refresh-marked-used` | `src/authserver/tests/integration/token_refresh_test.go` | `TestToken_Refresh_TokenMarkedAsUsed` | `The original refresh token should be marked as revoked after use` | the regression that must keep passing |
| `test/data-mark-code-as-used` | `src/authserver/tests/data/code_test.go` | `TestMarkCodeAsUsed` | `claimed, err := database.MarkCodeAsUsed(nil, code.Id)` | the data-test shape to mirror |
| `test/data-refresh-by-session` | `src/authserver/tests/data/refresh_token_test.go` | `TestGetRefreshTokensBySessionIdentifier` | `// Two codes share the same session identifier (e.g., user federated to two clients` | fixture pattern for a multi-row query test |
| `test/data-promote-generations` | `src/authserver/tests/data/refresh_token_test.go` | `TestPromoteRefreshTokenGenerations` | `revoked := createTestRefreshToken(t)` | fixture helper for refresh token rows |
| `test/handler-concurrent-loser` | `src/authserver/internal/handlers/handler_token_test.go` | `TestHandleTokenPost_AuthCode_ConcurrentDoubleSpendLoses` | `racedCode.Id).Return(false, nil)` | the unit-test shape for a lost claim |
| `test/handler-refresh-subtests` | `src/authserver/internal/handlers/handler_token_test.go` | `TestHandleTokenPost` | `Refresh_token and token is revoked` | the subtests whose mocks change |
| `test/handler-refresh-loser` | `src/authserver/internal/handlers/handler_token_test.go` | `TestHandleTokenPost_Refresh_ConcurrentDoubleSpendLoses` | `database.On("MarkRefreshTokenAsRevoked", (*sql.Tx)(nil), racedToken.Id).Return(false, nil)` | added by stage 3 |
| `test/refresh-concurrent` | `src/authserver/tests/integration/token_refresh_concurrent_test.go` | `TestToken_Refresh_ConcurrentDoubleSpend_IssuesOnlyOnce` | `at most one family member may be left live after the race` | added by stage 3; the weaker assertion is deliberate |
| `docs/security-single-use` | `site/src/content/docs/reference/security.mdx` | `n/a` | `**Refresh token rotation** - Each refresh token can only be used once` | overstated before stage 3; rewritten by stage 6 |
| `docs/tokens-chain-claim` | `site/src/content/docs/concepts/tokens.mdx` | `n/a` | `Attempting to reuse an old refresh token will fail and may invalidate the entire token chain for security reasons.` | asserts containment that arrives in stage 4; rewritten by stage 6 |
| `schema/refresh-tokens-sqlite` | `src/core/data/sqlitedb/schema.sql` | `n/a` | `first_refresh_token_jti TEXT NOT NULL,` | the column, no index on it before stage 1 |
| `migration/family-index` | `src/core/data/sqlitedb/migrations/000025_add_refresh_token_family_index.up.sql` | `n/a` | `CREATE INDEX idx_refresh_tokens_first_refresh_token_jti` | added by stage 1; three siblings under the other engines |
| `test/migration-000025` | `src/authserver/tests/data/migration_000025_family_index_test.go` | `TestMigration000025_RefreshTokenFamilyIndex` | `control index idx_refresh_token_jti is UNIQUE on every engine` | added by stage 1 |
| `test/describe-index` | `src/authserver/tests/data/migration_testdb_helper.go` | `describeIndex` | `// describeIndex reads an index's uniqueness and key columns from the configured` | the generalized helper stage 1 replaced the name-only check with |

## 1. Context

**This section records the code as it stood at verification time, 2026-07-31, before any
stage landed.** It is deliberately not updated as stages land, because it is the evidence
the decisions in section 3 were taken on, and rewriting it would erase the reasoning's
basis. Where a claim has since been changed by implementation, a bracketed note says which
stage changed it. Section 5's step statuses and as-built notes are the record of the
current state.

### Defect 1 is real, exactly as described

The `refresh_token` case of `HandleTokenPost` read `refreshToken.Revoked`
(`token/refresh-revoked-check`), rejected if set, then unconditionally assigned and wrote.
That write went through `UpdateRefreshToken`
(`data/update-refresh-token`), a full-row `UPDATE ... WHERE id = ?` with no predicate on
`revoked`. The `revoked` value the handler tested came from the validator's read
(`validator/refresh-lookup`), so read and write were separated by the entire validation
pass. Two concurrent presentations of one refresh token both observed `revoked = false`,
both wrote, and both minted a child. Confirmed by reading all three sites, and reproduced
end to end during stage 3: against the pre-fix handler the concurrent integration test
records 2 successes, 2 children from one parent and 2 live family members.

The authorization-code path solved this shape in #77 with a compare-and-set
(`data/mark-code-as-used`), called before any token is minted (`token/authcode-claim`).
There was no equivalent for refresh tokens. **[Stage 3 added one:
`token/refresh-claim`.]**

### Defect 2 is real, and the family identity is present and unread

`first_refresh_token_jti` is stamped at first issuance and carried forward on every
rotation, on both linkage shapes (`issuer/refresh-family-carry`,
`issuer/ropc-family-carry`), and `model/refresh-token-family-jti` is the only declaration
of it. Nothing in production reads either it or `previous_refresh_token_jti`:

```
grep -rn "FirstRefreshTokenJti\|PreviousRefreshTokenJti" --include=*.go src/ \
  | grep -v _test.go | grep -v mocks
```

returns 8 lines: two model field declarations and six write sites in the issuer. So the
family grouping exists on every row and has never been queried. **[Stage 2 added the
first reader, `data/revoke-refresh-token-family`; stage 4 wires it to the handler.]**

There was also no index on `first_refresh_token_jti` on any engine. Verified in the
migrations, which are the source of truth, not only in the schema snapshots: `grep -rn
first_refresh_token_jti src/core/data/*/migrations/` returned only column definitions in the
initial-create migrations and in sqlite's 000011 table rebuild, never a `CREATE INDEX`. The
snapshots agreed (`schema/refresh-tokens-sqlite`). **[Stage 1 added one on all four engines:
`migration/family-index`.]**

### The issue's grep claim about `revoked` is now stale

The issue asserts that the only production readers of `Revoked` are the handler's check,
its assignment, and the two `Revoked: false` initialisers. That was true on 2026-07-29.
#106 landed on 2026-07-31 and added `revokeRefreshTokens` (`handlers/revoke-refresh-tokens`),
which both reads and writes `Revoked`. The part of the claim that still holds, and is the
one defect 1 depends on, is that `ValidateTokenRequest` never checks `revoked`: `grep -n -i
revoked src/core/validators/token_validator.go` returns one line, an unrelated consent
message.

### #106 changed the ground under this issue in two ways that matter

**It supplies a filter the replay path needs.** `RevokeUserAuthState`
(`handlers/revoke-user-auth-state`) revokes tokens *and* advances the user's generation, and
the validator checks the generation before the handler ever sees the row
(`validator/refresh-generation-authcode`, `validator/refresh-generation-ropc`). So a token
revoked by a password change, a password reset, an admin password set or an account disable
is rejected as superseded and never reaches the handler's revoked check. Those revocations
cannot be mistaken for replays.

**It leaves one hole in that filter.** `revokeOnAuthCodeReuse` revokes by session identifier
without touching any generation, and it deletes the session. Session-bound tokens from that
session are then rejected by `validator/refresh-session-check`. Offline tokens are not: they
skip the session check entirely, their generation is unchanged, so a revoked offline token
from an auth-code-reuse cascade reaches the handler's revoked check looking exactly like a
replayed refresh token. This drives open question 2.

### The concurrency hazard, and why the issue's suggested shape does not clear it

The issue names the hazard correctly and then proposes, in "Suggested shape" item 3, to
revoke the family "on a false return from the compare-and-set". Verification says that is
the wrong trigger. A false return from a compare-and-set means only "the row was already
revoked when this statement ran", which merges two populations that #77 deliberately keeps
apart:

- the **concurrent loser**, whose validation read saw `revoked = false` and which lost the
  race by microseconds. #77 rejects this case *without* cascading
  (`token/authcode-loser-no-cascade`), precisely so the loser does not tear down the
  winner's in-flight mint;
- the **sequential replayer**, whose validation read already saw `revoked = true`. #77
  cascades on this case only (`token/authcode-reuse-dispatch`).

The distinguishing signal is the validation-time read, not the write's return value, and it
already exists on the refresh path at `token/refresh-revoked-check`. This is open question
1, and it is the root of the tree.

### The detection signal is deleted on a schedule nobody chose

`DeleteExpiredOrRevokedRefreshTokens` (`data/delete-expired-or-revoked`) deletes every row
with `revoked = true`, with no grace period and no age predicate. The background worker calls
it (`worker/refresh-token-sweep`) on a 12-hour cadence (`worker/cleanup-interval`). Once the
parent row is gone, `GetRefreshTokenByJti` returns nil and the validator fails with a plain
error (`validator/refresh-missing-row`), so the replay is refused but never *detected*, and
any family containment built on the revoked check never fires.

The contrast with authorization codes is sharp and was not designed: `DeleteUsedCodesWithoutRefreshTokens`
only reaps used codes that produced no refresh token, so a code that did produce one keeps
its `used = true` row indefinitely and stays detectable. The one grace period that exists
(`worker/used-code-grace`) was added for foreign-key safety during token generation, not for
detection retention. So the auth-code replay signal is durable and the refresh-token one
would be best-effort with an unspecified window. This drives open question 4.

### Severity, restated after verification

Fail-open on both counts, which matches the issue's Medium to High. Defect 1 lets two
holders of one refresh token both keep working. Defect 2 means the one moment the server
could notice a theft is spent locking out the victim while the thief keeps rotating. #106's
generation machinery does not help here: it is user-scoped and fires on credential change,
not on token replay.

### Test landscape

- **Data tests** (`src/authserver/tests/data/refresh_token_test.go`, 878 lines): the
  closest model for a new compare-and-set test is `test/data-mark-code-as-used`, which
  covers claim-once, already-claimed, missing id and id 0. Fixtures come from
  `createTestRefreshToken` (`test/data-promote-generations`) and the multi-row query pattern
  from `test/data-refresh-by-session`. These run against all four engines and are the only
  tier that does.
- **Handler unit tests** (`src/authserver/internal/handlers/handler_token_test.go`): the
  refresh subtests live inside the single large `TestHandleTokenPost`
  (`test/handler-refresh-subtests`). **Four** of them stub `UpdateRefreshToken` and would
  need their mocks changed by a compare-and-set: the update-error case, the issuer-error
  case, the session-bump case and the no-session case. This paragraph first said five and
  counted the revoked-token case, which returns before the write and stubs nothing; finding
  3 caught it. `test/handler-concurrent-loser` is the shape a new lost-race unit test should
  copy. **[Stage 3 restubbed all four.]**
- **Integration** (`src/authserver/tests/integration/`): `test/authcode-concurrent` is the
  concurrency template and `test/concurrent-post-helper` is already reusable as-is.
  `test/refresh-marked-used` is the regression that pins today's rotation behaviour, and
  `credential_change_revocation_test.go` is the closest precedent for asserting revocation
  effects end to end. `ropc_flow_test.go` covers the ROPC family shape.
- **Mocks**: `data.Database` is mocked into `src/core/data/mocks/database_mock.go` by
  mockery from `src/core/.mockery.yaml`. Any new interface method needs a regeneration, or
  every package that constructs the mock fails to compile.
- **Where tests run**: unit tests on the host; data and integration tests only inside
  `goiabada-devcontainer-1`, via `./run-tests.sh` from `src/authserver/`.
- **No exact-length assertions** were found that a new audit event would break. Adding an
  event does require appending to `constants/event-type-list`; `constants_test.go` asserts
  uniqueness and non-emptiness of that slice, not its length.
  **[Wrong, found in stage 4. `constants_test.go` has two more assertions that a new event
  breaks: `TestAuditEventTypes_Count` pins an exact length as a drift guard, and
  `TestAuditEventTypes_MatchesConstants` carries a hand-maintained list of every audit
  constant and cross-checks it against the slice in both directions. Both had to be updated.
  They are drift guards working as intended, not obstacles.]**

### Documentation already claims the behaviour this issue is adding

Two user-facing sentences were false at verification time and become true once both defects
are fixed: `docs/security-single-use` ("Each refresh token can only be used once", untrue
under concurrency) and `docs/tokens-chain-claim` ("may invalidate the entire token chain for
security reasons", which describes family containment that did not exist). Correcting or
earning these belongs in this change rather than in a follow-up. **[Stage 3 earned the
first; the second waits on stage 4. Stage 6 rewrites both, so until it lands they are
accidentally-true rather than accurate.]**

## 2. Goal

Presenting one refresh token twice yields at most one new token set, whatever the timing.
That guarantee is unqualified.

When the second presentation is a genuine replay of a token that rotation already retired,
every member of the rotation family sharing its `first_refresh_token_jti` that is committed
and live at that moment is revoked in one statement. A dedicated audit event records the
incident, but only when containment actually transitioned at least one live member: a genuine
replay against a family with nothing left to revoke deliberately emits none (decision 2). A concurrent loser is refused without triggering that cascade, so legitimate
double-submits whose lookup preceded that claim do not destroy a working grant. Normal
rotation behaviour, for both authorization-code and ROPC grants, is unchanged.

**Family containment is best-effort, deliberately.** A child whose insert commits after the
containment statement survives it, because rotation commits its parent claim separately from
its child insert. Decision 7 records why closing that needs a per-family serialization
boundary this change does not introduce, and why it is not #131's to own. It is tracked by
**#132**.

**Strict containment is chosen over retry tolerance.** A legitimate parallel refresh whose
lookup lands after the winner's claim can revoke the winner's child and force fresh
authorization. An earlier draft of this section promised that legitimate double-submits never
destroy a working grant; that promise was withdrawn, because it is not achievable from the
validation-time read alone. Decision 9 records the choice and the client contract that follows
from it.

### Out of scope

- **#132, making family containment atomic with rotation.** The residual decision 7 accepts,
  filed as its own issue so it stays tracked after this one closes. Does not block this change.
- **#131, coordinating rotation with the user-scoped generation sweep.** #131 states in its
  own text that #128 is not a superset of it and that a compare-and-set on the refresh-token
  row does not order rotation against a sweep touching different rows. Verified: the two
  operate on disjoint predicates, `refresh_tokens.id` here versus `users.auth_state_generation`
  plus a user-scoped token set there. Per decision 7.
- **#129, session termination not cutting off offline grants.** Different trigger, different
  scope. It is only adjacent because both end up revoking refresh tokens.
- **The broader authorization-grant entity from #127.** Closed as not planned; nothing here
  needs it. Any persistent state this change might add is justified as replay control alone.
- **Making replay detection proactive.** Rotation-based detection is inherently reactive: a
  stolen token that is never replayed is never noticed. Stated here so the tests do not
  claim otherwise.
- **Revoking access tokens already issued to the replayer.** Access tokens are short-lived
  JWTs with no revocation list; family containment stops the next rotation, not the current
  access token's remaining lifetime.

## 3. Open questions and decisions

1. **Family containment fires on the validation-time `revoked` read, not on the
   compare-and-set's false return.** Status: **Decided**

   > **Reopened and re-closed.** The mechanism stands; the reasoning first recorded under it
   > was false. The read establishes ordering relative to the *database lookup*, not relative
   > to request arrival. Sequence: A reads `revoked = false`; A wins the claim; **B's lookup
   > happens now and reads `revoked = true`**; A inserts its child; B takes the replay branch
   > and revokes A's child. B was a legitimate concurrent duplicate.
   > `token/authcode-reuse-dispatch` has the identical blind spot and shipped with it. So the
   > read separates "looked up before the winner's claim" from "looked up after it", never
   > "concurrent" from "sequential". Decision 9 chooses what to do about that.

   The trigger is persisted state observed at lookup, not an inference about request
   timing. A request whose validation read (`validator/refresh-lookup`, tested at
   `token/refresh-revoked-check`) observed `revoked = true` attempts containment. A request
   whose read observed `revoked = false` and which then loses the compare-and-set is refused
   and revokes nothing. This is the same split #77 makes, between
   `token/authcode-reuse-dispatch` and `token/authcode-loser-no-cascade`.

   What the loser branch does and does not buy: it protects requests whose lookup preceded the
   winning claim. It does not protect every concurrent duplicate, and decision 9 records why
   that gap is accepted rather than closed.

   **Rejected:** the issue's suggested shape, cascading on the compare-and-set's false
   return. A false return means only "the row was already revoked when this statement ran",
   which merges the concurrent loser with the sequential replayer. Cascading on it tears
   down the winner's freshly minted child, which is the exact hazard the issue itself calls
   "the crux". Client retries, impatient users and proxies all produce concurrent duplicates,
   so that version can destroy working grants. How often is not quantified here, for the same
   reason decision 9 declines to quantify its own residual.

   **Residual, direction one:** a genuine replay that happens to look up the row before the
   legitimate rotation's claim reads `revoked = false`, is classified as a loser, and is
   refused without containment. This is the same residual #77 accepted and recorded at
   `token/authcode-loser-no-cascade`. Containment still fires on the replayer's next attempt.

   **Residual, direction two, found by review after this item was first settled:** a
   legitimate concurrent duplicate whose lookup lands after the winner's claim attempts
   containment and can destroy the winner's freshly minted child. Accepted under decision 9.

2. **`revoked` stays the persisted replay *candidate* signal, and the audit event is gated
   on the cascade having transitioned at least one family member.** Status: **Decided**

   No revocation-reason column. When validation loads an already-revoked token, run the
   family cascade unconditionally, but emit the replay-containment audit event only after a
   successful commit and only when the cascade moved at least one member from live to
   revoked. The sequence is:

   1. a request reaches the handler with `Revoked == true`;
   2. execute the set-based family update (decision 7);
   3. always respond `invalid_grant`;
   4. emit the audit event only if that update returned successfully having transitioned at
      least one previously live member;
   5. otherwise emit no replay event.

   `revoked` alone identifies a replay candidate, not conclusively a replay, and the gate is
   what converts the candidate into a recorded incident. It excludes the two remaining
   non-rotation populations without any new schema state:

   - **Credential-change revocations never arrive.** #106's four sites bump the generation,
     and `validator/refresh-generation-authcode` and `validator/refresh-generation-ropc`
     reject on the mismatch before the handler runs.
   - **Authorization-code-reuse revocation arrives only for offline tokens**, which skip
     `validator/refresh-session-check` and whose generation is untouched. But that earlier
     transactional sweep already revoked the complete family: a family descends from one
     code, that code carries the session identifier, and
     `data/refresh-tokens-by-session` matches on it. The cascade is an idempotent no-op, so
     no event is emitted.
   - **Re-presenting a token that containment itself revoked** is likewise a no-op, so the
     audit log cannot be amplified by repeated replays.

   **Rejected:** a `revoked_reason` column. It gives more explicit provenance but does not by
   itself stop repeated audit events, and it costs four-engine migrations plus coordinated
   changes to every revocation path. The affected-row gate resolves the present ambiguity
   using state that already exists.

   **The invariant this rests on**, which must be documented in code and covered by tests:
   every non-generation revocation that can reach this branch revokes the *complete* family.
   Any future revocation path that could revoke one family member while leaving descendants
   live must either advance the authentication generation, revoke the complete family, or
   reopen the question of explicit revocation provenance.

   **On the precedent:** the transferable part is the contract of `revokeRefreshTokens`
   (`handlers/revoke-refresh-tokens`), whose returned JTIs include only rows it moved from
   live to revoked. It is *not* the existing audit behaviour:
   `revokeAndAuditAuthCodeReuse` (`token/reuse-audit`) logs whenever `code != nil`, even with
   an empty JTI list. The `len(revokedJtis) > 0` gate there sits on the session teardown
   inside `revokeOnAuthCodeReuse` (`token/reuse-conditional-teardown`), not on the event.

   **Not resolved here:** a cascade can still miss a descendant minted concurrently, after
   the family query has run. That is an issuance-ordering problem and belongs to decision 7.

3. **A family is exactly the rows sharing the presented token's `first_refresh_token_jti`,
   and containment touches nothing else.** Status: **Decided**

   The containment transaction affects only refresh-token rows matching
   `WHERE first_refresh_token_jti = ?`. It does not update or delete the originating
   authorization code, and it does not delete or modify any user-session row.

   The properties that make this the right set:

   - it contains every descendant, including the multiple live branches that defect 1 can
     currently produce from one parent;
   - it behaves identically for authorization-code and ROPC grants;
   - it does not reach unrelated grants belonging to the same user, client, or browser
     session;
   - it needs no flow-specific branching on the nullable `code_id`.

   For authorization-code grants, family scope and code-id scope are equivalent *today*, not
   merely close: `issuer/refresh-family-carry` keeps every descendant on the original
   `code_id`, and once defect 1 is fixed atomic redemption permits only one initial refresh
   token per code. The family identifier is still the correct abstraction, because it also
   covers ROPC chains, whose rows have no code, without a fallback branch, and because it
   states the intended security boundary directly.

   **Rejected:** session scope, and by extension the symmetry argument with
   `revokeOnAuthCodeReuse`. Authorization-code replay implicates the browser authorization
   ceremony, which is why that path deletes the session
   (`token/reuse-conditional-teardown`). Refresh-token replay instead implicates the
   client-side storage of one grant. Deleting the browser session, or revoking every token
   originating from it, would hit unrelated clients and families and punish the legitimate
   user for the thief's access, which is the inversion this issue exists to correct.

   **Rejected:** code-id scope, on the ROPC gap alone. It is set-equal for auth-code grants
   and empty for ROPC (`data/refresh-tokens-by-session` has the analogous problem).

   The code row needs no containment action: it is already `used = true` and cannot mint
   another token set.

   **Pinned behaviourally** by an integration test that establishes two families through
   different clients on one browser session, rotates family A, replays A's retired parent,
   then asserts A's live descendant is rejected, family B still rotates, and the browser
   session survives and remains usable. ROPC containment gets its own coverage, since that is
   where `first_refresh_token_jti` materially differs from `code_id`.

4. **Revoked refresh-token rows are retained until their natural token expiry, and the
   missing-row error is corrected to `invalid_grant`.** Status: **Decided**

   The sweep at `data/delete-expired-or-revoked` stops deleting a row merely because
   `revoked = true`. Its predicate becomes `expires_at < now OR max_lifetime < now`, and the
   method is renamed to `DeleteExpiredRefreshTokens` so its contract stays truthful.

   This makes retention coincide with the interval in which detection is possible.
   `DecodeAndValidateTokenString` is called with `withExpirationCheck = true` before
   `validator/refresh-lookup`, so an expired token cannot trigger containment even if its row
   survives; conversely, deleting a revoked row while its JWT is still presentable destroys
   the relationship information needed to detect the replay and revoke the live family. RFC
   9700 section 4.14.2 is explicit that rotation must retain enough relationship information
   for an invalidated token to reveal a breach
   (https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2).

   **Rejected:** a fixed grace period after revocation. It draws an arbitrary security
   boundary, where two otherwise identical replays get different containment based only on
   their proximity to the cleanup worker. Natural expiry gives the behaviour a protocol
   boundary instead.

   **Rejected:** leaving the sweep alone. Detection would work or not depending on when the
   worker last ran, which is not a property worth shipping.

   **What becomes exact is the detection window, not the physical deletion time.** The worker
   still runs on a 12-hour cadence (`worker/cleanup-interval`), so eligibility and deletion
   are not the same moment. A session-bound row becomes eligible within at most 2 hours
   (`UserSessionIdleTimeoutInSeconds`, default 7200) but can physically persist for roughly
   14 hours after revocation. So session-bound storage is not necessarily reduced relative to
   today's behaviour, and an earlier draft of this rationale claiming a reduction was wrong.

   **The storage cost is accepted explicitly.** With the default 30-day offline idle timeout
   (`RefreshTokenOfflineIdleTimeoutInSeconds`, default 2592000), a grant rotated every five
   minutes retains roughly 8,640 detection-relevant revoked rows, plus whatever is awaiting
   the next sweep. Deployments with longer timeouts or faster rotation retain proportionally
   more. This belongs in the documentation and is worth monitoring.

   **Separately, and in scope here:** a validly signed refresh token whose row is absent must
   return `invalid_grant`, not `server_error`. Today `validator/refresh-missing-row` returns a
   plain error, and `JsonError` maps anything that is not an `ErrorDetail` to a 500. Retention
   makes this rarer but cannot remove it: user deletion, referential cascades and database
   restores all leave a signed, unexpired token with no row. RFC 6749 section 5.2 classifies
   an invalid, expired or revoked refresh token as `invalid_grant`
   (https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2).

   **Tests this decision requires:** a revoked but unexpired row survives cleanup; a revoked
   row past `expires_at` is deleted; a revoked offline row past `max_lifetime` is deleted; an
   unexpired signed token with no row returns 400 `invalid_grant`; an expired token is
   rejected before `GetRefreshTokenByJti` is reached. The existing
   `TestDeleteExpiredOrRevokedRefreshTokens` asserts the behaviour this decision reverses, so
   its revoked-row case must be inverted deliberately rather than deleted as noise.

5. **Add a non-unique index `idx_refresh_tokens_first_refresh_token_jti` in migration
   000025, and no cleanup indexes.** Status: **Decided**

   ```sql
   CREATE INDEX idx_refresh_tokens_first_refresh_token_jti
     ON refresh_tokens(first_refresh_token_jti);
   ```

   For SQLite, MySQL, PostgreSQL and SQL Server, with the same index added to all four schema
   snapshots and dropped in each down migration. 000024 is the highest existing number on
   every engine, verified by `ls src/core/data/*/migrations | tail`.

   Required for two independent reasons. Decision 4 substantially increases the number of
   retained revoked rows, and family lookup sits on a request-driven path that a client
   holding a revoked token can repeat at will. Without the index that client forces a full
   scan of a table whose size grows with refresh frequency and token lifetime; with it the
   lookup is family-sized rather than table-sized.

   Non-unique by design: every descendant of one rotation chain intentionally shares the
   identifier (`issuer/refresh-family-carry`, `issuer/ropc-family-carry`). The column types
   all support an ordinary full-column index: sqlite `TEXT`, mysql and postgres
   `VARCHAR(64)`, mssql `NVARCHAR(64)`.

   No engine indexes the column today, verified in the migrations rather than only the
   snapshots. Each engine's migration must be written rather than copied, because the
   existing index sets already diverge: MySQL serves `code_id` through the inline
   `fk_refresh_tokens_code` key while the other three use `idx_refresh_tokens_code_id`, and
   SQLite has no `client_id` index at all.

   **Rejected:** adding `expires_at` and `max_lifetime` indexes in the same migration. Cleanup
   is a scheduled batch operation, and whether separate indexes improve an
   `expires_at < now OR max_lifetime < now` delete depends on engine plans, deletion
   selectivity and table size, with `max_lifetime` NULL for every session-bound row. Add them
   later only if query plans or operational measurements show a cleanup bottleneck. Recorded
   here so decision 4's added sweep cost is not lost.

   **Migration test must assert** that the index is absent at 000024, that applying 000025
   creates it, that it is non-unique and covers `first_refresh_token_jti` rather than merely
   existing under the expected name, that rolling back to 000024 removes it, and that
   reapplying restores it. The existing `index000024Exists` helper checks names only, so it
   needs generalizing to assert column membership and uniqueness; otherwise a wrongly defined
   index still passes.

6. **Keep `previous_refresh_token_jti`, document it, and add no production consumer.**
   Status: **Decided**

   The two columns answer different questions. `first_refresh_token_jti` answers "which
   family does this row belong to", and drives containment. `previous_refresh_token_jti`
   answers "which token directly produced this row", and reconstructs the chain's topology.
   Multiple rows sharing one non-empty previous JTI show that multiple children were
   persisted from a single parent, which is the structural fingerprint of a rotation fork and
   therefore evidence about the very invariant this issue establishes. Decision 4 raises its
   forensic value by retaining those rows until token expiry.

   **It is diagnostic evidence, not an authoritative security signal.** A fork proves that
   multiple child rows were persisted for one parent, not that both tokens reached clients:
   `issuer/refresh-insert` inserts the row before `token.SignedString` runs, so a later
   issuance failure can leave an undelivered child behind.

   **Rejected:** dropping it inside this security fix. That is migrations and model changes
   across four engines, and the down migration could recreate the column but not restore the
   discarded ancestry. The storage saving is also smaller than a naive reading suggests: the
   column has a 64-character capacity but holds 36-character UUID strings, and physical cost
   varies by engine, notably for SQL Server's `NVARCHAR`. If operational experience later
   shows the diagnostics are not worth it, removal belongs in a separate, explicitly
   destructive schema change, in the shape #98 uses for `users.otp_secret`.

   **No runtime consumer here.** The security mechanism rests on the atomic revocation claim
   and the family identifier, never on reconstructing the chain, so the column stays an
   independent way to validate the single-child invariant rather than part of it.

   Model comment to add at `model/refresh-token-family-jti`:

   ```go
   // PreviousRefreshTokenJti identifies the immediate parent of a rotated token.
   // It is empty for the first token in a family. It is retained for chain
   // reconstruction and fork diagnostics; family containment uses
   // FirstRefreshTokenJti instead.
   ```

   The concurrent-rotation integration test additionally asserts that the family contains at
   most one row whose `previous_refresh_token_jti` equals the presented token's JTI.

7. **Containment is one set-based conditional update; #131's coordination stays out; the
   remaining family race is owned by #128.** Status: **Decided**

   ```sql
   UPDATE refresh_tokens
   SET revoked = true, updated_at = ?
   WHERE first_refresh_token_jti = ?
     AND revoked = false;
   ```

   The data method returns the affected-row count, and returns an error on an empty family
   identifier. That is deliberately a *stronger* contract than the neighbouring guards:
   `data/refresh-tokens-by-session` and `data/refresh-tokens-by-user` return an empty result
   for an empty or zero key, whereas an empty family identifier here can only be a caller bug
   and must not be silently absorbed by a revocation path. The count is exactly how many
   members this call transitioned from live to revoked, and is the decision 2 gate for
   emitting the containment audit event.

   This is the strongest portable containment available without a shared family serialization
   boundary. It operates atomically on the rows visible to that update statement, avoids
   per-row round trips and full-row writes, uses the decision 5 index, and depends on no
   engine-specific locking syntax. Its visibility is also no worse than select-then-update and
   on some engines better: PostgreSQL and SQL Server take a fresh view per statement under
   READ COMMITTED, MySQL/InnoDB performs a current read for `UPDATE` rather than reusing the
   REPEATABLE READ snapshot, and SQLite serializes writers. It does not, on any engine, reach
   a row committed after its own statement snapshot.

   **Rejected:** engine-specific locking reads. `SELECT ... FOR UPDATE` on MySQL and
   PostgreSQL, `WITH (UPDLOCK)` on SQL Server, adds portability and deadlock complexity, and
   while rotation still commits its parent claim separately from child insertion it cannot
   protect a child that does not exist yet.

   **Rejected:** moving the rotation compare-and-set and the child insert into one
   transaction as a partial implementation of #131. #131 requires coordination between
   rotation and the user-scoped generation sweep; a refresh-token transaction that does not
   share that sweep's serialization boundary would not satisfy it, and
   `issuer/refresh-insert` would need an issuer signature change to reach a handler-level
   transaction anyway.

   **Accepted residual, tracked by #132.** A rotation can claim a live descendant, the replay
   cascade can then update every currently committed family member, and the rotation can
   afterwards insert its new child. That child is invisible to the containment statement and
   survives. Closing it requires rotation and containment to share a durable per-family
   serialization boundary, or persistent family-revocation state.

   This residual is **not** automatically resolved by #131, and an earlier draft of this
   decision that assigned it there was wrong. #131 coordinates rotation with a *user-scoped*
   generation change; its boundary might later supply usable machinery, but satisfying #131
   does not by itself serialize rotation against a family-replay cascade. It is therefore
   tracked by its own issue, #132, filed after plan approval so the gap keeps an open item once
   #128 closes rather than surviving only as prose here.

   **One interleaving is also silent.** If the attacker's claim commits, containment then finds
   zero live members, and the attacker's child commits afterwards, decision 2's zero-count gate
   suppresses the audit event. So the interleaving in which containment fails is the one in
   which it records nothing. A later replay would contain the child and emit the event, but the
   legitimate client has already had `invalid_grant` and typically stops. Recorded in #132's
   acceptance criteria rather than fixed here, since fixing it needs the same boundary.

   **Consequence for section 2:** family containment is best-effort against a child committed
   after the containment statement. Atomic single use carries no such qualification.

8. **`refresh_token_replay_detected`, with an exact count and no revoked-JTI list.**
   Status: **Decided**

   Add `AuditRefreshTokenReplayDetected = "refresh_token_replay_detected"` alongside
   `constants/authcode-reuse-event`, and append it to `constants/event-type-list`.

   ```go
   // AuditRefreshTokenReplayDetected records an authenticated presentation of an
   // already-revoked refresh token that caused at least one live member of the
   // same rotation family to be revoked.
   ```

   Emit it only when an authenticated presentation of an already-revoked refresh token causes
   containment to transition at least one member from live to revoked, and only after the
   containment update or its containing transaction has completed successfully.

   Payload:

   - `presentedRefreshTokenJti`, the JTI from the refresh token presented in this request;
   - `firstRefreshTokenJti`, the persisted family identifier used by the containment
     predicate;
   - `revokedCount`, the affected-row count from the decision 7 update;
   - `clientId`, the numeric id of the client validated for this request;
   - `userId`, the numeric id of the resource owner associated with the family;
   - `flow`, `auth_code` or `ropc`, identifying the flow that created the family.

   `revokedCount` is exact on all four engines: every row matching `revoked = false` is
   changed to `true`, so the matched-rows versus changed-rows distinction cannot affect it.

   Populate the principal fields uniformly for both linkage shapes, from the loaded code,
   client and user for authorization-code families and from the refresh-token linkage
   directly for ROPC. A security-event consumer should not need flow-specific payload logic
   just to identify the client and user. This departs from
   `AuditTokenIssuedRefreshTokenResponse`, which logs `codeId` on one shape and
   `userId`/`clientId` on the other.

   **Rejected:** a `revokedRefreshTokenJtis` list. A portable set-based update yields an exact
   count but not an exact cross-engine row set, and selecting live JTIs beforehand can
   under-report rows inserted before the update or over-report rows concurrently revoked
   elsewhere. Such a list would have ambiguous forensic meaning, and an inaccurate security
   field is worse than an omitted one. The family identifier preserves the investigation path
   instead: retained rows keep carrying `first_refresh_token_jti` even after the root row is
   gone, so the family stays queryable while its members are retained (decision 4).

   **The name** distinguishes the audited condition, an already-revoked token presentation
   that caused containment, from a reuse attempt that loses the compare-and-set and therefore
   causes neither cascade nor event, whatever the presenter's intent. It matches RFC 9700
   section 4.14.2's vocabulary and decision 1's split. It does **not** assert malicious
   intent: under decision 9 the event can legitimately describe a concurrent duplicate, and
   its doc comment must say so. (An earlier draft called the compare-and-set loser "benign",
   which is the same error: decision 1's first residual records that a genuine replay whose
   lookup preceded the winning claim is classified as a loser. The distinction is observable
   behaviour, not intent. Corrected during stage 4 review; the decision itself is unchanged.)
   **Rejected:** `refresh_token_reuse_detected`, more parallel with
   `auth_code_reuse_detected` but blurring exactly that distinction.

   When `revokedCount == 0`, respond `invalid_grant` and emit no event. A structured debug
   message may record the no-op, mirroring the #77 loser precedent at
   `token/authcode-loser-no-cascade`, but it must not be described as immune to log
   amplification: with debug logging enabled it is still repeatable by the client.

   **Tests this decision requires:** a real replay with a live descendant emits exactly one
   event carrying all six fields; `revokedCount` equals the update's affected-row count;
   authorization-code and ROPC families produce the same payload shape; a zero-count cascade
   emits no event; a concurrent compare-and-set loser emits neither this event nor a cascade;
   a containment error emits no event and surfaces as a server error; the payload contains
   neither the refresh token itself nor an inexact JTI list.

9. **Strict policy: any lookup that observes the token already revoked attempts
   containment.** Status: **Decided**, raised by review of section 4

   The rule is stated over observable persisted state, not over a claim that the server knows
   whether the HTTP request began before or after revocation.

   The server cannot distinguish a delayed legitimate duplicate from a malicious replay from
   the token and the row alone. RFC 9700's rotation model responds to the presentation of an
   invalidated refresh token by revoking the active token, precisely because the server cannot
   know which presenter is legitimate. Goiabada follows that strict model and adds no overlap
   window.

   **Consequence, accepted deliberately:** a legitimate parallel refresh can invalidate the
   winner's child, when its lookup occurs after the winner's claim and its cascade sees that
   child. This is an availability cost of strict containment. Its frequency is scheduling- and
   workload-dependent and is **not quantified by this specification**: the interval between
   lookup and claim is full request validation, and nothing in the code supports an estimate.

   **Client contract, which the documentation must state:** clients must serialize refresh
   operations and atomically replace their stored refresh token with the one returned by the
   successful response. Parallel refreshes, or a retry that presents a retired token, can
   revoke the family and require fresh authorization.

   **Rejected: a fixed overlap window.** It creates a period in which the defining theft
   scenario stays uncontained: the attacker rotates the stolen parent, and keeps the child
   when the legitimate client presents that parent inside the window. It also adds timing
   policy and revocation-provenance complexity the strict model does not have. Note this is
   **not** the same rejection as decision 4's: cleanup retention and an overlap window are
   genuinely different trades, and the latter deliberately exchanges replay containment for
   retry tolerance. Strict wins on its own merits, not by analogy.

   **Rejected: shared family coordination or idempotent rotation state.** Strongest and
   largest, and naive idempotent replay (returning the same child to a repeat presenter) would
   hand the child to a replayer, so it is not viable on its own.

   **On the mechanism an overlap window would need:** it would not strictly require a new
   column, since `MarkRefreshTokenAsRevoked` bumps `updated_at`. But that field is overloaded,
   carrying clock and other-revocation ambiguity, so a trustworthy overlap policy would merit
   dedicated state anyway.

   **What this means for the audit event:** `refresh_token_replay_detected` records an
   authenticated presentation observed after persisted revocation that actually revoked live
   family members. It does not prove malicious intent, and it may describe a legitimate
   concurrent duplicate.

   **Tests must cover both orderings deliberately:** both requests read the token live before
   any claim, so one wins and the other is a silent compare-and-set loser; and the second
   lookup reads the token revoked after the winner's claim, so it attempts containment and may
   revoke the winner's committed child.


10. **A revoked row with NULL `expires_at` and NULL `max_lifetime` is retained, not reaped.**
    Status: **Decided**, raised while executing the decision 4 test table

    Executed against SQLite in the scratchpad: such a row is deleted **today**, because the
    old predicate carries `OR revoked = true`, and is **never** deleted after decision 4,
    because both timestamp comparisons yield NULL. Confirmed still present after five
    consecutive sweeps.

    No production path creates one: `issuer/refresh-insert` and its ROPC twin both set
    `ExpiresAt` with `Valid: true`. But both columns are nullable on all four engines
    (verified in the schema snapshots), so a legacy or imported row would leak permanently,
    and "no current code path writes NULL" is not the same as "no row has NULL".

    `DeleteExpiredRefreshTokens` deletes only on `expires_at < now OR max_lifetime < now`.
    Such a row is retained, because the server cannot establish its natural expiry from the
    row at all.

    **Rejected:** the third disjunct
    `OR (revoked = true AND expires_at IS NULL AND max_lifetime IS NULL)`, which this item
    originally recommended. A revoked row is not disposable merely because it is no longer a
    live grant: it **is** the replay-detection signal. A signed token whose imported row has
    NULL expiry columns can still carry an unexpired `exp`, so deleting the row recreates
    exactly the defect decision 4 exists to fix, where the presentation is rejected as missing
    and its live descendants go uncontained. There is no principled safe deletion time here,
    because the database lacks the information to compute one, and a method named
    `DeleteExpiredRefreshTokens` would be deleting rows not known to be expired.

    Conservative retention is right because the anomalous population is bounded to legacy or
    imported data (no supported issuer creates such a row), and because these rows are stranded
    by the *time-based sweep* only: referential cascades and explicit operator cleanup still
    remove them. Security retention takes precedence over automatically tidying malformed
    external data.

    **Rejected:** making the two columns `NOT NULL` in migration 000025. It needs a backfill
    value for existing NULLs and touches a column this change otherwise does not need, which is
    a schema decision that does not belong inside a security fix.

    **Pinned** by a data test asserting the row survives the sweep. Documentation states that
    imports must populate `expires_at`; repairing or removing malformed legacy rows is left to
    an explicit operator action or a future data-quality migration.

## 4. Proposed solution

Five moving parts: an atomic claim on the presented row, a set-based family cascade behind
the validation-time revoked check, a retention change to the cleanup sweep, an error-mapping
fix in the validator, and one index migration.

### The handler's `refresh_token` case

The case splits into a replay branch and a claim, replacing the read-then-unconditional-write
at `token/refresh-revoked-check` and the unconditional write that used to follow it:

```go
case "refresh_token":
    refreshToken := validateResult.RefreshToken

    // The validation-time read observed this token already revoked. Under the
    // strict rotation policy, attempt family containment even though the server
    // cannot distinguish malicious replay from a delayed concurrent duplicate.
    if refreshToken.Revoked {
        revokedCount, err := database.RevokeRefreshTokenFamily(nil, refreshToken.FirstRefreshTokenJti)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }
        if revokedCount > 0 {
            auditLogger.Log(constants.AuditRefreshTokenReplayDetected, ...)
        } else {
            slog.Debug("refresh_token: revoked token presented, no live family members to revoke", ...)
        }
        httpHelper.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
            "This refresh token has been revoked.", http.StatusBadRequest))
        return
    }

    // Atomically claim the row before minting anything. A false return means the row
    // stopped being live between the validation read and here, so this request is
    // refused WITHOUT the cascade, as `token/authcode-loser-no-cascade` does. That
    // covers only duplicates whose lookup preceded the winning claim (decision 9).
    claimed, err := database.MarkRefreshTokenAsRevoked(nil, refreshToken.Id)
    if err != nil {
        httpHelper.InternalServerError(w, r, err)
        return
    }
    if !claimed {
        slog.Debug("refresh_token: token was no longer live at claim time, rejecting", ...)
        httpHelper.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
            "This refresh token has been revoked.", http.StatusBadRequest))
        return
    }

    // ... issuance, session bump and audit unchanged from here
```

Four details that are load-bearing:

- **The in-memory `refreshToken.Revoked = true` assignment is dropped, not moved.** Verified
  that nothing downstream reads it: `GenerateTokenResponseForRefresh` and
  `GenerateTokenResponseForRefreshROPC` read the parent's `Scope`, `MaxLifetime`,
  `RefreshTokenJti`, `FirstRefreshTokenJti`, `AuthStateGeneration`, `SessionIdentifier`,
  `Client` and `User`, and `grep -n Revoked src/core/oauth/token_issuer.go` returns only the
  two `Revoked: false` initialisers.
- **Both rejection branches return the same message.** The replay branch keeps the existing
  wording, which `test/refresh-marked-used` asserts. The loser branch reuses it so a client
  cannot distinguish the two paths from the response, with the debug line and the audit event
  carrying the distinction instead. This differs from #77, where the loser gets a separate
  generic "Code is invalid." string.
- **Which branch a concurrent duplicate takes is not controlled here.** Under decision 9 it
  depends on whether its lookup preceded the winner's claim, and the strict policy accepts
  that a duplicate landing on the replay side revokes the winner's child.
- **Containment needs no explicit transaction.** It is a single statement, so its successful
  return is its commit, which is what decision 2's "after a successful commit" means here.
  A `BeginTransaction`/`Commit` pair around one statement would add failure modes without
  adding atomicity.

### New data-layer methods

Both land in `commondb`, are delegated by the four engine types in the pattern
`data/refresh-tokens-by-user` already follows, and are declared next to
`data/iface-mark-code-as-used` and `data/iface-refresh-by-code`:

```go
// MarkRefreshTokenAsRevoked atomically transitions a refresh token from live to
// revoked via a conditional UPDATE (WHERE id = ? AND revoked = false), returning
// true only if this call made the transition. Compare-and-set for the same reason
// MarkCodeAsUsed is: read-then-unconditional-update leaves a double-spend window
// spanning the whole of request validation (#77, #128).
MarkRefreshTokenAsRevoked(tx *sql.Tx, refreshTokenId int64) (bool, error)

// RevokeRefreshTokenFamily revokes every currently live member of one rotation
// family in a single statement and returns how many rows it transitioned.
RevokeRefreshTokenFamily(tx *sql.Tx, firstRefreshTokenJti string) (int64, error)
```

`MarkRefreshTokenAsRevoked` mirrors `data/mark-code-as-used` including its zero-id guard, and
writes only `revoked` and `updated_at`, so it cannot touch `auth_state_generation` at all.
That is an independent guarantee rather than a repair of `data/update-refresh-token`, which
already excludes the column through its `dont-update` tag
(`model/refresh-token-generation`). Stating it in the statement means the boundary does not
rest on a struct tag a future full-row writer might not honour.
`RevokeRefreshTokenFamily` returns an error on an empty family identifier. Note this is a
stronger contract than the neighbouring guards, not the same one:
`data/refresh-tokens-by-session` returns an empty result for an empty key. On a revocation
path an empty identifier can only be a caller bug, and absorbing it silently would report a
zero count that decision 2 reads as "nothing to contain".

Adding two interface methods requires regenerating `src/core/data/mocks/database_mock.go`
from `src/core/.mockery.yaml`, or every package constructing the mock fails to compile.

### Retention and error mapping

`data/delete-expired-or-revoked` drops its `revoked = true` disjunct and is renamed
`DeleteExpiredRefreshTokens`, per decision 4. The rename reaches the interface, `commondb`,
four engine wrappers, the generated mock and `worker/refresh-token-sweep`.

`validator/refresh-missing-row` returns an `ErrorDetail` with `invalid_grant` and a 400
instead of a plain error, so `JsonError` stops mapping it to `server_error` with a 500. The
message stays generic ("The refresh token is invalid.") rather than revealing whether a row
existed. One existing unit test asserts the old string via `err.Error()` and is updated
deliberately, not deleted: it pins behaviour this change reverses.

### Migration 000025

One non-unique index on `refresh_tokens(first_refresh_token_jti)` named
`idx_refresh_tokens_first_refresh_token_jti`, on all four engines, with matching down
migrations and matching lines in all four schema snapshots. Per decision 5.

### Documentation

`docs/security-single-use` and `docs/tokens-chain-claim` both assert behaviour the code does
not have today and will have afterwards, so they are corrected in the same change rather than
left as accidentally-true. The tokens page also gains two things this change makes
operator- and client-visible:

- the **client contract** from decision 9: serialize refreshes, atomically replace the stored
  token with the one from the successful response, and expect that parallel refreshes or a
  retry presenting a retired token can revoke the family and require fresh authorization;
- the **storage consequence** of decision 4, since retaining revoked rows until token expiry
  is an operator-visible cost scaling with refresh frequency and configured lifetimes.

### Where this departs from the issue

- **The cascade trigger.** The issue's "Suggested shape" item 3 fires containment on the
  compare-and-set's false return. This spec fires it on the validation-time revoked read and
  treats the false return as a silent concurrent loser. Decision 1 records why: the false
  return cannot distinguish a replayer from a duplicate, and cascading on it destroys working
  grants.
- **The family query.** The issue proposes `GetRefreshTokensByFirstJti`, a read followed by
  per-row revocation. This spec uses a single set-based conditional update instead. Decision 7
  records why: it is atomic over the rows its statement sees, avoids the wider window of a
  read followed by per-row writes, and yields the exact count decision 2's gate needs.
- **The audit payload.** The issue asks for the revoked JTIs. This spec carries an exact count
  and the family identifier instead. Decision 8 records why: a portable set-based update
  cannot produce an exact list, and an inexact one labelled as revoked JTIs is a false record.
- **Two things the issue does not mention at all**, both found by verification and both in
  scope: revoked rows are deleted with no grace, which erases the detection signal on an
  arbitrary schedule (decision 4), and a missing row returns a 500 rather than
  `invalid_grant` (decision 4).

### What makes this safe, and what it does not promise

**Safe:** every new mutation and audit path is reachable only by a request carrying a validly
signed refresh token bound to the validated client, and for confidential clients only by one
that also authenticated with the client secret. Public clients have no secret, so for them the
signed token bound to the client is the whole gate, which is the same gate rotation itself
already stands behind. The missing-row `invalid_grant` path is deliberately excluded from that
statement: it cannot establish token-to-client binding, because the row needed to establish it
is the one that is absent. It mutates nothing and audits nothing, which is why it does not
need to. The claim replaces an unconditional write with a conditional one on
the same row, so a request that succeeds today still succeeds unless the row is no longer
live when the claim runs. After a successful claim, issuance, session bumping and issuance
auditing are unchanged.

A `!claimed` return does **not** mean specifically "another rotation claimed this row". It
means the row is no longer live: a concurrent rotation, a concurrent security revocation such
as `handlers/revoke-user-auth-state`, or the row having been deleted all produce it.

**Refusing without a cascade follows from that ambiguity, not from the cases being
individually harmless.** The handler cannot tell which of the three produced the false
return, and one of them is a concurrent rotation whose freshly minted child a cascade would
destroy. So containment cannot fire here at all, and each case is left as it is:

- **Concurrent rotation.** Cascading would be actively wrong. This is the case the branch
  exists for.
- **Credential-change revocation.** Genuinely benign: `handlers/revoke-user-auth-state`
  advanced the user's generation, so every family member is already rejected by
  `validator/refresh-generation-authcode` or `validator/refresh-generation-ropc` before
  reaching this handler.
- **Deleted row.** An **accepted residual**. Deletion is row-scoped and proves nothing about
  descendants, so live family members can survive a deletion of their ancestor and this
  branch will not contain them. An earlier draft claimed "a deleted row has no family left to
  contain", which is false. What bounds it: after decision 4 no sweep deletes an unexpired
  row, so reaching this state needs user deletion, a referential cascade or a restore, all of
  which remove or invalidate the wider grant anyway; and containment still fires on the next
  replay presented against any surviving family member, since that presentation reads its own
  row revoked and takes the branch above.

**Not promised:** family containment is best-effort against a child whose insert commits after
the containment statement (decision 7, residual owned here). Detection remains reactive: a
stolen token that is never replayed is never noticed. And a replay whose parent row has passed
its expiry is rejected by the JWT check before any of this runs, which is correct but means
containment has a bounded, protocol-defined horizon rather than an unlimited one.

## 5. Implementation plan

Six stages. Stages 1 and 2 are pure additions with no behaviour change; the observable
behaviour changes land in stages 3, 4 and 5.

**Where the tiers run.** Unit tests (`--type internal`, `--type core`) run on the host. Data
and integration tests run only inside `goiabada-devcontainer-1`, from `/workspaces/goiabada`,
via `src/authserver/run-tests.sh`. Any stage below that names a data or integration test
cannot be verified on the host, and a green host run says nothing about it.

**Every case in the tables below was executed** against a SQLite harness reproducing the
proposed statements before being written here: 30 cases, 30 passing, expectations written
before the run. The harness models the statements and the column nullability, not the Go
guards or the other three engines, and each table says which rows it therefore cannot prove.

### Stage 1: migration 000025, the family index
Status: **Done**

Tests: data tier only, dev container, all four engines.

1. Add `000025_add_refresh_token_family_index.{up,down}.sql` for sqlite, mysql, postgres and
   mssql. Status: **Done** (`migration/family-index`)
   Up creates `idx_refresh_tokens_first_refresh_token_jti` on
   `refresh_tokens(first_refresh_token_jti)`, non-unique. Down drops it. Per decision 5.
   Each engine's file is written rather than copied: MySQL serves `code_id` through the
   inline `fk_refresh_tokens_code` key while the others use `idx_refresh_tokens_code_id`, and
   SQLite has no `client_id` index, so the surrounding index sets already differ.
2. Add the same index line to all four `schema.sql` snapshots. Status: **Done**
   Documentation-only files, never loaded by Go, but they are the reference readers use.
3. Add `migration_000025_family_index_test.go`. Status: **Done** (`test/migration-000025`,
   `test/describe-index`)
   Modelled on `migration_000024_auth_state_generation_test.go` and using `newIsolatedDB`.
   Asserts: the index is absent at 000024; applying 000025 creates it; **it is non-unique and
   its column list is exactly `first_refresh_token_jti`**; rolling back to 000024 removes it;
   reapplying restores it. Per decision 5.
   The column-list and uniqueness assertions are the point of the test, not padding: the
   existing `index000024Exists` helper matches on **name only**, so an index created on the
   wrong column, or created `UNIQUE`, passes it. A `UNIQUE` index here would be actively
   harmful, since every family member shares the value, so the second row of any family would
   fail to insert and rotation would break entirely. Generalize the helper rather than copying
   the name-only version.
   Running this per engine in a loop exhausts the mssql container's 4GiB pool; if an
   unrelated test appears to hang afterwards, `docker restart` the mssql container.

   **As built.** Eight migration files under the four `migrations/` directories, the index line
   in all four `schema.sql` snapshots, and `migration_000025_family_index_test.go`. The
   name-only `index000024Exists` helper now delegates to a new `describeIndex`
   (`test/describe-index`) in `migration_testdb_helper.go`, which reports existence,
   uniqueness and the ordered key-column list from each engine's catalog. The 000024 test
   keeps its existence-only assertion and its own comments; only its per-dialect query block
   was removed, so there is one implementation of the introspection rather than two.

   Five things worth knowing, all contained inside these steps:

   1. **A control assertion was added that the plan did not list**, and it is the reason the
      "not unique" assertion means anything. Each catalog reports uniqueness differently and
      MySQL reports it *inverted* (`NON_UNIQUE` is 0 for a unique index), so a flag read
      backwards would make a wrongly-UNIQUE index pass as non-unique. The test therefore
      asserts first that `idx_refresh_token_jti`, which is UNIQUE on all four engines and
      present at 000024, reads as unique on the engine under test. Verified in the migrations,
      not only the snapshots: mssql/mysql/postgres declare it in `000001_initial_create`, and
      sqlite's `000011_ropc_refresh_token` recreates it during its table rebuild.
   2. **Uniqueness is normalized in SQL, not in Go.** The four catalogs disagree on polarity
      *and* on type (a PostgreSQL boolean, a SQL Server bit, a SQLite integer, a MySQL inverted
      integer), so every branch of `describeIndex` emits `'1'` or `'0'` and the Go side holds
      one meaning. This mirrors how `generationColumnShape000024` resolves the same problem
      for NOT NULL, which inverts between SQLite and SQL Server.
   3. **Both failure modes were executed, not assumed.** With the sqlite migration temporarily
      changed to `CREATE UNIQUE INDEX`, the test fails on the uniqueness assertion; with it
      pointed at `previous_refresh_token_jti`, it fails on the column-list assertion. The
      migration was restored afterwards. Without this, the two assertions the step exists for
      would have been unexecuted paths.
   4. **The MySQL snapshot takes an inline `KEY`, not a trailing `CREATE INDEX`.** Its
      `refresh_tokens` block already declares `idx_refresh_token_jti`,
      `fk_refresh_tokens_code`, `idx_refresh_tokens_user_id` and `idx_refresh_tokens_client_id`
      inline, so the new index is declared the same way. The other three snapshots append a
      `CREATE INDEX` to their trailing index block, and sqlite's block is backtick-quoted while
      postgres's is not. This is the divergence the step anticipated, landing in the snapshots
      rather than in the migrations.
   5. **The PostgreSQL branch bounds its key-column position by `indnkeyatts`**, added during
      review of this stage. `pg_index.indkey` holds INCLUDE columns after the key ones, so without the bound
      that branch would have reported payload columns as key columns, contradicting both
      `indexShape.Columns`'s stated contract and the mssql branch's `is_included_column` filter.
      It does not affect this stage's index, which has no INCLUDE columns, so it is hardening
      for later callers rather than a fix to a wrong result here.
   6. **Corrected during stage 2's review, after this stage was committed.** That comment
      originally used the bare word "ordinal", which Tailwind's scanner treats as a candidate
      for its `.ordinal` utility, so the next `build.sh` emitted 29 unrelated lines into
      `web/static/main.css`. Reported here first as pre-existing drift, which was wrong: this
      stage caused it. The word is now "position", and a rebuild leaves `main.css` clean. Worth
      knowing generally: Tailwind scans Go source in this repo, so a comment can change the
      generated stylesheet.

### Stage 2: the two new data-layer methods
Status: **Done**

Tests: data tier in the container for behaviour, host unit tests for compilation after the
mock regeneration.

1. Add `MarkRefreshTokenAsRevoked(tx, refreshTokenId) (bool, error)` to `commondb`, the
   `Database` interface next to `data/iface-mark-code-as-used`, and the four engine
   delegations. Status: **Done** (`data/mark-refresh-token-revoked`)
   Conditional `UPDATE ... SET revoked = true, updated_at = ? WHERE id = ? AND revoked =
   false`, returning `rowsAffected == 1`. Mirrors `data/mark-code-as-used` including its
   zero-id error guard. Writes only the two columns, so it cannot touch
   `auth_state_generation` at all. Independent of `data/update-refresh-token`, which
   already excludes that column through its `dont-update` tag rather than by its predicate.
2. Add `RevokeRefreshTokenFamily(tx, firstRefreshTokenJti) (int64, error)`.
   Status: **Done** (`data/revoke-refresh-token-family`, `data/iface-refresh-family`)
   `UPDATE ... SET revoked = true, updated_at = ? WHERE first_refresh_token_jti = ? AND
   revoked = false`, returning `RowsAffected`. Errors on an empty identifier. Per decision 7.
3. Regenerate `src/core/data/mocks/database_mock.go` from `src/core/.mockery.yaml`.
   Status: **Done**
   Not optional and not cosmetic: every package that constructs `mocks_data.Database` fails to
   compile against an interface with unimplemented methods. Verify by running the host unit
   tiers, which is what this step's "tests" are. Note this is **not** the only regeneration:
   stage 5 renames a third interface method and must regenerate again, since the mock produced
   here still carries `DeleteExpiredOrRevokedRefreshTokens`.
4. Extend `src/authserver/tests/data/refresh_token_test.go` with
   `TestMarkRefreshTokenAsRevoked`. Status: **Done** (`test/data-mark-refresh-revoked`)
   Modelled on `test/data-mark-code-as-used`.

   | Case | Expected | Why it fails for that reason |
   |---|---|---|
   | live row, first call | `true`, row now `revoked` | the only case where the predicate matches |
   | same row, second call | `false` | varies only the prior state; `revoked = false` no longer holds |
   | row revoked by another path first | `false` | same predicate miss, reached without this method having run |
   | non-existent id | `false`, **no error** | id predicate misses; distinguishes "not claimed" from "broken" |
   | id `0` | **error**, not `false` | the Go guard, not the SQL |

   The id-`0` row must assert an **error**. Executed: the bare SQL returns 0 rows for id 0, so
   an assertion of `false` would pass with the guard deleted and would be indistinguishable
   from the non-existent-id row. The guard is the only thing under test there.
5. Add `TestRevokeRefreshTokenFamily` to the same file. Status: **Done** (`test/data-revoke-family`)
   Fixtures follow `test/data-refresh-by-session` and `test/data-promote-generations`.

   | Case | Expected count | Pins |
   |---|---|---|
   | family with one retired parent and one live child | `1`, only the child flips | the core behaviour |
   | forked family, one parent and **two** live children | `2` | that containment covers the fork defect 1 produces |
   | family whose members are all revoked | `0` | decision 2's zero-count gate |
   | unknown family identifier | `0`, unrelated live row untouched | that the predicate is not a no-op match-all |
   | two families on one browser session, contain A | `1`, both of B's rows still live | **decision 3**, family scope not session scope |
   | ROPC family, `code_id` NULL throughout | `1` | **decision 3**, that no join is involved |
   | empty identifier | **error** | the guard |

   The empty-identifier row must assert an **error**, and this is the trap worth naming. No
   production row has an empty `first_refresh_token_jti`, so asserting "revokes nothing" would
   pass with the guard deleted: it would be the benign instance of the class. Confirmed against
   the implementation by deleting the guard and re-running: the statement revoked the seeded
   empty-family row and returned a nonzero count, which is what the guard exists to prevent.

   This table is the exhaustive owner of the family predicate's semantics. The handler tests in
   stages 3 and 4 are deliberately thin on it and assert only that the handler calls it and
   branches on the count.

   **What this tier cannot prove:** that anything calls either method, and that the three
   non-SQLite engines agree. The first is stages 3 and 4; the second is why this tier runs
   `--db all`.

   **As built.** Both methods in `commondb/refresh_token.go`, declared on the `Database`
   interface directly under `UpdateRefreshToken`, delegated by all four engine types, and
   the mock regenerated. Tests appended to `refresh_token_test.go`: the two flat tests
   listed above plus `TestMarkRefreshTokenAsRevoked_DoesNotClobberAuthStateGeneration`.

   Four things worth knowing, all contained inside these steps:

   1. **Both guards were verified by deleting them**, not by reading the code. With the
      id-zero guard removed, `MarkRefreshTokenAsRevoked(nil, 0)` returns `(false, nil)` and
      the test fails; with the empty-identifier guard removed,
      `RevokeRefreshTokenFamily(nil, "")` revoked the seeded row and returned a nonzero
      count, and both of that case's assertions fail. This is the check the plan called for
      on the empty-identifier row, since asserting "revokes nothing" there would have been
      the benign instance of the class. The guards were restored and the suite re-run.
   2. **A generation test was added that the plan did not list**,
      `TestMarkRefreshTokenAsRevoked_DoesNotClobberAuthStateGeneration`. It promotes a row to
      generation 5, claims it, and asserts the generation survived.
      It records an **independent** contract for the narrow writer, and review corrected the
      rationale first written here: rewriting the claim as `UpdateRefreshToken` with a stale
      model would **not** regress the column, because that path already excludes it through
      the field's `dont-update` tag, which
      `TestUpdateRefreshToken_DoesNotClobberAuthStateGeneration` already covers. The value of
      this test is that the guarantee then holds from the statement's own column list rather
      than from a struct tag a future full-row writer might not honour. The same false
      rationale appeared in the method's doc comment, the test's doc comment and section 4,
      and was corrected in all three.
   3. **`TestRevokeRefreshTokenFamily` uses subtests**, one per row of the table, because
      each case needs its own client, user, code and family and the shared test database is
      not reset between them. `refresh_token_test.go` had no subtests before; the package
      does use them (`unknown_id_test.go`, `load_helpers_test.go`).
   4. **Two fixture helpers were needed.** `seedFamilyToken` takes a `familyTokenSpec` so a
      case can choose the family identifier, the linkage shape and the revoked state;
      `createTestRefreshToken` fixes all three and leaves `first_refresh_token_jti` empty.
      `seedCodeOnSession` exists because `createTestCode` generates its own session
      identifier, and the decision 3 case needs two codes deliberately sharing one.

### Stage 3: atomic single use (defect 1)
Status: **Done**

Tests: handler unit tests on the host, one integration test in the container.

1. Replace the read-then-write that followed `token/refresh-revoked-check` with a call to
   `MarkRefreshTokenAsRevoked`, rejecting on `!claimed` without any cascade.
   Status: **Done** (`token/refresh-claim`, `token/refresh-loser-no-cascade`)
   The in-memory `refreshToken.Revoked = true` assignment is dropped, not moved. Verified
   nothing downstream reads it. Comment per decision 9's wording.
2. Update the four refresh subtests inside `test/handler-refresh-subtests` that stub
   `UpdateRefreshToken`. Status: **Done**
   The update-error case, the issuer-error case, the session-bump case and the no-session case
   stub it and must stub `MarkRefreshTokenAsRevoked` instead. Verified:
   `grep -c 'database.On("UpdateRefreshToken"' src/authserver/internal/handlers/handler_token_test.go`
   returns 4. The already-revoked subtest is **not** among them, because it returns before the
   write; it changes in stage 4 instead, when the replay branch gains a containment call it
   must stub. Mechanical, but a missed site fails as an unexpected-call panic rather than a
   clear assertion.
3. Add a handler unit test for the lost claim. Status: **Done** (`test/handler-refresh-loser`)
   Modelled on `test/handler-concurrent-loser`: stub the CAS to return `(false, nil)` and
   assert `invalid_grant`, **no** call to `RevokeRefreshTokenFamily`, and **no** audit event.
   The two negative assertions are the test: without them it passes under a design that
   cascades on the lost claim, which is exactly the design decision 1 rejected.
4. Add `TestToken_Refresh_ConcurrentDoubleSpend_IssuesOnlyOnce` to a new
   `token_refresh_concurrent_test.go`. Status: **Done** (`test/refresh-concurrent`)
   Mirrors `test/authcode-concurrent` and reuses `test/concurrent-post-helper` unchanged.
   Asserts, across 8 racing presentations:
   - exactly **one** successful response;
   - every loser receives neither an `access_token` nor a `refresh_token`;
   - exactly **one** persisted child referencing the presented parent;
   - **at most one** live family member;
   - **no fork**: at most one row whose `previous_refresh_token_jti` equals the presented JTI,
     which is decision 6's check.

   "At most one live member" rather than "exactly one" is load-bearing, not slack. Under
   decision 9's strict policy a delayed duplicate whose lookup lands after the winner's claim
   takes the replay branch and revokes the winner's child, so the family legitimately ends with
   **zero or one** live member. Asserting exactly one would make the test fail on correct
   behaviour. **Keep this weaker assertion.**

   **What it cannot prove:** which branch a given loser took, and it must not claim to force
   either ordering. The unit tests deterministically pin both observable branch outcomes:
   stage 3 step 3 above covers a validation read of live followed by a lost claim, and stage 4
   step 3 covers a validation read of already revoked. They do not prove or force the
   inter-request ordering that produced either state.
5. Confirm `test/refresh-marked-used` and `ropc_flow_test.go` still pass unchanged.
   Status: **Done**
   Rotation behaviour is not meant to change. Note this proves nothing about the new
   concurrent behaviour, which did not exist before.

**As built.** The claim replaces the read-then-write in the handler's `refresh_token` case
(`token/refresh-claim`), with the loser branch and its recorded rationale at
`token/refresh-loser-no-cascade`. Four subtests restubbed, one new handler unit test
(`test/handler-refresh-loser`), one new integration file (`test/refresh-concurrent`).

Four things worth knowing, all contained inside these steps:

1. **The defect was reproduced before the fix was trusted.** With the handler temporarily
   reverted to the pre-fix read-then-write, the new integration test fails on three
   assertions at once against sqlite: **2** successful concurrent presentations, **2**
   children persisted from one parent, and **2** live family members. That is defect 1
   exactly as #128 describes it. The handler was restored and the tier re-run. Without this
   the test would only have been known to pass, not to bite.
2. **The lost-claim unit test's negative assertions were verified the same way.** With a
   `RevokeRefreshTokenFamily` call inserted into the `!claimed` branch, the test fails on an
   unexpected mock call. That is the design decision 1 rejected, so the assertion that would
   have to catch it does.
3. **The error-case subtest was renamed and its message changed.** "Refresh_token
   UpdateRefreshToken gives error" is now "Refresh_token MarkRefreshTokenAsRevoked gives
   error", and its fixture message went from "Failed to update refresh token" to "Failed to
   claim refresh token", since the `httpHelper` matcher asserts on that string and a stale
   one would describe a call the handler no longer makes.
4. **The stubs pin the id, not the type.** The four restubbed sites match
   `int64(1)` rather than `mock.AnythingOfType`, which the old full-row stub needed because
   it took a `*models.RefreshToken`. Matching the id means a claim on the wrong row fails
   as an unexpected call rather than passing.
5. **Two wording corrections from review, no behaviour change.** The `!claimed` rationale
   said refusing without a cascade is "correct in every one of those cases" because "a
   deleted row has no family left to contain". That is false: deletion is row-scoped and
   proves nothing about descendants. The real reason is ambiguity, since a false return
   cannot be told apart from the concurrent-rotation case whose child a cascade would
   destroy, and deletion-with-surviving-family is an accepted residual rather than an
   impossibility. Corrected in the handler comment (`token/refresh-loser-no-cascade`) and in
   section 4. Section 1 also gained a scoping note: it records the code at verification time
   and is not rewritten as stages land, with bracketed markers where implementation has since
   changed a claim. Its "five subtests stub UpdateRefreshToken" count, which finding 3 had
   corrected only in stage 3's step text, now reads four there too.

### Stage 4: replay containment and the audit event (defect 2)
Status: **Done**

Tests: handler unit tests on the host, integration tests in the container.

1. Add `AuditRefreshTokenReplayDetected` to `constants/authcode-reuse-event`'s block and to
   `constants/event-type-list`. Status: **Done** (`constants/replay-event`)
   Doc comment per decision 8, including that the event does not assert malicious intent.
2. Add the replay branch to the handler ahead of the claim.
   Status: **Done** (`token/replay-containment`, `token/replay-audit`)
   Calls `RevokeRefreshTokenFamily`, audits when the count is positive, debug-logs when it is
   zero with the neutral wording, and always responds `invalid_grant`. No explicit
   transaction: one statement, so its return is its commit.
3. Handler unit tests for the branch. Status: **Done** (`test/handler-replay-payload`)
   This is where the audit payload is asserted exactly, because the mock logger makes it
   exact and the integration tier cannot. Cases: positive count emits exactly one event with
   all six fields of decision 8 and a `revokedCount` equal to the stubbed return; zero count
   emits **no** event; a containment error emits no event and returns a 500; the payload
   carries neither the refresh token itself nor any JTI list; the auth-code and ROPC shapes
   produce the same field set.
4. Add `TestToken_Refresh_Replay_ContainsFamily` (integration). Status: **Done**
   Rotate RT1 to RT2 legitimately, then present RT1. Assert RT1 is refused with
   `invalid_grant`, and that RT2 is now revoked in the database. Pins the core of decision 1.
5. Add the family-scope boundary test (integration). Status: **Done** (`test/replay-family-scope`)
   Two clients on one browser session, each with its own family. Rotate and replay family A,
   then assert family B still rotates successfully **and** the browser session still works.
   This is the assertion that pins **decision 3**, and it is the only test that would fail if
   containment were widened to session scope.
   Ordering is load-bearing: family B must be exercised **after** the replay, not before, or
   it proves nothing about what containment did.
6. Add the ROPC containment test (integration). Status: **Done** (`test/replay-ropc`)
   The same replay shape on a ROPC family. This is where `first_refresh_token_jti` materially
   differs from `code_id`, per decision 3, so the auth-code test cannot stand in for it.
7. Add the repeat-replay test (integration). Status: **Done**
   Present RT1 a third time after containment. Assert `invalid_grant` and that no further row
   changes state. The absence of a second audit event is asserted in step 3, not here.

**As built.** The constant at `constants/replay-event`, the replay branch at
`token/replay-containment` and `token/replay-audit`, three unit tests
(`test/handler-replay-payload` plus a containment-error case and the restubbed
already-revoked subtest), and four integration tests in a new
`token_refresh_replay_test.go`.

Five things worth knowing, all contained inside these steps:

1. **Every integration case was mutation-tested, and the results were not all the same.**
   With containment removed entirely, all four fail, each on the assertion it exists for.
   Then, with containment widened to SESSION scope (the shape `revokeOnAuthCodeReuse` uses),
   `TestToken_Refresh_Replay_ContainsFamily` still **passes** and only
   `test/replay-family-scope` fails, on "family B shares the browser session but not the
   family" and then on family B failing to rotate. That confirms the plan's claim that the
   boundary test is the only one with discriminating power over decision 3, and it means the
   other three could not have caught a session-scoped implementation.
2. **The already-revoked subtest became the zero-count case.** It now stubs
   `RevokeRefreshTokenFamily` returning 0 and asserts no audit event, which gives decision
   2's gate a home in the existing suite. Its fixture also gained a non-empty family
   identifier, since an empty one is a data-layer error rather than a realistic row.
3. **A malformed row with an empty family identifier yields a 500, not `invalid_grant`.**
   `RevokeRefreshTokenFamily` errors on an empty identifier (decision 7) and the handler maps
   that to `InternalServerError`, which is what section 4's sketch specifies. No issuer path
   creates such a row: `issuer/refresh-family-carry` stamps either the parent's identifier or
   the new JTI on every insert, so this needs legacy or imported data, the same population
   decision 10 covers. Recorded rather than special-cased: failing loudly on corrupt data on
   a security path is preferable to silently treating it as a family of one.
4. **The audit event's flow discriminator reuses `validateResult.CodeEntity == nil`**, which
   is the same test the issuance path below it already uses to pick the ROPC branch. The
   principal fields then come from the loaded code on one shape and the refresh-token row on
   the other, so the payload's field set is identical either way. The unit test runs both
   shapes against one expected map, which is what pins that.
5. **The repeat-replay test asserts `updated_at`, not just `revoked`.** Both rows are already
   revoked, so a second containment matches nothing; had it matched, it would have bumped the
   timestamp. Asserting only `revoked` would pass even if the statement rewrote every row.
6. **Two wording corrections from review, no behaviour change.** The handler said a
   zero-count containment means "none of those is an incident", which does not follow: a
   repeated replay may well be malicious, it simply caused no new containment. It now says
   the gate exists to avoid duplicate and misattributed rows and log amplification, and
   explicitly does not classify the presentation as benign. Decision 8's naming rationale
   carried the same error about the compare-and-set loser and is corrected the same way.

### Stage 5: retention and error mapping
Status: **Not started**

Tests: data tier in the container, validator unit tests on the host, one integration test.

1. Change the sweep predicate and rename the method to `DeleteExpiredRefreshTokens`.
   Status: **Not started**
   The predicate becomes exactly `expires_at < now OR max_lifetime < now`, per decisions 4
   and 10. No third disjunct.
   The rename reaches the `Database` interface, `commondb`, the four engine wrappers and
   `worker/refresh-token-sweep`, and also these test files, which do not compile until they
   are updated:
   - `src/authserver/internal/workers/background_worker_test.go`, **15 sites** including
     `AssertNumberOfCalls` expectations that name the method as a string, so they fail at
     runtime rather than at compile time if missed;
   - `src/authserver/tests/data/code_test.go`, 1 site;
   - `src/authserver/tests/data/refresh_token_test.go`, 2 sites, rewritten by step 2 anyway.

   Counts reproduce with
   `grep -rn DeleteExpiredOrRevokedRefreshTokens --include=*.go src/`.
2. Regenerate `src/core/data/mocks/database_mock.go` a second time.
   Status: **Not started**
   Stage 2's regeneration predates this rename, so the mock still carries the old method name.
   Skipping this leaves `background_worker_test.go`'s string-named expectations matching a
   method the interface no longer has.
3. Rewrite `TestDeleteExpiredOrRevokedRefreshTokens` as `TestDeleteExpiredRefreshTokens`.
   Status: **Not started**

   | Row | Today | After | Note |
   |---|---|---|---|
   | revoked, `expires_at` future | deleted | **retained** | **keep this**: it reverses the current behaviour and is the whole of decision 4 |
   | revoked, `expires_at` past | deleted | deleted | |
   | revoked, `expires_at` future, `max_lifetime` past | deleted | deleted | the offline branch of the predicate |
   | live, `expires_at` past | deleted | deleted | unchanged |
   | live, `expires_at` future | retained | retained | unchanged |
   | live, `expires_at` future, `max_lifetime` NULL | retained | retained | that `NULL < now` does not delete a session-bound row |
   | live, `expires_at` past, `max_lifetime` NULL | deleted | deleted | the same asymmetry in the other direction |
   | revoked, both timestamps NULL | deleted | **retained** | **keep this**: reverses today's behaviour and pins **decision 10** |

   All eight executed. The last row is the finding that produced decision 10: it survived five
   consecutive sweeps under the new predicate, which is now the intended behaviour rather than
   a defect. It reverses today's behaviour in the same way the first row does, so neither
   should be "corrected" back.
4. Map `validator/refresh-missing-row` to an `ErrorDetail` with `invalid_grant` and a 400.
   Status: **Not started**
   Generic message, not revealing whether a row existed.
5. Update the validator unit test asserting the old error string. Status: **Not started**
   `token_validator_test.go` asserts the old text through `err.Error()`. It pins behaviour
   this change reverses, so it is updated deliberately, not deleted as noise.
6. Add an integration case for a signed, unexpired token with no row. Status: **Not started**
   Delete the row directly, then present the token. Assert **400 `invalid_grant`**, not 500.
   Deleting the row rather than waiting for a sweep is deliberate: after step 1 no sweep would
   remove an unexpired row, so the only way to reach this state in a test is to construct it.
7. Add a **validator unit test** proving the expiry check precedes the lookup.
   Status: **Not started**
   Present an expired refresh token and assert the request is refused **and** that
   `GetRefreshTokenByJti` was never called, using the mocked database. This is the case that
   bounds containment's horizon, per section 4.
   It lives at the unit tier deliberately: an integration test can observe only the HTTP
   response, which is identical whether or not the lookup ran, so it could never prove the
   ordering. An integration case would pass with the ordering reversed.

### Stage 6: documentation
Status: **Not started**

Tests: none. No tier covers prose. Verify with `npm run build` in `site/`.

1. Correct `docs/security-single-use`. Status: **Not started**
   "Each refresh token can only be used once" becomes true only after stage 3, so this is the
   sentence the change earns rather than one it breaks.
2. Correct `docs/tokens-chain-claim` and add the client contract. Status: **Not started**
   The existing "may invalidate the entire token chain" becomes accurate after stage 4. Add
   decision 9's contract explicitly: serialize refreshes, atomically replace the stored token
   from each successful response, and expect that parallel refreshes or a retry presenting a
   retired token can revoke the family and require fresh authorization. This is the
   user-visible consequence of the strict policy and it must not live only in this document.
3. Document the retention cost from decision 4. Status: **Not started**
   Revoked rows are retained until token expiry, so `refresh_tokens` grows with refresh
   frequency and the configured offline idle timeout. Operator-facing, with the default
   30-day timeout named.

## 6. Plan review findings

1. **The concurrent integration test cannot require exactly one live family member.** Round 1.
   Status: **Resolved**

   Correct, and it would have failed on correct behaviour. Under decision 9's strict policy the
   winner inserts one child and a delayed duplicate may then revoke it, so the family
   legitimately ends with zero or one live member. Stage 3 step 4 now asserts exactly one
   successful response, exactly one persisted child referencing the presented parent, **at most
   one** live family member, and no fork. The weaker assertion is marked "keep this" so it is
   not tightened back.

2. **Decision 10 should retain the malformed row, not reap it.** Round 1.
   Status: **Resolved**

   Accepted, and it reverses the recommendation I made. The argument that settles it: a revoked
   row is not disposable merely because it is no longer a live grant, it **is** the
   replay-detection signal, and a signed token whose imported row has NULL expiry columns can
   still carry an unexpired `exp`. Deleting it recreates the exact defect decision 4 exists to
   fix. There is also no principled deletion time available, since the row lacks the
   information to compute one, and `DeleteExpiredRefreshTokens` would be deleting rows not
   known to be expired. Decision 10 is now `Decided` as retain-and-pin. Stage 5 step 1's
   predicate loses the third disjunct, and the last row of stage 5 step 3's table flips from
   "deleted" to "retained" and is marked "keep this".

3. **Stage 3 step 2 said five subtests stub `UpdateRefreshToken`; there are four.** Round 1.
   Status: **Resolved**

   Verified:
   `grep -c 'database.On("UpdateRefreshToken"' src/authserver/internal/handlers/handler_token_test.go`
   returns 4. The already-revoked subtest returns before the write and never stubs it. The step
   now names four and records that the already-revoked subtest changes in stage 4 instead, when
   the replay branch gains a containment call it must stub.

4. **The cleanup rename also breaks `code_test.go` and `background_worker_test.go`.** Round 1.
   Status: **Resolved**

   Verified with `grep -rn DeleteExpiredOrRevokedRefreshTokens --include=*.go src/`: 15 sites in
   `background_worker_test.go`, 1 in `code_test.go`, 2 in `refresh_token_test.go`. Stage 5 step
   1 now lists all three files with counts, and flags that
   `background_worker_test.go`'s `AssertNumberOfCalls` expectations name the method as a
   **string**, so those fail at runtime rather than at compile time if missed.

5. **The mock must be regenerated again in stage 5.** Round 1. Status: **Resolved**

   Correct: stage 2's regeneration predates the rename, so the generated mock still carries
   `DeleteExpiredOrRevokedRefreshTokens`. Added as stage 5 step 2, with a back-reference from
   stage 2 step 3 so the first regeneration does not read as the only one.

6. **The expired-token integration case cannot prove the lookup was never called.** Round 1.
   Status: **Resolved**

   Correct, and the case as written would have passed with the ordering reversed, since the
   HTTP response is identical either way. It is now a validator unit test asserting both the
   refusal and that `GetRefreshTokenByJti` was never called on the mocked database, with a note
   saying why it cannot live at the integration tier. The missing-row integration case, which
   asserts 400 `invalid_grant` rather than 500, is unaffected and stays.

7. **Decision 9's two orderings must map to specific tests, and the concurrency test must not
   claim to force either.** Round 1. Status: **Resolved**

   Stage 3 step 4 now states that it cannot prove which branch a loser took and must not claim
   to force an ordering. The unit tests pin the two observable branch outcomes deterministically
   instead: stage 3 step 3 covers a validation read of live followed by a lost claim, and stage
   4 step 3 covers a validation read of already revoked. They do not prove or force the
   inter-request ordering that produced either state, which no mocked unit test could.

8. **The unit tests pin handler states, not inter-request orderings, and the cross-reference
   pointed the wrong way.** Round 2. Status: **Resolved**

   Correct on both counts. A mocked unit test fixes the persisted state the handler reads and
   asserts the resulting branch; it cannot establish the concurrent ordering that would produce
   that state in production. Stage 3 step 4 and finding 7's resolution now both say the unit
   tests deterministically pin the two observable branch outcomes and explicitly disclaim
   proving the ordering. "step 3 below" is corrected to "stage 3 step 3 above".
