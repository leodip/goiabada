# Issue 129: ending a user session does not durably cut off access

**Issue:** [#129](https://github.com/leodip/goiabada/issues/129)
**Issue state:** open (labels: bug, security)
**Written:** 2026-08-04
**Last synced:** 2026-08-04 (issue has zero comments; body is the whole specification)
**Agreement sealed:** 2026-08-04, amended 2026-08-04 on a reconciliation pass, still sealed
**Run state:** in progress, started 2026-08-04. Stages 1 to 4 done, so the behaviour change has landed.
Stage 5, the `/auth/completed` gate, is next and is still a sketch.
**PR:** [#138](https://github.com/leodip/goiabada/pull/138) (draft)

**Related:** #106 (closed) built the per-user generation boundary and the revocation helper this
work sits next to. #128 (closed) built the atomic refresh claim and family containment. #77
(closed) built the atomic code claim. #127 (closed, not planned) proposed a grant entity. #130
(open) owns the used-code cleanup NULL bug this issue's body flagged. #131 and #132 (open) are
residuals of #106 and #128 in the same code. #109 (open) owns the RP-initiated logout surface this
work deliberately does not touch, per decision 13. #133, #135 and #137 (open) were filed out of an
earlier, discarded attempt at this issue and cite decision numbers from a document that no longer
exists; see "Prior attempt" below. #134 came from that attempt too and was **closed as not planned**
on 2026-08-04, because it tracked the retention of a terminated-session registry and decision 4
builds none. None of them blocks this work.

**Amended after sealing.** Sections 1 to 5 are meant to be frozen at the seal, so the edits of
2026-08-04 are recorded rather than absorbed. The skill's references gained a four-surface
documentation sweep and a follow-ups section after this document was written, and running both found
work the first pass missed: a falsified sentence in `concepts/tokens.mdx`, three confirmation modals
whose copy is now incomplete (decision 14), and the fact that interactive logout writes nothing to
the database (decision 13). Section 2 gained `Documentation owed` and a sixth goal, section 9 is new,
sections 0, 1, 3 and 5 carry marked corrections, and no sealed decision was reversed. The seal holds
because section 3 still has zero `Open` items.

**Prior attempt.** An earlier `/leo-spec` plus `/leo-run` cycle for #129 reached stage 4 and was
discarded by `git reset --hard origin/main` on 2026-08-04. The user chose to start over from zero.
That document, its 14 decisions and its 7 stages are deliberately **not** consulted here, and every
claim below is re-derived from the code as it stands on `main` at `f8d093f`. The four issues filed
out of that attempt survive it, but their `decision N` citations point at numbering that no longer
exists and will need reconciling against this document's section 3.

---

## 0. Code anchors

| Label | File | Function | Locate by | Note |
|---|---|---|---|---|
| `admin/session-delete` | `src/authserver/internal/handlers/apihandlers/handler_api_users_sessions.go` | `HandleAPIUserSessionDelete` | `result, err := handlers.TerminateUserSessionTx(database, userSession)` | termination site 1. **Locator re-swept by stage 4**, which is what replaced the bare delete this row used to cite |
| `account/session-delete` | `src/authserver/internal/handlers/apihandlers/handler_api_account_sessions.go` | `HandleAPIAccountSessionDelete` | `result, err := handlers.TerminateUserSessionTx(database, us)` | termination site 2, ownership checked. **Locator re-swept by stage 4**, same reason |
| `logout/last-client-delete` | `src/authserver/internal/handlers/handler_account_logout.go` | `handleExistingSessionOnLogout` | `if len(userSession.Clients) == 1 {` | termination site 3, deletes the session only when the last client logs out |
| `logout/basic-post-fork` | `src/authserver/internal/handlers/handler_account_logout.go` | `HandleAccountLogoutPost` | `if hint := httpHelper.GetFromUrlQueryOrFormPost(r, "id_token_hint"); len(hint) > 0 {` | without a hint the handler clears the cookie and writes nothing to the database |
| `catalog/end-session-modal` | `src/core/i18n/catalogs/active.en.toml` | `n/a` | `adminconsole.account.sessions.modal_confirm_body_prefix` | one of three end-session modals; decision 14 adds a key beside each |
| `completed/start-new-session` | `src/authserver/internal/handlers/handler_auth_completed.go` | `HandleAuthCompletedGet` | `newSession, err := userSessionManager.StartNewUserSession(` | gap 3: reached unconditionally, no proof anyone authenticated |
| `completed/really-authenticated` | `src/authserver/internal/handlers/handler_auth_completed.go` | `HandleAuthCompletedGet` | `userReallyAuthenticated := authContext.AuthenticatedAt != nil` | computed, then read only inside the valid-session branch |
| `completed/set-acr-level` | `src/authserver/internal/handlers/handler_auth_completed.go` | `HandleAuthCompletedGet` | `err = authContext.SetAcrLevel(targetAcrLevel, userSession)` | runs after the branch, on the ambient session, whoever it belongs to |
| `issue/sid-from-context` | `src/authserver/internal/handlers/handler_auth_issue.go` | `HandleIssueGet` | `sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)` | the sid stamped on the code comes from the cookie, not the AuthContext |
| `issue/create-code` | `src/authserver/internal/handlers/handler_auth_issue.go` | `HandleIssueGet` | `code, err := codeIssuer.CreateAuthCode(createCodeInput)` | the insert gap 3 has to stop; no session lookup precedes it |
| `pwd/authenticated-at` | `src/authserver/internal/handlers/handler_auth_pwd.go` | `HandleAuthPwdPost` | `authContext.AuthenticatedAt = &utcNow` | the only writer on the level 1 path, so the discriminator for gap 3 |
| `authorize/prompt-login` | `src/authserver/internal/handlers/handler_authorize.go` | `HandleAuthorizeGet` | `if authContext.HasPromptValue("login") {` | returns before the session lookup, leaving the cookie session live (#133) |
| `authorize/hint-mismatch` | `src/authserver/internal/handlers/handler_authorize.go` | `HandleAuthorizeGet` | `if authContext.IdTokenHintSub != "" && userSession.User.Subject.String() != authContext.IdTokenHintSub {` | second entry to the same defect, from inside the valid-session block |
| `authorize/sso-reuse` | `src/authserver/internal/handlers/handler_authorize.go` | `HandleAuthorizeGet` | `authContext.AuthState = oauth.AuthStateLevel1ExistingSession` | the SSO path that never sets `AuthenticatedAt` |
| `authcontext/generation` | `src/core/oauth/auth_context.go` | `n/a` | `AuthStateGeneration int64` | the AuthContext carries no session identifier of its own |
| `sessionmgr/start-new` | `src/core/user/usersession_manager.go` | `StartNewUserSession` | `sess.Values[constants.SessionKeySessionIdentifier] = userSession.SessionIdentifier` | rewrites the cookie, so `/auth/issue` sees the replacement sid |
| `sessionmgr/bump-no-userid` | `src/core/user/usersession_manager.go` | `BumpUserSession` | `if authMethods != "" && authMethods != userSession.AuthMethods {` | assigns methods and ACR, never `UserId` (#133 consequence 2) |
| `issuer/grant-is-offline` | `src/core/oauth/token_issuer.go` | `grantIsOffline` | `func grantIsOffline(authorizedScope string, sessionIdentifier string) bool {` | an empty sid alone makes a grant offline |
| `issuer/refresh-type-branch` | `src/core/oauth/token_issuer.go` | `generateRefreshToken` | `if grantIsOffline(scope, code.SessionIdentifier) {` | Offline stores a max lifetime, Refresh stores the sid, never both |
| `issuer/store-sid` | `src/core/oauth/token_issuer.go` | `generateRefreshToken` | `refreshTokenEntity.SessionIdentifier = claims["sid"].(string)` | so an offline token's own `session_identifier` is empty |
| `issuer/create-refresh-token` | `src/core/oauth/token_issuer.go` | `generateRefreshToken` | `err := t.database.CreateRefreshToken(nil, refreshTokenEntity)` | gap 2: the child insert, outside any transaction |
| `issuer/suppress-sid-claim` | `src/core/oauth/token_issuer.go` | `generateAccessTokenCore` | `if len(input.SessionIdentifier) > 0 && !input.GrantIsOffline {` | an offline grant's ACCESS token carries no sid either |
| `validator/authcode-preauth` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `if !wasReused {` | user, generation and expiry checks, all ahead of client auth (#137) |
| `validator/code-generation` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `if codeEntity.AuthStateGeneration != codeEntity.User.AuthStateGeneration {` | #106's redemption gate, the precedent for a code-level marker |
| `validator/session-branch` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `case "Refresh":` | already fails once the session row is gone |
| `validator/offline-branch` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `case "Offline":` | checks only the max lifetime, never the session |
| `validator/refresh-generation` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `if refreshToken.AuthStateGeneration != refreshToken.Code.User.AuthStateGeneration {` | sits ahead of the client-ownership check below it |
| `validator/client-ownership` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `if tokenClientId != client.Id {` | the ownership gate a new refresh check should sit behind |
| `db/refresh-by-sid` | `src/core/data/commondb/refresh_token.go` | `GetRefreshTokensBySessionIdentifier` | `selectBuilder.JoinWithOption(sqlbuilder.InnerJoin, "codes", "codes.id = refresh_tokens.code_id")` | joins through `codes`, so it does reach offline tokens |
| `db/mark-code-used` | `src/core/data/commondb/code.go` | `MarkCodeAsUsed` | `ub.Equal("used", false),` | the compare-and-set predicate, no revoked term today |
| `db/delete-used-codes` | `src/core/data/commondb/code.go` | `DeleteUsedCodesWithoutRefreshTokens` | `deleteBuilder.Equal("used", true),` | reaps used codes only; #130 owns its NULL bug |
| `revoke/refresh-tokens` | `src/authserver/internal/handlers/revocation.go` | `revokeRefreshTokens` | `if err := db.UpdateRefreshToken(tx, rt); err != nil {` | #106's helper, read-modify-write rather than compare-and-set |
| `middleware/session-check` | `src/authserver/internal/middleware/api_auth.go` | `RequireValidSession` | `session, err := database.GetUserSessionBySessionIdentifier(nil, sid)` | reached only when the token carries a sid |
| `worker/perform-task` | `src/authserver/internal/workers/background_worker.go` | `performTask` | `func (w *Worker) performTask(ctx context.Context) {` | where any reaper for new durable state would go |
| `schema/user-sessions` | `src/core/data/sqlitedb/schema.sql` | `n/a` | `CREATE TABLE user_sessions (` | documentation snapshot, not loaded by Go |
| `test/fresh-ceremony-after-delete` | `src/authserver/tests/integration/session_deletion_test.go` | `TestSessionDeletedDuringAuthFlow_LoginSucceeds` | `assert.Equal(t, 1, len(userSessions2), "Should have a new session after second login")` | #46's regression guard; the case gap 3's fix must NOT break |
| `test/completed-new-session` | `src/authserver/internal/handlers/handler_auth_completed_test.go` | `TestHandleAuthCompletedGet` | `t.Run("Successful flow, new session, consent not required", func(t *testing.T) {` | one of three subtests reaching `StartNewUserSession` with a nil `AuthenticatedAt` |

Rows below this line were added **by the run**, for code the run created, so later stages and the run
log can cite it the same way. Nothing above the line changed.

| Label | File | Function | Locate by | Note |
|---|---|---|---|---|
| `model/code-revoked` | `src/core/models/code.go` | `n/a` | `// Revoked records that the session this code was issued through was explicitly` | stage 1, the marker field and its `dont-update` tag |
| `db/revoke-codes-by-sid` | `src/core/data/commondb/code.go` | `RevokeCodesBySessionIdentifier` | `ub.Equal("session_identifier", sessionIdentifier),` | stage 1, the termination sweep |
| `migration/000026` | `src/core/data/sqlitedb/migrations/000026_add_code_revoked.up.sql` | `n/a` | `ALTER TABLE codes ADD COLUMN revoked numeric NOT NULL DEFAULT 0;` | stage 1, one of four engines |
| `test/revoke-codes-data` | `src/authserver/tests/data/code_test.go` | `TestRevokeCodesBySessionIdentifier` | `assertCodeRevoked(t, unrelated.Id, false, "a code of an unrelated session")` | stage 1, seam 1's negative control |
| `test/migration-000026` | `src/authserver/tests/data/migration_000026_code_revoked_test.go` | `TestMigration000026_CodeRevoked` | `require.NoError(t, h.Migrator.Migrate(25), "roll back 000026")` | stage 1, the down migration case |
| `validator/code-revoked` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `if codeEntity.Revoked {` | stage 2, the redemption rejection, behind client auth, PKCE and the reuse return |
| `validator/refresh-code-revoked` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `if !isROPCToken && refreshToken.Code.Revoked {` | stage 2, the refresh rejection, behind ownership and ahead of the `typ` switch, so it reaches Offline |
| `test/revoked-code-ordering` | `src/core/validators/token_validator_test.go` | `TestValidateTokenRequest_RevokedCode` | `ordering: a wrong client secret answers before the revoked check` | stage 2, the row the review's round 1 finding added |
| `audit/terminated-session` | `src/core/constants/constants.go` | `n/a` | `AuditTerminatedUserSession = "terminated_user_session"` | stage 3, decision 9's second event, emitted by stage 4 |
| `revoke/terminate-session` | `src/authserver/internal/handlers/revocation.go` | `TerminateUserSessionTx` | `revokedCodeCount, err := db.RevokeCodesBySessionIdentifier(tx, userSession.SessionIdentifier)` | stage 3, the first of decision 5's three writes and the only one that survives |
| `test/terminate-offline-token` | `src/authserver/internal/handlers/revocation_test.go` | `TestTerminateUserSessionTx_RevokesTheGrantsOfTheSession` | `the offline token of the terminated session must be revoked` | stage 3, decision 2's guard at this seam |
| `test/terminate-zero-result` | `src/authserver/internal/handlers/revocation_test.go` | `TestTerminateUserSessionTx_AnyFailureYieldsTheZeroResult` | `the count must not survive a rolled-back transaction` | stage 3, the keep-this row of the failure table |
| `revoke/log-terminated` | `src/authserver/internal/handlers/revocation.go` | `LogTerminatedUserSession` | `func LogTerminatedUserSession(auditLogger AuditLogger, userSession *models.UserSession,` | stage 4, decision 9's payload, one emitter for both endpoints |
| `catalog/modal-revocation-note` | `src/core/i18n/catalogs/active.en.toml` | `n/a` | `adminconsole.account.sessions.modal_revocation_note` | stage 4, one of decision 14's six keys |
| `test/terminate-endpoint-audit` | `src/authserver/internal/handlers/apihandlers/handler_api_users_sessions_test.go` | `TestHandleAPIUserSessionDelete_TerminatesAndAuditsBothEvents` | `assert.Len(t, terminatedPayload, 6)` | stage 4, decision 9's payload asserted field by field |
| `test/failure-suppresses-events` | `src/authserver/internal/handlers/apihandlers/handler_api_users_sessions_test.go` | `TestHandleAPIUserSessionDelete_TerminationFailureIsA500` | `is the case that decided this file had to` | stage 4, the contract no other tier can reach |
| `test/forbidden-does-not-terminate` | `src/authserver/internal/handlers/apihandlers/handler_api_account_sessions_test.go` | `TestHandleAPIAccountSessionDelete_ForbiddenDoesNotTerminate` | `func TestHandleAPIAccountSessionDelete_ForbiddenDoesNotTerminate(t *testing.T) {` | stage 4, ownership ahead of termination |
| `test/terminate-offline-endpoint` | `src/authserver/tests/integration/api_users_sessions_test.go` | `TestAPIUserSessionDelete_TerminatesTheOfflineGrantsOfThatSession` | `THE SURVIVOR IS THE HALF THAT CARRIES THIS TEST` | stage 4, seam 8's headline claim and its same-user control |
| `test/second-offline-grant` | `src/authserver/tests/integration/credential_change_revocation_test.go` | `secondOfflineGrantForSameUser` | `func secondOfflineGrantForSameUser(t *testing.T, base *offlineGrant, password string) *offlineGrant {` | stage 4, the one new harness helper |
| `test/logout-revokes-nothing` | `src/authserver/tests/integration/api_account_logout_request_test.go` | `TestLogout_WithIdTokenHint_RevokesNoGrants` | `logout must revoke nothing, decision 3` | stage 4, decision 3 pinned |

Counts in this document carry their command:

- 3 termination sites (`admin/session-delete`, `account/session-delete`, `logout/last-client-delete`),
  the third reachable only with an `id_token_hint`, per the correction in section 1.
- 3 admin console pages end sessions, through 2 API endpoints
  (`grep -c 'http.NewRequest("DELETE"' src/adminconsole/internal/apiclient/user_session_client.go`
  returns 3, of which `DeleteUserSessionById` and `DeleteAccountSession` are the session ones and
  `DeleteUserConsent` is not).
- 1263 keys in each catalog, at parity
  (`grep -c '^"' src/core/i18n/catalogs/active.en.toml src/core/i18n/catalogs/active.pt-BR.toml`).
- 3 subtests reach `StartNewUserSession`
  (`grep -c 'StartNewUserSession", rr, req' src/authserver/internal/handlers/handler_auth_completed_test.go`).
- Next free migration number is **000026** on all four engines
  (`for db in sqlitedb mysqldb postgresdb mssqldb; do ls src/core/data/$db/migrations | grep -o '^[0-9]*' | sort -u | tail -1; done`).

---

## 1. Context

### The three termination sites

All three reach `DeleteUserSession` and revoke nothing. Each passes `nil` for the transaction, so
none of them is a boundary against anything running concurrently.

| Site | What it does | Revokes tokens? |
|---|---|---|
| `DELETE /api/v1/admin/user-sessions/{id}` (`admin/session-delete`) | deletes the `UserSession` | no |
| `DELETE /api/v1/account/sessions/{id}` (`account/session-delete`) | deletes the `UserSession`, ownership checked | no |
| `/auth/logout` **with an `id_token_hint`** (`logout/last-client-delete`) | deletes one `UserSessionClient`, and the `UserSession` when it was the only one | no |

The logout case is per-client and only incidentally ends a session. The predicate is
`len(userSession.Clients) == 1`, evaluated after the client row is deleted, so the session dies
exactly when the departing client was the sole one on it.

Above them sit three admin console pages, all funnelling into the two API endpoints rather than
adding a fourth site: the account sessions page through `DeleteAccountSession`, and both the admin
users and admin clients session pages through `DeleteUserSessionById`. Those are the only two
`DELETE` methods in `apiclient/user_session_client.go`
(`grep -c 'http.NewRequest("DELETE"' src/adminconsole/internal/apiclient/user_session_client.go`
returns 3, the third being `DeleteUserConsent`). Decision 14 owns their copy.

> **Correction, made on the reconciliation pass of 2026-08-04.** The table above originally listed
> the logout site as `GET/POST /auth/logout` without qualification. That overstates it, and the real
> behaviour matters because decision 3 pins it with tests.
>
> `handleExistingSessionOnLogout` is reachable **only** through `doLogoutWithIdToken`, so only when
> an `id_token_hint` is supplied, and per #109 item 1 only when `post_logout_redirect_uri` is
> supplied too, since that parameter is wrongly treated as required and its check returns before the
> teardown. The ordinary interactive path does not reach it at all: `logout_consent.html` posts back
> with only a csrf field, so `HandleAccountLogoutPost` takes the no-hint branch at
> `logout/basic-post-fork`, clears the cookie, audits `AuditLogout`, redirects, and **writes nothing
> to the database**.
>
> So after an ordinary logout the `user_sessions` row survives with every client still attached.
> Session-bound refresh tokens keep working at `validator/session-branch`, access tokens keep passing
> `middleware/session-check`, and the row is orphaned from the browser, since the cookie no longer
> carries the sid. It still appears as an active session on the user's own sessions page, endable
> only by clicking "End session".
>
> Decision 13 records why this stays out of scope. It is drafted onto #109 in section 9, whose
> divergence B describes the same asymmetry one path over.

### Gap 1: an offline grant outlives its session

Session deletion already contains a **session-bound** refresh token. `validator/session-branch`
loads the session by identifier and rejects with `invalid_grant` when the row is missing.

It does not contain an **offline** one. `validator/offline-branch` checks only the
`offline_access_max_lifetime` claim and never consults the session. Offline refresh tokens also
carry no session identifier of their own: `issuer/refresh-type-branch` chooses one of two storage
shapes, and `issuer/store-sid` sets `session_identifier` on the Refresh branch only, so the Offline
branch leaves it empty and stores a `max_lifetime` instead.

So after "end session", a client holding an `offline_access` grant that was authorized through that
session keeps refreshing, bounded only by that grant's max lifetime.

The join that reaches those rows does exist. `db/refresh-by-sid` inner-joins `codes` on
`codes.id = refresh_tokens.code_id` and filters `codes.session_identifier`, and the **code** row
does carry the sid even for an offline grant, because `issuer/grant-is-offline` returns true from
the `offline_access` scope rather than from an empty sid. ROPC tokens have `code_id = NULL` and are
correctly excluded, having no session to belong to.

**Access tokens are affected too, and this is not in the issue body.** `issuer/suppress-sid-claim`
omits the `sid` claim for an offline grant. `middleware/session-check` reaches its session lookup
only for a token that has a sid, so an offline grant's access token is checked against the user's
generation instead. Session termination does not move that generation, and must not, so an offline
access token issued before termination stays acceptable at Goiabada's own endpoints until it
expires. Revoking refresh tokens alone leaves that window open.

### Gap 2: a concurrent refresh inserts a surviving replacement

Rotation claims the presented token and inserts its replacement as two separate commits.
`issuer/create-refresh-token` passes `nil` for the transaction. A refresh that validated before a
termination sweep therefore inserts its child after the sweep commits, and for an offline grant
nothing invalidates that child.

> **Correction to the issue body.** It describes rotation as marking the parent revoked with
> `UpdateRefreshToken(nil, ...)`. #128 replaced that with a compare-and-set,
> `MarkRefreshTokenAsRevoked`. The race the body describes survives the change, because it is the
> child *insert* that escapes, not the parent claim, but the citation is stale.

`revoke/refresh-tokens` is #106's sweep helper and is a read-modify-write over rows it already
loaded, not a compare-and-set. It skips rows already marked revoked and reports only the JTIs it
transitioned, which is a contract #77's reuse cascade depends on.

**Gap 2 may cost nothing beyond gap 1, depending on decision 4.** The issue's sketch closes it with
a `codes.revoked` column plus an edit to `db/mark-code-used`. Verified that a cheaper route exists:

- A rotated child **inherits its parent's `code_id`**. `issuer/create-refresh-token` sets `CodeId`
  from the `code` it was handed, and on the refresh path that code is
  `validateResult.CodeEntity`, which the validator derives as `codeEntity = &refreshToken.Code`.
  So every descendant of a grant points at the same `codes` row.
- The refresh validator therefore **already holds the originating session identifier** for every
  auth-code-derived refresh token, offline ones included, as `refreshToken.Code.SessionIdentifier`.
  No new join and no new column are required to read it.

A refresh-path check keyed on that value rejects every present *and future* descendant of the
grant, because the racing child inherits the same code and so the same sid. Under a design that
marks the *session* rather than the *rows*, gap 2 closes as a consequence of gap 1's check rather
than as separate work, and `db/mark-code-used` needs no edit. This is a claim about the refresh
path only; an unredeemed code still needs its own gate, which is decision 7.

### Gap 3: an in-flight ceremony recreates the session

Verified sequence, and the reason a marker on existing rows is not by itself a boundary.

1. An SSO ceremony validates session S at `authorize/sso-reuse`, copies its `UserId`, `AcrLevel`,
   `AuthMethods` and `AuthStateGeneration` onto the AuthContext, and proceeds. It never reaches the
   password handler, so `AuthenticatedAt` stays nil.
2. "End session" deletes S.
3. The ceremony resumes at `/auth/completed`.
4. `HandleAuthCompletedGet` finds no valid session and takes the else branch, which calls
   `completed/start-new-session` **unconditionally**, from `authContext.UserId`, with no requirement
   that anyone authenticated. `completed/really-authenticated` computes the very fact that would
   distinguish the two cases and is consulted only inside the *valid session* branch, to refresh
   `AuthTime`.
5. `sessionmgr/start-new` writes the replacement session's identifier into the cookie.
6. `/auth/issue` reads the sid from the request context at `issue/sid-from-context`, which is now
   the replacement, and `issue/create-code` inserts a fresh, unmarked code.
7. Nothing rejects it. The code is new, so no marker on old rows applies, and the user's generation
   never moved.

The consent screen delays code insertion the same way, widening the window from milliseconds to
however long a person takes to click.

**The AuthContext carries no session identifier.** `authcontext/generation` is the neighbouring
field; there is no sid field beside it. The ceremony's originating session is knowable only from
the cookie, and the cookie is rewritten in step 5. Nothing durable ties the code issued in step 6
back to the session that was terminated in step 2.

> **Departure from the issue body.** It calls the fix "almost certainly: fail and force
> re-authentication". Verification says the predicate cannot be "no valid session", because
> `test/fresh-ceremony-after-delete` covers a legitimate case with exactly that shape: session
> deleted, then a **new** ceremony in which the user really does enter a password, which must keep
> succeeding. That is #46's regression guard. The discriminator that separates the two is whether
> *this ceremony* performed level 1 authentication, which is what
> `completed/really-authenticated` already computes and `pwd/authenticated-at` is the only level 1
> writer of.

### Costs already visible in the tests

Three subtests in `test/completed-new-session`'s file drive the else branch with a nil
`AuthenticatedAt` and assert `StartNewUserSession` is called. Any gate on
`completed/really-authenticated` breaks all three, so the gap 3 work is **not** additive at the
unit tier.

### What #106 already built, and why it does not extend

#106 added a per-user `auth_state_generation`, checked at `validator/code-generation`,
`validator/refresh-generation` and `middleware/session-check`, plus `RevokeUserAuthState` and
`revoke/refresh-tokens` in `revocation.go`. The generation is the part that survives a race,
precisely because a rotated child inherits its parent's generation rather than the user's current
value.

It cannot be reused here. Incrementing a user-wide counter to sign out one device invalidates every
other device that user has, which is the opposite of what the action means. The sweep helper is
reusable; the boundary is not.

### The pre-authentication oracle in the same block

`validator/authcode-preauth` runs the user-enabled check, the generation check and the expiry check
**before** client-secret validation and before PKCE. So a presenter holding a stolen code learns
whether the account's generation moved without proving anything. This is live today and #137 owns
it. It matters here because a new redemption check placed in that block inherits the same leak.

On the refresh path, `validator/refresh-generation` likewise sits ahead of
`validator/client-ownership`.

### Test landscape

- **Style.** `testify/assert` throughout, `t.Run` subtests rather than table structs in the handler
  tests, `mockery` mocks under `src/core/data/mocks` and `mocks_*` packages.
- **Unit.** `handler_auth_completed_test.go` is a single `TestHandleAuthCompletedGet` with 10
  subtests. `token_validator_test.go` is 33 tests over 5168 lines. `revocation_test.go` has 8.
- **No unit tests exist for either session-delete endpoint.** Neither
  `handler_api_users_sessions_test.go` nor `handler_api_account_sessions_test.go` exists. Absent
  infrastructure, so whichever stage touches those handlers creates the file.
- **Data.** `src/authserver/tests/data/` runs all four engines and holds per-migration tests
  (`migration_000024_auth_state_generation_test.go`, `migration_000025_family_index_test.go`) as the
  precedent for a new migration.
- **Integration.** `session_deletion_test.go` (the #46 guard), `session_bearer_revocation_test.go`
  (3 tests pinning that a deleted session rejects bearer tokens),
  `token_refresh_concurrent_test.go` and `token_authcode_concurrent_test.go` (the double-spend
  harness a gap 2 test would mirror), `api_users_sessions_test.go`, `api_account_sessions_test.go`,
  `authorize_existing_session_test.go`.

### Documentation

`concepts/user-sessions.mdx` documents credential changes and live sessions for #106 and says
nothing about explicit termination. `integration/rest-api.mdx` describes the admin endpoint as
"Terminates a user session by ID" and the account one as "Terminate session", with no claim about
tokens. The word "terminates" currently overpromises, and the gap that makes it overpromise is what
this issue closes.

The falsified sentence is in `concepts/tokens.mdx`, under offline refresh tokens: "Offline refresh
tokens are not linked to a user session", and further down, an offline token "keeps working after the
browser session that created it has gone". Both stay true of a session **expiring**, which is the
feature per decision 2, and both become false of an explicit termination. Section 2 lists what each
page owes.

> **Correction, made on the reconciliation pass of 2026-08-04.** This subsection previously concluded
> "Nothing in the docs is falsified by this change". That was wrong on `concepts/tokens.mdx` above,
> and it rested on a sweep of one surface. The message catalogs and the templates were never searched,
> and they carry three "End session" confirmation modals whose copy this change makes incomplete,
> which is now decision 14. The four-surface sweep is the one in the skill's documentation reference;
> the earlier pass did not run it.

### Failure direction

Every gap here **fails open**: it preserves access that an operator or user believed they had
removed. That is the opposite of #131's residual, which its own body calls fail-closed. It is the
argument against deferring any of the three on grounds of window size, since the window is
attacker-influenceable: a holder of a stolen offline refresh token can rotate in a loop while
termination is attempted.

---

## 2. Goal

1. Ending a session at an explicit "end this session" endpoint durably cuts off the grants that
   session authorized, including offline ones, and cannot be undone by anything already in flight.
2. A ceremony whose originating session was terminated mid-flight cannot complete into a usable
   authorization code, while a ceremony in which the user actually authenticated still succeeds.
3. A refresh racing a termination cannot leave a usable descendant.
4. Whatever durable state is introduced has a stated retention position, whether that is a reaper
   or a defended decision to keep the rows.
5. The behaviour of ordinary RP-initiated logout is a recorded decision rather than an accident.
6. Someone about to end a session is told, at the point of clicking, that it disconnects the
   applications that session authorized, in both locales.

### Out of scope

- **#130**, the `DeleteUsedCodesWithoutRefreshTokens` NULL bug. Live today, already filed,
  independent of this change unless a decision here edits that predicate.
- **#133**'s full remedy: the cross-user session binding defect, its
  browser-stays-signed-in-as-A consequence, the `completed/set-acr-level` leak and its test
  coverage. Whether this issue implements the one-line guard is decision 10.
- **#137**, moving the pre-existing generation and disabled-user checks behind client
  authentication. Decision 7 covers only where a *new* check goes.
- **#131** and **#132**, the rotation coordination residuals of #106 and #128.
- **#135**, client-scoped "disconnect this application" revocation.
- Third-party resource servers accepting an already-issued access token by signature alone. Inherent
  to stateless tokens and already documented.
- Reaping anything that exists today. `user_sessions` and its two existing reapers are untouched.
- **#109**, the RP-initiated logout surface: the wrongly required `post_logout_redirect_uri`, the
  URL construction, the non-standard `sid`, and its divergence B on the cookie-versus-database
  asymmetry. Also the interactive logout path that writes nothing to the database at all, per
  decision 13, which section 9 drafts onto #109.

  **Not a landing-order constraint, and this is worth stating because it looks like one.** #109 and
  #129 touch the same file, `handler_account_logout.go`, and nothing else. #129 does not modify that
  file: decision 3 leaves logout unchanged, and its only presence there is the pinning tests at seam
  9. Those pin behaviour #109 will deliberately change, so they must drive logout through request
  shapes #109 is not rewriting, which seam 9 now spells out. Either issue can land first.

### Documentation owed

From the four-surface sweep. Each item names the behaviour that falsifies it rather than a stage
number, because section 6 does not exist yet; the plan attaches each to the stage that changes the
behaviour, never to a tidy-up stage at the end.

- **`concepts/tokens.mdx`, offline refresh tokens.** Says offline tokens "are not linked to a user
  session" and that one "keeps working after the browser session that created it has gone".
  Falsified by decision 2. The distinction to draw is the one decision 4 rests on: a session
  **expiring** still leaves an offline grant working, a session **explicitly ended** does not.
- **`concepts/user-sessions.mdx`.** Has no section on ending a session. Needs a new one, next to
  "Credential changes and live sessions", covering what the two endpoints now revoke (decision 2),
  that an in-flight ceremony cannot recreate the session (decision 6), and the limit from decision
  11: an access token already issued for an offline grant keeps working until it expires, because it
  carries no `sid` for `middleware/session-check` to check. Without that last sentence a reader
  generalizes the credential-change bullet, "Goiabada's own endpoints reject a token from a
  superseded session on the very next request", to termination, and is wrong.
- **`integration/rest-api.mdx`, both endpoints.** "Terminates a user session by ID" and the bare
  "Terminate session" heading. Each gains a sentence on what termination revokes, linking to the new
  concepts section.
- **`reference/security.mdx`, "Authentication security".** Its "Session management" bullet covers
  only configurable timeouts. Gains a durable-termination bullet in the shape of the existing
  "Replay containment" one, which is the precedent for how a security property gets summarized here.
- **Message catalogs, both.** Three new keys in `active.en.toml` and three in `active.pt-BR.toml`,
  per decision 14, plus a line in each of the three templates it names.

Verified as owing nothing, stated because silence reads the same as forgetting:

- **`concepts/audit-log.mdx`.** Does not enumerate event identifiers, it points at
  `src/core/constants/constants.go`. So decision 9's second event falsifies no page.
- **`integration/endpoints.mdx`, `/auth/logout`.** Decision 3 leaves logout unchanged, and decision
  13 leaves the interactive path's defect to #109. The page's description stays accurate, including
  "Immediately logs out the user", which describes the cookie effect it always described.
- **`CLAUDE.md` and `AGENTS.md`.** Byte identical (`diff AGENTS.md CLAUDE.md`, empty). Neither
  enumerates migrations, the `codes` table, nor the test tiers this change adds to, so migration
  000026 and `codes.revoked` owe them nothing. Any future edit goes to both.

---

## 3. Open questions and decisions

Fourteen items. Opened at eleven; decision 4's reversal onto a code-level marker exposed a residual
at `/auth/issue` that the registry design did not have, which is item 12. The reconciliation pass of
2026-08-04 added two more: tracing which endpoints the "End session" buttons reach found that
interactive logout writes nothing to the database (item 13), and the four-surface documentation sweep
found three confirmation modals whose copy this change makes incomplete (item 14). Numbers are never
reused, and decision 4 records its own reversal rather than being rewritten silently.

1. **All three gaps land in #129, with gap 2 staged last.** Status: **Decided** Raised by: user

   The issue does not close until the concurrency window is shut. Gaps 1 and 3 are implemented and
   reviewed as earlier stages, which is delivery sequencing rather than scope reduction.

   The deciding argument is that gap 2's marginal cost collapsed under verification. Because a
   rotated child inherits its parent's `code_id` (`issuer/create-refresh-token` takes `CodeId` from
   the code it is handed, and on the refresh path that code is `&refreshToken.Code`), a refresh-path
   check keyed on the grant's originating session identifier rejects every present and future
   descendant. So gap 2 needs no `codes.revoked` column, no new bulk method, and no edit to the
   `db/mark-code-used` predicate that #77 hardened. The issue's own cost estimate for gap 2 priced a
   design this document is not obliged to adopt.

   Supporting: all three gaps fail open, preserving access someone believed they had removed, which
   is the opposite direction from #131's residual that its own body calls fail-closed. And the
   window is not merely theoretical: a holder of a stolen offline refresh token can rotate in a loop
   while termination is attempted, so its size is adversary-influenceable.

   **Rejected:** gaps 1 and 3 only, deferring gap 2 to a follow-up scoped alongside #131 and #132.
   That would require amending goal 3, which promises a racing refresh leaves no usable descendant,
   so the issue would assert something false. It also rested on the three races sharing a
   serialization boundary, and their own texts refute that: #132 carries a section headed "Why #131
   does not own this", and #132's race is family-scoped where gap 2's is session-scoped.

   **Also rejected:** gap 1 only. It leaves the headline defect intact, since an in-flight ceremony
   still recreates the session and mints a code no marker on existing rows reaches.

   Note the sequencing commitment: gap 2 is staged last, but it still blocks #129 closing.

2. **Yes. Ending a session revokes the offline grants whose ceremony rode it.** Status: **Decided**
   Raised by: user

   "Originated in it" means `codes.session_identifier` matches the terminated session, which is the
   grant whose authorization ceremony rode that session. `db/refresh-by-sid` is exactly that query.

   The deciding argument is that the repository has already taken this position for a neighbouring
   action, and the inconsistency of not taking it here would be indefensible. `RevokeUserAuthState`
   sweeps `GetRefreshTokensByUserId`, which is user-scoped and so includes offline tokens, and
   `site/src/content/docs/concepts/user-sessions.mdx` states that a credential change covers "every
   kind of grant, including offline refresh tokens whose browser session has already expired".
   An operator told that a password change kills offline grants but an explicit "end this session"
   does not has been handed a distinction with no principle behind it.

   Supporting: the session list surfaces device name, type, OS and IP, so the action already reads
   as "this device", and an offline grant obtained through a ceremony on that device is that
   device's access.

   Also supporting, and convenient: #106 already calls `db/refresh-by-sid` in production for its
   *preserved* set, for the mirror-image reason (it reaches offline tokens through the `codes`
   join). The query gap 1 needs is therefore already exercised on all four engines rather than new.

   **Rejected:** leaving offline grants alone, on a literal reading of OIDC Core section 11
   ("usable even when the End-User is not present (not logged in)"). It contradicts #106 and the
   shipped documentation, and it reduces gap 1 to a no-op, since session-bound tokens already stop
   working at `validator/session-branch` the moment the row is gone.

   **Also rejected:** a setting. A security boundary behind a flag means the insecure position
   exists, has to be documented, and has to be tested in both states, and nothing indicates demand.

3. **No. RP-initiated logout's revocation behaviour is unchanged, and pinned by tests.**
   Status: **Decided** Raised by: user

   The dividing line is **intent, not database effect**. "End this session" is a security action
   aimed at a device. Logout is navigation: the user is finished with one application. That
   `logout/last-client-delete` deletes the session row when the departing client was the only one is
   session-lifecycle bookkeeping, and it does not convert the action into a revocation decision.

   This is what makes decisions 2 and 3 coherent rather than contradictory despite sharing a
   database effect. It is also where the specifications land: OIDC Core section 11's statement that
   an offline token is usable when the End-User is "not logged in" addresses exactly the logout case
   and says nothing about administrative or account-level termination. OIDC RP-Initiated Logout is
   silent on token revocation, and RFC 9700 section 4.14.2 says an authorization server **may**
   revoke on a security event such as logout, permitting either answer.

   Consequence for the current behaviour, which the stage that touches logout pins with tests so a
   later change has to be deliberate: an offline grant survives logout in every case, and a
   session-bound grant belonging to the client that just logged out **keeps working** while other
   clients remain on the session, because neither `validator/session-branch` nor
   `middleware/session-check` reads `UserSessionClient` at all.

   > **Amended on the reconciliation pass of 2026-08-04.** The paragraph above is true of the
   > `id_token_hint` path and describes only that path, which flatters the current behaviour. On the
   > ordinary interactive path (`logout_consent.html` posting back with only a csrf field, taking the
   > no-hint branch at `logout/basic-post-fork`) the session row is not deleted at all, so a
   > session-bound grant keeps working whether or not other clients remain. The correction sits in
   > section 1 and decision 13 records why it stays out of scope.
   >
   > This does not disturb the reasoning here. The dividing line is still intent, and a path that
   > performs no termination is not evidence about what termination should mean. It does change what
   > seam 9 pins, which is why the amendment is recorded rather than left as a detail.

   **Rejected:** sweeping sid-wide on logout. `handleExistingSessionOnLogout` is per-client, so this
   revokes grants belonging to clients that never logged out.

   **Also rejected:** sweeping only when logout deletes the session. The outcome would depend on how
   many other clients happen to share the session, which is invisible to the person clicking log
   out, so the same action revokes nothing or everything.

   The capability a user might actually want here, revoking one client's grants without touching the
   session, needs client-scoped revocation within a session, which no query provides today. That is
   #135 and it stays out of scope per section 2.

   **Constrains decision 5:** enforcement cannot sit unconditionally inside `DeleteUserSession`,
   because logout reaches it.

4. **`codes.revoked` carries the boundary. The grant record is the marker.** Status: **Decided**
   Raised by: user

   > **This reverses a first answer, and the reversal is the interesting part.** The registry of
   > terminated session identifiers was chosen first, then withdrawn when the user required that the
   > state be reaped rather than retained. Keep this history: the registry is a reasonable design and
   > the only thing wrong with it is its retention profile, so anyone revisiting this should know it
   > lost on that ground and not on correctness.

   At termination, mark every code of that session revoked. Reject a revoked code at redemption, and
   reject a refresh token whose code is revoked. Semantics: **revoked means reject, not revoked means
   continue normal processing.**

   The boundary must still be a **positive record of termination**, and that requirement is what
   rules out the obvious non-solution. The absence of a session row cannot mean "terminated":
   `performTask` calls `DeleteIdleSessions` and `DeleteExpiredSessions`, so sessions vanish as
   routine housekeeping, and per decision 2 an offline grant is designed to survive exactly that. So
   `validator/offline-branch` cannot simply be made to consult the session the way
   `validator/session-branch` does; that would kill every offline grant whose browser session merely
   expired, which is the feature working as intended. Something has to be written down at
   termination. The question decided here is only *where*.

   Two properties make `codes` the right place, and both were verified rather than assumed.

   **(a) It closes gap 2 structurally, with no race left to bound.** A rotated child inherits its
   parent's `code_id` (`issuer/create-refresh-token`, and on the refresh path the code is
   `&refreshToken.Code`). Marking the code therefore marks every present and future descendant at
   once. The child is **born already rejected**, because the fact predates its existence. This is
   categorically stronger than a sweep over rows that happen to exist, which is what every
   timing-based design reduces to.

   **(b) Its retention manages itself, so there is no horizon to defend.** `db/delete-used-codes`
   reaps a code only when no refresh token references it, and `DeleteExpiredRefreshTokens` removes
   descendants once past `expires_at` or `max_lifetime`. So the marker outlives every token that
   could reference it, automatically, and becomes reclaimable exactly when the last one dies. This
   is what decision 8 rests on.

   `fieldtag:"dont-update"` on the model field keeps a stale `Code` from writing `revoked = false`
   back: `UpdateCode` builds with `WithoutTag("dont-update")`, and #106 tags
   `RefreshToken.AuthStateGeneration` the same way for the same reason.

   Cost: a `codes.revoked` column via migration 000026 on four engines,
   `RevokeCodesBySessionIdentifier(tx, sid)` plus four engine wrappers, `AND revoked = false` added
   to the `db/mark-code-used` predicate that #77 hardened, rejections at both validator sites, an
   extension to `db/delete-used-codes` so unused revoked codes are reaped (decision 8), and an
   `/auth/issue` liveness check for the one case a code-level marker cannot reach (decision 6).

   **Rejected: a registry of terminated session identifiers, retained indefinitely.** Correct, and
   the only design that is airtight even against an unbounded handler stall. Rejected because it
   never frees disk: it is keyed on a session identifier, which has no natural lifetime, and gap 2's
   racing child (an offline token with up to `RefreshTokenOfflineMaxLifetimeInSeconds`, seeded at
   31536000 seconds) means no finite horizon can be shown safe. The user's requirement is that the
   state be reclaimable, and this design cannot satisfy it.

   **Rejected: a registry with a bounded horizon plus conditional inserts.** Making `CreateCode` and
   `CreateRefreshToken` refuse atomically when the grant's session is marked would let the horizon
   shrink to the code lifetime. But its safety then rests on a statement's read snapshot never being
   meaningfully older than the statement itself, which is engine-specific, and it adds
   conditional-insert plumbing to two hot data-layer paths across four engines. `codes.revoked` gets
   the same guarantee from row inheritance instead of from isolation semantics.

   **Rejected: a tombstone on `user_sessions`.** It changes the semantics of
   `GetUserSessionBySessionIdentifier`, which has 23 call sites across 14 files
   (`grep -rn "GetUserSessionBySessionIdentifier(" src/ --include=*.go | grep -v mock | grep -v _test | grep -v "func (" | wc -l`),
   including both middlewares, the validator, the token issuer, `BumpUserSession` and both list
   endpoints. A missed call site fails open, and a tombstone reaching `BumpUserSession` is brought
   back to life.

   **Rejected: a per-session generation.** Tombstone blast radius plus more machinery, for nothing.
   #106 needed a counter to preserve one session while revoking the rest; inside a single terminated
   session there is no such requirement, so the fact is a boolean and a counter is strictly more.

   **Rejected: transactional serialization as the carrier.** By the issue's own note it cannot
   recognise a ceremony that began before the termination, so it still needs a persisted marker.

   **#134 becomes moot** and should be closed: it tracks the retention of a terminated-session
   registry, and no registry is being built.

5. **The two explicit endpoints only, through a shared helper.** Status: **Decided**
   Raised by: user

   A helper called from `admin/session-delete` and `account/session-delete` performs three writes
   **in one transaction**, so the durable fact and the revocation cannot land separately:
   `RevokeCodesBySessionIdentifier`, the sid-scoped refresh-token sweep through `db/refresh-by-sid`,
   and `DeleteUserSession`.

   `DeleteUserSession` has six callers
   (`grep -rn "DeleteUserSession(" src/ --include=*.go | grep -v mock | grep -v _test | grep -v "func (" | grep -v "data/"`),
   and only two of them are the action this issue is about:

   | Caller | Marker? | Why |
   |---|---|---|
   | `admin/session-delete` | yes | the explicit administrative action |
   | `account/session-delete` | yes | the explicit self-service action |
   | `logout/last-client-delete` | no | decision 3 |
   | `sessionmgr/start-new` device sweep | no | displaces a session on ordinary re-login by the same user on the same device; not a security action, and it would revoke the grants of a session the user is actively replacing |
   | `revocation.go` (#106 sweep) | no | the per-user generation is a strictly stronger boundary already, so a marker adds nothing |
   | `handler_token.go` (#77 reuse cascade) | no | already sweeps sid-scoped tokens including offline ones through `db/refresh-by-sid` |

   The background reapers call `DeleteIdleSessions` and `DeleteExpiredSessions` rather than
   `DeleteUserSession`, so they are excluded by construction rather than by choice.

   **Rejected:** enforcing inside `DeleteUserSession` with an opt-out. It guarantees no call site
   forgets, but four of the six callers would pass the opt-out, and a flag that most callers disable
   expresses intent worse than two explicit calls do. It also puts a registry write inside the reuse
   cascade and the #106 sweep, where decision 4's own reasoning says it is redundant.

   **Rejected:** adding the #77 reuse cascade. It would harden that path against a racing child, but
   it widens this change into #77's territory, and the cascade already revokes offline tokens, so the
   only gain is against the race #132 tracks.

6. **Restart level 1 authentication. The gate is `!hasValidUserSession && !userReallyAuthenticated`.**
   Status: **Decided** Raised by: user

   In `HandleAuthCompletedGet`, the else branch reaches `completed/start-new-session` only when this
   ceremony actually authenticated. Otherwise set `AuthStateRequiresLevel1`, save, and redirect to
   `/auth/level1`.

   Per section 1 the predicate **cannot** be "no valid session": `test/fresh-ceremony-after-delete`
   is #46's guard over a legitimate case with exactly that shape, and it must stay green. The
   discriminator is whether *this ceremony* performed level 1 authentication, which
   `completed/really-authenticated` already computes from `AuthenticatedAt` and never consults here.

   Restarting is chosen over failing to the client because the situation is precisely "this person
   needs to authenticate", and it is how the codebase already expresses that at
   `authorize/prompt-login` and on the no-valid-session path in `HandleAuthorizeGet`. It preserves
   the ceremony's client, scope, state, nonce and PKCE parameters. There is no loop risk: the second
   pass has `AuthenticatedAt` set by `pwd/authenticated-at` and takes the branch legitimately.

   **The gate is broader than gap 3**, and that is deliberate. `completed/start-new-session` today
   mints a session from `authContext.UserId` with no proof anyone authenticated, in *any* scenario
   where the session vanished, not only after a deliberate termination.

   Verified supporting facts:

   - `AuthContext` is stored as JSON in the session cookie (`json.Marshal` in `SaveAuthContext`,
     `json.Unmarshal` in `GetAuthContext`), so `AuthenticatedAt` round-trips as RFC 3339 and the
     discriminator survives the redirect chain.
   - On the path that reaches `/auth/completed` the only writers of `AuthenticatedAt` are
     `pwd/authenticated-at` and the OTP handler, both real authentication. `authorize/sso-reuse`
     leaves it nil.
   - **`prompt=none` needs no separate answer.** `handlePromptNone` sets
     `AuthStateReadyToIssueCode` and goes directly to `/auth/issue`, so it never reaches this gate.
     Its own exposure is the case below, covered by the redemption check.

   > **Load-bearing fragility, worth a test and a comment.** `handlePromptNone` *does* set
   > `AuthenticatedAt` from the session it reused. It never reaches `/auth/completed` today, so the
   > discriminator holds, but if that ever changed the gate would silently pass. The gate's meaning
   > is "this ceremony authenticated", and only its current call graph makes `AuthenticatedAt` mean
   > that.

   **This gate closes only part of gap 3.** Two sub-cases:

   - **Before `/auth/completed`.** The SSO ceremony is stopped by this gate. No durable state needed.
   - **After `/auth/completed`, before `/auth/issue`.** The session was alive at `/auth/completed`
     and was bumped; the user then sits on the consent screen. `issue/sid-from-context` still reads
     the terminated session's identifier from the cookie, and `issue/create-code` stamps it onto a
     **brand-new** code. Decision 4's marker cannot reach it, because a code-level fact cannot be
     written onto a row that does not exist yet. This is also the `prompt=none` exposure, since
     `handlePromptNone` bumps the session and goes straight to `/auth/issue`.

   The second sub-case is closed by a **liveness check at `/auth/issue`**: refuse to mint a code when
   the ceremony's bound session identifier no longer resolves to a session row, and restart level 1
   as above. This is deliberately a *liveness* check rather than a termination check, so it needs no
   marker and no registry, and it is correct on its own terms: a ceremony must not bind a grant to a
   session that no longer exists, whether it was terminated or merely reaped. Its residual is
   decision 12.

   **Cost, already verified:** three subtests in `test/completed-new-session`'s file drive the else
   branch with a nil `AuthenticatedAt` and must gain one. The gap 3 work is not additive at the unit
   tier.

   **Rejected:** failing to the client with `login_required` or `access_denied`. It costs the user a
   round trip through the client to arrive at the same password form, and discards a ceremony that
   could have completed correctly.

   **Also rejected:** a 500. The state is reachable through a legitimate administrative action, so it
   is not an invariant violation, and it would surface as an error page instead of a login prompt.

7. **After client authentication and PKCE, and after the reuse return.** Status: **Decided**
   Raised by: user

   Two placements, one per grant type:

   - **`authorization_code`:** client secret, then PKCE, then the `if wasReused` return, **then** the
     revoked-code check. Not in `validator/authcode-preauth`.
   - **`refresh_token`:** after `validator/client-ownership`, rejecting when
     `refreshToken.Code.Revoked`. Client-secret validation already runs at the top of that case,
     before the token is even parsed, so the refresh path is behind client authentication by
     construction and only the ownership ordering is a choice.

   The code path's check reads `codeEntity.Revoked` and the refresh path's reads
   `refreshToken.Code.Revoked`, both already loaded: `RefreshTokenLoadCode` populates the whole code
   row, and the validator derives `codeEntity = &refreshToken.Code`. No new query is needed at either
   site.

   The deciding argument is that the codebase already took a position against this disclosure and
   ordering silently undoes it. `invalidGenerationMessage`'s own comment says that naming the cause
   "would tell an attacker holding a stolen token exactly what happened". A generic message is
   defeated when *which* generic message you get is itself the signal, which is the defect #137
   describes. Adding a new member to a class that already has an open issue to close it would be
   going backwards.

   The reuse return stays ahead of the registry check so #77's containment cascade is not pre-empted:
   the reused-code error carries the code entity and drives `revokeAndAuditAuthCodeReuse`, and a
   registry rejection landing first would suppress it. Reuse is also the stronger signal, and it
   already revokes everything the registry check would have refused.

   Placing this check correctly gives #137 a pattern to follow plus a negative control to copy, which
   is worth more than consistency with the neighbours it is deliberately not joining.

   **Cost:** a comment explaining why the check sits apart from the checks around it, or a reviewer
   tidies it back into `validator/authcode-preauth`. Section 5's negative controls are what make the
   ordering testable rather than merely intended.

   **Rejected:** placing it in `validator/authcode-preauth` with its neighbours. Consistent and
   comment-free, but it widens the exact class #137 exists to close, letting an unauthenticated
   presenter of a stolen code learn whether the session was terminated.

   **Also rejected:** absorbing #137 by reordering the pre-existing generation and disabled-user
   checks in the same change. Cleaner end state, but those checks belong to #106 and #137 was filed
   deliberately to own the behaviour change, and folding it in enlarges this issue's review surface
   and regression risk. #137 stays out of scope per section 2.

8. **The two existing reapers already do it, plus one predicate extension for unused revoked codes.**
   Status: **Decided** Raised by: user

   Settled by decision 4 rather than independently, since the carrier chosen is the one whose
   retention needs no horizon.

   **Used revoked codes: nothing changes.** `db/delete-used-codes` reaps a code only when no refresh
   token references it, and `DeleteExpiredRefreshTokens` removes descendants once past `expires_at`
   or `max_lifetime`. So a revoked code survives exactly as long as some descendant could present it
   and is reclaimed once the last one dies. That is the correct lifetime, derived rather than chosen,
   and it is why no cutoff has to be defended.

   **Unused revoked codes need a new predicate.** A code revoked at termination while still
   unredeemed has `used = false`, and `db/delete-used-codes` filters `used = true`, so those rows
   would accumulate forever. The extension reaps `revoked = true AND used = false AND created_at <
   cutoff`. Safe with a short cutoff, and provably so: an unused code has no refresh tokens by
   definition, and it is unredeemable after 60 seconds anyway per `authCodeExpirationInSeconds`. So
   the cutoff here really is the code lifetime plus a clock allowance, which is the horizon that was
   *wrong* for a session-keyed registry and is *right* for a code-keyed one.

   The distinction is worth keeping straight, because the wrong version looks identical: a
   session-keyed marker cannot use a code-lifetime horizon, because a refresh token references it for
   up to `RefreshTokenOfflineMaxLifetimeInSeconds` (seeded at 31536000). A code-keyed marker can,
   *for the unused case only*, because an unused code has no descendants at all.

   **Rejected:** a time horizon on the whole marker, of any length. Under decision 4's carrier it is
   unnecessary for used codes and would be actively unsafe, since it could reap a code whose live
   offline descendant is still refreshing.

   **Rejected:** leaving unused revoked codes in place. It reintroduces unbounded growth, which is the
   defect that moved decision 4 off the registry in the first place.

   > **Note for the run.** Disk is only actually reclaimed once #130 is fixed:
   > `db/delete-used-codes` builds `NotIn("id", SELECT code_id FROM refresh_tokens)`, and because ROPC
   > refresh tokens have `code_id = NULL`, `x NOT IN (…, NULL)` is UNKNOWN rather than TRUE, so the
   > predicate matches nothing once any ROPC token exists. #130 owns that and it stays out of scope
   > per section 2, but the reclamation claimed here is latent until it lands. The correctness of
   > decision 4 does not depend on it; only the disk saving does.

9. **Emit both events.** Status: **Decided** Raised by: user

   `AuditDeletedUserSession` keeps its existing payload untouched (`userSessionId`, `loggedInUser`),
   and a new `terminated_user_session` event carries the security detail: `userId`, `userSessionId`,
   `sessionIdentifier`, `revokedRefreshTokenJtis` and `revokedCodeCount`, plus `loggedInUser`.

   The user's choice, taken over the recommendation below. Its argument is compatibility: any external
   consumer parsing `deleted_user_session` with a strict schema keeps working untouched, and the two
   records carry different meanings, one a session-lifecycle fact and one a security action.

   Both are emitted **after the termination transaction commits**, following
   `revokeAndAuditAuthCodeReuse`, which audits only once the revoke succeeded, so neither event can
   claim something that rolled back.

   Field choices follow existing precedent rather than invention: `AuditAuthCodeReuseDetected` already
   carries `sessionIdentifier` and `revokedRefreshTokenJtis` for this exact shape, and #106's
   `AuditRevokedUserAuthState` lists JTIs too. Codes get a **count** rather than a list of IDs because
   no event in the codebase lists code IDs, and a count answers the only question an auditor has here,
   whether anything was revoked.

   Cost: a new constant plus an entry in the audit event list in `constants.go`.

   **The known downside, and its mitigation.** Two rows per action makes "how many sessions were
   terminated" ambiguous to count. Mitigation, which the documentation stage must state:
   `terminated_user_session` is the event to count for terminations, and `deleted_user_session` is the
   lifecycle record that accompanies it.

   **Not chosen (was recommended):** extending `AuditDeletedUserSession` in place. The action is the
   same action doing more, a JSON payload makes added keys additive, both emitters were being changed
   together so no partial payload could arise, and one row per action avoids the correlation the
   chosen option requires. Recorded because if the counting ambiguity ever becomes a nuisance, this is
   the alternative and the reason it lost was compatibility, not correctness.

10. **No. #133 stays whole and #129 does not touch it.** Status: **Decided** Raised by: user

    #133 is independent on its own terms: it needs no termination, no offline grant and no race, and
    both its entry paths (`authorize/prompt-login`, `authorize/hint-mismatch`) leave a live session
    cookie in place with no user comparison anywhere downstream. `sessionmgr/bump-no-userid` assigns
    methods and ACR but never `UserId`.

    The only argument for entangling them was decision 4's original registry design, which needed the
    ceremony's originating session identifier bound onto the `AuthContext`, and would therefore have
    persisted a wrong user association deliberately rather than incidentally. **Decision 4's reversal
    removed that need**: `codes.revoked` requires no `AuthContext` field, and both of this issue's
    gates read the ambient sid the way `/auth/issue` already does.

    Verified that #129 is neutral rather than merely uninvolved:

    - Decision 6's gate fires only when there is **no** valid session. #133's `prompt=login` path has
      user A's session valid, so the gate never sees it and the bump branch is taken exactly as today.
    - Decision 12's statement reads the same ambient session identifier `issue/sid-from-context`
      already uses, so it introduces no new association.

    **Rejected:** taking the one-line guard as cheap hardening while `HandleAuthCompletedGet` is open
    anyway. It splits #133's coverage across two issues, and by #133's own analysis the guard alone is
    not the fix: `completed/set-acr-level` runs after the branch and must be fed the new session or
    nil, or A's ACR is still grafted onto B's code. Shipping the guard without that leaves the leak
    live while looking fixed, which is worse than not starting.

    **Action for #133:** its text claims "#129 implements the same-user guard as part of its stage 5".
    That is no longer true and should be corrected when its decision-number citations are reconciled.

11. **Out of scope, and documented explicitly rather than inherited.** Status: **Decided**
    Raised by: user

    Goal 1's "durably cuts off" covers refresh tokens and authorization codes. An offline grant's
    access token stays acceptable until it expires, 5 minutes by default.

    The reason it cannot be reached is structural rather than a matter of effort.
    `issuer/suppress-sid-claim` omits the `sid` claim for an offline grant, and the token carries no
    other grant identifier, so `middleware/session-check` has nothing to look up. It falls through to
    the per-user generation comparison, and termination must not move that counter, since doing so
    would invalidate every other device belonging to that user, which is the whole reason this issue
    exists separately from #106.

    **The documentation consequence is the load-bearing part of this decision.**
    `site/src/content/docs/concepts/user-sessions.mdx` currently says that after a credential change,
    Goiabada's **own** endpoints "reject a token from a superseded session on the very next request".
    That is true for #106, because the generation moves. It is **false** for session termination of an
    offline grant, where even Goiabada's own endpoints keep accepting the access token until expiry.
    The stage that touches documentation must state that difference rather than let the existing
    sentence be read as covering this case too, because a reader would otherwise conclude the opposite
    of what is true.

    **Rejected:** including the `sid` claim on offline access tokens so the middleware can reach them.
    It would make every offline grant's access token stop working as soon as its browser session was
    reaped, since the middleware treats a missing session as invalid. That breaks `offline_access` by
    design, and it is exactly the outcome decision 2 was careful to avoid.

    **Rejected:** adding a grant identifier claim plus a lookup. It closes the window properly, but it
    is a wire-format change plus a database read on every authenticated API request, which is
    disproportionate to a 5 minute default window whose mitigation (short access-token expiry) is
    already documented.

12. **A compensating revoke after the insert, as one statement.** Status: **Decided** Raised by: user

    Exposed by decision 4's reversal. The registry design did not have this residual, because a marker
    keyed on the session identifier catches a code inserted at any later time. A marker keyed on the
    code cannot, so decision 6 adds a liveness check at `/auth/issue`, and that check is a read
    followed by an insert.

    The interleaving it leaves: `/auth/issue` reads the session and finds it live, termination commits,
    then `issue/create-code` commits. That code is bound to a session that no longer exists and
    carries no marker, because it did not exist when `RevokeCodesBySessionIdentifier` ran.

    What survives such a code's redemption, verified:

    - A **session-bound** refresh token dies at `validator/session-branch`, which finds no session
      row. Nothing to do.
    - An **offline** refresh token survives, up to `RefreshTokenOfflineMaxLifetimeInSeconds`. This is
      the residual worth closing.
    - The **access token** survives to its expiry either way, which is decision 11.

    **The fix.** Keep the liveness read, because it produces the good outcome in the common case where
    the session is genuinely gone: restart level 1 per decision 6, rather than minting a code and
    revoking it. Then, immediately after `issue/create-code`, run one statement:

    ```sql
    UPDATE codes SET revoked = true, updated_at = ?
    WHERE id = ?
      AND NOT EXISTS (SELECT 1 FROM user_sessions WHERE session_identifier = ?)
    ```

    **Why this composes rather than merely narrowing.** Two sweepers now cover each other:

    - If the code insert commits **before** termination's `RevokeCodesBySessionIdentifier` statement
      reads `codes`, termination marks it.
    - If it commits **after**, this statement observes the session already gone and marks it.

    The only interleaving escaping both is one where the code insert lands between the termination
    transaction's `UPDATE` statement and that transaction's `COMMIT`, so this statement still reads the
    session as present. That is a genuinely tight window between two bounded statements, rather than
    the unbounded handler stall the read-only check leaves.

    It also reuses the column decision 4 already adds, needs no new insert path, and keeps
    `CreateCode` on the `sqlbuilder` struct-insert pattern.

    **Cost:** one extra indexed `UPDATE` per authorization code issued, normally matching zero rows.
    Accepted as the price of not leaving a fail-open hole.

    **Rejected:** a conditional insert,
    `INSERT INTO codes (...) SELECT ... WHERE EXISTS (SELECT 1 FROM user_sessions WHERE session_identifier = ?)`.
    It prevents rather than compensates, so no bad code ever exists, which is the stronger property.
    Rejected on maintenance risk: it means a hand-written insert for `codes` on four engines, diverging
    from the struct-insert every other create method uses, on the most security-critical insert in the
    codebase, and a hand-written column list is exactly where a later added column gets forgotten.

    **Rejected:** accepting the residual and filing a follow-up alongside #131 and #132. Defensible,
    since those three want the same missing primitive, but the compensating statement closes most of
    it now for one `UPDATE`, so deferring would be paying a security cost to avoid a trivial one.

    > **Residual, stated rather than implied.** The interleaving above is not closed. It belongs to the
    > same class as #131 and #132: ordering a write against a sweep portably across four engines. The
    > run should record it in section 7, and it is drafted as follow-up 1 in section 9, but it does not
    > block this issue.

13. **The interactive logout path stays out of scope, and #129 does not touch logout.**
    Status: **Decided** Raised by: user

    Found on the reconciliation pass, by tracing which endpoint each "End session" button reaches.
    `logout_consent.html` posts back carrying only a csrf field, so the ordinary logout takes the
    no-hint branch at `logout/basic-post-fork`, clears the cookie, audits, redirects, and writes
    nothing to the database. The session row survives with every client attached. Section 1 carries
    the full correction.

    **Why this is not #129's problem, which is the whole argument.** #129 makes termination
    **durable**. This path performs no termination at all, so there is nothing for `codes.revoked` to
    mark and no durability to add: the marker is written by the shared helper in decision 5, which
    this path never calls. Fixing it means first deciding what interactive logout should do, whole
    session or per-client, and that is exactly the model question #109 divergence B raises. Answering
    it here would settle #109's design from inside an issue about something else.

    Decision 3's reasoning is untouched. The dividing line is intent, and a path that terminates
    nothing is not evidence about what termination means.

    **Rejected: a stage making the no-hint POST delete the session, still without revoking.** It
    would make logout stop lying for one line of code, which is tempting. Rejected because it edits
    `handler_account_logout.go`, the one file #109 rewrites, and because "delete the whole session"
    prejudges #109-B against the per-client model already in `handleExistingSessionOnLogout`. #129
    modifies no logout code; its only presence in that file is seam 9's pinning tests.

    **Rejected: treating interactive logout as a termination.** Reverses decision 3, and contradicts
    the OIDC Core section 11 reading that decision 3 rests on.

    **Consequence for seam 9.** The pinning tests must drive logout through request shapes #109 is
    not rewriting, and must not encode #109's defects as intended behaviour. Seam 9 spells this out.

    Drafted onto #109 as follow-up 2 in section 9, rather than as a new issue, because #109 already
    owns this surface and divergence B is the same asymmetry one path over.

14. **Yes, all three confirmation modals say what ending a session disconnects, in both locales.**
    Status: **Decided** Raised by: user

    Found by the four-surface sweep, which the earlier pass never ran past the docs site. Three admin
    console pages carry an "End session" button, and all three funnel into the two endpoints decision
    5 names, so all three inherit the new consequence: ending a session disconnects the long-lived
    integrations that session authorized.

    Today each modal promises only that a session on a device ends, plus a conditional warning that
    ending your own logs you out. Nobody clicking it can discover the rest, and for an administrator
    it is the fact that decides whether ending the whole session is even the right control, given
    that the narrower capability is #135 and does not exist yet.

    **What lands.** Three new keys in `active.en.toml` and three in `active.pt-BR.toml`, following
    the per-surface prefix convention that already gives "End session" three separate keys, plus one
    `msg +=` line in each of the three templates:

    | Surface | Template | New key |
    |---|---|---|
    | account | `account_user_sessions.html` | `adminconsole.account.sessions.modal_revocation_note` |
    | admin users | `admin_users_sessions.html` | `adminconsole.admin_users.sessions.modal_revocation_note` |
    | admin clients | `admin_clients_usersessions.html` | `adminconsole.admin_clients.usersessions.modal_revocation_note` |

    Two wordings, not one, because person differs. The account page is the user acting on their own
    session; the two admin pages act on somebody else's:

    - account, second person: `" <br /><br />Applications you authorized from this session, including
      ones that keep working in the background, will need to sign in again."`
    - admin, third person: `" <br /><br />Applications the user authorized from this session,
      including ones that keep working in the background, will need to sign in again."`

    pt-BR drafts, in the register of the neighbouring strings, which use "aplicativos" and
    "autentique-se novamente": `" <br /><br />Os aplicativos que você autorizou nesta sessão,
    incluindo os que continuam funcionando em segundo plano, precisarão se autenticar novamente."` and
    the same with "que o usuário autorizou". The run treats these as drafts to refine, not sealed
    wording, and must not ship English in the pt-BR catalog. The English is the user's chosen wording
    and the pt-BR follows it rather than paraphrasing.

    **Two mechanical constraints, verified, because getting either wrong breaks the page silently.**
    The string is interpolated into a JavaScript double-quoted literal inside `endSessionClick`, so it
    may contain **no double quote**, which is why the existing modal strings use
    `<span class='text-accent'>` with single quotes. And it is appended unconditionally, placed
    **before** the `if (isCurrent)` append so the immediate-logout warning stays last.

    **Left alone deliberately:** the pre-existing key-name inconsistency, where two surfaces use
    `modal_current_warning` and `admin_users` uses `modal_confirm_current_warning`. Renaming is not
    this change's job, and the new keys use one consistent suffix rather than copying the divergence.

    **Rejected: only the account modal.** The admin surfaces would stay silent about a consequence
    that changes which control an admin should reach for, and an admin ending a contractor's session
    to cut off access needs to know it also disconnects that person's background integrations.

    **Rejected: the docs site only.** `concepts/user-sessions.mdx` carries the full semantics either
    way, per section 2, but a reader at the decision point is in a modal, not on the docs site.

    **Rejected: one shared key for all three surfaces.** It would be less churn, and it is against the
    established convention here, where identical strings like "End session" and "Are you sure?" each
    carry three per-surface keys. Mixing a shared key into a per-surface scheme is what review flags.

---

## 4. Design

Ending a session becomes a security action with a durable consequence, and the durable consequence
lives on the **grant record** rather than on the session or in a side table.

### 4.1 The property that makes this safe

**A refresh token can only ever descend from a code, and a descendant inherits its parent's
`code_id`.** So marking a code is not a sweep over rows that happen to exist; it is a statement about
the whole grant, past and future. A child inserted a millisecond or a month after termination reads
its own grant as revoked, because the fact was written before that child existed.

Everything else follows from this. Gap 2 needs no serialization, because there is no window between
"the fact is true" and "the row exists" to serialize. And retention needs no defended horizon,
because `db/delete-used-codes` already refuses to reap a code while any refresh token references it,
so the marker outlives every token that could present it and becomes reclaimable exactly when the
last one dies (decision 8).

The second property, which the first does not give: **absence of a session never means terminated.**
`performTask` reaps idle and expired sessions routinely and offline grants are designed to outlive
them, so termination has to write something positive down. That is why `validator/offline-branch`
cannot simply be taught to consult the session, and it is the constraint that ruled out every design
inferring termination from a missing row (decision 4).

### 4.2 Termination

One helper, called from `admin/session-delete` and `account/session-delete` only (decision 5), doing
three writes in **one transaction**:

1. `RevokeCodesBySessionIdentifier(tx, sid)`, marking every code of that session revoked.
2. The sid-scoped refresh-token sweep: `db/refresh-by-sid` to load, then `revoke/refresh-tokens` to
   mark. This reaches offline tokens because the query joins through `codes` (decision 2), and it is
   the same call #106 already makes for its preserved set.
3. `DeleteUserSession(tx, id)`.

Step 1 is what survives; steps 2 and 3 are cleanup that makes the effect immediate. Both audit events
fire after the commit (decision 9).

The four other `DeleteUserSession` callers are untouched, each for a reason recorded in decision 5.
`logout/last-client-delete` in particular keeps its current behaviour exactly, pinned by tests
(decision 3).

### 4.3 Where the marker is checked

Two reads, both of data already loaded, so neither adds a query (decision 7):

| Site | Reads | Position |
|---|---|---|
| `authorization_code` redemption | `codeEntity.Revoked` | after client secret, after PKCE, after the `if wasReused` return |
| `refresh_token` validation | `refreshToken.Code.Revoked` | after `validator/client-ownership` |

Both sit **behind** client authentication, deliberately apart from the checks in
`validator/authcode-preauth`. That block leaks whether a user's generation moved to anyone holding a
stolen code, which is #137, and a new check placed there would join that class. The `wasReused`
return stays ahead so #77's containment cascade is not pre-empted, and reuse already revokes
everything a revoked-code rejection would have refused.

`MarkCodeAsUsed` gains `AND revoked = false`, so a code cannot be claimed between validation and
claiming. Without it, validation and claiming are separate steps and a code revoked in between would
still be claimed.

### 4.4 Gap 3, in two halves

The issue proposes failing when the session is gone. **Verified wrong, and decision 6 records the
departure:** `test/fresh-ceremony-after-delete` is #46's guard over a legitimate case with exactly
that shape. The discriminator is whether *this ceremony* authenticated.

**Half one, before `/auth/completed`.** The else branch reaches `completed/start-new-session` only
when `userReallyAuthenticated`. Otherwise set `AuthStateRequiresLevel1` and redirect to
`/auth/level1`. `completed/really-authenticated` already computes this and currently consults it only
in the branch where it does not matter. No durable state involved.

This is broader than gap 3 by design: `completed/start-new-session` today mints a session from
`authContext.UserId` with no proof anyone authenticated, whenever the session has vanished for any
reason.

**Half two, after `/auth/completed`.** The session was alive and bumped, then the user sits on the
consent screen; `prompt=none` reaches the same place by going straight from `handlePromptNone` to
`/auth/issue`. Here `issue/create-code` mints a **new** code, which a code-level marker cannot reach.
Two statements cover it (decisions 6 and 12):

1. A liveness read at `/auth/issue`: if the bound sid resolves to no session row, restart level 1.
   This is a liveness check, not a termination check, so it needs no marker and is right on its own
   terms, since a ceremony must not bind a grant to a session that no longer exists.
2. Immediately after the insert, one compensating statement:
   `UPDATE codes SET revoked = true, updated_at = ? WHERE id = ? AND NOT EXISTS (SELECT 1 FROM user_sessions WHERE session_identifier = ?)`.

Statement 2 and termination's own step 1 cover each other. A code committing before termination reads
`codes` is marked by termination; a code committing after is marked by statement 2. Only a code
landing between the termination transaction's `UPDATE` and its `COMMIT` escapes both, which decision
12 records as an open residual in the same class as #131 and #132.

### 4.5 Retention

Nothing new to reap for used codes: the existing pair already gives the right lifetime. One predicate
is added so unused revoked codes do not accumulate, reaping
`revoked = true AND used = false AND created_at < cutoff`. Safe with a short cutoff because an unused
code has no refresh tokens by definition and is unredeemable after 60 seconds anyway.

The horizon that is **wrong** for a session-keyed marker is **right** here, and the difference is
worth keeping straight because the two look identical: a session-keyed marker is referenced by
refresh tokens for up to `RefreshTokenOfflineMaxLifetimeInSeconds` (seeded at 31536000), while an
unused code has no descendants at all.

Actual disk reclamation is latent until #130 lands, since `db/delete-used-codes` currently matches
nothing once any ROPC refresh token exists. Correctness here does not depend on that; only the saving
does.

### 4.6 What deliberately does not change

- **RP-initiated logout**, in any respect (decision 3), with today's contract pinned by tests
  including that a logged-out client's session-bound token keeps working while others share the
  session.
- **The per-user generation.** Termination must never move it, or one device's sign-out would
  invalidate every other device. That asymmetry with #106 is the reason this issue exists separately.
- **`validator/authcode-preauth`'s existing checks.** #137 owns reordering them.
- **`#133`'s same-user guard** (decision 10). Verified that #129 is neutral on it.
- **Offline grants' access tokens** (decision 11), scoped out with a documentation obligation rather
  than silently.

### 4.7 Departures from the issue

| Issue says | Verified reading | Recorded in |
|---|---|---|
| gap 3 should "fail and force re-authentication" when the session is gone | the predicate must be "this ceremony did not authenticate", or #46's regression breaks | decision 6 |
| gap 2 needs `codes.revoked` plus a bulk method plus a `MarkCodeAsUsed` edit, priced as significant | the same column closes gaps 1 and 2 together, because descendants inherit `code_id`; the marginal cost of gap 2 is close to zero | decisions 1, 4 |
| a session tombstone or registry is the natural carrier | both were considered; the registry lost on retention, the tombstone on blast radius across 23 call sites | decision 4 |
| rotation marks the parent with `UpdateRefreshToken(nil, ...)` | #128 replaced that with a compare-and-set; the race survives but the citation is stale | section 1, gap 2 |
| the fix is about refresh tokens | offline grants' **access** tokens survive too, and the shipped documentation currently implies otherwise | decision 11 |

---

## 5. Seams

Nine boundaries. Existing ones are marked, because preferring them is the point: **every seam here is
an existing test file**, and the only new artefacts are two data methods.

### Data tier, all four engines

1. **`Database.RevokeCodesBySessionIdentifier(tx, sid)`** (new). Owns the exhaustive table for which
   rows the marker reaches: codes of the target session, codes of an unrelated session left alone,
   unknown sid, empty sid, a session whose codes are already revoked (idempotent, and the returned
   count reflects rows actually transitioned). Also owns the two questions a mock can never answer:
   does the **failure path** return an error rather than a benign zero, and does it **enlist in the
   caller's transaction** rather than the pool. A rolled-back transaction forces both, following
   `TestTransaction_RollbackUndoesMultiStatementDelete` in `transaction_test.go`.

2. **`Database.MarkCodeAsUsed(tx, id)`** (existing, in `code_test.go`). Owns the claim predicate. The
   new row is a revoked but unused code, which must **not** be claimable. Keep the existing
   already-used row: together they prove the predicate has both terms, and either alone passes with
   the other term deleted.

3. **`Database.DeleteUsedCodesWithoutRefreshTokens(tx, before)` and the unused-revoked reaper**
   (existing method, extended). Owns what is reaped and, more importantly, **what is retained**: a
   revoked code with a live refresh token must survive, because decision 8's whole safety argument is
   that the marker outlives its descendants. That retention row is the regression guard for decision
   4 and its value is invisible once the design is right, so it gets a "keep this" note.

4. **The compensating revoke** (new method, decision 12). Owns: marks the code when no session row
   exists, does nothing when one does, and is a single statement. The "does nothing" row is the one
   that matters, since a method that always revoked would pass every other assertion.

### Unit tier

5. **`validators.ValidateTokenRequest`** (existing, `token_validator_test.go`). Owns the exhaustive
   rejection **and ordering** table for both grant types. The ordering rows are decision 7's only
   testable content and are what stop the checks drifting back into `validator/authcode-preauth`:

   - a revoked code with a **wrong PKCE verifier** returns the PKCE error, not the revoked-code error;
   - a revoked code presented with a **wrong client secret** returns the client-authentication error;
   - a **reused** revoked code still returns the reuse error, so #77's cascade is not pre-empted;
   - a revoked grant's refresh token presented by the **wrong client** returns the ownership error.

   Each of those is a negative case that names the gate meant to reject it, so none can pass with the
   revoked check deleted. Consumers elsewhere get thin tests, deliberately, per section 8 of the
   testing reference.

6. **`HandleAuthCompletedGet`** (existing, `handler_auth_completed_test.go`, 10 `t.Run` subtests).
   Owns decision 6's branch table. New row: no valid session and `AuthenticatedAt` nil, asserting a
   redirect to `/auth/level1` and that `StartNewUserSession` is **not** called. The three existing
   subtests reaching `StartNewUserSession` gain a non-nil `AuthenticatedAt`, which is the recorded
   non-additive cost.

7. **`HandleIssueGet`** (existing, `handler_auth_issue_test.go`, `TestHandleIssueGet` with 3 `t.Run`
   subtests). Owns the liveness branch from decision 6: a bound sid resolving to no session redirects
   to `/auth/level1` and no code is created; a live session proceeds. Extend `TestHandleIssueGet`
   rather than adding a sibling, inheriting its setup. Its "Successfully issues a code" subtest gains
   the session lookup and the compensating call to its mock expectations, which is a second
   non-additive cost alongside seam 6's. Whether the compensating statement *works* belongs to seam 4,
   so this seam asserts only that it is issued.

   Note the implicit-flow subtests in the same file also reach `HandleIssueGet`, and
   `handleImplicitFlow` issues tokens directly without creating a code. Whether the liveness check
   sits before or after the implicit-flow branch decides whether those subtests change; put it after,
   so implicit flow is untouched and the check guards only `issue/create-code`.

### Integration tier, dev container

8. **`POST /auth/token`** (existing suites). The highest seam that can observe the advertised
   behaviour, and where the headline claim is proven without reaching into storage: authorize with
   `offline_access`, terminate the session, then refresh and expect rejection. Paired with the reverse
   assertion, that a grant on an **unrelated** session still refreshes, since without it the test
   passes against a change that revokes everything.

9. **The session-management endpoints** (existing suites: `api_users_sessions_test.go`,
   `api_account_sessions_test.go`, `api_account_logout_request_test.go`, `session_deletion_test.go`).
   Owns three contracts at once:

   - both `DELETE` endpoints revoke, with ownership still enforced on the account one;
   - `/auth/logout` behaviour is **unchanged**, decision 3, including that a logged-out client's
     session-bound refresh token keeps working while other clients share the session. This pins
     today's behaviour so #135 has to change it deliberately.

     **Drive it through request shapes #109 is not rewriting**, per decision 13, or these tests
     encode #109's defects as intended behaviour and its author has to delete them. Concretely: the
     path that reaches `logout/last-client-delete` needs both `id_token_hint` and
     `post_logout_redirect_uri`, because #109 item 1 is that the second is wrongly required and its
     check returns before the teardown. Assert what #129 cares about, that no grant was revoked, and
     assert nothing about whether the parameter was required or how the redirect was built. If a case
     covers the no-hint POST at `logout/basic-post-fork`, it asserts only that #129 revoked nothing
     there; the surviving session row is #109's business, not a #129 expectation to lock in;
   - the mid-flight ceremony, gap 3, driven on one HTTP client so the cookie is shared: begin an SSO
     ceremony, terminate the session before it completes, and assert no usable code is issued. Plus
     the #46 case, `test/fresh-ceremony-after-delete`, still green, which is the pair that proves
     decision 6 chose the right predicate rather than merely a strict one.

### Catalog, host

10. **`src/core/i18n/catalog_hygiene_test.go`** (existing suite). Decision 14's six new keys need
    **no new test code**, and that is the finding rather than an omission: `TestCatalog_ParityEnPtBR`
    already fails in both directions when a key exists in one catalog and not the other, and
    `TestCatalog_NoEmptyValues` already fails on a key present with an empty value, which go-i18n
    otherwise renders as the raw key in the UI. Adding the keys to both files is what makes the
    existing guard cover them. The step that adds them states this explicitly, so a reviewer does not
    read the absence of new cases as the copy being untested.

**Rejected seams**

- **Asserting `codes.revoked` from handler or integration tests.** A side channel into storage: it
  passes with the endpoint broken, and it breaks on any refactor that moves the fact. The endpoint
  observation is "the refresh is refused". Seams 1 to 4 own the column.
- **Mock expectations as the only evidence for the new data methods.** A mock proves callers propagate
  what it returned, never that the real implementation avoids collapsing a query, scan or `rows.Err()`
  failure into a benign zero. For a method that gates access, that fails open for the duration of a
  database fault with the suite green. Seams 1 and 4 carry real cases for exactly this.
- **A unit seam as the primary home for the termination helper's atomicity.** `revocation_test.go` is
  mock-based, following #106, so it can show the transaction is threaded through all three writes but
  not that a failure rolls them back. The helper gets unit coverage there for the threading, and
  seam 1's rolled-back-transaction case plus seam 9 carry the atomicity.
- **A new test file for the termination helper.** `revocation_test.go` already exists beside it and
  owns this shape.
- **A render test for the three session templates.** `internal/rendertest` covers account phone,
  address and profile only, so the session pages would need new harness setup to assert that one
  `msg +=` line reaches a JavaScript string. That proves the template compiles, which the existing
  build already proves, and it is the padding testing.md warns about. Seam 10 covers what can
  actually regress: a key missing from one catalog, or present and empty.

> **Obligation for the run.** Per section 5 of the testing reference, every table above is executed in
> the scratchpad before it is written into section 6, and re-run after any revision. Counts are never
> carried forward across a change.

---

## 6. Plan

Eight stages, written by the run on 2026-08-04. The order is chosen so that no intermediate commit
leaves the tree half live: the column and its sweep exist before anything rejects on them, rejection
exists before anything writes the marker, and gap 2 lands last per decision 1 while still blocking
the issue.

**On the two unit test files section 1 says do not exist.** Neither
`handler_api_users_sessions_test.go` nor `handler_api_account_sessions_test.go` exists, and section 1
says "whichever stage touches those handlers creates the file". **Stage 4 creates both**, per section
1, and the history is recorded because the first draft of this plan declined to.

The first draft read section 5's "every seam here is an existing test file" as overriding section 1,
and cited `testing.md`'s rule against testing at an unconfirmed seam. The plan review refuted that,
and the refutation is right. Section 5 rejects **mock expectations as the only evidence for the new
data methods** and rejects **a unit seam as the primary home for the helper's atomicity**. It rejects
neither a handler test for handler-owned behaviour, and an HTTP handler is a public boundary that
section 1 named explicitly, so the seam is confirmed rather than invented.

What decided it is that decision 9's contract has no other home. Each handler must emit **both** audit
events after the termination commits, and **neither** when it fails. The integration tier can observe
the success half, since `api_settings_audit_logs_test.go` reads `GetAuditLogsPaginated` directly, but
it cannot force the termination transaction to fail, so nothing there can prove the events are
suppressed on failure. A mock-based handler test is the only seam that can. `revocation_test.go` still
owns the transaction threading and seams 8 and 9 still own the observable token rejection, because the
handler tests do not replace either. Precedent for the harness: `handler_api_account_password_test.go`
and five siblings, over `test_main_test.go`.

**The obligation above was met before this section was written.** Stage 1's tables were executed
against all four engines first, and three of its rows changed as a result. What changed is recorded in
the stage 1 entry of section 7.

### Stage 1: the marker column and its sweep
Status: **Done**
Seams: 1 and 2, plus a migration test following the 000024 and 000025 precedent.
Tiers: unit (three modules), data (four engines). Integration not applicable, no endpoint changes.
Docs: none, internals only. Verified in section 2 that `CLAUDE.md` and `AGENTS.md` enumerate neither
migrations nor the `codes` table, and no page on the docs site describes either.

Each step carries its status on its own numbered line, because that is what the guard parses. A status
on a continuation line reads as an untraced step and refuses the gate.

1. **Migration `000026_add_code_revoked`, up and down, on four engines.** Status: **Done**
   Types follow `refresh_tokens.revoked` on each: sqlite `numeric`, mysql `tinyint(1)`, postgres
   `boolean`, mssql `BIT`. Each declares `NOT NULL DEFAULT` false, and mssql names its default
   constraint `df_codes_revoked` so the down migration can drop the constraint before the column,
   which is the hazard 000024 documents. **No index**: the sweep is keyed on `session_identifier`,
   which `idx_codes_session_identifier` from 000024 already covers, and stage 7's reaper scans by
   `created_at`.
2. **The four `schema.sql` snapshots gain the column.** Status: **Done**
   In the position the migration puts it, after `used`. Documentation only, never loaded by Go.
3. **`models.Code.Revoked`, tagged `dont-update`.** Status: **Done**
   With the comment decision 4 requires: an ordinary full-row `UpdateCode` must not be able to write
   the marker back to false. Mirrors `Code.AuthStateGeneration`.
4. **`RevokeCodesBySessionIdentifier(tx, sid) (int64, error)`.** Status: **Done**
   In `commondb/code.go`, declared in the `Code` block of `data/database.go`, with the one-line
   wrapper in each of the four engine packages and regenerated mocks
   (`authserver/generate-mocks.sh`, run in the dev container). The predicate is
   `session_identifier = ? AND revoked = false`, the assignment sets `revoked` and `updated_at`, and
   the return is `RowsAffected`. An empty identifier returns an error rather than being used as a
   filter.
5. **`db/mark-code-used` gains `AND revoked = false`.** Status: **Done**
   With the comment section 4.3 requires: validation and claiming are separate steps, so without this
   term a code revoked in between is still claimed. The interface doc comment gains the same note.
6. **Data cases at seam 1, in `code_test.go`, all four engines.** Status: **Done**
   Two tests: the sweep's table, and the transaction and failure path a mock cannot answer for. The
   rows, all executed before being written here:

   | Case | Expected | Which gate rejects it, or what it proves |
   |---|---|---|
   | two codes on session A, sweep A | count 2, both `Revoked` | the sweep reaches every code of the session |
   | a code on unrelated session B | stays `Revoked = false` | the negative control; without it a method revoking the whole table passes |
   | sweep A again | count 0, rows stay revoked | idempotent, and the count means rows transitioned |
   | unknown identifier | count 0, no error | absence is not an error |
   | empty identifier | error, nothing swept | the explicit guard, not the `=` predicate |
   | sweep inside a transaction, then roll back | `Revoked = false` afterwards | it enlisted in the caller's transaction rather than the pool |
   | sweep on the finished transaction | error, count 0 | the failure path does not collapse into a benign zero |

   **Keep the unrelated-session row and the rolled-back row.** The first is the only case that fails
   if the sweep is written session-wide by mistake, which would sign out every device of every user.
   The second is the only case exercising the real implementation's transaction handling; every
   mock-based test above it passes with the parameter ignored.
7. **Data cases at seam 2, extending `TestMarkCodeAsUsed`.** Status: **Done**
   A revoked but unused code is **not** claimable, and stays unused afterwards. **Keep the existing
   already-used row beside it**, since either row alone still passes with the other term deleted from
   the predicate. Plus `TestUpdateCode_DoesNotClobberRevoked`, mirroring the four existing
   `DoesNotClobber` tests, which is the only case that fails if the `dont-update` tag on the model
   field is dropped.
8. **`migration_000026_code_revoked_test.go`.** Status: **Done**
   Following 000024 and 000025: the column is absent at 000025, is `NOT NULL` defaulting to false
   afterwards, a `codes` row that predates it lands `revoked = false`, and the down migration then
   the re-apply are clean. The pre-existing row is seeded through the ORM at 000026 and carried down
   to 000025 and back, rather than hand-written at 000025, which is what makes the case affordable:
   `codes` has twenty NOT NULL columns and foreign keys into `clients` and `users`.
9. **Verify.** Status: **Done**
   `check-anchors.sh`, then `where.sh test --type modules` and
   `where.sh test --type data --db <each of the four>`.

**As built.** Every step landed as written, with two departures worth naming.

`handler_token.go` was edited, which no step listed: a comment rewrite and one changed `slog.Debug`
message, no behaviour. Step 5 made the old text false, because a false return from
`db/mark-code-used` now means "no row transitioned" rather than "already used", and the comment there
told the reader it meant authorization-code reuse. The reviewer found it, and the fix belongs to this
stage rather than a later one because this stage is what falsified it.

The order was inverted against the skill: the code existed before section 6 did. Section 5's closing
obligation requires the case tables to be executed before they are written down, and a data-tier table
cannot run without the migration and the method. Section 7's plan entry records what executing them
changed, which is the return on doing it in that order.

### Stage 2: rejection at redemption and at refresh
Status: **Done**
Seams: 5. Tiers: unit. Docs: none, internals only. Nothing a user can observe changes until stage 4
writes a marker, and no page states today's behaviour on either path.

1. **The `authorization_code` rejection.** Status: **Done**
   In `ValidateTokenRequest`, read `codeEntity.Revoked` after client-secret validation, after PKCE and
   after the `if wasReused` return, immediately before the success return. Generic `invalid_grant`,
   "Code is invalid.", matching its neighbours. Carries the comment decision 7 requires: it sits apart
   from `validator/authcode-preauth` because that block runs before client authentication, so a check
   placed there tells a presenter of a stolen code whether the session was terminated, which is the
   class #137 exists to close; and it sits after the reuse return so #77's cascade is not pre-empted,
   reuse being the stronger signal that already revokes everything this check would refuse.
2. **The `refresh_token` rejection.** Status: **Done**
   Read `refreshToken.Code.Revoked` immediately after `validator/client-ownership`, before the `typ`
   switch. Guarded by `!isROPCToken`: a ROPC token has `code_id = NULL` and no session, so it has no
   grant origin to terminate, and reading the zero-valued `Code` on that path would be meaningless
   rather than merely harmless. Reuses the Refresh branch's existing message by lifting its `const`
   to the case scope, so the two paths cannot drift into two spellings of one fact.
3. **Unit cases at seam 5.** Status: **Done**
   New `TestValidateTokenRequest_RevokedCode`, mirroring `TestValidateTokenRequest_AuthStateGeneration`
   in shape: table-driven subtests over both grant types plus ROPC, on the same mock trio. The rows,
   expectations written before running them:

   | Case | Expected | Which gate rejects it |
   |---|---|---|
   | auth code, revoked, everything else correct | `invalid_grant` | the new revoked check |
   | auth code, not revoked | accepted | none, the positive control |
   | auth code, revoked, wrong PKCE verifier | `invalid_grant`, "Invalid code_verifier (PKCE)." | PKCE, which is ahead of it |
   | auth code, revoked, confidential client with no secret | `invalid_client` | client authentication, ahead of it |
   | auth code, revoked, already used so reuse is detected | `AuthCodeReusedError` | the `wasReused` return, ahead of it |
   | refresh, revoked code, correct client | `invalid_grant` | the new refresh check |
   | refresh, revoked code, wrong client | `invalid_request`, "does not belong to the client" | ownership, ahead of it |
   | refresh, ROPC token with no code | accepted | not applicable, no grant origin to terminate |
   | refresh, code not revoked | accepted | none, the positive control |

   **The three ordering rows are decision 7's only testable content.** Each varies exactly one thing
   from the first row and names the gate that must answer instead, so none of them can pass if the
   revoked check drifts up into `validator/authcode-preauth`. Two positive controls, one per grant
   type, because a check that rejected everything would pass every negative row.
4. **Verify.** Status: **Done**
   `check-anchors.sh`, then `where.sh test --type modules`. No data or integration tier: this stage
   adds no query and changes no endpoint.

**As built.** Both checks landed exactly where step 1 and step 2 put them, and the `const
invalidTokenMessage` was lifted to the case scope as planned, so the two ways a grant's session can
stop backing it share one spelling. Three anchor rows were added to section 0 for the new code:
`validator/code-revoked`, `validator/refresh-code-revoked` and `test/revoked-code-ordering`.

**One departure, and it is the review's.** Step 3's table listed nine rows; ten shipped. The extra one
is `test/revoked-code-ordering`, a **present but wrong** client secret, added because the review's
round 1 finding showed the planned missing-secret row was the benign member of its class. Recorded in
full in section 7, because the reasoning is the useful part: a missing secret is refused by a length
check that runs before decryption, so that row alone would have stayed green under a relocation of the
revoked check into the confidential branch just ahead of `subtle.ConstantTimeCompare`, which is
exactly the oracle decision 7 exists to prevent.

### Stage 3: the termination helper, uncalled
Status: **Done**
Seams: `revocation_test.go`, which section 5 names as the helper's home and which owns the
transaction threading, the zero result on the error path, and decision 5's write order. Section 5's
rejected-seams list is what keeps that scope honest: this file is mock based, so seam 1's
rolled-back-transaction case and seam 9 own the atomicity, and this seam owns only what a mock can
answer for.
Tiers: unit (three modules). Integration and data not applicable: no endpoint changes, no query added,
and every data method called here was covered on four engines in stage 1 or already existed.
Docs: none, internals only. Nothing calls the helper, so nothing observable changes until stage 4.

Deliberately inert, which is the plan review's second finding: stage 4 carries the endpoint calls and
every piece of user-facing material about them in one commit, so this stage cannot deploy the broader
security action ahead of the copy describing it.

**The docs line is verified rather than assumed, because the new audit event does reach a UI
surface.** `AuditEventTypes` feeds the audit log viewer's event filter, and
`admin_settings_audit_log_viewer.html` renders `{{range .auditEventTypes}}` into
`<option value="{{.}}">{{.}}</option>` with no `T` call, so the new event appears there as the raw
identifier exactly as the other 94 do. No catalog key, and per section 2 `concepts/audit-log.mdx`
points at `constants.go` rather than enumerating events.

1. **`AuditTerminatedUserSession`, and its three registrations.** Status: **Done**
   Landed at `audit/terminated-session`, with `constants_test.go` at `expectedCount` 95.
   In `constants.go`, the constant `terminated_user_session` placed after `AuditRevokedUserAuthState`,
   whose doc comment is the convention for a security event of this shape: why it exists beside
   `AuditDeletedUserSession` rather than replacing it, that it fires only after the termination
   transaction commits, and that it is the event to count for terminations, which is decision 9's own
   stated downside. Plus its entry in `AuditEventTypes`, which `TestAuditEventTypes_Alphabetical`
   sorts by **value**, so it belongs between `AuditStartedNewUserSesson` and
   `AuditTokenIssuedAuthorizationCodeResponse`. Plus `constants_test.go`: `expectedCount` 94 to 95 and
   the entry in `allAuditConstants`, which `TestAuditEventTypes_MatchesConstants` compares in both
   directions and by count. Three registrations rather than one, and those two tests are why
   forgetting any of them fails loudly instead of quietly.
2. **`TerminationResult`.** Status: **Done**
   Landed in `revocation.go` beside `RevocationResult`, two fields, as written.
   In `revocation.go` beside `RevocationResult`, carrying exactly what decision 9's payload needs
   beyond the caller's own inputs: `RevokedCodeCount int64` and `RevokedRefreshTokenJtis []string`.
   The count is what this call **transitioned**, not what the session has, so a second termination of
   the same session reports 0, which is the only question the audit event has to answer. `userId`,
   `userSessionId` and `sessionIdentifier` stay out: the caller already holds the session row, and
   restating them here would let a result and its payload disagree.
3. **`TerminateUserSessionTx(db, userSession) (TerminationResult, error)`.** Status: **Done**
   Landed at `revoke/terminate-session`, no inner variant, both entry guards ahead of the
   transaction.
   In `revocation.go`, owning its own transaction and committing it, with decision 5's three writes in
   decision 5's order: `RevokeCodesBySessionIdentifier`, then the sid-scoped sweep through
   `db/refresh-by-sid` fed into `revoke/refresh-tokens`, then `DeleteUserSession`. The zero result on
   every error path, since the code sweep can succeed and the transaction still roll back, and a
   caller that audits a count from a rolled-back transaction records a revocation that never happened.
   The comment carries three things a later reader needs: that step 1 is the write which survives and
   steps 2 and 3 are cleanup, that the sid-scoped **query** is the only thing reaching an offline
   grant's tokens because their own `session_identifier` is empty (decision 2), and that this
   deliberately does not advance the user's generation, because that would sign out every other device
   the user has (section 4.6).

   Takes the loaded `*models.UserSession` rather than an id plus a sid, because two of the writes key
   on the identifier and the third on the id: from one row they cannot disagree, and both call sites in
   stage 4 already load it for their 404 and their ownership check. Nil and an empty identifier are
   refused at entry, before the transaction opens, which is where `RevokeUserAuthState` puts its own
   precondition for the same reason.

   **No inner `TerminateUserSession(db, tx, ...)` variant**, which is the one place this departs from
   the shape of `RevokeUserAuthStateTx`. #106 needed the split because a credential write had to join
   the same transaction through a callback; nothing composes with this one, so a second entry point
   would be surface with no caller and a second contract to keep straight.
4. **Unit cases at the seam.** Status: **Done**
   Landed as four test functions over 10 leaf cases, including `test/terminate-offline-token` and
   `test/terminate-zero-result`. Every row below shipped.
   In `revocation_test.go`, on the strict `mocks_data.Database` the file already uses, so an
   unexpected or missing call fails a case on its own. Fixture: three refresh tokens on the terminated
   session, `rt-session-bound` (own sid set), `rt-offline` (own sid **empty**, code id set) and
   `rt-already-gone` (already revoked). Expectations written before running them:

   | Case | Expected | Which mechanism rejects it, or what it proves |
   |---|---|---|
   | a session with two live grants and one already-revoked token | the sweep's count reported as-is, JTIs `[rt-session-bound, rt-offline]`, session deleted, committed | the happy path and decision 9's payload |
   | the offline token, whose own `session_identifier` is empty | revoked | decision 2: the sid-scoped query is the only thing that reaches it, and this row fails against an implementation that filters the returned rows by `rt.SessionIdentifier` |
   | the already-revoked token | absent from the JTIs, and not written again | #77's invariant, inherited from `revoke/refresh-tokens` |
   | the user's generation, and the user-scoped token query | never called | section 4.6 and decision 5's table: a user-scoped sweep signs out every other device |
   | write order | codes, then tokens, then the delete | decision 5 states it. Within one transaction it is **not** a safety boundary, and neither sweep reads `user_sessions`, so this pins the design's order rather than a correctness property |
   | nothing to revoke: no codes, no tokens | count 0, JTIs empty and non-nil, session still deleted and committed | ending a session with no grants is not an error, and the payload carries `[]` rather than null |
   | nil session | error, `BeginTransaction` never called | the entry guard |
   | empty session identifier | error, `BeginTransaction` never called | the entry guard. Without it the sweep refuses it three statements later, inside an open transaction, and it reads as a database fault |
   | `BeginTransaction` fails | zero result, error | |
   | the code sweep fails | zero result, and no token query, no delete, no commit | |
   | the token query fails **after the code sweep returned 2** | zero result, `RevokedCodeCount` **0** | **keep this row.** It is the only one that fails against a partially populated result, which is exactly what would let a caller audit a revocation that rolled back |
   | a token write fails | zero result, and no delete, no commit | |
   | the delete fails | zero result, and no commit | |
   | the commit fails | zero result | the caller must not audit, and the durable outcome is indeterminate per the helper's comment |
5. **Verify.** Status: **Done**
   `check-anchors.sh`, then `where.sh test --type modules`. Four anchor rows added for the new code,
   not three: the plan undercounted, because `TerminationResult`'s two fields need no anchor of their
   own but both new test functions do.

**As built.** All five steps landed as written. Four anchor rows in section 0 rather than the three
step 5 predicted, and 10 leaf cases rather than the "13" an earlier draft of this note claimed, which
is what re-running the suite at the gate rather than quoting it is for: 2 standalone tests plus 2 and 6
subtests, over `TestTerminateUserSessionTx_RevokesTheGrantsOfTheSession`, `_NothingToRevoke`,
`_RejectsAnUnusableSession` and `_AnyFailureYieldsTheZeroResult`.

Two deviations, both in `constants_test.go` and both small. The event was also added to
`criticalEvents` in `TestAuditEventTypes_ContainsCriticalEvents`, which step 1 named only
`expectedCount` and `allAuditConstants`; the argument is #106's own, one entry above it in the same
list, that `deleted_user_session` survives either way, so an event that stopped being emitted would
leave the security action with only a lifecycle record and nothing attesting what it revoked. And the
review moved one displaced comment in `revocation_test.go`, recorded in section 7.

### Stage 4: both endpoints terminate, and everything that says so
Status: **Done**
Seams: the two new handler test files section 1 asked for, 8 (`POST /auth/token`), 9 (the
session-management endpoints) and 10 (the catalogs, which need no new test code).
Tiers: unit (three modules), integration (dev container). Data not applicable, and deliberately so:
this stage adds no query and no migration, and every data method it reaches was covered on four
engines in stage 1 or already existed.
Docs: all of section 2's "Documentation owed", minus the two ceremony sentences held back for stages
5 and 6.

The activation stage. It carries the endpoint calls **and** every piece of user-facing material about
them, in one commit, so no deploy can perform the broader security action while a page or a modal
still describes the narrower one. That pairing is the plan review's second finding and the reason
stage 3 above is inert.

**The new concepts section is limited to what is true when this lands**: what the two endpoints revoke
(decision 2) and decision 11's limit, that an offline grant's access token keeps working until it
expires. It must **not** yet claim that an in-flight ceremony cannot recreate the session, because
that is stages 5 and 6, and documenting a fail-open path as closed is worse than documenting nothing.
Those two sentences land with the stages that make them true.

1. **`LogTerminatedUserSession`, one emitter for decision 9's payload.** Status: **Done**
   In `revocation.go` beside `LogRevokedUserAuthState`, which is the precedent and states the reason:
   one function rather than two literals, so the payload cannot differ between the two sites and there
   is a single place to assert its shape field by field. Takes the loaded `*models.UserSession` for the
   same reason `TerminateUserSessionTx` does, since `userId`, `userSessionId` and `sessionIdentifier`
   all come off that one row and so cannot describe two different sessions. Six keys, exactly decision
   9's: `userId`, `userSessionId`, `sessionIdentifier`, `revokedRefreshTokenJtis`, `revokedCodeCount`,
   `loggedInUser`.
2. **`admin/session-delete` terminates.** Status: **Done**
   Replace `database.DeleteUserSession(nil, sessionId)` with `handlers.TerminateUserSessionTx(database,
   userSession)`, the session row being already loaded for the pre-existing 404. On error, the existing
   500 and **no** audit event of either kind. On success, `AuditDeletedUserSession` first with its
   payload untouched, then `LogTerminatedUserSession`. The 404 and the two 400s answer before the
   helper, unchanged, so a missing session never opens a transaction.
3. **`account/session-delete` terminates.** Status: **Done**
   The same replacement, with the ownership check still ahead of it: `us.UserId != user.Id` answers 403
   before the helper is entered. Same event pair, same order, same failure contract.
4. **Unit cases at the admin handler, in a new `handler_api_users_sessions_test.go`.**
   Status: **Done**
   Section 1 recorded that neither handler test file exists, and the preamble to this section records
   why the first draft of the plan wrongly declined to create them. On the strict `mocks_data.Database`
   and `mocks_audit.AuditLogger` the sibling files already use, with a thin `stubTermination` helper
   following `stubSweep`'s precedent in `handler_api_account_password_test.go`: thin because
   `revocation_test.go` owns the termination table exhaustively and restating it here would mean two
   places to update. Expectations written before running them:

   | Case | Expected | Which mechanism answers, or what it proves |
   |---|---|---|
   | a live session, helper succeeds | 200, both events, and `terminated_user_session` carrying exactly decision 9's six keys | decision 9's payload, field by field, asserted with a length check so a dropped key cannot pass |
   | the same case, the older event's payload | exactly `userSessionId` and `loggedInUser` | decision 9 promises it is untouched, so an external consumer parsing it strictly keeps working |
   | the helper fails, the code sweep erroring | 500, **neither** event, no commit | **keep this row.** It is the contract that decided the file's existence: the integration tier can read audit rows but cannot force the termination transaction to fail, so nothing above the unit tier can prove the events are suppressed |
   | the session id is not found | 404, and `BeginTransaction` never called | the pre-existing 404 still answers first. Without this row a handler that terminated before checking would pass every other row |

5. **Unit cases at the account handler, in a new `handler_api_account_sessions_test.go`.**
   Status: **Done**
   Same harness, and the token context through `setTokenContextWithClaims`, which the profile-picture
   test file already provides:

   | Case | Expected | Which mechanism answers, or what it proves |
   |---|---|---|
   | the caller's own session, helper succeeds | 200, both events, decision 9's six keys | the self-service half of decision 5 |
   | another user's session | 403, and `BeginTransaction` never called | ownership answers before termination. **Keep this row:** a handler that terminated first and then returned 403 satisfies every existing test in the suite, because the pre-existing integration case asserts only the status code |
   | the helper fails | 500, neither event | the same suppression contract, at the second site, because the two emitters are adjacent in the code and it is easy to leave one outside the error check |

6. **Decision 14's three keys in each catalog, and one line in each of three templates.**
   Status: **Done**
   `modal_revocation_note` under the three prefixes decision 14's table names, placed between
   `modal_confirm_body_suffix` and the current-session warning in each catalog, which is the order the
   template appends them in. Two wordings, second person on the account page and third person on the
   two admin pages, exactly as decision 14 sealed them, plus the pt-BR drafts refined against the
   register of the neighbouring strings. **No double quote in any of the six values**, since each is
   interpolated into a JavaScript double-quoted literal inside `endSessionClick`, and the `msg +=` line
   goes **before** the `if (isCurrent)` append so the immediate-logout warning stays last.
   **Seam 10 needs no new test code, and that is the finding rather than an omission.**
   `TestCatalog_ParityEnPtBR` already fails in both directions when a key exists in one catalog and not
   the other, and `TestCatalog_NoEmptyValues` already fails on a key present with an empty value, which
   go-i18n otherwise renders as the raw key in the UI. Adding the keys to both files is what puts them
   under the existing guard. Stated explicitly so the absence of new cases does not read as untested
   copy.
7. **The docs site, four pages.** Status: **Done**
   Per section 2's "Documentation owed", and per section 2's verified list of what owes nothing:
   `concepts/audit-log.mdx` points at `constants.go` rather than enumerating events,
   `integration/endpoints.mdx`'s `/auth/logout` description stays accurate because decision 3 leaves
   logout unchanged, and `CLAUDE.md` and `AGENTS.md` enumerate neither migrations nor the `codes` table.
   - `concepts/tokens.mdx`, offline refresh tokens: the two falsified sentences. The distinction
     decision 4 rests on is the one to draw, a session **expiring** still leaves an offline grant
     working and a session **explicitly ended** does not.
   - `concepts/user-sessions.mdx`: a new `## Ending a session` section after "Credential changes and
     live sessions" and before "Forcing re-authentication", covering what the two endpoints revoke
     (decision 2), decision 11's limit that an offline grant's access token keeps working until it
     expires because it carries no session identifier to check, and decision 9's counting note. Without
     that limit a reader generalizes the credential-change bullet, "reject a token from a superseded
     session on the very next request", to termination and is wrong.
   - `integration/rest-api.mdx`: one sentence on each of the two endpoints, linking to the new section.
   - `reference/security.mdx`, "Authentication security": a durable-termination bullet in the shape of
     the "Replay containment" one, which is the established shape for a security property here.
8. **Integration cases at seams 8 and 9.** Status: **Done**
   All in existing suites, per section 5. The harness is #106's: `createOfflineGrant` runs a full
   `offline_access` ceremony through the real login and consent screens and returns the grant plus the
   session identifier read off the `codes` row, and `offlineGrant.refresh` presents its refresh token.
   One new helper, `secondOfflineGrantForSameUser`, which is `secondSessionFor` with the offline scope:
   a fresh cookie jar and a distinct `User-Agent`, the latter load bearing rather than cosmetic because
   `StartNewUserSession` deletes other sessions of the same user sharing device name, type, OS and IP.

   | Case | File | Expected | What it proves |
   |---|---|---|---|
   | two offline grants of the **same user** on sessions A and B, admin `DELETE` on A | `api_users_sessions_test.go` | both refresh before, then A's refresh `invalid_grant` and B's still works | the headline claim at the highest seam that can observe it, plus the control seam 8 requires. **The control belongs to the same user deliberately:** it varies only the session, so it rejects a table-wide sweep and a user-scoped one at once, where an unrelated user's grant would leave the second untested |
   | one offline grant, account `DELETE` on the caller's own session | `api_account_sessions_test.go` | refresh refused | the self-service half, end to end |
   | another user's session holding an offline grant, account `DELETE` | `api_account_sessions_test.go` | 403 **and** that grant still refreshes | ownership answers before termination, observed rather than mocked. The pre-existing 403 case asserts only the status, which a handler terminating first would still satisfy |
   | `/auth/logout` with `id_token_hint` and `post_logout_redirect_uri`, the session's only client | `api_account_logout_request_test.go` | 302 to the post-logout redirect, and the offline refresh token still works | decision 3: logout revokes nothing, in every case. The 302 assertion is what stops the case passing because logout did nothing at all |
   | the same, with a second client on the session | `api_account_logout_request_test.go` | the logged-out client's **session-bound** refresh token still works | decision 3's second contract, pinned so #135 has to change it deliberately. The second client is created directly with `CreateUserSessionClient`, which this suite already does, because what matters is the count `handleExistingSessionOnLogout` reads |
   | `test/fresh-ceremony-after-delete` | `session_deletion_test.go` | unchanged and green | #46's guard. No new code, named because it is the case decision 6 must not break and stage 5 depends on it |

   **Driven through request shapes #109 is not rewriting**, per decision 13. Both logout cases supply
   `id_token_hint` **and** `post_logout_redirect_uri`, because #109 item 1 is that the second is wrongly
   required and its check returns before the teardown. They assert only what #129 cares about, that no
   grant was revoked, and nothing about whether the parameter was required, how the redirect was built,
   or whether the session row survived, which is #109 divergence B's business. The hint is taken from
   the token exchange's own `id_token` rather than from the logout-request API, so the case does not
   depend on that API's client resolution, which is also #109's surface.

   **What this tier deliberately does not prove.** The marker's distinctive property, that a child
   inserted after termination is born already rejected, is invisible here: the sweep revokes every
   token that exists at termination, so these cases would pass against a sweep with no marker at all.
   That is correct division of labour, seams 1 to 4 own the column and section 5 rejects asserting
   `codes.revoked` from an integration test, and stage 8 owns the racing-child evidence.
9. **Verify.** Status: **Done**
   `check-anchors.sh`, then `where.sh test --type modules` and `where.sh test --type integration`. The
   integration tier runs for the first time this run, so a failure there is as likely to be harness as
   regression and gets diagnosed rather than worked around.

**As built.** All nine steps landed as written. Five deviations, all small, plus one omission with a
stated reason.

1. **Two sealed anchor rows were re-swept**, which no earlier stage had to do: `admin/session-delete`
   and `account/session-delete` cited the bare `DeleteUserSession` calls this stage replaced, so their
   locators resolved to nothing. Both now cite the helper call and say in their note that stage 4
   re-swept them. Stage 1's line "Nothing above the line changed" no longer holds, and saying so here
   is cheaper than leaving a reader to notice.
2. **Nine anchor rows added**, more than any earlier stage, because the stage created two test files,
   an emitter, a catalog key and four integration cases.
3. Both handlers hoist `authHelper.GetLoggedInSubject(r)` into a local rather than calling it twice,
   one call per event. No behaviour change; it just stops the two payloads reading as though they
   could disagree.
4. `secondOfflineGrantForSameUser` landed in `credential_change_revocation_test.go`, which is #106's
   file, rather than in the suite that uses it. That is where `offlineGrant`, `createOfflineGrant` and
   `secondSessionFor` already live, and it sits directly beneath the helper it mirrors.
5. The consent branch the helper was going to need turned out to be unnecessary: both
   `HandleAuthCompletedGet` and `HandleConsentGet` route an `offline_access` request to consent
   unconditionally, to re-confirm the refresh token grant, so the second ceremony is deterministic and
   the helper asserts the consent screen rather than branching on it. Verified in both handlers.
6. **Omitted deliberately: a case for the no-hint POST at `logout/basic-post-fork`.** Seam 9 made it
   conditional, "if a case covers the no-hint POST", and it was not written. That path calls no
   revocation code at all, so a case there would pin nothing the `id_token_hint` cases do not already
   pin, and decision 13 leaves the path itself to #109, where it is drafted as follow-up 2.

### Stage 5: the `/auth/completed` gate
Status: **Not started**
Detail: **sketch**

Decision 6's first half: in `HandleAuthCompletedGet`, reach `completed/start-new-session` only when
`!hasValidUserSession && !userReallyAuthenticated` is false, otherwise set `AuthStateRequiresLevel1`,
save, and redirect to `/auth/level1`. The discriminator is already computed at
`completed/really-authenticated` and today is consulted only in the branch where it does not matter.
Carries the comment decision 6 asks for about `handlePromptNone` being the fragile neighbour. Seam 6,
whose new row asserts the redirect and that `StartNewUserSession` is not called, and whose three
existing subtests gain a non-nil `AuthenticatedAt`, which is the non-additive cost section 1 recorded.
Tier: unit. Docs: the first of the two sentences held back from stage 4's concepts section, that a
ceremony in flight cannot complete into a recreated session. Expand against stage 4's code.

### Stage 6: the `/auth/issue` liveness check and the compensating revoke
Status: **Not started**
Detail: **sketch**

Decision 6's second half plus decision 12. A liveness read at `/auth/issue`, placed **after** the
implicit-flow branch so `handleImplicitFlow` is untouched and only `issue/create-code` is guarded:
when the bound session identifier resolves to no session row, restart level 1 as in stage 5.
Immediately after the insert, one compensating statement as a new data method on four engines,
`UPDATE codes SET revoked = true, updated_at = ? WHERE id = ? AND NOT EXISTS (SELECT 1 FROM
user_sessions WHERE session_identifier = ?)`, so a code that committed after the termination's sweep
read `codes` is marked by the second sweeper. Seams 4 (the data method, whose "does nothing when a
session exists" row is the one that matters, since a method that always revoked would pass every
other assertion) and 7 (the liveness branch, extending `TestHandleIssueGet`). Tiers: unit, data,
integration for the mid-flight ceremony on one HTTP client, plus the #46 guard still green, which is
the pair proving decision 6 chose the right predicate rather than merely a strict one. Docs: the
second sentence held back from stage 4's concepts section, the consent-screen window.

### Stage 7: reaping unused revoked codes
Status: **Not started**
Detail: **sketch**

Decision 8's one predicate extension, so a code revoked while still unredeemed does not accumulate
forever: `revoked = true AND used = false AND created_at < cutoff`, which is safe with a short cutoff
because an unused code has no refresh tokens by definition and is unredeemable after 60 seconds
anyway. Seam 3, whose load-bearing row is the **retention** one: a revoked code with a live refresh
token must survive, because decision 8's whole safety argument is that the marker outlives its
descendants, and that row's value is invisible once the design is right. Tier: data, four engines.
Docs: to confirm at expansion; the sweep of section 2 found no page describing the reapers, and
`concepts/audit-log.mdx` points at `constants.go` rather than enumerating events.

**Extend `DeleteUsedCodesWithoutRefreshTokens` itself. No second method and no second worker call.**
The first draft of this sketch offered the choice, which reopened something the seal had settled:
section 4.5 says one predicate is added, and seam 3 names the existing method extended. A new method
would add an unconfirmed data seam plus an interface method, four wrappers, regenerated mocks and its
own wiring in `worker/perform-task`. The method keeps its name, and its doc comment states the widened
contract, since renaming it would touch the interface, four wrappers, the mocks and the call site for
no behavioural gain.

### Stage 8: gap 2's evidence
Status: **Not started**
Detail: **sketch**

Gap 2 closes structurally in stages 1 and 2, since a rotated child inherits its parent's `code_id`
and so is born already rejected. What is missing is the proof, and decision 1 requires it before the
issue closes. An integration test mirroring `token_refresh_concurrent_test.go`'s harness: a grant
whose refresh races a termination leaves no usable descendant, checked both ways round, the child
issued before termination and the child issued after it, on an `offline_access` grant since a
session-bound one already dies at `validator/session-branch`. Seam 8. Tier: integration. Docs: none
unless the evidence contradicts what stage 3 documented, which would be a blocking decision rather
than a docs edit. Staged last per decision 1.

---

## 7. Run log

Append-only. The run started 2026-08-04T21:34:38Z, after an earlier start the same evening was
aborted before any stage began.

### Plan, 2026-08-04

**Landed.** Section 6, eight stages, stage 1 in full and the rest as sketches. Five rows added to
section 0 for the code stage 1 creates, below a line marking them as the run's rather than the seal's.
Draft PR [#138](https://github.com/leodip/goiabada/pull/138) opened and recorded in the header.

**Sequencing deviation, deliberate.** Stage 1's implementation was written **before** section 6 was.
Section 5's closing obligation, from `testing.md` section 5, is that every case table is executed
before it is written into the plan, and a data-tier table cannot be executed without the migration and
the method existing. So stage 1 was built, its tables were run on all four engines, and only then was
stage 1 written down. The code sat uncommitted through the plan review, which was told so and used it
as evidence.

**What executing the tables changed**, which is the return on doing it in that order:

1. The `revoked = false` term in the sweep predicate is load bearing for the **count**, not only for
   idempotence. MySQL reports changed rows rather than matched rows, and the `updated_at` assignment
   alone makes an already-revoked row count as changed, so without the term the same call reports 2 on
   MySQL and 0 on the other three. Decision 9's audit event carries that count.
2. SQLite declares `codes.code_challenge` and `code_challenge_method` NOT NULL where the other three
   engines allow NULL, so the migration test's seed passes on three engines and fails on one.
3. A zero `time.Time` for `authenticated_at` reaches MySQL as `'0000-00-00'`, rejected outright.

**Environment finding, not a code defect, and it cost half an hour.** The shared server test databases
`goiabada_data` and `goiabada_integration` on mysql, postgres and mssql were left at
`schema_migrations.version = 26` by the **discarded** earlier attempt at this issue, whose 000026 built
the `terminated_sessions` registry that decision 4 rejected. golang-migrate therefore reported "no need
to migrate" and every `codes` test failed with `Unknown column 'revoked'` on those three engines, while
sqlite was fine because its test database is a fresh file per run. Fixed by rewinding the recorded
version to 25 in those six databases. The orphaned `terminated_sessions` tables are still present and
inert; dropping tables was not something to do unattended. `goiabada` on mssql, a dev database rather
than a test one, is at 23 and clean.

**Review, round 1.** `gpt-5.6-sol`, effort high, `type: plan-review`. Conformance, quality and security
all reviewed. Ran: the request and the whole agreement, the complete stage 1 diff and its neighbours,
`check-anchors.sh` (42 anchors pass), `git diff --check`, and an attempt at `where.sh test --type
modules`.

**Not reached.** The reviewer could not run any test tier: `where.sh test` exited 3 for it, reporting
the dev container down, although the container is up and the run's own tiers were green from it. The
reviewer's sandbox cannot reach docker. So the tier results in this document are the run's, verified
from its own logs, and no review of this work will independently reproduce them. Later code-review
requests carry the test output in the request rather than expecting the reviewer to re-run it.

**Hash check.** `git diff | sha256sum` mismatched afterwards, which reviewer.md treats as a stop.
Investigated rather than accepted: every changed file's mtime predates the review except the
agreement, which the run itself edited at 18:54:30 local to record the PR. Reverting only that header
edit reproduced the `BEFORE` hash exactly, so the reviewer changed no tracked file. The real lesson is
procedural: do not edit tracked files while a review is running, or compute `BEFORE` immediately before
the call.

1. **The plan wrongly declined the two handler test files.** `Raised by: reviewer`, blocking,
   confidence high. Status: **Resolved**
   Verified and accepted. Section 5 rejects mock expectations as the only evidence for the **new data
   methods** and rejects a unit seam as the primary home for the **helper's atomicity**; it rejects
   neither a handler test for handler-owned behaviour, and section 1 named those two files explicitly,
   so the seam was confirmed rather than invented. What settles it is that decision 9's contract has no
   other home: the integration tier can read audit rows (`api_settings_audit_logs_test.go` calls
   `GetAuditLogsPaginated`) but cannot force the termination transaction to fail, so nothing there can
   prove both events are suppressed on failure. Stage 4 now creates both files, and the preamble to
   section 6 records the reversal instead of hiding it. Harness precedent confirmed:
   `handler_api_account_password_test.go` and five siblings over `test_main_test.go`.
2. **User-facing material was staged apart from the behaviour it describes.** `Raised by: reviewer`,
   significant, confidence high. Status: **Resolved**
   Verified in both directions. Forwards: the original stage 3 called both endpoints while decision
   14's modal copy waited until stage 4, so one deploy could perform the broader revocation without
   telling the person clicking, which contradicts goal 6. Backwards: the original stage 3 claimed all
   of section 2's docs, and section 2's new concepts section includes the in-flight ceremony guarantee,
   which does not exist until stages 5 and 6, so it would have documented a fail-open path as closed.
   Fixed by splitting: stage 3 is now an inert helper nobody calls, stage 4 is the activation stage
   carrying the endpoints, both handler suites, the integration cases, every docs page and all three
   modals in one commit, and the two ceremony sentences are explicitly held back for stages 5 and 6.
3. **Stage 7 reopened a seam the seal had settled.** `Raised by: reviewer`, significant, confidence
   high. Status: **Resolved**
   Verified: section 4.5 says one predicate is added and seam 3 names
   `DeleteUsedCodesWithoutRefreshTokens` extended, while the sketch offered "wire a second call or
   extend the method, whichever is cleaner". That is a design choice the seal removed, and the second
   option would add an unconfirmed data seam plus an interface method, four wrappers, regenerated mocks
   and its own worker wiring. Stage 7 now forces extending the existing method, keeping its name and
   widening its doc comment.

No finding needed the user. All three are conformance findings whose answer the sealed agreement
already fixes, so escalating them would have asked the user to re-decide what sections 1, 4.5 and 5
decide. Nothing was deferred and nothing is contested.

### Stage 1, 2026-08-04

**Landed.** Migration 000026 on four engines, the four `schema.sql` snapshots, `model/code-revoked`,
`db/revoke-codes-by-sid` with its interface declaration and four wrappers, the regenerated `Database`
mock, and `AND revoked = false` added to `db/mark-code-used`. Tests: `test/revoke-codes-data` and its
transaction-and-failure sibling, the revoked-but-unused row inside `TestMarkCodeAsUsed`,
`TestUpdateCode_DoesNotClobberRevoked`, and `test/migration-000026`. Commit `066d289`.

Nothing reads the marker yet, so this commit changes no observable behaviour. Stage 2 adds the
rejections and stage 4 wires the endpoints that write it.

**Tiers.** Unit green, all three modules. Data green on sqlite, mysql, postgres and mssql, each run
separately (`where.sh test --type data --db <engine>`), including the stage's five new or extended
tests on every engine. Integration not applicable: no endpoint, handler or observable flow changes
here, which the reviewer confirmed independently.

**Deviation 1, the sequencing.** Recorded in the plan entry above: the code preceded section 6 because
the tables had to be executed before they were written. Nothing else about the stage departs from the
plan as written.

**Deviation 2, one file the plan did not list.** `handler_token.go` gained a comment rewrite and one
changed `slog.Debug` message, no behaviour. It is the fix for finding 1 below, and it belongs to this
stage because this stage is what made the old comment false. The alternative, leaving a comment that
says every failed claim is reuse, would have handed the next reader a wrong contract.

**Review, round 1.** `gpt-5.6-sol`, effort high, `type: code-review`. Conformance, quality and security
all reviewed. Ran: the request and the full agreement, the complete stage 1 diff and the neighbouring
redemption paths, `git diff --check`, `gofmt -d` on the changed Go files, `check-anchors.sh`, and an
attempt at `where.sh test --type modules`. Hash check clean: `git diff | sha256sum` identical before
and after, so the reviewer changed no tracked file.

**Not reached.** No test tier, for the container reason in the plan entry. The reviewer read the
recorded results rather than reproducing them and said so plainly, which is the honest form of a
partial review. Everything static was reviewed, including a search for any other writer of
`codes.revoked`, which found none.

1. **The failed-claim contract still said every miss was authorization-code reuse.** `Raised by:
   reviewer`, minor, confidence high. Status: **Resolved**
   Correct, and it also refuted a premise in the run's own request. Adding `revoked = false` makes a
   false return from `db/mark-code-used` mean "no row transitioned", which is now three states rather
   than one: used, revoked, or missing. The doc comment still said "already used, i.e. a concurrent
   request redeemed the same code first. Callers treat that as authorization-code reuse", and
   `handler_token.go`'s branch comment and debug message still said the race had been lost.
   The runtime was already safe, and the run had verified this before the review returned: the
   `!claimed` branch answers a generic `invalid_grant` and deliberately does **not** call
   `revokeAndAuditAuthCodeReuse`, which only the validator's `AuthCodeReusedError` path does, pinned by
   `TestHandleTokenPost_AuthCode_ConcurrentDoubleSpendLoses`. So the defect was the written contract,
   which would have invited a later caller to treat a termination race as reuse.
   Fixed in three places: the `db/mark-code-used` doc comment, its interface declaration, and the
   handler's branch comment plus its debug message, now "code could not be claimed" rather than "lost
   the concurrent claim race". Unit tier re-run green afterwards. Bookkeeping class under the
   reviewer reference's table, prose disagreeing with behaviour, so it does not justify a second round.

**Gate passed on one round.** Zero conformance findings and zero security findings. The reviewer
confirmed, against the diff rather than from the request, that the stage touches no index, no endpoint,
`token_validator.go` not at all, and `DeleteUsedCodesWithoutRefreshTokens` not at all, which are the
four out-of-scope boundaries this stage could plausibly have crossed.

### Stage 2, 2026-08-04

**Landed.** `validator/code-revoked` and `validator/refresh-code-revoked` in `ValidateTokenRequest`,
the `invalidTokenMessage` const lifted to the `refresh_token` case scope so both rejections spell one
fact one way, and `test/revoked-code-ordering`'s parent test `TestValidateTokenRequest_RevokedCode`
with ten subtests. Three anchor rows added to section 0. Commit `266615b`.

The marker now means something. Stage 1 wrote the column and its sweep with nothing reading it; after
this commit a revoked code cannot be redeemed and no refresh token descended from one can be
exchanged. Still nothing **writes** a marker in production, because that is stage 4, so no observable
behaviour changes yet.

**Tiers.** Unit green, all three modules (`where.sh test --type modules`), re-run from scratch at the
gate rather than carried forward from the implementation session. `TestValidateTokenRequest_RevokedCode`
verified individually: 10 leaf subtests, all pass. No data or integration tier, correctly: this stage
adds no query and changes no endpoint. `check-anchors.sh` passes all 45 rows, the 42 sealed ones plus
the three this stage added.

**The stage spanned two driver sessions**, which is worth recording because the run log is the only
place it shows. The first implemented all three steps and ran both review rounds; it ended before
writing any of this down. The second re-verified from disk rather than trusting the document: the
`git diff | sha256sum` hash still matched `.review/before.sha` exactly, so the reviewer had changed no
tracked file, the round 2 verdict's `request_id` still matched the live request, and the tiers were
re-run rather than quoted. Nothing was rebuilt, because the code on disk matched the plan's steps.

**Deviation, and it is the review's.** Step 3's table specified nine rows and ten shipped. The added
row is a **present but wrong** client secret, and it exists because round 1 showed the planned
missing-secret row could not do the job alone. Nothing else departs from the plan.

**Review, round 1.** `gpt-5.6-sol`, effort high, `type: code-review`. Conformance, quality and security
all reviewed.

1. **The client-secret ordering row did not cover a present but incorrect secret.** `Raised by:
   reviewer`, security, blocking, confidence high. Status: **Resolved**
   Verified and correct, for a subtler reason than "a case was missing". The planned row supplied
   **no** secret, which `ValidateTokenRequest` refuses at a `len(input.ClientSecret) == 0` guard that
   runs before decryption, so it pinned only that the revoked check sits after the missing-credential
   return. It did not pin that the check sits after authentication *completes*. Relocating the revoked
   check into the confidential branch, after that guard and before `subtle.ConstantTimeCompare`, would
   have handed a termination-state oracle to anyone holding a stolen code and any nonempty string,
   which is precisely what decision 7 exists to prevent.
   **Demonstrated rather than argued.** The relocation was applied to the real code and the suite
   re-run. Under it the missing-secret row **passed**, confirming it as the benign member of its class;
   the new wrong-secret row **failed**, which is its whole purpose; `a revoked code is refused` also
   failed, incidentally, because its fixture uses a public client so the relocated check never runs;
   and every other row passed, which is what they are for, each being refused by a different gate. The
   mutation was reverted and the suite is green. The round 1 no-op mutation also holds: with both
   checks deleted, exactly the two direct rejection rows fail and nothing else.

**Review, round 2, clean.** Same model and effort, resumed in the same Codex thread, scoped to two
narrow questions rather than a re-review: does the added row close the gap, and is any other row the
benign member of its class in the same way. Zero findings, verdict `static-review-exhausted`, all
three axes `reviewed`. The reviewer answered the second question against the code rather than in
general terms, and its answer is the part worth keeping: the wrong-PKCE row is present and nonempty so
it reaches the challenge comparison; the wrong-client refresh row authenticates the presenter and
loads a revoked code owned by another client; and the reuse row is found only by the used-code lookup
and asserts both the error type and its carried `Code`. It also noted the one relocation the reuse row
alone would survive, moving the check inside `if !wasReused`, and that the wrong-secret and wrong-PKCE
rows reject that placement. Hash check clean, identical before and after.

**Not reached, both rounds.** No test tier. `where.sh test` exits 3 in the reviewer's sandbox because
it cannot reach docker, the standing limitation recorded in the plan entry. The reviewer read the
run's recorded results and said so plainly rather than implying it had reproduced them, which is the
honest form of a partial review. The gate is not weakened by it here: the tier in question is unit,
the run executed it at the gate, and every finding this stage produced was a static reading of test
coverage rather than a failure the reviewer needed to run anything to see.

**Nothing deferred, nothing contested, no decision raised.** Section 3 keeps its fourteen items, all
`Decided`.

### Stage 3, 2026-08-04

**Landed.** `revoke/terminate-session`, that is `TerminateUserSessionTx` in `revocation.go`, with
`TerminationResult` beside `RevocationResult`; `audit/terminated-session`, the
`AuditTerminatedUserSession` constant and its three registrations; and four new test functions in
`revocation_test.go` over 10 leaf cases, covering the happy path, the empty case, both entry guards
and every one of the six failure points. Four anchor rows added to section 0. Commit `d19d8b5`.

Nothing calls the helper and nothing emits the event, which is the stage's defining property: this
commit changes no observable behaviour. Stage 4 wires both endpoints and carries every piece of
user-facing material about them in the same commit, per the plan review's finding 2.

**Tiers.** Unit green, all three modules (`where.sh test --type modules`, exit 0, no `FAIL` lines,
"All tests completed successfully"), run at the gate rather than carried forward from the
implementation session. The stage's 10 leaf cases pass, and so do all six `TestAuditEventTypes_*`
guards with the new event, the count guard now at 95 and `_Alphabetical` accepting
`terminated_user_session` between `started_new_user_session` and
`token_issued_authorization_code_response`. No data tier and no integration tier, correctly: this
stage adds no query, changes no endpoint, and every data method it calls was covered on four engines
in stage 1 or already existed. `check-anchors.sh` passes all 49 rows, `gofmt -l` is silent on all four
changed files, `git diff --check` is clean.

**Mutation evidence, because a green mock-based suite is worth what its rows would catch.** Two
mutations applied to the real helper, run, and reverted, in this session rather than quoted from the
implementation session's notes.

1. Re-filtering the swept rows by `rt.SessionIdentifier == userSession.SessionIdentifier`, the
   plausible tidy-up that silently drops offline tokens. Exactly one test failed,
   `test/terminate-offline-token`'s parent, on three independent assertions: the JTI list came back
   `[rt-session-bound]`, the offline assertion reported "the offline token of the terminated session
   must be revoked", and the strict mock reported "7 out of 8 expectation(s) were met" for the
   unreached `UpdateRefreshToken`. That is gap 1 reintroduced, caught three ways.
2. Populating the result as the helper goes and returning it on the error path. **This refutes what
   the implementation session wrote in the mailbox**, and the correction is the useful part. That note
   claimed exactly one row failed, `test/terminate-zero-result`, and concluded it was therefore the
   only row with teeth against a partially populated result. Measured here, **four** of the six failure
   rows fail: the keep-this row plus `a token write fails`, `the deletion fails` and `the commit
   fails`, because the shared `assert.Equal(t, TerminationResult{}, result)` in the table's loop
   catches every path where a write had already succeeded. The row is still worth keeping, for the
   narrower reason that it names the property and is the only one asserting the count itself, so its
   failure reads as a contract violation rather than a struct mismatch. Step 4's table keeps its
   original wording, because it is the prediction and editing it would erase the evidence that the
   prediction was wrong; the comment in the test file was corrected, since a comment stating a
   measured falsehood is the same defect class as stage 1's finding 1.

**Deviations from the plan as written.** Three, all small.

1. Step 1 named `expectedCount` and `allAuditConstants`; the event was also added to `criticalEvents`
   in `TestAuditEventTypes_ContainsCriticalEvents`, with a comment in the shape of the
   `AuditRevokedUserAuthState` entry immediately above it. The argument is #106's own, one issue over:
   `deleted_user_session` survives either way, so if this event stopped being emitted the security
   action would leave only a lifecycle record and nothing attesting what it revoked.
2. Four anchor rows, not the three step 5 predicted. `TerminationResult`'s fields need no anchor of
   their own, but both new test functions do.
3. 10 leaf cases, not the 13 the mailbox note claimed. Counted from the suite's own output at the
   gate: 2 standalone tests, 2 subtests under `_RejectsAnUnusableSession`, 6 under
   `_AnyFailureYieldsTheZeroResult`.

**Design choice worth recording, since it departs from #106's shape.** There is no inner
`TerminateUserSession(db, tx, ...)` beside the `Tx` variant. #106 needed that split because a
credential write had to join the same transaction through a callback; nothing composes with this one,
so a second entry point would be surface with no caller and a second contract to keep straight. If a
later stage does need to compose a write into the termination transaction, splitting it is mechanical.

**Review, round 1.** `gpt-5.6-sol`, effort high, `type: code-review`, request
`129-20260804T225911Z`. Conformance, quality and security all `reviewed`, verdict `findings`.

**The reviewer reached a test tier for the first time in this run**, which matters because the stage 1
and stage 2 entries above both record that it could not. Its `ran` list: `leo-review/SKILL.md` and the
full agreement, the complete uncommitted diff and the neighbouring code, `git diff --check`, `gofmt -d`
on all four changed Go files, `check-anchors.sh` with 49 anchors passing, and `where.sh test --type
modules` reported as all three modules passing. Recorded as the reviewer's claim rather than as
independent confirmation, since the run cannot see into its sandbox; the run executed the tier itself
either way. Its `unchecked` list holds nothing the gate depended on: the data and integration tiers,
correctly not applicable to an uncalled helper, the unchanged PKCE, redirect, token-validation,
rate-limiting and secret-comparison internals, and the run's own source mutations, which it assessed
statically because a reviewer may not edit source.

**Hash check clean.** `git diff | sha256sum` was still `1ca531ab…`, matching `.review/before.sha`, when
this session started, so the reviewer changed no tracked file and reviewed exactly the code committed
here apart from this session's two comment edits.

1. **A stage 3 fixture was inserted between `stubRevocationSweepTx`'s doc comment and the function.**
   `Raised by: reviewer`, quality, minor, confidence high. Status: **Resolved**
   Verified against the file and correct. The comment sat at the end of the #106 material and the new
   termination fixtures went in directly beneath it, so it attached to the `terminateSessionId` and
   `terminateSid` constants, describing a mock-stubbing helper that was by then 300 lines further down
   and undocumented. Resolved by the reviewer's own forced answer, moving the eleven-line comment back
   above `stubRevocationSweepTx`, which is the smaller of the two fixes and keeps that cross-file
   helper last in the file where it already was; the alternative, moving the whole stage 3 block below
   it, would have put a helper shared with `handler_reset_password_test.go` in the middle. Unit tier
   re-run green afterwards.
   Bookkeeping class under the reviewer reference's table, prose disagreeing with what it sits above,
   so it does not justify a second round. Same class and same disposition as stage 1's finding 1.

**No round 2, and the gate passes on one round.** Zero conformance findings and zero security
findings, all three axes reviewed, and the only finding was a comment position. What this session
changed since the reviewed hash is two comments in one test file, no behaviour, suite green, so a
second round would be reviewing comment placement.

**The stage stalled between sessions, and the reason belongs here because nothing else records it.**
The implementation session wrote its trace to `.review/stage3-log.md` instead of this section, and the
mailbox does not survive the next gate, so on the skill's own terms the stage had recorded nothing. No
session then ran to ingest round 1, and the driver re-invoked the reviewer three further times against
a byte-identical request. Each re-invocation correctly refused to treat it as a new round, verified the
request hash `719cb6cb…` and the diff hash unchanged, re-raised the same finding and marked it
`needs_human: true`, that flag meaning "somebody has to notice the request was never rewritten" rather
than a question for the user, since the same finding carried a mechanical `forced_answer` on its first
emission. No new findings came from any of them. Because the driver clears `verdict.json` and
`response.md` before each reviewer run, round 1's own verdict was recovered from `.review/drive.log`,
and its content was verified against the code before being written up here. Two lessons, both
procedural: the trace goes in the agreement at the moment it is known, and a round-2 request that is
never written stalls the loop silently rather than loudly.

**Nothing deferred, nothing contested, no decision raised.** Section 3 keeps its fourteen items, all
`Decided`. No follow-up found: the only defect this stage surfaced was in its own comments.

### Stage 4, 2026-08-04

**Landed.** The activation stage, in one commit as the plan review's finding 2 requires.
`revoke/log-terminated`, that is `LogTerminatedUserSession`; both endpoints calling
`TerminateUserSessionTx` at `admin/session-delete` and `account/session-delete`, each emitting
`AuditDeletedUserSession` with its payload untouched plus `terminated_user_session` with decision 9's
six keys, both after the commit and neither on the error path; the two handler test files section 1
asked for, six cases over `test/terminate-endpoint-audit`, `test/failure-suppresses-events` and
`test/forbidden-does-not-terminate` among them; five integration cases, `test/terminate-offline-endpoint`,
its account sibling, the account 403 pairing, and the two logout pinnings starting at
`test/logout-revokes-nothing`; one new harness helper at `test/second-offline-grant`; decision 14's
`catalog/modal-revocation-note` and its five siblings plus one line in each of the three templates; and
the four documentation pages. Nine anchor rows added and two sealed ones re-swept.

**This is the commit where the behaviour changes.** Stages 1 to 3 were inert by construction: the
column existed with nothing writing it, the rejections existed with nothing marked, and the helper
existed with no caller. After this commit ending a session at either endpoint revokes the codes of that
session and the refresh tokens those grants issued, offline ones included, and every page and modal
that describes the action says so in the same commit.

**Tiers.** Unit green, all three modules, run at the gate after the mutations below were reverted
("All tests completed successfully", no `FAIL` lines). The stage's six new unit cases pass.
Integration green on **all four engines**, `where.sh test --type integration` exit 0, 3544 passing
tests, zero `FAIL` lines; each of the five new cases passes four times, once per engine. No data tier,
correctly: this stage adds no query and no migration, and every data method it reaches was covered on
four engines in stage 1 or already existed. `check-anchors.sh` passes all 57 rows, `gofmt -l` is silent,
`git diff --check` is clean, and `cd site && npm run build` completes with 42 pages and no link errors.

**The integration tier ran for the first time in this run**, and it needed no repair: the two earlier
stages recorded it as not applicable rather than untried.

**Mutation evidence, because three of this stage's rows exist to catch specific mistakes.** Each
mutation was applied to the real code, run, and reverted, in this session.

1. **The sid-scoped sweep replaced by the user-scoped one**, `GetRefreshTokensByUserId`, which is the
   plausible tidy-up that reuses #106's query. At the integration tier exactly one assertion failed,
   the survivor half of `test/terminate-offline-endpoint`: "the same user's OTHER session must be
   untouched: map[error:invalid_grant error_description:This refresh token has been revoked.]". The
   terminated half still passed, which is the point: without the survivor row this mutation ships. At
   the unit tier it also failed four `TestTerminateUserSessionTx_*` cases on the strict mock, so both
   tiers catch it, and the integration one catches it as the observable outcome rather than as an
   unexpected call.
2. **Termination moved ahead of the account handler's ownership check.** Exactly
   `test/forbidden-does-not-terminate` and `TestHandleAPIAccountSessionDelete_TerminationFailureIsA500`
   failed. The happy-path case still passed, and so, by reading, would the pre-existing integration
   case `TestAPIAccountSessionDelete_ForbiddenOnOtherUsersSession`, which asserts only the status code
   and the error description. That is the whole argument for adding both the unit row and its
   integration pairing: before #129 the mistake leaked nothing, and after it revokes a stranger's
   grants.
3. **`AuditDeletedUserSession` moved above the error check**, in both handlers, which is the one-line
   mistake the two adjacent emitters invite. Exactly the two `_TerminationFailureIsA500` cases failed,
   one per handler, and nothing else. That is the contract the plan review said had no other home, and
   it now has a measurement rather than an argument.

**Deviations from the plan as written.** Six, recorded in full in the stage's as-built note above: two
sealed anchor rows re-swept, nine anchor rows rather than an unstated number, `GetLoggedInSubject`
hoisted to one call per handler, the new harness helper placed in #106's test file beside the helper it
mirrors, the helper's consent branch dropped once both handlers were verified to route
`offline_access` to consent unconditionally, and the no-hint POST logout case deliberately not written.

**Nothing deferred, nothing contested, no decision raised.** Section 3 keeps its fourteen items, all
`Decided`. No follow-up found: the only surprise this stage produced was that the consent path is
unconditional, which is existing behaviour working as its comments describe.

**Review request.** `129-20260805T000627Z`. The two new test files were marked intent-to-add so
`git diff` covers them, which no earlier stage needed; the request carries the resulting hash and this
entry deliberately does not, since recording it here changes it. Everything above this line was written
before the review ran, which is stage 3's lesson: the trace goes into the agreement at the moment it is
known, because the mailbox does not survive the next gate.

**Review, round 1, clean.** `gpt-5.6-sol`, effort high, `type: code-review`. Conformance, quality and
security all `reviewed`, verdict `clean`, zero findings and zero follow-ups. The scope is recorded
below rather than summarised, because zero findings in a narrow scope reads exactly like zero findings
in a thorough one.

**What it ran**, its own list: `where.sh test --type modules` passing all three modules,
`where.sh test --type integration` passing on mysql, postgres, mssql and sqlite, `npm run build`
completing with 42 pages, `check-anchors.sh` passing all 57 rows, `git diff --check HEAD` clean, and
`gofmt -l` silent on every changed Go file. This is the second gate at which the reviewer reached a
test tier and the first at which it reached the integration one, which the stage 1 and 2 entries above
record it could not.

**What it checked by reading**, named because these are the stage's contracts rather than general
approval: that `admin/session-delete` and `account/session-delete` are the only production callers this
stage adds for `TerminateUserSessionTx`, with decision 5's four excluded `DeleteUserSession` callers
untouched; that the account handler resolves the token subject and compares `us.UserId` to it before
opening the transaction, and the admin handler's 404 and two 400s still answer first; that both
handlers emit `deleted_user_session` with exactly its two prior keys and then `terminated_user_session`
with exactly decision 9's six, both after a successful helper return and so after the commit, and
neither reachable from an error path; that the six catalog values contain no double quote that would
break their JavaScript literal and each template appends before its current-session warning; that the
four pages describe what stage 4 actually provides and do **not** claim the stage 5 and 6 ceremony gap
is closed; and that the logout production path is unchanged, with both new cases supplying
`id_token_hint` and `post_logout_redirect_uri` and asserting only what decision 3 owns. On security it
recorded that storage failures fail closed through both handlers and the helper, that the marker
update, the sid-scoped sweep and the session delete share one transaction with parameterised
predicates, that the join reaches offline tokens through their code without widening to another session
or user, and that no raw code, refresh token, client secret or OTP reaches a log, response, template or
URL.

**Its `unchecked` list holds nothing the gate depended on.** The data tier, correctly not applicable to
a stage adding no query, interface method, migration or schema change, with stage 1's four-engine
evidence standing behind every data method it reaches; the run's own three source mutations, which it
assessed statically by inspecting each target branch and the tests claimed to catch it, because a
reviewer may not modify source under review; and unchanged cryptography, token signature internals,
global PKCE policy, redirect matching and unrelated rate limiting, none of which the diff reaches.

**Hash check clean.** `git diff HEAD | sha256sum` was still `570a8395…` when this session started,
matching both `.review/before.sha` and the hash the reviewer reported after its run, so it changed no
tracked file and reviewed exactly the code committed here. `check-anchors.sh` re-run at ingestion, 57
rows passing, and the two handler diffs re-read against the reviewer's conformance claims before this
was written.

**No round 2.** All three axes reviewed with the tiers actually executed and zero findings is the clean
case the reviewer reference describes, and nothing changed after the reviewed hash.

---

## 9. Follow-ups

Both found while grounding, both verified against code, both outside this change under section 2, and
neither is a way to avoid work #129 owes. The run appends here as it finds more, and never files
anything.

1. **A code insert can still land between a termination's `UPDATE` and its `COMMIT`.**
   `bug`, `security`, `go`. Found while settling decision 12. Status: **Drafted**

   Decision 12 closes gap 3's fail-open window with two sweepers that cover each other: termination
   marks codes that already exist, and `/auth/issue` marks its own code when the session is already
   gone. One interleaving escapes both. If the code insert commits after the termination transaction's
   `RevokeCodesBySessionIdentifier` statement has read `codes` but before that transaction commits,
   the compensating statement's `NOT EXISTS` still sees the session row, so neither marks it. What
   survives is an offline refresh token, for up to `RefreshTokenOfflineMaxLifetimeInSeconds`.

   Verified at `db/mark-code-used` and `issue/create-code`: nothing orders the insert against the
   sweep, and the window is between two bounded statements rather than the unbounded handler stall the
   read-only check leaves, which is why decision 12 accepted it.

   Out of scope here because closing it needs the same primitive #131 and #132 want, a portable way to
   order a write against a sweep across SQLite, MySQL, PostgreSQL and SQL Server, and whichever of the
   three lands first should establish it. #134 held the previous version of this residual and was
   closed as moot when decision 4 moved the marker off a session-keyed registry, so nothing tracks it
   now.

   Searched `gh issue list --state open --search "serialization boundary sweep"` and the full open
   list: #131 and #132 are the rotation residuals of #106 and #128, neither covers code issuance.

   **Body:** #129 marks a terminated session's authorization codes revoked, and `/auth/issue` runs a
   compensating `UPDATE ... WHERE NOT EXISTS (SELECT 1 FROM user_sessions ...)` immediately after
   inserting a code, so a code created after the termination is marked even when the termination could
   not see it. The remaining window is an insert committing after the termination's `UPDATE` has read
   `codes` and before that transaction commits: the compensating statement still observes the session
   as present, so the code carries no marker, and redeeming it yields an offline refresh token good
   for up to the configured offline maximum lifetime. Closing it needs issuance ordered against the
   revocation sweep, which is the same missing primitive as #131 and #132. Scope the three together.

2. **Add to #109: the interactive logout path writes nothing to the database.**
   `bug`, `go`, `security`. Found on the reconciliation pass of 2026-08-04. Status: **Drafted**

   A comment on #109 rather than a new issue, because #109 already owns the RP-initiated logout
   surface and its divergence B is this same asymmetry on the neighbouring path. Filing separately
   would split one design question across two issues.

   Verified at `logout/basic-post-fork`: `HandleAccountLogoutPost` takes the no-hint branch, clears
   the cookie, audits `AuditLogout`, redirects, and never calls `handleExistingSessionOnLogout`.
   `logout_consent.html` posts back with only a csrf field, so this is the path every interactive
   logout takes. Decision 13 records why #129 leaves it alone.

   **Body:** Divergence B notes that the cookie is wiped unconditionally while the database teardown
   is per-client. There is a path where the teardown does not happen at all. `POST /auth/logout`
   without an `id_token_hint` clears the cookie session, writes an `AuditLogout` entry, redirects, and
   never touches `user_sessions`. Since `logout_consent.html` posts back carrying only a csrf field,
   that is the path taken by every logout a person performs in a browser, and by the admin console's
   account menu.

   The row therefore survives with every client still attached. Session-bound refresh tokens keep
   working, access tokens keep passing `RequireValidSession`, and the row is orphaned from the browser
   because the cookie no longer carries the session identifier. The user still sees it listed as an
   active session on that device and can only end it with the "End session" button. Whatever B decides
   about per-client versus whole-session teardown, this path should reach the same code as the
   `id_token_hint` path rather than bypassing it.
