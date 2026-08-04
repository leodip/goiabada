# Issue 129: ending a user session does not durably cut off access

**Issue:** [#129](https://github.com/leodip/goiabada/issues/129)
**Issue state:** open (labels: bug, security)
**Written:** 2026-08-04
**Last synced:** 2026-08-04 (issue has zero comments; body is the whole specification)
**Agreement sealed:** 2026-08-04, amended 2026-08-04 on a reconciliation pass, still sealed
**Run state:** not started
**PR:** none

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
| `admin/session-delete` | `src/authserver/internal/handlers/apihandlers/handler_api_users_sessions.go` | `HandleAPIUserSessionDelete` | `err = database.DeleteUserSession(nil, sessionId)` | termination site 1, bare delete, no revocation |
| `account/session-delete` | `src/authserver/internal/handlers/apihandlers/handler_api_account_sessions.go` | `HandleAPIAccountSessionDelete` | `if err := database.DeleteUserSession(nil, sessionId); err != nil {` | termination site 2, ownership checked, bare delete |
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
