# Issue 106: password reset, password change and account disable do not invalidate live sessions or refresh tokens

**Issue:** [#106](https://github.com/leodip/goiabada/issues/106)
**Issue state:** open (labels: bug, security)
**Spec written:** 2026-07-29
**Last synced:** 2026-07-29 (no comments on the issue)
**Plan approved:** 2026-07-30 (through finding 28)
**Delivery:** lands as a single PR, staged internally for review rather than split across issues.
**Related:** #127 (closed, not planned) proposed an authorization-grant refactor to precede this;
deferred after review, so this change proceeds on the current schema. #128 (open) covers
refresh-token replay containment. #129 (open) covers durable session termination, split out of this
issue by finding 15. #130 (open) is the `NOT IN` cleanup bug found while designing decision 12. None
of them blocks this issue, and this issue blocks none of them.

## 0. Code anchors

| Label | File | Function | Locate by | Note |
|---|---|---|---|---|
| `reset/password-write` | `src/authserver/internal/handlers/handler_reset_password.go` | `HandleResetPasswordPost` | `user.ForgotPasswordCodeIssuedAt = sql.NullTime{Valid: false}` | site 1, the forgot-password reset |
| `reset/success-render` | `src/authserver/internal/handlers/handler_reset_password.go` | `HandleResetPasswordPost` | `"passwordReset":       true,` | the success path, which emits no audit event |
| `reset/audit-failure-only` | `src/authserver/internal/handlers/handler_reset_password.go` | `auditFailedResetPasswordCode` | `constants.AuditFailedResetPasswordCode` | the only audit event this file emits |
| `account-pwd/write` | `src/authserver/internal/handlers/apihandlers/handler_api_account_password.go` | `HandleAPIAccountPasswordPut` | `user.PasswordHash = passwordHash` | site 2, self-service change |
| `account-pwd/audit` | `src/authserver/internal/handlers/apihandlers/handler_api_account_password.go` | `HandleAPIAccountPasswordPut` | `constants.AuditChangedPassword` | the only emitter of this event |
| `account-pwd/subject` | `src/authserver/internal/handlers/apihandlers/handler_api_account_password.go` | `HandleAPIAccountPasswordPut` | `subject := jwtToken.GetStringClaim("sub")` | the validated token is in hand here |
| `admin-enabled/write` | `src/authserver/internal/handlers/apihandlers/handler_api_users_crud.go` | `HandleAPIUserEnabledPut` | `user.Enabled = req.Enabled` | site 3, admin disable |
| `admin-enabled/audit` | `src/authserver/internal/handlers/apihandlers/handler_api_users_crud.go` | `HandleAPIUserEnabledPut` | `constants.AuditUpdatedUserDetails` | disable is audited as a generic detail update |
| `admin-pwd/write` | `src/authserver/internal/handlers/apihandlers/handler_api_users_crud.go` | `HandleAPIUserPasswordPut` | `user.PasswordHash = passwordHash` | site 4, missed by the issue |
| `admin-pwd/audit` | `src/authserver/internal/handlers/apihandlers/handler_api_users_crud.go` | `HandleAPIUserPasswordPut` | `constants.AuditUpdatedUserAuthentication` | |
| `middleware/sid-passthrough` | `src/authserver/internal/middleware/api_auth.go` | `RequireValidSession` | `// Non-session-bound token (client_credentials, ROPC): no session to check.` | the gate that lets a sid-less token past unchecked |
| `middleware/session-lookup` | `src/authserver/internal/middleware/api_auth.go` | `RequireValidSession` | `session, err := database.GetUserSessionBySessionIdentifier(nil, sid)` | the session is loaded here, and carries UserId |
| `middleware/session-validity` | `src/authserver/internal/middleware/api_auth.go` | `RequireValidSession` | `if !session.IsValid(settings.UserSessionIdleTimeoutInSeconds` | idle and max-lifetime bounds, no user check |
| `middleware/fail-closed` | `src/authserver/internal/middleware/api_auth.go` | `RequireValidSession` | `// Fail closed: without settings we cannot enforce idle/max-lifetime` | the precedent for failing closed on a lookup problem |
| `revoke/family` | `src/authserver/internal/handlers/handler_token.go` | `revokeOnAuthCodeReuse` | `revokedJtis := make([]string, 0, len(refreshTokens))` | the template the issue points at |
| `revoke/conditional-teardown` | `src/authserver/internal/handlers/handler_token.go` | `revokeOnAuthCodeReuse` | `if code.SessionIdentifier != "" && len(revokedJtis) > 0 {` | teardown is conditional, load-bearing for #77 |
| `revoke/audit-reuse` | `src/authserver/internal/handlers/handler_token.go` | `revokeAndAuditAuthCodeReuse` | `"revokedRefreshTokenJtis": revokedJtis,` | the audit shape the issue asks us to copy |
| `token/revoked-enforcement` | `src/authserver/internal/handlers/handler_token.go` | `HandleTokenPost` | `if refreshToken.Revoked {` | the only place `Revoked` is read |
| `rt-query/session-join` | `src/core/data/commondb/refresh_token.go` | `GetRefreshTokensBySessionIdentifier` | `selectBuilder.Equal("codes.session_identifier", sessionIdentifier)` | joins through `codes`, so it excludes ROPC rows |
| `rt-issue/offline-or-sid` | `src/core/oauth/token_issuer.go` | `generateRefreshToken` | `// Store either max lifetime (for Offline type) or session identifier (for Refresh type)` | offline rows carry no `session_identifier` of their own |
| `rt-issue/ropc-userid` | `src/core/oauth/token_issuer.go` | `generateRefreshTokenForROPC` | `UserId:           sql.NullInt64{Int64: input.User.Id, Valid: true},` | the only refresh tokens with a direct user link |
| `rt-issue/family-id` | `src/core/oauth/token_issuer.go` | `generateRefreshToken` | `refreshTokenEntity.FirstRefreshTokenJti = refreshToken.FirstRefreshTokenJti` | family identity, carried forward and never read |
| `rt-issue/token-input-sid` | `src/core/oauth/token_issuer.go` | `createTokenInputFromCode` | `SessionIdentifier: code.SessionIdentifier,` | why offline access tokens carry a doomed `sid` |
| `validator/refresh-session-required` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `const invalidTokenMessage =` | `typ=Refresh` needs a live session |
| `validator/offline-not-session-bound` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `// its lifetime is not linked to the user session` | `typ=Offline` does not |
| `validator/refresh-enabled-authcode` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `if !refreshToken.Code.User.Enabled {` | disable already blocks auth-code refresh |
| `validator/refresh-enabled-ropc` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `if !refreshToken.User.Enabled {` | disable already blocks ROPC refresh |
| `validator/ropc-enabled` | `src/core/validators/token_validator.go` | `ValidateTokenRequest` | `if !user.Enabled {` | disable already blocks ROPC issuance |
| `worker/idle-session-reap` | `src/authserver/internal/workers/background_worker.go` | `performTask` | `w.database.DeleteIdleSessions(nil,` | why an offline token often has no session row |
| `worker/revoked-rt-reap` | `src/authserver/internal/workers/background_worker.go` | `performTask` | `w.database.DeleteExpiredOrRevokedRefreshTokens(nil)` | revoked rows are cleaned up later |
| `data/iface-rt-by-sid` | `src/core/data/database.go` | `n/a` | `GetRefreshTokensBySessionIdentifier(tx *sql.Tx, sessionIdentifier string)` | |
| `data/iface-rt-by-code` | `src/core/data/database.go` | `n/a` | `GetRefreshTokensByCodeId(tx *sql.Tx, codeId int64)` | |
| `data/iface-sessions-by-user` | `src/core/data/database.go` | `n/a` | `GetUserSessionsByUserId(tx *sql.Tx, userId int64)` | |
| `data/iface-update-rt` | `src/core/data/database.go` | `n/a` | `UpdateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken)` | |
| `data/iface-delete-session` | `src/core/data/database.go` | `n/a` | `DeleteUserSession(tx *sql.Tx, userSessionId int64)` | |
| `admin-session-delete` | `src/authserver/internal/handlers/apihandlers/handler_api_users_sessions.go` | `HandleAPIUserSessionDelete` | `constants.AuditDeletedUserSession` | deletes the session, revokes nothing |
| `account-sessions/is-current` | `src/authserver/internal/handlers/apihandlers/handler_api_account_sessions.go` | `HandleAPIAccountSessionsGet` | `us.SessionIdentifier == currentSid` | precedent for identifying the caller's own session |
| `otp/current-sid-only` | `src/authserver/internal/handlers/apihandlers/handler_api_account_otp.go` | `HandleAPIAccountOTPPut` | `// Flag session Level2AuthConfigHasChanged = true for this sid if present` | adjacent gap, out of scope |
| `routes/admin-group` | `src/authserver/internal/server/routes.go` | `n/a` | `s.router.Route("/api/v1/admin", func(r chi.Router) {` | `RequireValidSession` applies, `RequireUserBoundToken` does not |
| `routes/account-group` | `src/authserver/internal/server/routes.go` | `n/a` | `s.router.Route("/api/v1/account", func(r chi.Router) {` | both guards apply |
| `console/session-refresh` | `src/core/middleware/middleware_jwt.go` | `JwtSessionHandler` | `refreshed, err := m.refreshToken(w, r, &tokenResponse)` | the console only revalidates when its access token expires |
| `seed/token-expiration` | `src/core/data/database_seeder.go` | `n/a` | `TokenExpirationInSeconds:                300,` | 5 minute access token by default |
| `seed/offline-max-lifetime` | `src/core/data/database_seeder.go` | `n/a` | `RefreshTokenOfflineMaxLifetimeInSeconds: 31536000,` | 1 year offline refresh by default |
| `seed/session-idle` | `src/core/data/database_seeder.go` | `n/a` | `UserSessionIdleTimeoutInSeconds:         7200,` | 2 hour session idle timeout by default |
| `schema/refresh-tokens` | `src/core/data/sqlitedb/schema.sql` | `n/a` | `CREATE TABLE refresh_tokens (` | `code_id`, `user_id` and `session_identifier` all present |
| `constants/audit-list` | `src/core/constants/constants.go` | `n/a` | `var AuditEventTypes = []string{` | a new event must be registered here |
| `test/middleware-valid-session` | `src/authserver/internal/middleware/api_auth_test.go` | `n/a` | `func TestRequireValidSession(t *testing.T) {` | the suite to extend for the Enabled check |
| `test/reset-happy-path` | `src/authserver/internal/handlers/handler_reset_password_test.go` | `n/a` | `func TestHandleResetPasswordPost_HappyPath(t *testing.T) {` | |
| `test/token-reuse-500` | `src/authserver/internal/handlers/handler_token_test.go` | `n/a` | `func TestHandleTokenPost_AuthCodeReuse_RevokeFailureReturns500(t *testing.T) {` | precedent for asserting a revoke failure surfaces |
| `test/integration-bearer-revocation` | `src/authserver/tests/integration/session_bearer_revocation_test.go` | `n/a` | `func TestSession_AdminAPI_DeletedSessionRejectsBearer(t *testing.T) {` | closest integration precedent |
| `test/integration-account-password` | `src/authserver/tests/integration/api_account_password_test.go` | `n/a` | `func TestAPIAccountPasswordPut_Success(t *testing.T) {` | |
| `test/integration-set-password-helper` | `src/authserver/tests/integration/api_account_password_test.go` | `n/a` | `func setUserPassword(t *testing.T, user *models.User, newPassword string) {` | |

## 1. Context

Four state changes write the `users` row and stop. None of them touches `user_sessions` or
`refresh_tokens`.

- Forgot-password reset (`reset/password-write`).
- Self-service password change (`account-pwd/write`).
- Admin disable (`admin-enabled/write`).
- Admin set-user-password (`admin-pwd/write`). **The issue lists three sites and misses this
  one.** Verified: it is byte-for-byte the same three-line write as the other two password
  sites, reached from `PUT /api/v1/admin/users/{id}/password`.

### What already contains a disabled account

`user.Enabled` is checked on every path that mints a token. Verified by reading each one:
authorization_code issuance, auth-code refresh (`validator/refresh-enabled-authcode`), ROPC
refresh (`validator/refresh-enabled-ropc`), ROPC issuance (`validator/ropc-enabled`), and
`/userinfo`. So a disabled user cannot obtain new tokens and **cannot use an existing refresh
token either**, on any grant. The issue's framing is slightly generous to itself here: for
disable, refresh-token revocation is defence in depth, not the fix.

What disable does not contain is the access-token window. `RequireValidSession`
(`middleware/session-validity`) resolves the `sid` claim to a `UserSession` and checks its idle
and max-lifetime bounds. It never loads the user. So a disabled user keeps working access to
`/api/v1/account/*` and, with the right scopes, `/api/v1/admin/*` for the remainder of the
access token lifetime, 300 seconds by default (`seed/token-expiration`).

### What nothing contains: a password that has been reset or changed

No validation path consults the password hash or an "issued before" timestamp. Verified across
`ValidateTokenRequest` and `RequireValidSession`: after a reset, every live session, refresh
token and access token remains exactly as valid as before. This is the serious half of the
issue, and the issue is right that it defeats the canonical account-recovery action.

### The issue's recommended fix does not close the worst of it

The issue recommends walking `GetUserSessionsByUserId` and revoking each session's refresh
tokens via `GetRefreshTokensBySessionIdentifier`. Two classes of refresh token escape that
walk:

1. **Offline (`offline_access`) tokens whose session row is gone.** `generateRefreshToken`
   stores either a max lifetime or a session identifier, never both (`rt-issue/offline-or-sid`),
   and `typ=Offline` validation deliberately does not consult the session
   (`validator/offline-not-session-bound`). Meanwhile the background worker reaps idle sessions
   at 2 hours by default (`worker/idle-session-reap`, `seed/session-idle`) while an offline
   refresh token lives up to 1 year (`seed/offline-max-lifetime`). Once the session row is
   reaped there is no `sid` for the walk to find, so the offline token survives the reset and
   stays usable for up to a year.

   Note the query is subtler than it looks: `GetRefreshTokensBySessionIdentifier` matches
   `codes.session_identifier`, not `refresh_tokens.session_identifier` (`rt-query/session-join`).
   So while a session row exists the walk *does* reach that session's offline tokens. The hole
   is only the reaped-session case, which the defaults make the common case rather than the
   rare one.

2. **ROPC refresh tokens, always.** They carry a direct `user_id` and no `code_id`
   (`rt-issue/ropc-userid`), and that same join is an inner join through `codes`, so they are
   invisible to any session-scoped query. ROPC is deprecated and off by default, which is the
   only thing keeping this narrow.

Conversely, the tokens the walk *does* reliably find, `typ=Refresh`, are the ones that least
needed finding: their validation already requires a live, in-bounds session
(`validator/refresh-session-required`), so deleting the session kills them without any
revocation. The proposal as written revokes mostly what was already dead and misses what was
alive.

There is no user-scoped refresh-token query in the data layer. Verified: the only lookups are
by id, by jti, by code id and by session identifier (`data/iface-rt-by-sid`,
`data/iface-rt-by-code`).

### Adjacent facts that shape the change

- **`revokeOnAuthCodeReuse` is not a clean template.** Its session teardown is conditional on
  having actually revoked something (`revoke/conditional-teardown`), and the comment there
  records why: an unconditional teardown breaks concurrent code redemption (#77). A
  credential-invalidation helper wants the opposite, unconditional teardown.
- **`Revoked` has exactly one reader** (`token/revoked-enforcement`), in the token handler, not
  in the validator. Setting the flag is sufficient, and the worker reaps the rows later
  (`worker/revoked-rt-reap`).
- **`first_refresh_token_jti` is write-only.** Verified: it is set on issuance and carried forward
  across rotations (`rt-issue/family-id`) and never read anywhere in production code
  (`grep -rn "FirstRefreshTokenJti" --include=*.go src/ | grep -v _test.go | grep -v mocks`
  returns only the two write sites and the model field). So a token-family identity is maintained
  that nothing consults, and family-scoped revocation is done by session identifier instead.

### A live defect, folded into this change by decision 9

Access tokens minted on an `offline_access` grant carry a `sid` claim that
`RequireValidSession` will eventually reject, guaranteed rather than occasionally.

The chain, each link verified: `createTokenInputFromCode` copies `code.SessionIdentifier` into
every token minted from that code (`rt-issue/token-input-sid`), so every access token on the
grant carries `sid = S` on every refresh. Offline refresh tokens store no session identifier of
their own (`rt-issue/offline-or-sid`), so the refresh path's `BumpUserSession` never fires for
them and offline activity never keeps S alive. The worker reaps S at the idle timeout
(`worker/idle-session-reap`, 2 hours by default). The refresh still succeeds, because `typ=Offline`
validation ignores the session (`validator/offline-not-session-bound`). The resulting access token
is then rejected by `RequireValidSession`, which resolves `sid = S` to nothing.

So every offline grant that idles past two hours ends up able to mint tokens it cannot use against
`/userinfo`, `/api/v1/account/*` or `/api/v1/admin/*`. Third-party resource servers are unaffected,
since they never consult session state.

This contradicts OIDC Core section 11, which defines `offline_access` as obtaining "an Access Token
that grants access to the End-User's UserInfo Endpoint even when the End-User is not present (not
logged in)". `/userinfo` is the named endpoint and it is one of the ones that fails.

It is attributable to the same conflation as everything else in this section: the access token
inherits *session* identity from the code because the code doubles as the grant record, and nothing
distinguishes a session-bound grant from an offline one except a column the middleware never reads.

It **fails closed**, denying access rather than granting it, which is presumably why it has gone
unnoticed. No test covers it: no integration test deletes a session, refreshes an offline token and
then calls a protected endpoint (verified by inspecting every test that mentions `offline_access`
and every test that calls `DeleteUserSession`).
- **A successful password reset emits no audit event at all.** Verified:
  `handler_reset_password.go` emits only `AuditFailedResetPasswordCode`
  (`reset/audit-failure-only`), on failures. The success path just renders
  (`reset/success-render`).
- **Admin disable is audited as `updated_user_details`** (`admin-enabled/audit`), a generic
  event, even though a dedicated `AuditUserDisabled` constant exists and is used by six auth
  paths to record a *rejected* disabled user.
- **Admin single-session delete has the same defect class** (`admin-session-delete`): it deletes
  the session and revokes nothing, so an offline token issued in that session outlives the
  administrative action that was meant to end it.
- **The caller's own session is identifiable.** `HandleAPIAccountPasswordPut` already holds the
  validated token (`account-pwd/subject`), and the account sessions endpoint already compares
  `sid` this way (`account-sessions/is-current`).
- **The admin console needs no change.** It disables users and changes passwords by calling
  these same authserver endpoints, so fixing the API covers the UI. Its own cookie session is
  only revalidated when its access token expires (`console/session-refresh`), so a console user
  whose session was revoked keeps rendering pages for up to the access token lifetime, but any
  page that fetches through the API fails immediately once `RequireValidSession` rejects the
  token.
- **The issue's claim that the account page has no "sign out other devices" affordance is
  wrong.** `/account/user-sessions` in the admin console lists sessions with an `IsCurrent`
  marker and an end-session action. It is manual rather than automatic, which is the real
  point, but the affordance exists.

### Test landscape

- **Unit, host.** `api_auth_test.go` has `TestRequireValidSession`
  (`test/middleware-valid-session`), table-driven with `t.Run` subtests over
  `mocks_data.Database`. `handler_reset_password_test.go` is thorough
  (13 test functions) and already asserts negative paths do not change the password.
  `handler_token_test.go` has the precedent for asserting a revoke failure surfaces as a 500
  (`test/token-reuse-500`).
- **Absent unit tests.** There is no `handler_api_account_password_test.go` and no
  `handler_api_users_crud_test.go`. The apihandlers package has unit tests for only four
  handlers (profile picture x2, client logo, permissions). Sites 2, 3 and 4 therefore have no
  unit-test home today, and creating one is part of the work rather than an extension of
  something existing.
- **Integration, dev container only.** `session_bearer_revocation_test.go` is the closest
  precedent (`test/integration-bearer-revocation`): it extracts the `sid` claim, deletes the
  session directly through `database`, and asserts the bearer token is rejected on both the
  admin and account surfaces. `api_account_password_test.go` has a `setUserPassword` helper
  (`test/integration-set-password-helper`). Integration and data tests need
  `goiabada-devcontainer-1`; the host lacks the DB hostnames.
- **Data, dev container only.** `tests/data/refresh_token_test.go` exists and is where a new
  data-layer query would be exercised against every engine.
- **A new `Database` interface method means regenerating `src/core/data/mocks/database_mock.go`
  with mockery** (config at `src/core/.mockery.yaml`), and implementing it in commondb.
- **A new audit event must be added to `AuditEventTypes`** (`constants/audit-list`), which is
  covered by uniqueness and non-empty tests and feeds the admin console's audit log filter
  dropdown.
- No test asserts an exact length over anything this change would extend. The auth handler
  `len(bind)` assertions noted in project memory are in the auth flow handlers, which this
  change does not touch.

### Prior art and docs

Nothing in `site/src/content/docs/` asserts the current behaviour, so nothing there is
falsified. `concepts/user-sessions.mdx` documents only the timeout settings,
`reference/security.mdx` lists session timeouts as a feature, and `concepts/audit-log.mdx`
deliberately points at `constants.go` rather than enumerating event identifiers, so a new event
needs no doc edit. Whether the new behaviour *should* be documented is a separate question from
whether anything is now wrong.

No i18n string asserts the old behaviour either. `reset_password.modal_body` says "Your
password has been successfully set." and stays true.

## 2. Goal

After any of the four credential-invalidating actions, the affected user's live authentication
state is gone:

- The user's generation advances, so nothing authenticated before the action can create or use
  authentication state after it. That is the security boundary; the sweep below is immediate
  invalidation, cleanup and audit detail.
- Every `UserSession` row for that user is deleted, except the caller's own on self-service password
  change (decision 4), so SSO cannot continue and every session-bound refresh token is dead.
- Every refresh token belonging to that user is marked `Revoked`, whatever its linkage shape:
  session-bound, offline with a live session, offline with a reaped session, or ROPC. Again except
  the preserved session's, per decision 4.
- Every access token for that user is rejected on the goiabada API surface at the next request:
  those carrying a `sid` because the session no longer resolves, and those without one because their
  generation claim no longer matches. Tokens presented to third-party resource servers are
  unreachable, which is inherent.
- An outstanding authorization code, and any replacement refresh token inserted by a refresh racing
  the action, are both rejected by their superseded generation.
- The action is audited with the user, the reason, the old and new generations, the terminated
  session identifiers and the revoked JTIs.

Plus, as defence in depth, a disabled user is rejected by `RequireValidSession` rather than
riding a still-valid access token to expiry.

And, folded in at the user's request rather than split out, the offline-grant `sid` defect from
section 1 is fixed, so an `offline_access` client can use its access tokens against `/userinfo`
and the account API when the user is not logged in, as OIDC Core section 11 requires. The shape of
that fix is decision 9.

**Session termination is not in this issue.** An earlier version included the admin and account
end-session endpoints. Finding 15 showed that no marker over existing rows can be a durable boundary
there, because an in-flight ceremony recreates the session and writes a fresh code afterwards, so
they were split into #129 along with decision 12's grant marker.

### Out of scope

- **Revoking access tokens held by third-party resource servers.** Access tokens are stateless
  JWTs. Goiabada can gate its own API surface and nothing else. This is inherent, and it is why
  a short `TokenExpirationInSeconds` matters; worth documenting, not fixable here.
- **OTP enable and disable as revocation triggers.** Named in the issue as a future case. The
  existing `Level2AuthConfigHasChanged` flag already forces OTP re-verification on the next
  level2 request, so the exposure is different in kind from a changed password.
- **The `Level2AuthConfigHasChanged` flag being set only on the caller's own session**
  (`otp/current-sid-only`). Verified: self-service OTP changes flag one session, so the user's
  other sessions are not forced to re-verify. Real, adjacent, separate.
- **Email change as a revocation trigger.** Named in the issue as a future case.
- **A stable authorization-grant identity.** The `codes` row is doing double duty as both the
  one-time authorization code and the permanent grant record, which is why refresh tokens have two
  linkage shapes, why the validator branches on `isROPCToken` in four places, why nothing above the
  individual token row can be marked revoked, and why the section 1 defect was writable at all. Raised as #127 and
  closed as not planned: the proposal bundled separable concerns into one four-engine migration
  whose lifecycle, concurrency and middleware semantics were unsettled, and no scheduled feature
  requires a persistent grant entity. Deferred until one does (an RFC 7009 revocation endpoint,
  per-client logout, or user-visible grant management).
- **Refresh-token replay containment**, tracked as #128. Two defects there: refresh-token single use
  is a read-then-unconditional-write so concurrent presentations both succeed, and a detected replay
  is rejected without revoking the token family. Verified independent of this change: #128 adds
  family-scoped revocation keyed on `first_refresh_token_jti` while this adds user-scoped, and the
  queries do not overlap. Kept separate so #128's concurrency guard, which is the same hazard class
  as `revoke/conditional-teardown`, gets its own review.
- **Durable session termination**, tracked as #129, split out of this issue by finding 15 together
  with decision 12's `codes.revoked` marker. The two explicit end-session endpoints still revoke
  nothing, and an offline grant authorized through a terminated session keeps renewable access.
- **The `NOT IN` nullable trap in `DeleteUsedCodesWithoutRefreshTokens`**, filed as **#130**.
  Verified live bug, unrelated to revocation, found while designing decision 12. #129 cross-references
  it because a durable session boundary would need this cleanup path to work; neither blocks the other.
  The predicate is
  `NotIn("id", SELECT code_id FROM refresh_tokens)`, and because ROPC rows carry `code_id = NULL`,
  `x NOT IN (..., NULL)` evaluates to UNKNOWN rather than TRUE, so **the sweep deletes nothing at all
  once any ROPC refresh token exists**. Wants a correlated `NOT EXISTS`. Out of scope here only
  because dropping decision 12 means this change no longer touches that predicate; it deserves its
  own issue, now filed as #130.
- **A "sign out all devices" affordance on the self-service password change page.** Recorded as the
  mitigation for decision 4's accepted risk (finding 10), since a preserved session can be one an
  attacker shares via a cloned cookie. It is a UI addition rather than part of the revocation
  mechanism, and the machinery it would call already exists after this change.
- **Closing the 300-second offline access-token window on session termination.** Decision 3 and
  finding 14 record it. It would need a grant-identifier claim plus a per-request lookup.
- **Reworking how the admin console revalidates its cookie session.** Its access-token-expiry
  revalidation (`console/session-refresh`) is a design choice with its own tradeoffs.

## 3. Open questions and decisions

Fifteen decisions. It was eight until interviewing turned up the live offline-grant `sid` defect
recorded in section 1, which this change has to take a position on because it shares the middleware
with decision 6; that is item 9. Item 10 arrived when #127 was closed and its index finding needed a
home, this being the change that makes those indexes matter. Items 11 and 12 arrived from review
finding 1, which showed that a transaction around the sweep is not a boundary against concurrent or
subsequent issuance, so a durable marker was needed. Items 13 to 15 came from round 2 of review, which found decision 11
underspecified on access-token provenance and on legacy tokens, and found a pre-existing full-row
update defect that would undo a disable. Decisions 3 and 12 were reversed by round 2 and their
subject matter moved to #129. Item 1 is the root: it decides
whether this change reaches the data layer at all, and items 5 and 7 read differently depending on
it.

1. **Revocation is user-scoped, via a new data-layer query.** Status: **Decided**

   Add `GetRefreshTokensByUserId(tx, userId)` to the `Database` interface, implemented in
   commondb as two `UNION ALL` branches, one joining `codes` on `codes.user_id` and one selecting on
   `refresh_tokens.user_id`, so it reaches every linkage shape: session-bound, offline with a
   live session, offline with a reaped session, and ROPC. Sessions are still enumerated with the
   existing `GetUserSessionsByUserId` (`data/iface-sessions-by-user`) and deleted, but refresh
   tokens are no longer discovered through them.

   Accepted cost, measured rather than estimated: 1 interface line, 1 commondb implementation, 4
   two-line delegating wrappers (verified that every engine delegates
   `GetRefreshTokensBySessionIdentifier` straight to `CommonDB`, so there is one real
   implementation, not four), a regenerated `database_mock.go`, and a data test across all four
   engines. The join is unindexed, but so is the existing session-identifier join, so this adds
   no new class of problem.

   **The deciding case:** a user's laptop is stolen; they reset their password from their phone.
   The laptop had an `offline_access` grant and was last used three hours ago, so the background
   worker has already reaped the session row (`worker/idle-session-reap`) while the offline
   refresh token has another year to run. A session walk has no `sid` to look up and revokes
   nothing, so the thief keeps minting access tokens and the reset accomplishes nothing against
   them. This is not an edge case: a 2 hour idle timeout against a 1 year offline lifetime makes
   "session row gone, offline token alive" the normal resting state of an offline grant.

   **Rejected:** the issue's session walk. Beyond the case above it also cannot reach ROPC
   refresh tokens in principle, because the existing query's `INNER JOIN codes` excludes rows
   with a null `code_id`. And its marginal value is smaller than it looks: the `typ=Refresh`
   tokens it reliably finds are already dead the moment the session is deleted
   (`validator/refresh-session-required`), so all it adds over deleting sessions alone is offline
   tokens whose session row still happens to exist. **Also rejected:** shipping the session walk
   now with the user-scoped query as a follow-up, which would leave a one-year credential alive
   after a password reset for another release.

2. **The admin set-user-password endpoint is a fourth site and is in scope.** Status: **Decided**

   `PUT /api/v1/admin/users/{id}/password` (`admin-pwd/write`) revokes everything
   unconditionally, like the reset. It is the administrative equivalent of a recovery action, so
   an operator setting a compromised user's password gets the same eviction the user would get
   from the forgot-password flow.

   This departs from the issue, which lists three sites. Verified that the omission is identical:
   the same three-line write with no session or token handling. The endpoint takes no
   current-password check, unlike self-service, and is what the admin console's User
   authentication page posts to when an admin fills in the new-password field.

   Two scenarios carry the decision, both of them the issue's own attack reached through a
   different door. **Compromise response:** an admin resetting a reportedly compromised user's
   password is at least as common as the user doing it through forgot-password, and today the
   attacker's session, refresh token and offline grant all survive it. **Offboarding:** an admin
   sets a departing employee's password to something random instead of disabling the account, and
   the ex-employee's live session keeps working while their offline grant refreshes for up to a
   year.

   No scenario was found where revoking here is harmful. The worst case is an admin setting a
   password for someone currently working, who is then signed out mid-task, and that is the
   expected consequence of an admin changing your password.

   **Rejected:** confining the change to the issue's three sites and filing a follow-up. It would
   ship a fix whose most likely operator-driven trigger still leaves the attacker's session
   alive, and fixing three of four doors is a strange place to stop.

3. **Session termination is out of scope; the two end-session endpoints are not touched.**
   Status: **Decided**

   **Reversed by finding 15**, having been Decided the other way earlier in this interview. The
   earlier decision had `DELETE /api/v1/admin/user-sessions/{id}` (`admin-session-delete`) and
   `DELETE /api/v1/account/sessions/{id}` revoke sid-scoped before deleting, with `/auth/logout`
   untouched. Both are now out of scope and tracked in #129, along with decision 12's grant marker.

   **Why it reversed.** Verified that no marker over existing rows can be a durable boundary for
   session termination. `HandleAuthCompletedGet` evaluates `hasValidUserSession` and, finding none,
   takes an else branch that calls `StartNewUserSession` **unconditionally** from
   `authContext.UserId`, with no requirement that anyone authenticated; it computes
   `userReallyAuthenticated` but consults it only inside the valid-session branch to refresh
   `AuthTime`. So an SSO ceremony in flight when a session is terminated resumes, silently receives a
   brand-new session, and `/auth/issue` writes a fresh unrevoked code outside the termination
   transaction. The user's generation never moves, since bumping a user-wide counter here would
   invalidate every one of that user's other devices, so nothing rejects the new code. The consent
   screen can delay code insertion past the sweep the same way.

   **Why not simply document the residual.** This issue rejected the cheap option for the credential
   scope precisely because it would ship a documented escape (decision 11). Keeping a knowingly racy
   session boundary in the same change would apply the opposite standard to the two scopes at once.

   Closing it properly means either a session tombstone or per-session generation plus an
   issuance-time check, or cross-engine transactional serialization, and in either case deciding what
   a ceremony whose session vanished should do. That is almost certainly "fail and re-authenticate",
   which is an auth-flow behaviour change to be reasoned about alongside `prompt=none`, step-up and
   `Level2AuthConfigHasChanged`. Too large for this issue, and it was an addition beyond what the
   issue asked for in the first place.

   **What the reversal costs, recorded honestly.** Ending a session still revokes nothing. An
   `offline_access` grant authorized through that session keeps renewable access for up to its max
   lifetime, seeded at one year, because `typ=Offline` validation does not consult the session.

   **Kept from the earlier decision, since #129 inherits them.** RP-initiated logout should stay
   untouched even when #129 lands: sid scope is wrong for it, because logging out of one client leaves
   the session alive for the others, and OIDC Core section 11 defines `offline_access` as usable when
   the user is not logged in. Also kept: no specification compels either answer. RFC 9700 section
   4.14.2 says, verbatim, "Authorization servers MAY revoke refresh tokens automatically in case of a
   security event, such as: password change or logout at the authorization server", which permits but
   does not require it, and which equally sanctions the credential-change revocation in decisions 1
   and 2. RFC 7009 governs a revocation endpoint this server does not implement.

   > **Corrected by finding 11.** An earlier version of this decision claimed RFC 9700 "never names
   > logout or session termination as a trigger". That was wrong, based on summarised fetches that
   > dropped the sentence twice; the verbatim text above was confirmed against `rfc9700.txt`.

4. **Self-service password change preserves the caller's own session, and its refresh tokens.**
   Status: **Decided**

   The helper takes an optional except-sid, populated from the validated token's `sid` claim
   (`account-pwd/subject`) at this one site. The other three credential sites pass nothing and
   revoke everything. This follows the issue's recommendation.

   **Preserving means both the session row and that session's refresh tokens.** Revoking the
   refresh tokens of a session you are keeping means the admin console's refresh fails at the next
   access-token expiry and the user is bounced anyway, which quietly defeats the exception. A test
   pins this by asserting the preserved session's refresh tokens are still unrevoked.

   **This is a product choice with an accepted risk, not a free one.** Corrected by finding 10; an
   earlier version of this decision claimed the exception "costs nothing", which is wrong in two
   concrete ways.

   *The attacker may share the preserved SID.* A stolen or cloned session cookie carries the **same**
   session identifier, not a different one. So when a user changes their password to evict someone
   holding a clone of their cookie, `exceptSid` preserves exactly the session the attacker is using.
   The earlier claim that "the attacker is on a different session" holds only for an attacker who
   obtained their own session, not for cookie theft, which is the commoner case.

   *Re-authentication is not always available to the attacker.* The claim that an attacker who knows
   the password "can sign straight back in" fails when the account requires OTP and they lack the
   secret. Preserving their level-2 session is then materially more valuable to them than anything
   revoke-all would leave.

   What does hold: the endpoint verifies `CurrentPassword` with `VerifyPasswordHash`, so an attacker
   with only a session cookie cannot *trigger* this path, and the preserved session is by
   construction one that just proved knowledge of the old password.

   **Accepted on these grounds.** OWASP ASVS 5.0 V3.3 is framed as terminating "all other" sessions
   after a password change, and OWASP's Forgot Password guidance permits either offering session
   invalidation or performing it automatically. So preserve-current is the standards-aligned default.
   The residual risk above is accepted, and the right mitigation is a **"sign out all devices"
   affordance** on the self-service password change page, which is recorded in out of scope rather
   than built here.

   Note the console-500 consequence below is a usability cost of revoke-all, not a security argument
   for preserve-current, and should not be read as one.

   **What revoke-all would have cost.** Verified: the change-password GET does not call the API (its
   `apiclient.ApiClient` parameter is deliberately `_`), so the success page renders regardless. But
   `HandleAPIError` maps every non-400 API error to `InternalServerError`, so the user's next
   API-backed console page would be a 500 rather than a clean re-login, until their access token
   expires at 300 seconds by default (`seed/token-expiration`) and the console's failed refresh
   redirects them to re-authenticate.

   **Rejected:** revoking everything including the caller. It is the security-stronger option, and
   per the corrections above it does gain real containment in the cloned-cookie and OTP cases, so this
   is a product choice trading that containment for not signing a user out of the tab they are working
   in. Choosing it would also want the console's 401 handling fixed first, or the user meets a 500.
   **Also rejected:** preserving the caller *and* fixing the console's 401 handling to redirect
   instead of erroring. That is a real improvement and would help every revocation path, but it
   touches shared console error handling used by every admin page, so it belongs on its own.


5. **The caller owns the transaction; the helper takes a `*sql.Tx`.** Status: **Decided**

   Each site begins a transaction, writes the user row and calls the helper inside it, then commits.
   The credential write, the generation increment and the revocation are therefore atomic, so the
   operation cannot half-apply. Note the narrower claim, per finding 1: a transaction bounds *this
   operation*, and does not bound issuance racing it. That is what decision 11 is for. This departs from `revokeOnAuthCodeReuse` (`revoke/family`), which opens its
   own, and the departure is deliberate: that function has no companion write to be atomic with.

   `UpdateUser` already accepts a `tx`, and every data-layer method takes one precisely so callers
   can compose, so this is idiomatic here rather than novel. Cost is roughly five lines of
   `BeginTransaction` / `defer RollbackTransaction` / `CommitTransaction` at the four credential call
   sites. (It was six until finding 15 reversed decision 3.) The reset handler's
   `database.UpdateUser(nil, user)` (`reset/password-write`) becomes `UpdateUser(tx, user)`.

   **Audit fires after commit, on success only.** Verified that it has to: `AuditLogger.Log` takes
   no transaction and internally reads settings with a nil tx, so audit writes cannot join the
   caller's transaction. `revokeAndAuditAuthCodeReuse` (`revoke/audit-reuse`) already establishes
   this ordering, emitting the event only once the revoke succeeded so the audit reflects real
   revoked JTIs.



   **Rejected:** the helper owning its own transaction. That forces two transactions and an ordering
   choice where both options are bad: write-then-revoke leaves the password changed with the
   attacker still holding a live session, which is a smaller instance of the very bug this issue
   fixes, and revoke-then-write leaves the user signed out everywhere with an unchanged password.
   **Also rejected:** the helper taking a tx and opening its own when nil, following the data
   layer's convention. It would make atomicity a property of each call site rather than of the
   helper's contract, which is exactly the thing that should not vary.

   > **Assumed:** that holding a write transaction across the revocation sweep does not cause
   > problematic lock contention on SQLite. These are infrequent operations on a path with no
   > benchmark, so this is judgement rather than measurement.


6. **The `Enabled` check covers every user token, session-bound and sid-less alike.**
   Status: **Decided**

   `RequireValidSession` resolves the user by the `sub` claim whenever `auth_time` is present and
   rejects when the account is not enabled, in addition to the session checks it already performs
   for tokens carrying a `sid`. On a lookup error it returns 500, consistent with the existing
   fail-closed precedent for missing settings (`middleware/fail-closed`). A nil user is a rejection.

   **`auth_time` is the discriminator, not `sid`.** Verified that client-credentials tokens carry
   only `iss`, `sub`, `iat`, `nbf` and `jti`, with no `auth_time`, so machine callers to the admin
   API pass through with no added lookup. This reuses the reasoning already documented on
   `RequireUserBoundToken`, which relies on the same claim for the same reason.

   **Why the narrow variant would have been nearly worthless.** Decisions 1 to 4 make disable delete
   the user's sessions, so a session-bound access token is already rejected by the existing session
   lookup with no `Enabled` check involved. A session-keyed check would therefore only catch a
   disabled user whose session still exists, which after this change requires a future code path
   that disables without calling the helper. Meanwhile the entire residual exposure sits precisely
   where a session-keyed check cannot reach: sid-less user tokens, meaning ROPC and, after decision
   9, offline grants. Those are never subject to session lookup, so a disabled user would keep
   working account and admin API access for the full access-token lifetime, 300 seconds by default
   (`seed/token-expiration`).

   **The middleware is the only sensible home for this.** Verified that of the eleven
   `/api/v1/account/*` handlers that resolve the caller by subject, **none** checks `Enabled`. So a
   disabled user can today change their own password, change their email, manage consents and enrol
   OTP. Putting the check in eleven handlers would be eleven chances to omit it.

   Accepted cost: one `GetUserBySubject` per request from a sid-less user token, partly duplicative
   since `/userinfo` already loads the user and checks `Enabled` itself, and the account handlers
   each load the user by subject anyway.

   **Rejected:** keying the check on the already-resolved `session.UserId`, which avoids the extra
   lookup but covers only the case session deletion already handles. **Also rejected:** the same
   coverage plus stashing the resolved user in the request context so handlers stop re-querying. That
   removes the duplication and is probably right eventually, but it touches all eleven account
   handlers and is a refactor rather than a security fix.


7. **One new audit event carrying a reason, emitted unconditionally.** Status: **Decided**

   `AuditRevokedUserAuthState = "revoked_user_auth_state"`, added to `AuditEventTypes`
   (`constants/audit-list`), emitted by the caller after commit in the shape
   `revoke/audit-reuse` already uses:

   ```
   revoked_user_auth_state {
     userId, reason, loggedInUser,
     terminatedSessionIdentifiers: [...],
     revokedRefreshTokenJtis: [...],
     preservedSessionIdentifier: "...",
     oldGeneration: N, newGeneration: N+1
   }
   ```

   `reason` is one of `password_reset`, `password_change`, `admin_password_set` or
   `account_disabled`. `session_ended` was dropped with decision 3, per finding 15. Every existing
   event stays exactly as it is.

   `preservedSessionIdentifier` is a Go `string`, so it marshals to `""` and never to JSON `null`
   (finding 8). All four reasons advance the generation, so both generation fields are always
   populated.

   **Emitted even when nothing was revoked**, with empty lists. That is deliberate: it makes the
   event the record that the action happened, not merely that something was found to revoke, and it
   incidentally covers the forgot-password reset, which emits nothing at all on success today
   (`reset/success-render`, `reset/audit-failure-only`). Acknowledged as an imperfect fix for that
   gap, since someone filtering the log for password resets would be reading an event whose type is
   about revocation.

   **`AuditUserDisabled` is deliberately not reused.** It already means "a disabled user was
   rejected" and is emitted from six auth paths. Overloading it with "an admin disabled a user"
   would make the event ambiguous in the log.

   Note the full JTI list, rather than only counts, follows `revoke/audit-reuse` and is what makes
   the entry useful for forensics. For a user with many long-lived offline grants the list can be
   sizeable; the details column is JSON, so this is a size consideration rather than a constraint.

   **Rejected:** adding a dedicated reset-success event alongside this one. It would close the reset
   audit gap properly rather than as a side effect, and is worth doing, but it is a pre-existing gap
   independent of revocation. **Also rejected:** threading revocation details into the four existing
   events. The reset has no event to extend, and revocations would become unqueryable as a class,
   spread across four generic event types.



8. **Two scope-named entry points over one shared revoke primitive, returning a result struct.**
   Status: **Decided**

   ```go
   // Returns the JTIs this call transitioned from live to revoked. Already-revoked
   // tokens are skipped and NOT reported: callers rely on "we actually revoked
   // something" to tell a real revocation from a no-op (see #77).
   func revokeRefreshTokens(db data.Database, tx *sql.Tx,
       tokens []*models.RefreshToken) ([]string, error)

   type RevocationResult struct {
       TerminatedSessionIdentifiers []string
       RevokedRefreshTokenJtis      []string
       PreservedSessionIdentifier   string   // "" when nothing was preserved, never null
       OldGeneration                int64
       NewGeneration                int64
   }

   // exceptSid preserves one session and its refresh tokens; empty revokes everything.
   func RevokeUserAuthState(db data.Database, tx *sql.Tx, userId int64,
       exceptSid string) (RevocationResult, error)
   ```

   `RevokeSessionAuthState` was part of this decision until finding 15 moved session termination to
   #129, so only the user-scoped entry point remains. The two-named-functions rationale still holds
   and applies again as soon as #129 lands.

   `revokeOnAuthCodeReuse` keeps its own body, its own transaction and its #77 comment
   (`revoke/conditional-teardown`); only its loop (`revoke/family`) becomes a call to
   `revokeRefreshTokens`. The existing reuse tests passing unmodified, including
   `test/token-reuse-500`, is the evidence that nothing about #77's behaviour changed.

   **This departs from the issue**, which proposes extracting a shared
   `revokeAllUserSessions` from `revokeOnAuthCodeReuse`. Verified that the two differ on four
   behavioural axes: who owns the transaction (decision 5), whether session teardown is conditional
   (load-bearing for #77) or unconditional, whether discovery is by sid-with-code-id-fallback or by
   user, and whether a session is preserved (decision 4). A single function spanning those would
   take four behaviour switches, which is configuration rather than shared logic.

   **Why this shape on maintainability grounds**, which is the criterion that decided it:

   - The extracted primitive has exactly one job and no behaviour parameters, so it gets one doc
     comment and one exhaustive test. More importantly it **names an invariant that is load-bearing
     and currently implicit**: today "return only what this call transitioned" exists solely as an
     unremarked `continue` inside a loop, and #77's guard depends on it.
   - Call sites are self-describing. `RevokeUserAuthState(db, tx, user.Id, "")` versus
     `RevokeSessionAuthState(db, tx, sid)` needs no flag decoded to be understood. Only the
     user-scoped one survives finding 15, but the rationale is what rules out a scope discriminator
     when #129 adds the session-scoped one back.
   - Each function has one reason to change: user-scoped discovery, session-scoped discovery, or the
     meaning of "revoked".
   - The teardown policy difference stays visible at the top of each function, where a reader wants
     it, instead of behind a parameter.
   - `RevocationResult` maps one-to-one onto decision 7's audit payload, so the audit call is a
     spread of the result rather than four separately threaded values, and later fields do not break
     every signature.

   The one accepted smell is `exceptSid string` where three of the four call sites pass `""`. Kept
   because this codebase already uses that convention throughout the data layer, where a nil
   `tx *sql.Tx` means no transaction.

   **Rejected:** the shared primitive with a single entry point taking a scope discriminator. Fewer
   exported symbols, but call sites stop being readable without decoding the scope argument.
   **Also rejected:** duplicating the loop and touching `revokeOnAuthCodeReuse` not at all. Zero risk
   to #77, but the skip-already-revoked contract would then have two implementations free to drift,
   and it would stay implicit rather than named and tested.

9. **The offline-grant `sid` defect is fixed here, by omitting `sid` from access tokens on
   offline grants.** Status: **Decided**

   Raised during the interview, by asking what concrete harm the current grant model causes. The
   defect is described at the end of section 1. Folded into this change at the user's request
   rather than split into its own issue: both fixes land in `RequireValidSession`'s neighbourhood,
   so separating them would mean the second reworks the first.

   Access-token generation omits `sid` when the grant is offline, reusing the predicate that
   already exists in `generateRefreshToken` (`rt-issue/offline-or-sid`):
   `slices.Contains(scopes, oidc.OfflineAccessScope) || code.SessionIdentifier == ""`. The second
   clause is moot for this fix, since no session identifier means there is no `sid` to emit.

   **The predicate must read the grant's scope, not the request's.** On refresh,
   `GenerateTokenResponseForRefresh` sets `scopeToUse = input.ScopeRequested` when the caller
   supplies a scope, and a caller may legitimately down-scope to a subset that omits
   `offline_access`. A predicate reading the access token's effective scope would therefore re-emit
   `sid` on exactly those refreshes, resurrecting the defect intermittently, which is worse than
   failing consistently. Use the authorized scope (`code.Scope`) on initial exchange and
   `RefreshToken.RefreshTokenType == "Offline"` on refresh. Note `generateRefreshToken` is already
   handed `input.RefreshToken.Scope`, the original scope rather than the down-scoped one, so this
   keeps the two decisions consistent. A test pins the down-scoped refresh case specifically.

   **The trap, and why the fix cannot go in the shared input builder.** `createTokenInputFromCode`
   (`rt-issue/token-input-sid`) feeds the access token, the ID token and the refresh token from one
   struct. RP-initiated logout reads `sid` from the `id_token_hint` and requires it to match
   (`handler_account_logout.go`), so dropping `sid` there would break logout for every offline-grant
   client. The change is scoped to access-token generation only; ID tokens on **auth-code** grants
   keep `sid` unchanged. ROPC ID tokens never carried one, since no session exists (finding 20).

   **Why this shape.** ROPC access tokens already carry no `sid`, because no session exists, and
   ROPC grants are always `typ=Offline`. So omitting `sid` for auth-code offline grants collapses
   two token shapes into one and makes "offline" mean the same thing everywhere, rather than
   introducing a third convention.

   **Blast radius, checked rather than assumed.** Six sites read `sid` off an access token. Four
   are admin console only, and the console requests
   `openid email profile authserver:manage-account authserver:manage` with no `offline_access`, so
   it always holds a session-bound grant and is unaffected. The two that can see an offline-grant
   caller are `IsCurrent` marking (`account-sessions/is-current`) and OTP session flagging
   (`otp/current-sid-only`), and both already guard on an empty `sid` and degrade to a no-op.

   **The residual window this leaves, largely closed by decision 11.** Dropping `sid` means the
   middleware can no longer reject an offline-grant access token by session lookup. As originally
   recorded, that left such tokens usable for up to 300 seconds after a credential change. Decision
   11's generation claim closes that for **credential changes**, since those increment the user's
   generation and the middleware compares the claim against it. It does **not** close it for
   **session termination**, which cannot bump a user-wide generation without invalidating that user's
   other devices. Session termination left this issue entirely with decision 3's reversal, so the
   residual belongs to #129 rather than being something this change ships.

   **This pushes decision 6.** With no `sid`, `RequireValidSession` returns early
   (`middleware/sid-passthrough`), so an `Enabled` check keyed on the resolved session would never
   run for an offline grant. Decision 6 was decided in that light, and decision 11's generation
   check rides the same code path.

   Note that once #127 lands, this fix becomes unwritable rather than merely fixed, because
   `RequireValidSession` would read grant persistence instead of inferring session-boundness from
   the presence of a `sid` claim. The fix recorded here is the pre-#127 form of it, and #127 records
   the same defect as its "Harm 1".

   **Rejected:** keeping `sid` and adding an offline marker claim for the middleware to skip on.
   Purely additive to the token contract and preserves all six consumers, but it adds a
   non-standard claim and touches two places, to preserve consumers that are either console-only or
   already degrade gracefully. **Also rejected:** making `RequireValidSession` pass through whenever
   `sid` is present but the session is missing, which is the tempting one-liner and would defeat
   this entire issue, since a deleted session would stop rejecting anything at all.

10. **Add the indexes the new lookups need, in the same change.** Status: **Decided**

    Raised when #127 was closed: its index finding needed a home, and this is the change that makes
    those indexes matter, since it introduces a user-scoped join over `codes.user_id` and leans on
    `codes.session_identifier` for the end-session path from decision 3.

    Migration 000024 (verified as the next free number on all four engines) adds, per engine, only
    what that engine lacks:

    | Column | Needed on | Already indexed on |
    |---|---|---|
    | `codes.user_id` | postgres, mssql, sqlite | mysql (`KEY fk_codes_user`, inline) |
    | `codes.session_identifier` | **all four** | none, it has no foreign key |
    | `refresh_tokens.code_id` | postgres, mssql, sqlite | mysql (`KEY fk_refresh_tokens_code`, inline) |
    | `refresh_tokens.user_id` | **sqlite** | mysql, postgres, mssql (migration 000011) |
    | `user_sessions.user_id` | postgres, mssql, sqlite | mysql (`KEY fk_user_sessions_user`, inline) |

    The last two rows were added by finding 5. `refresh_tokens.user_id` matters because it is the
    ROPC branch of decision 1's query, and `user_sessions.user_id` because
    `GetUserSessionsByUserId` (`data/iface-sessions-by-user`) is now on a security-critical path.

    **The per-engine picture, twice corrected.** #127 originally claimed nothing indexed
    `refresh_tokens.user_id`; that was wrong, derived from the SQLite schema snapshot and
    generalised, when migration 000011 creates it on three engines and SQLite's 000011 recreated the
    table restoring only `idx_refresh_token_jti`. A later version of this decision then *assumed*
    InnoDB auto-indexing covered the MySQL column. Finding 7 removed that assumption: verified that
    MySQL's initial migration declares `KEY fk_codes_user (user_id)`,
    `KEY fk_refresh_tokens_code (code_id)` and `KEY fk_user_sessions_user (user_id)` explicitly
    inline, so the table above rests on read DDL rather than on engine behaviour and no live
    `SHOW INDEX` is needed.

    **Rejected:** leaving indexes to a follow-up, which is where they sat before #127 was closed.
    The existing session-identifier join is already unindexed, so this change would inherit and
    widen an unindexed access pattern rather than introduce one, and a revocation sweep that scans
    is a poor thing to add to a password-reset path.

11. **A per-user `auth_state_generation` is the user-scoped security boundary; the sweep becomes
    cleanup and audit.** Status: **Decided**

    Raised by review finding 1, which showed that decision 5's transaction removes half-applied state
    *within* the operation but establishes no boundary against issuance that is concurrent with it or
    subsequent to it. Verified: refresh rotation marks the old token revoked with
    `UpdateRefreshToken(nil, ...)` and inserts its replacement with `CreateRefreshToken(nil, ...)`,
    both outside any transaction, so a refresh that validated before the sweep inserts a surviving
    child after it commits. For a session-bound grant, session deletion contains that child. For an
    offline or ROPC grant nothing does, and the child is good for up to a year.

    The invariant:

    > Credentials authenticated under generation N cannot create or use authentication state after
    > the user advances to generation N+1, except where rule 8 explicitly promotes the preserved
    > session and its refresh tokens forward.

    A monotonically increasing `auth_state_generation` is added to `users`, `user_sessions`, `codes`
    and `refresh_tokens`, to `AuthContext` as transient flow state, and to user access tokens as a
    claim. Existing rows migrate to 0. Rules:

    1. Password verification captures the user's current generation into `AuthContext`.
    2. A newly created session and authorization code inherit the captured generation.
    3. ROPC tokens inherit the generation current when the password was verified.
    4. Initial refresh tokens inherit their code's generation.
    5. Rotated refresh tokens copy the **parent refresh token's** generation. They must never read
       the user's current generation, which would launder an old grant into the new generation.
    6. Code redemption and refresh validation reject a generation mismatch.
    7. Credential-invalidating actions atomically increment the user's generation and perform the
       sweep, in decision 5's transaction.
    8. The `exceptSid` path promotes only the preserved `UserSession` and its unrevoked refresh
       tokens to the new generation.
    9. Unused codes are not promoted; they are rejected by their old generation and reaped.
    10. The audit event carries `oldGeneration` and `newGeneration` (decision 7).

    Six refinements, each from verification rather than preference:

    **(a) Refresh validation reads the generation from the `refresh_tokens` row, never from the
    joined `codes` row.** Rule 8 promotes the preserved session's tokens to N+1 while their codes
    stay at N, so a code-joined check would reject them and silently break decision 4. The code's
    generation is authoritative only at initial redemption.

    **(b) Every persisted generation field carries `fieldtag:"dont-update"`**, on `User`,
    `UserSession`, `Code` and `RefreshToken`. Verified that `UpdateUser`, `UpdateRefreshToken`,
    `UpdateUserSession` and `UpdateCode` all build with
    `WithoutTag("pk").WithoutTag("dont-update")`, while `InsertInto` uses only `WithoutTag("pk")`.
    So the tag gives exactly the semantics wanted: **written once at creation, then immutable except
    through an explicit method**, which is compatible with rules 2 to 5. Intentional changes go
    through narrow methods only: `IncrementUserAuthStateGeneration`,
    `PromoteUserSessionGeneration`, `PromoteRefreshTokenGenerations`.

    Note the failure this prevents is fail-closed, not a security hole: a clobber can only write N
    over N+1, because a model read *after* a promotion already holds the new value. So the defect it
    avoids is decision 4's preserved session breaking under concurrency.

    **(c) For a token carrying a `sid`, the live session's generation decides and the token's own
    claim is ignored.** This asymmetry is what lets decision 4's preserved session keep working after
    promotion, and it looks exactly like an oversight someone will "tidy" into checking both. It gets
    a test whose name states the intent.

    **(d) On the existing-session SSO path, `AuthContext` inherits the generation from the reused
    `user_sessions` row, never from the current user.** Rule 1 captures at password verification, but
    `AuthStateInitial` to `AuthStateLevel1ExistingSession` to `AuthStateLevel1PasswordCompleted`
    skips password verification entirely. Reading the user's current generation there would launder
    an old ceremony into the new generation, the same fault rule 5 forbids for rotation. This is also
    why `user_sessions.auth_state_generation` is necessary: a ceremony that began before the change
    can create a session after the sweep, so session deletion cannot catch it.

    **(e)** Covered by (b), which the review expanded from `User` alone to all four models.

    **(f)** The generation cannot serve session-scoped revocation, because end-session must not bump a
    user-wide counter. That was decision 12, now reversed by finding 15 and moved to #129.

    **What this gains beyond closing the race.** The access-token generation claim makes sid-less
    offline and ROPC access tokens immediately rejectable on goiabada's own API, which closes the
    300-second residual window decision 9 had accepted and section 4 had documented as its honest
    limit. Third-party resource servers remain unreachable, which is inherent.

    **Rejected:** deleting outstanding codes in the sweep and documenting the refresh race as
    residual. It closes the 60-second no-race hole but trades a millisecond race for a credential
    good for a year, which is a poor trade in a fix whose purpose is eviction, and it would make
    #106 a partial mitigation rather than a closure. **Also rejected:** a timestamp boundary, which
    is the same machinery with equality, precision and clock hazards, and which cannot express
    rule 8's promotion cleanly. **Also rejected:** per-user row locking, which needs
    `SELECT FOR UPDATE` semantics across four engines, needs transactions threaded through issuance
    paths that currently pass nil, and still cannot identify a multi-request ceremony that began
    before the change and completes after it.

12. **Not adopted. The `codes.revoked` grant marker moved to #129 with decision 3.**
    Status: **Decided**

    Recorded rather than deleted, because the number is cited elsewhere and because the analysis is
    what produced #129.

    The marker was adopted mid-interview as the session-scoped counterpart to decision 11, on the
    grounds that a rotated refresh token inherits `code_id` from its parent, so revoking the code
    catches every present and future descendant. **Finding 15 showed that is not sufficient**: it
    protects grants that already have a `codes` row when termination runs, and an in-flight ceremony
    writes a new one afterwards. See decision 3 for the verified sequence.

    Its full seven-item scope, worked out here from finding 13 and carried into #129 verbatim, is
    still correct as far as it goes: the column and a `dont-update` model field, a narrow
    `RevokeCodesBySessionIdentifier`, rejection at initial redemption, folding the marker into
    `MarkCodeAsUsed`'s compare-and-set as `WHERE id = ? AND used = false AND revoked = false`,
    rejection in auth-code refresh validation, extending
    `DeleteUsedCodesWithoutRefreshTokens` to reach unused revoked codes, and tests for redemption and
    refresh each racing termination.

    Also carried into #129: the separate live bug found while designing item six. Verified that
    `DeleteUsedCodesWithoutRefreshTokens` builds `NotIn("id", SELECT code_id FROM refresh_tokens)`,
    and because ROPC rows carry `code_id = NULL`, `x NOT IN (..., NULL)` is UNKNOWN rather than TRUE,
    so the sweep deletes nothing once any ROPC refresh token exists (finding 19).

13. **Every access token inherits its generation from the credential that authorized the issuance.**
    Status: **Decided**

    Raised by finding 16, which found decision 11 silent on this and load-bearing in both directions.

    > The generation stamped on an access token comes from the credential authorizing *that*
    > issuance: `AuthContext` for implicit issuance, the `Code` row for an initial code exchange, the
    > **`User` snapshot returned by password validation** for initial ROPC issuance, and the **parent
    > `RefreshToken` row** for both refresh paths. It is never read from a freshly loaded `User`, and
    > never from the `Code` joined to a refresh token.

    The initial-ROPC clause was added by finding 23, which found it missing: that path has neither a
    code nor a parent refresh token, so nothing in the original rule covered it. Verified the snapshot
    is already threaded through, since `HandleTokenPost`'s `password` case builds
    `ROPCGrantInput{User: validateResult.User, ...}`. **The user must not be reloaded between password
    validation and stamping**, or a credential change racing the request would launder the new
    generation onto a grant authenticated under the old one. Using the snapshot fails closed instead:
    the token is stamped with the old generation and the middleware rejects it.

    Both halves fix a real failure, verified against the issuer:

    - Auth-code refresh builds its access token from `input.Code` via `createTokenInputFromCode`. A
      preserved offline refresh token promoted to N+1 by decision 4 keeps a code at N, so reading the
      code would emit N and the middleware would wrongly reject a token it just issued.
    - ROPC refresh reconstructs its input from a freshly loaded user. Reading the current user would
      emit N+1 for a grant authenticated at N, laundering it forward, which is exactly what decision
      11 rule 5 forbids for the refresh token itself.

    A test pins each direction, since neither is visible in ordinary single-request flows.

14. **Credential and security fields are written through narrow methods, and disable is a
    compare-and-set.** Status: **Decided**

    Raised by finding 17. Verified pre-existing defect: `UpdateUser` writes every field not tagged
    `dont-update` (`WithoutTag("pk").WithoutTag("dont-update")`), and both `HandleAPIAccountPasswordPut`
    (`account-pwd/write`) and `HandleAPIUserEnabledPut` (`admin-enabled/write`) load the whole user and
    write it back. So a password change that loaded `Enabled = true` can commit after an admin disable
    and **silently re-enable the account**, and a disable can restore a stale password hash.

    That defeats site 3 outright, which is why it is in scope rather than adjacent. Decision 11(b)'s
    `dont-update` tagging does not help, because this is cross-field clobbering rather than generation
    regression.

    The four credential actions write through narrow methods instead of the full-row update. The
    enabled field specifically goes through **one** conditional method covering both directions,
    `TrySetUserEnabled(tx, userId, expected, desired) (bool, error)`, implemented as
    `SET enabled = ? WHERE id = ? AND enabled = ?` and reporting `rowsAffected == 1`, mirroring
    `MarkCodeAsUsed`.

    Finding 21 is why it covers both directions rather than being a `TryDisableUser`: the same endpoint
    serves `Enabled = true`, and leaving that on the full-row `UpdateUser` would keep this very
    clobbering defect alive in half of it.

    The disable direction's return also supplies finding 4's transition detection for free: a false
    return means the account was already disabled, so the revocation and the new audit event are both
    skipped. Enabling never revokes and never emits the new event; the endpoint's existing
    `AuditUpdatedUserDetails` (`admin-enabled/audit`) continues to fire unchanged in both directions,
    per decision 7's rule that existing events are left alone.

15. **Legacy access tokens with no generation claim are treated as generation 0.** Status: **Decided**

    Raised by finding 18. Existing rows migrate to generation 0, but access tokens already issued and
    still within their lifetime carry no claim at all, so the middleware needs a defined reading:

    - **Claim absent** on an otherwise valid user token: treat as generation 0. It therefore continues
      to work while that user is still at 0, and stops the moment the user's generation advances,
      which is exactly the intended semantics.
    - **Claim present but not an integer**: reject. A malformed claim is not a legacy token.
    - **Claim absent and the user has advanced**: reject, by the ordinary mismatch rule.

    Without this the deployment either invalidates every live sid-less access token at once, which
    would contradict section 4's claim that nothing currently succeeding starts failing, or silently
    accepts any token lacking the claim, which would leave a permanent bypass.

    **The claim arrives as `float64`, not `int`**, discovered by executing the decision table rather
    than reasoning about it. `jwt.MapClaims` unmarshals every JSON number through `encoding/json`, so
    a numeric claim is always `float64`; verified that `JwtToken.GetTimeClaim` type-asserts to exactly
    that, and that the codebase has **no** integer claim accessor. An implementation asserting to
    `int` would therefore reject every token, including well-formed ones. So this decision also
    requires a new `JwtToken.GetIntClaim(name) (int64, bool)` mirroring `GetTimeClaim`, and
    "malformed" means: not `float64`, non-integral, negative, or beyond the exact-integer range of
    `float64`. Stage 3 owns the table that pins each of those.

    **Absence and malformation must not collapse into one signal**, per finding 22. A conventional
    `(int64, bool)` accessor returns `false` for both, which would make an absent claim indistinguishable
    from a malformed one and therefore reject every legacy token, the exact outage this decision exists
    to prevent. Resolution: `GetIntClaim` keeps the conventional contract and reports only whether a
    **present** claim parsed, while the middleware tests raw map presence first:

    ```go
    if _, present := jwtToken.Claims["auth_state_generation"]; !present {
        gen = 0                                  // legacy token
    } else if v, ok := jwtToken.GetIntClaim("auth_state_generation"); !ok {
        reject                                   // present but malformed
    } else {
        gen = v
    }
    ```

    This is already the idiom in this file: `RequireUserBoundToken` distinguishes its cases with
    `if _, hasAuthTime := jwtToken.Claims["auth_time"]; !hasAuthTime`. So the generic accessor stays
    unsurprising and the tri-state lives at the one call site that needs it.

## 4. Proposed solution

A durable per-user boundary plus a physical sweep. The boundary is the security mechanism; the sweep
is immediate invalidation, cleanup and audit detail.

> **The generation is the boundary** (decision 11). Decision 5's transaction makes the credential
> write atomic with the sweep, but a transaction bounds only *that operation*: it is not a boundary
> against issuance racing it, which is what the generation is for.

Session-scoped revocation is **not** in this change. Finding 15 showed no marker over existing rows
can be durable there, so decisions 3 and 12 were reversed and the work moved to #129.

### 4.1 The generation boundary

`auth_state_generation` on `users`, `user_sessions`, `codes` and `refresh_tokens`, on `AuthContext`
as transient flow state, and on user access tokens as a claim. All existing rows migrate to 0. The
ten rules and the refinements are in decision 11. The load-bearing ones to keep in view:

- Rotation copies the **parent refresh token's** generation, never the user's current one.
- Refresh *validation* reads the generation from the `refresh_tokens` row, not from the joined
  `codes` row, or decision 4's promoted session breaks.
- An **access token** inherits from the credential authorizing that issuance: `AuthContext` for
  implicit, the `Code` for an initial exchange, the **parent `RefreshToken`** for both refresh paths.
  Never a freshly loaded `User`, never a refresh token's joined `Code`. Per decision 13.
- Every persisted generation field is `fieldtag:"dont-update"`, so it is written on insert and
  thereafter only through `IncrementUserAuthStateGeneration`, `PromoteUserSessionGeneration` or
  `PromoteRefreshTokenGenerations`.
- SSO ceremonies inherit the generation from the reused session, never from the user.
- A token with **no** generation claim reads as generation 0; a malformed claim is rejected. Per
  decision 15, which is what stops the deployment invalidating every live sid-less access token.

### 4.2 Data layer: a user-scoped refresh-token query

`GetRefreshTokensByUserId(tx *sql.Tx, userId int64) ([]*models.RefreshToken, error)` on the
`Database` interface (`data/iface-rt-by-sid` is its nearest neighbour), implemented once in
`commondb`, plus four two-line delegating wrappers.

Built as **two `UNION ALL` branches**, not a `LEFT JOIN` with an `OR`: one joining `codes` on
`codes.user_id`, one selecting on `refresh_tokens.user_id`. The shapes are mutually exclusive,
verified from the issuer (the auth-code path sets only `CodeId`; the ROPC path sets only `UserId` and
`ClientId`), so the union cannot duplicate and each branch can use its own index. Per finding 6.

Reaching all three shapes is the point. The existing session-scoped query cannot, because its
`INNER JOIN codes` excludes rows with a null `code_id` (`rt-query/session-join`) and because it needs
a live session row to supply the `sid`. Per decision 1.

The invariant gets a comment on the function: **every refresh token reaches its user through
`codes.user_id` or `refresh_tokens.user_id`, and nothing else.** If a fifth issuance shape is ever
added, the data test enumerating shapes is what should fail.

### 4.3 Narrow writes for credential and security fields

Verified pre-existing defect (decision 14): `UpdateUser` writes every field not tagged
`dont-update`, and the credential handlers load the whole user and write it back, so a password
change that loaded `Enabled = true` can commit after an admin disable and silently re-enable the
account. The four actions therefore write through narrow methods rather than the full-row update, and
**disable becomes a compare-and-set** (`enabled = true -> false`) returning whether it transitioned.

### 4.4 Migration 000024

Four generation columns and, per engine, only the indexes that engine lacks. The per-engine index
table is in decision 10, which also records the two corrections it went through.
`codes.session_identifier` is still on that list even though session-scoped revocation left with
decision 3, because `GetRefreshTokensBySessionIdentifier` remains in use by 4.5's preserved-set query
and by `revokeOnAuthCodeReuse`.

### 4.5 The revocation helper

In `src/authserver/internal/handlers` (package `handlers`), which `apihandlers` already imports, so
one location serves all four call sites.

```go
// Returns the JTIs this call transitioned from live to revoked. Already-revoked
// tokens are skipped and NOT reported: callers rely on "we actually revoked
// something" to tell a real revocation from a no-op (see #77).
func revokeRefreshTokens(db data.Database, tx *sql.Tx,
    tokens []*models.RefreshToken) ([]string, error)

type RevocationResult struct {
    TerminatedSessionIdentifiers []string
    RevokedRefreshTokenJtis      []string
    PreservedSessionIdentifier   string   // "" when nothing was preserved, never null
    OldGeneration                int64
    NewGeneration                int64
}

// exceptSid preserves one session and its refresh tokens; empty revokes everything.
func RevokeUserAuthState(db data.Database, tx *sql.Tx, userId int64,
    exceptSid string) (RevocationResult, error)
```

It increments the user's generation, loads the user's refresh tokens with 4.2 and their sessions with
`GetUserSessionsByUserId` (`data/iface-sessions-by-user`), revokes and deletes everything outside the
preserved set, and promotes the preserved session and its surviving refresh tokens to the new
generation.

**How the preserved set is identified**, per finding 3. A user-scoped query returns
`[]*models.RefreshToken`, and an offline row's `session_identifier` is empty while its originating sid
lives only on the `codes` row, which the model exposes as `db:"-"`. So the preserved set cannot be
derived from the returned rows. When `exceptSid != ""` the helper additionally calls
`GetRefreshTokensBySessionIdentifier(tx, exceptSid)`, which matches `codes.session_identifier` and
therefore does return the preserved session's offline tokens, and excludes those ids from the sweep.
Without this, a straightforward implementation revokes the preserved session's offline tokens and
contradicts decision 4.

`revokeOnAuthCodeReuse` keeps its own body, its own transaction and its #77 comment
(`revoke/conditional-teardown`). Only its loop (`revoke/family`) becomes a call to
`revokeRefreshTokens`.

`RevocationResult` fields map onto decision 7's audit payload directly.

### 4.6 The four call sites

Each opens a transaction, performs its own narrow write plus the revocation inside it, commits, then
emits the audit event. Audit after commit is forced rather than chosen: `AuditLogger.Log` takes no
transaction (decision 5).

| Site | exceptSid | Runs when | Audit reason |
|---|---|---|---|
| `reset/password-write` | none | always | `password_reset` |
| `account-pwd/write` | caller's `sid` | always | `password_change` |
| `admin-enabled/write` | none | **only on the enabled to disabled transition** | `account_disabled` |
| `admin-pwd/write` | none | always | `admin_password_set` |

The conditional on the disable row is finding 4: `user.Enabled = req.Enabled`
(`admin-enabled/write`) serves both directions, so revoking unconditionally would sign a user out
when an admin *enables* them. Gating on the compare-and-set's return (decision 14) rather than on
`req.Enabled == false` also makes re-disabling an already-disabled user a no-op rather than a spurious
revocation and audit entry.

Site 4 is an addition to what the issue asked for, per decision 2. The `exceptSid` on the
self-service change is per decision 4, and it preserves that session's refresh tokens as well as its
session row.

The admin console needs no change: it reaches all four through the same endpoints, and it does not
request `offline_access`, so 4.8 does not affect it either.

### 4.7 `RequireValidSession` gains an `Enabled` check and a generation check

Resolve the user by `sub` whenever `auth_time` is present, rejecting an empty `sub` explicitly. Reject
when the account is not enabled (decision 6). Then check the generation, with the asymmetry decision
11(c) requires:

- **`sid` present:** require a live, in-bounds session whose generation equals the user's current
  generation. The token's own generation claim is deliberately **ignored**, which is what lets
  decision 4's promoted session keep serving its existing access tokens.
- **`sid` absent, `auth_time` present** (offline, ROPC): require the token's generation claim to
  equal the user's current generation, reading an absent claim as 0 per decision 15.
- **`auth_time` absent** (client_credentials): no user, no checks, pass through.

Lookup error is a 500, consistent with `middleware/fail-closed`; a nil user is a rejection.

### 4.8 Access tokens on offline grants stop carrying `sid`

`generateAccessTokenCore` omits `sid` when the grant is offline. The predicate reads the **grant's**
offline-ness, never the request's: `code.Scope` on initial exchange,
`RefreshToken.RefreshTokenType == "Offline"` on refresh. ID tokens on auth-code grants keep `sid`
unchanged, or RP-initiated logout breaks; ROPC ID tokens never had one. Per decision 9.

### 4.9 One audit event

`AuditRevokedUserAuthState = "revoked_user_auth_state"`, added to `AuditEventTypes`
(`constants/audit-list`), emitted unconditionally so it also records actions that had nothing to
revoke, and carrying the old and new generations. Per decision 7.

### What this achieves, and what it does not

After a credential change, per credential type:

| | Session-bound grant | Offline grant | ROPC |
|---|---|---|---|
| `UserSession` row | deleted | deleted, if one still exists | none exists |
| Refresh token | revoked | revoked | revoked |
| Replacement inserted by a racing refresh | rejected, session gone | rejected, old generation | rejected, old generation |
| Outstanding authorization code | rejected, old generation | rejected, old generation | none exists |
| Ceremony completing after the change | rejected, old generation via `AuthContext` | rejected, old generation | none exists |
| Access token, goiabada API | rejected, session gone | rejected, old generation | rejected, old generation |
| Access token, third-party RS | valid until expiry | valid until expiry | valid until expiry |

Except, in every column, the one session preserved by decision 4 on self-service password change,
which is promoted rather than revoked.

The third-party row is inherent to stateless JWTs and is out of scope. So is session termination,
which #129 covers: ending a session still revokes nothing today.

### Departures from the issue

1. **The issue's session walk is not used** (decision 1). It cannot reach an offline refresh token
   once the session row is reaped, which at seeded defaults is the normal resting state of an offline
   grant, and it cannot reach ROPC tokens at all.
2. **A fourth site exists** (decision 2), `admin-pwd/write`, unmentioned in the issue.
3. **`revokeAllUserSessions` is not extracted from `revokeOnAuthCodeReuse`** (decision 8). The two
   differ on four behavioural axes, one of which is load-bearing for #77.
4. **The `Enabled` check is keyed on `auth_time` and `sub`, not on the resolved session** (decision
   6). The issue's framing assumed keying off the session the middleware already loads, which after
   4.8 would cover almost nothing.
5. **The fix is a durable generation boundary, not only a sweep** (decision 11). The issue proposes
   revoke-and-delete, which finding 1 showed a concurrent refresh can outrun.

The issue is also slightly generous to itself on severity for disable: `user.Enabled` is already
checked on every mint path including both refresh paths, so for disable this change is defence in
depth plus closing the access-token window, not the fix. For a password reset it is the fix.

### Why this is safe

**Nothing that currently succeeds starts failing, except deliberately.** The behaviour changes that
reject more are the point of the issue: a disabled user on the API surface, a token whose session was
revoked, and a credential from a superseded generation. Decision 15 is what keeps that claim true
across the deployment itself, since a token issued before the migration reads as generation 0 and
keeps working until that user's generation advances.

**The operation cannot half-apply**, because the narrow credential write, the generation increment and
the sweep share one transaction (decisions 5 and 14). Note the narrow claim: a transaction bounds this
operation and does not bound issuance racing it. Finding 1 correctly rejected the broader wording, and
the generation is what covers the rest, as the matrix above sets out row by row.

**The generation cannot be laundered forward.** Rotation copies the parent's value, SSO copies the
session's, and an access token copies whichever credential authorized it (decision 13), so no path
lets an old grant acquire a new generation except the two explicit promotion methods called inside
the credential transaction.

**Security-relevant fields cannot be regressed by ordinary writes.** Generation fields are excluded
from every full-model update by `dont-update`, and the four credential actions use narrow methods so
they cannot clobber each other's fields (decision 14). The regression `dont-update` prevents is
fail-closed anyway: a clobber can only write an older generation over a newer one.

**The one relaxation is strictly a relaxation.** 4.8 causes some previously rejected requests to
succeed, and only for tokens on offline grants. It cannot grant access to anyone who could not already
mint that token, and it restores behaviour OIDC Core section 11 requires.

**Both new rejection paths fail closed**, following `middleware/fail-closed`: a lookup error is a 500,
not a pass-through.

## 5. Implementation plan

Seven stages. Each is one review, one test run and one commit, and all seven land as a single PR per
the `Delivery` line in the metadata. Stage 1a first is not preference: every later stage reads columns
and methods it creates.

Stage 1 was **split into 1a and 1b at the user's request during implementation**, because as a single
stage it was about thirty new functions, eight migration files, four snapshots, four models, a mock
regeneration and tests across five files, which is more than one sitting can review. The seam is
schema and models against methods and mocks. The split is lettered rather than renumbered so that
every "stage 2 step 7" style citation elsewhere in this document stays valid.

Note the seam is **not** exactly steps 1 and 2 against steps 3 to 6, which would have left the first
half with no tests at all and broken this section's own rule that every stage names a tier it
exercises. The schema and model tests, the migration assertions and the `dont-update` tag assertions,
move into 1a with the thing they test. Those are self-contained: `InsertInto` writes `dont-update`
fields, verified, so 1a can create a row with a nonzero generation and assert a full-row update leaves
it alone, without needing 1b's promotion methods.

**Test tiers and where they run.** Unit tests run on the host with `go test`. **Data and integration
tests do not**: they need `goiabada-devcontainer-1` up, driven by `docker exec` with the repo at
`/workspaces/goiabada`, because the host has neither the database hostnames nor tailwindcss. Every
stage below says which tiers it actually exercises, so a green host run is never mistaken for a green
suite.

**What each tier can and cannot prove here.** The decision tables in stages 2 and 3 are pure-function
or mock-backed, so they prove the branch logic and nothing about whether the real database or a real
JWT agrees. The data tests in stage 1 are the only tier that runs against all four engines, which is
why the `UNION ALL` query and the migration are owned there rather than being asserted through mocks.
The integration tests in stage 5 are the only tier that shows the advertised behaviour actually
happens end to end, and they are too expensive to enumerate shapes in, which is why they are thin by
design and say so.

**Tables in this plan were executed before being written down**, per the project's testing
discipline: a throwaway sketch of the middleware decision, the `sid`-emission predicate, the
provenance rule, the preserved-set sweep and the disable conditionality was run over every row. **48
asserted cases, 0 mismatches** on the final revision. Revisions matter and the count is never carried
across one: an early run modelled the generation claim as a Go `int` and produced a table that would
have rejected every well-formed token (decision 15), a later run added the initial-ROPC provenance row
from finding 23 and corrected a sweep expectation that contradicted the sketch's own output
(finding 27), and the final run added the persisted-state stamping table from finding 28.

### Stage 1a: schema and models
Status: **Done**

Tests: **data tests only, dev container, all four engines.** No unit tests; there is no logic here,
only columns and struct tags.

1. Migration `000024` for sqlite, mysql, postgres and mssql. Status: **Done**
   Adds `auth_state_generation` to `users`, `user_sessions`, `codes` and `refresh_tokens`, each
   `NOT NULL DEFAULT 0` so existing rows migrate to generation 0 (decision 11). Adds only the indexes
   each engine lacks, per decision 10's table: `codes.user_id`, `codes.session_identifier`,
   `refresh_tokens.code_id`, `refresh_tokens.user_id` (sqlite only) and `user_sessions.user_id`.
   Column types per engine follow the existing convention, and the documentation-only
   `schema.sql` snapshots are updated in the same step since they have drifted before.
2. Model fields, each tagged `fieldtag:"dont-update"`. Status: **Done**
   On `models.User`, `models.UserSession`, `models.Code` and `models.RefreshToken`. Verified this is
   the right mechanism: all four `Update*` methods build with
   `WithoutTag("pk").WithoutTag("dont-update")` while `InsertInto` uses only `WithoutTag("pk")`, so
   the field is written at creation and immutable thereafter except through stage 1b step 2's methods
   (decision 11(b)).
3. Data tests for the schema and the tags. Status: **Done**
   A migration test in the style of `migration_000021_countries_test.go` asserts pre-existing rows land
   at generation 0 on every engine, **and that each expected index exists afterwards**. The index
   assertion is not redundant: every behavioural query test stays green with an index accidentally
   omitted, so nothing else in the suite would notice. It needs a per-engine index-listing helper,
   since the four engines expose indexes differently (`sqlite_master` / `PRAGMA index_list`,
   `SHOW INDEX`, `pg_indexes`, `sys.indexes`).
   The `dont-update` tag is pinned on **all four** models, not three: `user_test.go`, `code_test.go`,
   `user_session_test.go` and `refresh_token_test.go` each create a row with a nonzero
   `auth_state_generation`, perform a full-row `Update*` with a stale model, and assert the value did
   **not** change. Those are the rows that pin decision 11(b) and would silently pass if the tag were
   dropped. They work without stage 1b because `InsertInto` builds with `WithoutTag("pk")` only, so a
   `dont-update` field is written on creation.

   **As built.** Migration files at `000024_add_auth_state_generation.{up,down}.sql` in all four
   `migrations/` directories, snapshots updated in all four `schema.sql` files, model fields visible at
   the `AuthStateGeneration` declaration in `models.User`, `models.UserSession`, `models.Code` and
   `models.RefreshToken`, tests in `migration_000024_auth_state_generation_test.go` plus
   `TestUpdateUser_DoesNotClobberAuthStateGeneration` and its three siblings.

   Five things worth knowing that the plan did not anticipate, all contained inside this step:

   1. **mssql needs named default constraints.** Probed empirically against the running SQL Server:
      `ALTER TABLE ... DROP COLUMN` is refused while a default constraint depends on the column
      ("failed because one or more objects access this column"). So 000024 names each default and the
      down migration drops them by name. The existing mssql down migrations 000004 and 000017 do a bare
      `DROP COLUMN` on defaulted columns and would therefore fail; pre-existing, left alone.
   2. **A down/up round trip was added to the migration test**, which the plan did not list. Nothing
      else in the suite ever executes a down migration: `Migrate()` only calls `Up()`, and the other
      migrator test starts from an empty database so its `Migrate(20)` goes *up*. Without this case my
      own down migration would have been unverified, and it is what proves point 1.
   3. **The migration test reads the generation with raw SQL**, not `GetUserById`. The pre-migration
      seed has to use raw SQL (the Go model already references the column), which leaves nullable string
      columns as SQL NULL, and the model scanner cannot map those into Go strings. The model mapping is
      covered by the four `dont-update` tests instead.
   4. **`TestMigration000021_CountryData` had to be fixed.** It seeded via `CreateUser` at schema
      version 20, so the new column broke it with `Unknown column 'auth_state_generation'`. Changed to
      `Up()` then `Force(20)`, which moves the version marker without touching the schema. That is the
      same trick the test already used for its own idempotency check, and 000021 is data-only, so it
      still applies the transformation to pre-migration data.
   5. **The tag assertions were verified to have teeth.** Removing `fieldtag:"dont-update"` from
      `models.User` makes `TestUpdateUser_DoesNotClobberAuthStateGeneration` fail with
      "UpdateUser regressed auth_state_generation to 0, want 7". Restored afterwards.

   **Review round on this stage.** One finding, valid: the migration test proved the generation-0
   backfill for `users` only, while the four tag tests create rows with an explicit generation of 7 and
   so never exercise the default at all. A `DEFAULT 1` typo on `user_sessions`, `codes` or
   `refresh_tokens` would therefore have passed the entire suite and invalidated existing
   authentication state on deployment.

   Resolved by asserting each of the four columns is `NOT NULL` with a default of 0, on every engine,
   rather than by seeding a full pre-migration user, client, session, code and refresh-token graph. The
   reasoning: the `ALTER ... DEFAULT 0` backfill is a property of the engine and the seeded `users` row
   already proves this engine applies it, so what remained to catch was a per-column DDL typo, which is
   exactly what the declared default reports. It costs four one-statement metadata queries instead of a
   raw-SQL fixture carrying forty-odd `NOT NULL` columns with per-dialect datetime and boolean literals,
   which is its own bug surface. The reviewer named the graph seed as the strongest evidence and this as
   a reasonable lower-noise compromise; this is the compromise, taken deliberately.

   Verified to have teeth on two engines rather than one: injecting `DEFAULT 1` on `codes` fails with
   `codes.auth_state_generation must default to 0, got "1"` on sqlite **and** on mssql, the latter
   confirming the normalisation genuinely parses `((0))` rather than passing by accident.

   Also corrected in that round: `TestMigration000021_CountryData`'s opening comment now says it runs
   000021 against the schema at head with the version marker forced to 20, rather than implying it runs
   against the version-20 schema.

### Stage 1b: data-layer methods, mocks and query tests
Status: **Done**

Tests: **data tests only, dev container, all four engines.**

1. `GetRefreshTokensByUserId(tx, userId)` on the `Database` interface, one `commondb`
   implementation, four delegating wrappers. Status: **Done**
   Two `UNION ALL` branches, one joining `codes` on `codes.user_id` and one selecting on
   `refresh_tokens.user_id` (decision 1, finding 6). Carries the invariant comment: every refresh
   token reaches its user through one of those two columns and nothing else.
2. Narrow write methods. Status: **Done**
   `IncrementUserAuthStateGeneration(tx, userId) (int64, error)` returning the new value;
   `PromoteUserSessionGeneration(tx, sessionId, gen)`; `PromoteRefreshTokenGenerations(tx, ids, gen)`;
   `SetUserPasswordHash(tx, userId, hash)` clearing the forgot-password fields in the same statement;
   and `TrySetUserEnabled(tx, userId, expected, desired bool) (bool, error)` as a compare-and-set
   (`SET enabled = ? WHERE id = ? AND enabled = ?`, reporting `rowsAffected == 1`), mirroring
   `MarkCodeAsUsed`. Decision 14. It covers **both** directions deliberately, per finding 21: the
   enabled endpoint also serves `Enabled = true`, and leaving that on the full-row update would keep
   the clobbering defect alive in half of it. The disable direction's return gates stage 5's
   revocation.
3. Regenerate `src/core/data/mocks/database_mock.go` with mockery (`src/core/.mockery.yaml`).
   Status: **Done**
4. Data tests in `src/authserver/tests/data/`. Status: **Done**
   This is the exhaustive owner of the query's shape coverage; later stages test consumers thinly and
   say so. `refresh_token_test.go` gains a `GetRefreshTokensByUserId` table enumerating every linkage
   shape adversarially: session-bound with a live session; offline with a live session; **offline
   whose session row has been deleted**, which is the stolen-laptop case from decision 1 and the row
   whose absence made the issue's own proposal insufficient; ROPC with a direct `user_id`; a token
   belonging to a **different** user, which must not be returned; and the empty result for a user with
   no tokens. The different-user row is the negative case that fails for the right reason: it varies
   only the user id, so it cannot pass with the predicate removed.
   Every narrow method from step 2 is exercised here, on all four engines, not only the enabled one:
   `TrySetUserEnabled` returns true exactly once across two identical calls in **each** direction, and
   false when `expected` does not match; `IncrementUserAuthStateGeneration` called twice returns
   successive values, which pins monotonicity; `PromoteRefreshTokenGenerations` changes only the named
   rows, leaves unnamed rows untouched, and skips already-revoked rows; **an empty id list is a no-op**,
   which matters because an empty `IN ()` is either a syntax error or a match-everything depending on
   the builder, so this row is a real hazard rather than a formality;
   `PromoteUserSessionGeneration` changes only the named session; and `SetUserPasswordHash` clears the
   forgot-password fields without touching any other column.
   The migration and `dont-update` assertions are **stage 1a's**, not repeated here.

   **As built.** `GetRefreshTokensByUserId` and `PromoteRefreshTokenGenerations` in
   `commondb/refresh_token.go`; `IncrementUserAuthStateGeneration`, `SetUserPasswordHash` and
   `TrySetUserEnabled` in `commondb/user.go`; `PromoteUserSessionGeneration` in
   `commondb/user_session.go`; six declarations on the `Database` interface; 24 delegating wrappers
   across the four engine packages; `database_mock.go` regenerated (+401 lines). Tests:
   `TestGetRefreshTokensByUserId`, `TestGetRefreshTokensByUserId_NoTokens`,
   `TestPromoteRefreshTokenGenerations`, `TestIncrementUserAuthStateGeneration`,
   `TestSetUserPasswordHash`, `TestTrySetUserEnabled`, `TestPromoteUserSessionGeneration`.

   Two things the plan did not anticipate, both contained inside steps:

   1. **`Assign(col, nil)` is not portable.** `SetUserPasswordHash` has to clear
      `forgot_password_code_encrypted` and `forgot_password_code_issued_at`, and passing a Go
      `nil` through sqlbuilder sends an untyped parameter that the SQL Server driver types as
      `nvarchar`, which it then refuses to convert to `varbinary(max)`:
      *"Implicit conversion from data type nvarchar to varbinary(max) is not allowed."* Caught by
      the four-engine data tests, passing on the other three. Replaced with literal
      `column = NULL` fragments, which have no parameter type to get wrong.
   2. **`IncrementUserAuthStateGeneration` reads the new value back** rather than computing the
      successor in Go, since the increment happens in the database and the read-back is the value
      that actually landed. It also treats a zero `rowsAffected` as an error, because a caller
      asking to advance a boundary for a user that does not exist should not receive a silent 0.

   **Verified on all four engines**: sqlite 265 pass, mysql 267, postgres 267, mssql 266, zero
   failures throughout, and the seven new tests pass on every engine.

   Getting mssql there needed an environment diagnosis, recorded here because the symptom pointed
   somewhere misleading. The full suite first hung for 9m49s in the pre-existing
   `TestRefreshTokenLoadClient` and was killed by Go's 600s test-binary timeout, which reads like a
   deadlock in that test. It was not: `docker stats` showed the server spinning at 294% CPU with no
   OOM kill, and its log carried `Error: 701 ... There is insufficient system memory in resource
   pool 'default'`, each occurrence immediately following an
   `[DBMgr::EnqueueDbFileDeletes] ... goiabada_mig_*.mdf` line. That is the isolated-database
   migration helper: it creates and drops a real database per call, SQL Server does not promptly
   return the committed memory, and the 4GiB container pool ran out after this session's repeated
   runs. No disk leakage (`/var/opt/mssql/data/` had no leftover files) and no leaked databases.
   `docker restart` cleared it: CPU to 0.43%, a query that had been timing out past 100 seconds
   answered in 0.046s. The lesson for later stages is to iterate on sqlite and widen to `--db all`
   once, rather than looping four-engine runs.

   **Review round on this stage.** Three findings, all valid, all inside step boundaries.

   1. **`GetRefreshTokensByUserId` did not check `rows.Err()`.** A mid-stream failure would have
      returned a partial token set as success, and the caller would have committed a revocation
      sweep that missed rows it never saw. Both sibling queries (`GetRefreshTokensByCodeId` and
      `GetRefreshTokensBySessionIdentifier`) already had the check, so this was a consistency break
      as well as a correctness one. Added, matching their wording. **Untested**, stated plainly: the
      failure path needs a mid-iteration database fault, which the data tests have no harness to
      inject, so this rests on inspection and on matching the neighbours.
   2. **`IncrementUserAuthStateGeneration` now requires a transaction** and rejects a nil one. The
      increment and the read-back are two statements, because no single syntax for both
      increments-and-returns is portable across all four supported engines. Outside a transaction, a
      concurrent
      increment can land between them and the caller returns the *other* caller's generation, then
      stamps it on the session and tokens it is preserving, leaving them valid past the boundary the
      other credential change had just established. The test previously used `nil` and therefore
      endorsed exactly that unsafe usage; it now goes through `beginTx(t)` and asserts a nil
      transaction is refused. Decision 5 already has every caller owning a transaction, so this
      tightens the contract to match the design rather than constraining it.
   3. **`PromoteUserSessionGeneration` now requires exactly one affected row.** It previously ignored
      `RowsAffected`, so promoting a session that does not exist succeeded silently. That would leave
      decision 4's preservation half applied: the tokens promoted, the session not, and the session
      then rejected on its next request. A nonzero unknown-id case was added alongside the zero-id
      one.

      Note `PromoteRefreshTokenGenerations` deliberately does **not** get the same check: it skips
      already-revoked rows by design, so a row count below the id count is expected there.

   Both new guards were verified to have teeth: neutralising each makes its test fail with the
   intended message, and both were restored. Re-run after the corrections: the twelve affected tests
   pass on all four engines, zero failures, with mssql healthy at 0.54% CPU throughout.

### Stage 2: generation stamping at issuance, and the offline `sid` fix
Status: **Not started**

Tests: **unit tests only, host.** They cannot show that a real JWT round-trips the claim; stage 5's
integration tests do that.

1. `JwtToken.GetIntClaim(name) (int64, bool)` in `src/core/oauth/jwt_token.go`.
   Status: **Not started**
   Mirrors `GetTimeClaim`'s `float64` assertion, and additionally rejects non-integral, negative and
   beyond-exact-range values. Decision 15 records why an `int` assertion would have rejected every
   well-formed token. Its contract is the conventional one, reporting only whether a **present** claim
   parsed; distinguishing absent from malformed is the middleware's job via a raw map presence check,
   following the `auth_time` idiom already in `RequireUserBoundToken` (finding 22).
2. `AuthContext.AuthStateGeneration`, captured at password verification and inherited from the reused
   session on the SSO path. Status: **Not started**
   The SSO half is decision 11(d): `AuthStateLevel1ExistingSession` never reaches the password
   handler, so reading the current user there would launder an old ceremony forward.
3. Stamp code creation (`CodeIssuer`) and session creation (`StartNewUserSession`) from the
   `AuthContext` value. Status: **Not started**
4. Stamp refresh-token creation in both `generateRefreshToken` and `generateRefreshTokenForROPC`, and
   make rotation copy the **parent refresh token's** value. Status: **Not started**
   Rule 5 of decision 11. Never the user's current value.
5. Emit the `auth_state_generation` claim on user access tokens, sourced per decision 13.
   Status: **Not started**
   `AuthContext` for implicit, the `Code` for an initial exchange, the **`User` snapshot from password
   validation** for initial ROPC issuance, and the parent `RefreshToken` for both refresh paths. Never
   a freshly loaded `User`, never a refresh token's joined `Code`. The ROPC clause is finding 23;
   `ROPCGrantInput` already carries `validateResult.User`, and the user must not be reloaded between
   validation and stamping.
6. Omit `sid` from access tokens on offline grants. Status: **Not started**
   Predicate reads the grant: `code.Scope` on initial exchange,
   `RefreshToken.RefreshTokenType == "Offline"` on refresh (decision 9). ID tokens on auth-code grants
   keep `sid`; ROPC ID tokens never had one.
7. Unit tests. Status: **Not started**
   **Exhaustive owner of the `sid`-emission table** (6 rows, executed): initial session-bound emits;
   initial with `offline_access` does not; initial with an empty session identifier does not; refresh
   on `typ=Refresh` emits; refresh on `typ=Offline` does not; and **refresh on an offline grant whose
   request down-scoped away `offline_access` does not**. That last row is the regression guard for the
   trap in decision 9: the sketch confirmed a request-scope-based predicate emits `sid` there and
   resurrects the bug intermittently. **Keep it** even though it looks redundant once the predicate
   reads the grant.
   **Exhaustive owner of the provenance table** (6 rows, executed): implicit from `AuthContext`;
   initial from the `Code`; auth-code refresh of a **promoted** token emits the parent's N+1 while its
   code still says N; ROPC refresh of a racing old grant emits N, not the user's N+1; initial ROPC with
   the snapshot matching the current user; and initial ROPC where a reset raced in, which emits the
   snapshot's N and is then rejected downstream rather than laundering N+1. The two refresh rows each
   **failed under the design before decision 13**, and the last row is the one finding 23 added, so all
   three are the only reason the rule is visible and none is to be tidied away.
   `GetIntClaim` gets its own table, with the **exact returned tuple pinned per row** so the
   absent-versus-malformed distinction cannot silently collapse (finding 22): integral `float64`
   returns `(n, true)`; non-integral, negative, beyond-exact-range, string, bool and nil each return
   `(0, false)`; and an absent claim also returns `(0, false)`, which is why the middleware checks map
   presence **before** calling it. That last row is the one that would otherwise reject every legacy
   token, so its expected tuple is the load-bearing assertion in the table rather than a formality.
   Also extend `handler_auth_pwd_test.go` and `handler_auth_level1_test.go` thinly, one case each,
   asserting only that the `AuthContext` carries a generation and that SSO inherits it from the
   session. Deliberately thin: stage 2 step 7's tables own the logic.
8. Unit tests for the generation actually persisted on new rows. Status: **Not started**
   **Exhaustive owner of the persisted-state stamping table** (6 rows, executed), added by finding 28.
   Steps 3 to 5 above stamp `codes`, `user_sessions` and `refresh_tokens`, and nothing else in the plan
   would notice if a stamp were silently omitted: the validator tests of stage 3 build
   `models.Code{AuthStateGeneration: N}` fixtures directly and never traverse issuance, and stage 1b's
   data tests exercise the narrow methods rather than the issuers.

   The failure that omission produces is severe and quiet. A missing stamp leaves the row at the column
   default of 0, which behaves correctly while that user is still at generation 0, and then **the first
   credential change locks the user out of every subsequent login**, because each new code compares 0
   against their advanced generation.

   Assert the model handed to `CreateCode`, `CreateUserSession` and `CreateRefreshToken` through the
   `mocks_data.Database` argument capture. Every row uses **nonzero, deliberately conflicting**
   generations, which is load-bearing twice over: a table written with 0 would coincide with the column
   default and pass with the assignment missing, and giving the correct and incorrect sources the same
   value would make a read of the wrong one indistinguishable.

   | Row | Correct source | Conflicting values | Expected |
   |---|---|---|---|
   | `codes` on creation | `AuthContext` | authctx 7, current user 9 | 7 |
   | `user_sessions` on creation | `AuthContext` | authctx 7, current user 9 | 7 |
   | initial auth-code refresh token | its `Code` | code 7, current user 9 | 7 |
   | auth-code rotation | parent refresh token | parent 7, **code 3**, user 9 | 7 |
   | initial ROPC refresh token | validated `User` snapshot | snapshot 7, reloaded user 9 | 7 |
   | ROPC rotation | parent refresh token | parent 7, reloaded user 9 | 7 |

   The rotation row is a **three-way** conflict on purpose, so a wrong read of either the code or the
   user is caught rather than only one of them.

### Stage 3: enforcement at validation
Status: **Not started**

Tests: **unit tests only, host.** Mock-backed, so they prove the branch conditions and not that the
real database agrees.

1. Code redemption rejects a generation mismatch. Status: **Not started**
   In `ValidateTokenRequest`'s `authorization_code` case, alongside the existing
   `codeEntity.User.Enabled` check.
2. Both refresh branches reject a generation mismatch, reading the value from the
   **`refresh_tokens` row**. Status: **Not started**
   Decision 11(a). Reading the joined `codes` row instead would reject the preserved session's
   promoted tokens, which is exactly the bug this wording exists to prevent.
3. `RequireValidSession` gains the `Enabled` and generation checks. Status: **Not started**
   Resolve the user by `sub` when `auth_time` is present, rejecting empty `sub`; reject when not
   enabled (decision 6); then the asymmetric generation check of decision 11(c): with a `sid`, the
   live session's generation decides and the token's own claim is **ignored**; without one, the
   token's claim decides, an absent claim reading as 0 (decision 15). Lookup errors are 500, per
   `middleware/fail-closed`.
4. Unit tests. Status: **Not started**
   **Exhaustive owner of the middleware table**: 30 rows, all executed. Extend
   `TestRequireValidSession` (`test/middleware-valid-session`) rather than adding a parallel suite, so
   the existing harness and mock setup are inherited. Rows, with the gate each negative case is meant
   to hit: pass-through for no bearer token, a non-`JwtToken` value, and a token with no `auth_time`
   (the client_credentials gate); 401 for empty and whitespace-only `sub`; 500 on user lookup error
   and 401 on user not found (the fail-closed gate); 401 for a disabled user in **both** the
   session-bound and sid-less branches, which is the sibling-branch audit the testing discipline
   asks for; then the session-bound branch, pass when all good, 401 terminated, 500 on lookup error,
   500 on missing settings, 401 expired, 401 when the session's generation is behind the user's, pass
   when a promoted session matches, and **pass when the token's own generation claim is stale or
   malformed**, which pins decision 11(c) and is the row that will look like a bug; then the sid-less
   branch, pass on a matching `float64` claim, 401 behind, 401 ahead, pass for an absent claim while
   the user is at 0, 401 for an absent claim once the user has advanced, pass for an explicit
   `float64` 0, and 401 for each malformed shape (string, bool, nil, non-integral, negative, beyond
   exact range).
   Each negative row varies exactly one field from a passing row, so none can pass with its gate
   removed. Two rows deserve the "keep this" note in the test file: the stale-claim-ignored row,
   because it reverses the intuitive reading, and the absent-claim-passes row, because deleting it
   would let a change silently invalidate every legacy token.
   **`token_validator_test.go` owns the validator's three branches**, per finding 24, since that is
   where the logic lives and the file already has 31 test functions and the harness for it: an
   authorization-code redemption mismatch, an auth-code refresh mismatch, and a **ROPC** refresh
   mismatch, the last being an independent branch that a single "one refresh case" would have left
   uncovered entirely. Each pairs with a matching-generation case so the negative varies exactly one
   field. The auth-code refresh case additionally asserts the value is read from the `refresh_tokens`
   row and not the joined `codes` row, by giving the two different generations, which is the only
   assertion that can distinguish decision 11(a) from its opposite.
   `handler_token_test.go` keeps one thin smoke case confirming the handler surfaces the rejection.
   Deliberately thin at that layer: the validator tests own the comparison logic.

### Stage 4: the revocation helper
Status: **Not started**

Tests: **unit tests only, host.**

1. Extract `revokeRefreshTokens(db, tx, tokens) ([]string, error)` and have
   `revokeOnAuthCodeReuse` call it. Status: **Not started**
   Its doc comment states the contract #77 depends on: return only the JTIs this call transitioned.
   Decision 8.
2. `RevokeUserAuthState(db, tx, userId, exceptSid) (RevocationResult, error)`.
   Status: **Not started**
   Increments the generation, sweeps via stage 1b step 1, and when `exceptSid != ""` additionally
   queries `GetRefreshTokensBySessionIdentifier(tx, exceptSid)` to build the preserved id set,
   because an offline row's own `session_identifier` is empty and its originating sid lives only on
   the `codes` row (finding 3).
3. Unit tests. Status: **Not started**
   **Exhaustive owner of the sweep table**, executed. With `exceptSid` set: a session-bound token on
   the preserved session is promoted; **an offline token on the preserved session is promoted**, which
   is the row that fails against any implementation deriving the preserved set from the returned rows;
   a token on another session is revoked; an already-revoked token is neither revoked again nor
   reported; a ROPC token is revoked; the preserved session row is promoted and every other session
   deleted. With `exceptSid` empty: **every live token transitions to revoked while the already-revoked
   one stays excluded from the reported JTIs**, so the reported list has four entries and not five; both
   sessions deleted; nothing promoted. The earlier wording said "all five tokens revoked", which
   contradicted the sketch's own output (finding 27).
   `RevocationResult.OldGeneration` and `NewGeneration` are asserted in both cases, since nothing else
   would catch the increment being skipped or misreported, and decision 7's audit payload reads them
   straight off this struct.
   Then `revokeRefreshTokens` in isolation: empty input, all-already-revoked input, mixed input, and
   an `UpdateRefreshToken` error mid-loop.
   `handler_token_test.go`'s existing reuse tests, including `test/token-reuse-500`, must pass
   **unmodified**. That is the evidence step 1 changed no behaviour, and it is the only check that
   #77's conditional teardown still holds.

### Stage 5: the four call sites, the audit event, and end-to-end tests
Status: **Not started**

Tests: **unit tests on the host, plus integration tests in the dev container.** This is the only
stage whose integration tests show the advertised behaviour actually happening.

1. `AuditRevokedUserAuthState` in `src/core/constants/constants.go`, added to both the constant block
   and `AuditEventTypes` (`constants/audit-list`). Status: **Not started**
2. Wire the four sites, each opening a transaction and using stage 1b's narrow writes.
   Status: **Not started**
   `reset/password-write`, `account-pwd/write` (passing the caller's `sid` as `exceptSid`),
   `admin-pwd/write`, and `admin-enabled/write` where **both** directions go through
   `TrySetUserEnabled` and revocation runs only when the disable direction reports a transition, so
   enabling never revokes and re-disabling is a no-op (findings 4 and 21, decision 14). Enabling emits
   no new revocation event, and the endpoint's existing `AuditUpdatedUserDetails`
   (`admin-enabled/audit`) fires unchanged in both directions. The new event fires after commit, on
   success only.
3. Unit tests for the handlers. Status: **Not started**
   `handler_reset_password_test.go` exists and gains cases; `handler_api_account_password_test.go`
   and `handler_api_users_crud_test.go` **do not exist and must be created**, which is a finding from
   the test-landscape sweep rather than an oversight. Thin at this layer, one case per site asserting
   the helper is called with the right scope and `exceptSid`, plus the disable conditionality matrix
   (four rows, executed: disable a live account sweeps and audits; disable an already-disabled account
   does neither; enable does neither in both starting states, meaning no revocation and no new
   revocation event, while `AuditUpdatedUserDetails` still fires).
   **Plus the atomicity and audit tests finding 26 asks for**, which are the only tests that exercise
   the plan's central safety promise rather than its happy path. On one representative site: the narrow
   credential write succeeds, `RevokeUserAuthState` then fails (once during discovery, once during
   revocation), and the test asserts the transaction is rolled back, not committed, a 500 is returned,
   and **the new revocation event is not emitted**. A second case makes the commit itself fail and
   asserts the same about the audit. `test/token-reuse-500` is the precedent for this shape.
   One case asserts the **audit payload** field by field: `reason`, `oldGeneration`, `newGeneration`,
   `terminatedSessionIdentifiers`, `revokedRefreshTokenJtis` and `preservedSessionIdentifier`,
   including that the last is `""` rather than absent on the three sites that preserve nothing.
4. Integration tests in `src/authserver/tests/integration/`. Status: **Not started**
   Following `session_bearer_revocation_test.go` (`test/integration-bearer-revocation`) for shape and
   `setUserPassword` (`test/integration-set-password-helper`) for fixtures. Thin by design, one case
   per property, because enumerating shapes here is what stages 1 to 4 are for:
   an offline grant whose session was deleted stops refreshing after a reset, which is the
   stolen-laptop case and the issue's headline; a ROPC grant stops refreshing after a reset; the
   caller's own session survives a self-service change **including its offline tokens**, while another
   device's does not; an outstanding authorization code is rejected after a reset; a disabled user's
   sid-less access token is rejected on `/api/v1/account/*` immediately rather than at expiry; and an
   `offline_access` client can call `/userinfo` after its session has been deleted, which is decision
   9's fix and currently fails.
   **Plus the generation round-trip case finding 25 asks for**, which is the one that proves the
   central new mechanism end to end: obtain a sid-less offline access token, change or reset the
   password, then present that same token to `/userinfo` and the account API and assert immediate
   rejection. Because the token carries no `sid`, a generation mismatch is the **only** reason it can
   fail, so this single case exercises claim emission, the `float64` JSON round-trip, parsing through
   `GetIntClaim` and middleware enforcement together. Those are exactly the things the stage 2 and 3
   tables cannot prove, per this section's opening note, and without it the plan's headline mechanism
   has no end-to-end coverage at all.
   **The preserved-session case needs its bearer chosen deliberately.** The password-change request must
   be made with a **session-bound** bearer carrying the caller's `sid`, and the thing asserted to
   survive is a separate offline family originating from that same session. Using an offline bearer
   would not work: after decision 9 it carries no `sid`, so `exceptSid` would be empty and the test
   would preserve nothing while appearing to exercise preservation.
   **Ordering is load-bearing in the outstanding-code case**: request the code, then reset, then
   redeem. Redeeming first spends the code and the later assertion would pass for that reason instead.
   **One deliberate gap, stated rather than implied:** the concurrent-refresh race from finding 1 is
   *not* covered by an integration test. Reliably interleaving a refresh with a credential transaction
   from a black-box test is not practical here, and the generation boundary is what makes the race
   safe by construction rather than by timing. The provenance rows in stage 2 step 7 are the closest
   proxy, since they assert a racing grant emits its own generation rather than the user's.

### Stage 6: documentation
Status: **Not started**

Tests: none. Prose only.

1. Document the access-token contract change. Status: **Not started**
   `site/src/content/docs/concepts/tokens.mdx` documents ID token claims but not access token claims,
   so this adds a short access-token section covering two observable facts: access tokens on
   `offline_access` grants do not carry `sid`, and access tokens carry an `auth_state_generation`
   claim that integrators should treat as opaque and reserved.
2. Note the credential-invalidation behaviour where sessions are described. Status: **Not started**
   `site/src/content/docs/concepts/user-sessions.mdx` currently documents only the timeout settings.
   Verified nothing there is falsified by this change, so this is an addition rather than a
   correction: a password reset, password change or account disable terminates that user's sessions
   and revokes their refresh tokens, with self-service password change preserving the caller's own
   session. It also states the access-token limitation plainly, since operators will otherwise assume
   more than the change delivers: goiabada's own APIs reject a superseded generation on the next
   request, while a stateless access token already held by a third-party resource server stays usable
   until it expires, which is why a short `TokenExpirationInSeconds` matters. No audit-log doc change is
   needed, since `concepts/audit-log.mdx` deliberately points at `constants.go` rather than enumerating
   event identifiers.

## 6. Plan review findings

Round 1 was raised against **section 4 at the shared-understanding gate**, before section 5 existed,
so these findings are about the design rather than the plan. Numbering is stable and continues across
rounds.

Every finding was verified against the code before being accepted; none was taken on assertion. Two
were errors of mine (11 and 12), and one of my own claims was found too strong (finding 1's
consequence for the safety section).

1. **A transaction around the sweep is not a boundary against concurrent or subsequent issuance.**
   Round 1. Status: **Resolved**

   Confirmed: refresh rotation marks the old token revoked and inserts its replacement with
   `UpdateRefreshToken(nil, ...)` and `CreateRefreshToken(nil, ...)`, both outside any transaction, so
   a refresh that validated before the sweep inserts a surviving child after it commits. Session-bound
   grants are contained by session deletion; offline and ROPC grants are not, and the child is good for
   up to a year.

   Resolved by **decision 11**, the per-user generation boundary, and by rewriting section 4's safety
   claims to drop "no half-applied state to reason about" in favour of the narrower and true statement.
   Decision 12 was adopted alongside it as a session-scoped counterpart and then reversed by finding 15,
   so the session scope leaves this issue rather than being fixed in it.

2. **An outstanding authorization code survives a credential change.** Round 1. Status: **Resolved**

   Confirmed, and narrower than reported: code redemption checks `codeEntity.User.Enabled` and a
   hard-coded `authCodeExpirationInSeconds = 60`, with no session check, so the window is bounded at 60
   seconds. Crucially it needs **no race at all**. Resolved by decision 11 rule 6 for credential
   changes, which is this issue's scope. The equivalent for session termination moved to #129 with
   finding 15.

3. **`exceptSid` cannot preserve offline refresh tokens as section 4 described it.** Round 1.
   Status: **Resolved**

   Confirmed: an offline row's `session_identifier` is empty and its originating sid lives only on the
   `codes` row, which `models.RefreshToken` exposes as `db:"-"`. So "revoke every token whose session is
   not the preserved one" is not implementable from the query's return value. Resolved in section 4.5
   with the second query and an id-exclusion set, which works because
   `GetRefreshTokensBySessionIdentifier` matches `codes.session_identifier`.

4. **The enabled endpoint serves both directions, so revocation must be conditional.** Round 1.
   Status: **Resolved**

   Confirmed: `user.Enabled = req.Enabled`. Resolved in section 4.6's table, gated on the
   enabled-to-disabled transition rather than on `req.Enabled == false`, so re-disabling is a no-op.

5. **The index list is incomplete.** Round 1. Status: **Resolved**

   Confirmed on both counts: SQLite lacks `refresh_tokens.user_id`, which is decision 1's ROPC branch,
   and `user_sessions.user_id` is unindexed on PostgreSQL, SQL Server and SQLite while
   `GetUserSessionsByUserId` is now on a security-critical path. Both added to decision 10's table.

6. **Prefer two `UNION ALL` branches over a `LEFT JOIN` with an `OR`.** Round 1. Status: **Resolved**

   Confirmed the shapes are mutually exclusive from the issuer: the auth-code path sets only `CodeId`,
   the ROPC path only `UserId` and `ClientId`. So the union cannot duplicate and each branch can use its
   own index. Section 4.3 changed.

7. **The MySQL index assumption can be removed.** Round 1. Status: **Resolved**

   Confirmed: MySQL's initial migration declares `KEY fk_codes_user (user_id)`,
   `KEY fk_refresh_tokens_code (code_id)` and `KEY fk_user_sessions_user (user_id)` explicitly inline.
   Decision 10's assumption block is replaced by a per-engine table resting on read DDL.

8. **`PreservedSessionIdentifier` marshals to `""`, not JSON `null`.** Round 1. Status: **Resolved**

   Correct. Documented on the field in section 4.5 rather than changed to `*string`, since an empty
   string is the codebase's existing idiom for "no session identifier".

9. **Add a concrete acceptance-test section.** Round 1. Status: **Resolved**

   Correct, and it belongs in section 5, which this gate is holding. Recorded as a requirement on the
   plan: at minimum offline tokens with and without a live session, ROPC, current-session preservation
   including its offline tokens, concurrent refresh versus credential change, concurrent refresh versus
   session termination, outstanding code redemption in both scopes, enable versus disable, the
   down-scoped offline refresh from decision 9, and the sid-present precedence rule from decision 11(c).

10. **Decision 4's safety argument is overstated.** Round 1. Status: **Resolved**

    Valid, and the sharpest of the non-blocking findings. A cloned session cookie carries the **same**
    sid, so `exceptSid` preserves the attacker's session in the commonest hijack scenario; and "they can
    just sign back in" fails when OTP is required and the attacker lacks the secret. Decision 4 keeps its
    outcome as a standards-aligned product choice but now states the accepted risk, drops the "costs
    nothing" framing, notes the console-500 point is usability rather than security, and records a
    "sign out all devices" affordance as the mitigation.

11. **Decision 3 misstated RFC 9700 section 4.14.** Round 1. Status: **Resolved**

    My error. The verbatim text is "Authorization servers MAY revoke refresh tokens automatically in case
    of a security event, such as: password change or logout at the authorization server", confirmed
    against `rfc9700.txt` after two summarised fetches had dropped it. Decision 3 corrected, with the
    correction marked so it is not silently rewritten. The outcome is unchanged, since a MAY permits
    rather than compels.

12. **Decisions 4 to 7 each retained a stale pre-decision paragraph.** Round 1. Status: **Resolved**

    My error: those edits replaced the headings and not the bodies, so each decision ended with its
    exploratory text, and decision 6's leftover contradicted the corrected text above it by claiming the
    broad check adds a lookup to client-credentials requests. All four removed.

13. **`codes.revoked` is more than a column and two touchpoints.** Round 1. Status: **Resolved**

    Confirmed all three sub-points. `MarkCodeAsUsed`'s predicate is `id = ? AND used = false`, so
    validation and claiming are separate and a code revoked between them would still be claimed; the
    marker must join that compare-and-set. Initial redemption must reject it too, or a revoked session's
    unused code can still mint its first offline family. And
    `DeleteUsedCodesWithoutRefreshTokens` filters on `used = true`, so an unused revoked code would never
    be reaped. That seven-item scope was added to decision 12 at the time and moved to #129 when
    finding 15 retired decision 12.

14. **Decision 3's promise must be stated honestly.** Round 1. Status: **Resolved**

    Confirmed: after decision 9 an offline access token carries no `sid`, no grant identifier, and a
    generation still matching the user's, since end-session does not bump it. So nothing in the
    middleware can reject it for up to 300 seconds. Decision 3 was corrected to claim that ending a
    session makes the device durably lose **renewable** access rather than all access immediately.

    **Superseded in part by finding 15**, which reversed decision 3 altogether. So this issue no longer
    makes any promise about session termination; the corrected claim and the 300-second residual moved
    to #129, which is where the wording now has to hold.

15. **`codes.revoked` is not a durable session-scoped boundary.** Round 2. Status: **Resolved**

    Confirmed, and it is the gate blocker. `HandleAuthCompletedGet` evaluates `hasValidUserSession`
    and, finding none, takes an else branch calling `StartNewUserSession` **unconditionally** from
    `authContext.UserId`, with no requirement that anyone authenticated; `userReallyAuthenticated` is
    computed but consulted only inside the valid-session branch. So an SSO ceremony in flight when a
    session is terminated resumes, silently receives a new session, and `/auth/issue` writes a fresh
    unrevoked code outside the termination transaction, at a generation the termination never moved.
    A marker over existing rows cannot see a row that does not exist yet.

    Resolved by **reversing decision 3 and retiring decision 12**, moving both to **#129** along with
    the full seven-item marker scope, the two candidate durable designs, and the auth-flow question
    about what a ceremony whose session vanished should do. Section 4 loses its grant marker, its
    session-termination matrix and two of its six call sites.

    The reversal is recorded rather than quietly applied because decision 3 was settled by the user
    earlier in this interview.

16. **Access-token generation provenance was unspecified.** Round 2. Status: **Resolved**

    Confirmed load-bearing in both directions. Auth-code refresh builds its access token from
    `input.Code` via `createTokenInputFromCode`, so a preserved offline refresh token promoted to N+1
    keeps a code at N and would emit N, and the middleware would reject a token it had just issued.
    ROPC refresh reconstructs its input from a freshly loaded user, so it would emit N+1 for a grant
    authenticated at N and launder it forward. Resolved as **decision 13**, with a test pinning each
    direction since neither is visible in ordinary single-request flows.

17. **Full-row `UpdateUser` can undo a credential or security change.** Round 2. Status: **Resolved**

    Confirmed pre-existing defect: `UpdateUser` writes every field not tagged `dont-update`, and both
    `HandleAPIAccountPasswordPut` and `HandleAPIUserEnabledPut` load the whole user and write it back.
    A password change that loaded `Enabled = true` can commit after an admin disable and silently
    re-enable the account; a disable can restore a stale password hash. In scope because it defeats
    site 3 outright. Resolved as **decision 14**: narrow writes for the four actions, and disable as a
    compare-and-set whose return also supplies finding 4's transition detection.

18. **Pre-migration access-token semantics were undefined.** Round 2. Status: **Resolved**

    Correct: rows migrate to generation 0 but already-issued tokens carry no claim, so without a rule
    the deployment either invalidates every live sid-less access token or accepts any token lacking the
    claim forever. Resolved as **decision 15**: absent claim reads as 0, malformed claim is rejected,
    and an absent claim therefore stops working the moment that user advances past 0.

19. **`DeleteUsedCodesWithoutRefreshTokens` has a nullable `NOT IN` trap.** Round 2.
    Status: **Resolved**

    Confirmed live pre-existing bug: the predicate is `NotIn("id", SELECT code_id FROM refresh_tokens)`
    and ROPC rows carry `code_id = NULL`, so `x NOT IN (..., NULL)` evaluates to UNKNOWN rather than
    TRUE and **the sweep deletes nothing at all** once any ROPC refresh token exists. Wants a
    correlated `NOT EXISTS`.

    Resolved as out of scope **with the finding recorded**, in this document's out-of-scope list and in
    #129, filed as **#130** and cross-referenced by #129. It only surfaced because decision 12 would
    have changed that
    predicate, and dropping decision 12 means this change no longer touches it.

20. **Eleven internal contradictions.** Round 2. Status: **Resolved**

    All valid; swept as one finding rather than eleven, following the convention that citation-class
    problems are reported once. Applied: the goal now accounts for `exceptSid` and for sid-less access
    tokens; "no grant-level revoked state" reworded now that nothing adds one; decision 1 prescribes
    `UNION ALL` to match section 4; decision 3 says "renewable access" where it survives at all;
    decision 4 no longer claims revoke-all gains no containment, which contradicted its own
    cloned-cookie and OTP analysis; decision 5's broad "no half-applied state" is narrowed where it is
    stated rather than only later; decision 7 shows `preservedSessionIdentifier` as `""` and carries the
    generation fields; decision 8's result struct gains `OldGeneration` and `NewGeneration`; the ID
    token claim now says auth-code grants, since ROPC ID tokens never carried a `sid`; decision 11's
    invariant acknowledges the explicit preserved-session promotion exception; and the audit
    generation fields are unambiguous now that every remaining reason advances the generation.

21. **The enable direction has no narrow write method.** Round 3. Status: **Resolved**

    Valid. Stage 1 defined only a disable-shaped compare-and-set, but `HandleAPIUserEnabledPut` serves
    `Enabled = true` through the same handler, so enabling would have stayed on the full-row
    `UpdateUser` and decision 14's clobbering defect would have survived in half the endpoint.

    Resolved by replacing it with one conditional method covering both directions,
    `TrySetUserEnabled(tx, userId, expected, desired)`, in decision 14 and stage 1b step 2. Also
    clarified in decision 14 and stage 5 step 2 that "enable does neither" means no revocation and no
    new revocation event, while the endpoint's existing `AuditUpdatedUserDetails` fires unchanged in
    both directions.

22. **`GetIntClaim`'s absent-versus-malformed contract was ambiguous.** Round 3. Status: **Resolved**

    Valid, and it would have caused the exact outage decision 15 exists to prevent. A conventional
    `(int64, bool)` accessor returns `false` for both an absent claim and a malformed one, collapsing
    the distinction decision 15 depends on, so every legacy token would have been rejected.

    Resolved with the reviewer's least-surprising option: the accessor keeps its conventional contract
    and reports only whether a **present** claim parsed, while the middleware tests raw map presence
    first. Verified this is already the idiom in the same file, since `RequireUserBoundToken`
    distinguishes its cases with `if _, hasAuthTime := jwtToken.Claims["auth_time"]`. Stage 2 step 7
    now pins the exact returned tuple for every row, including `(0, false)` for absent, which is the
    row that makes the collapse visible.

23. **Initial ROPC access-token provenance was missing.** Round 3. Status: **Resolved**

    Valid. Decision 13 covered implicit, initial code exchange and both refresh paths, but the initial
    ROPC issuance has neither a code nor a parent refresh token, so no clause reached it.

    Resolved by adding the `User` snapshot from password validation as the fifth source, with an
    explicit prohibition on reloading the user between validation and stamping. Verified the snapshot
    is already threaded through: `HandleTokenPost`'s `password` case builds
    `ROPCGrantInput{User: validateResult.User, ...}`. Two rows were added to the provenance table and
    executed, including one where a reset races the request: it stamps the snapshot's old generation and
    is rejected downstream, which is the fail-closed direction.

24. **Validator branch coverage sat in the wrong file and missed a branch.** Round 3.
    Status: **Resolved**

    Valid on both counts. The generation comparison lives in `ValidateTokenRequest` across three
    independent branches, and the plan proposed a single thin refresh case in `handler_token_test.go`,
    which would have left the ROPC refresh branch with no coverage at all.

    Resolved by moving ownership to `token_validator_test.go`, which already has 31 test functions and
    the harness, with all three branches covered and each negative paired to a matching-generation case
    so it varies exactly one field. The auth-code refresh case additionally gives the token row and its
    joined code different generations, which is the only assertion that can tell decision 11(a) from
    its opposite. A thin handler smoke case remains.

25. **No integration test proved the generation claim round-trips.** Round 3. Status: **Resolved**

    Valid, and the sharpest finding of the round. The integration list covered refresh rejection,
    disabled-user rejection and the offline `sid` fix, but not the central new access-token mechanism.
    This document's own preamble says the stage 2 and 3 tables cannot prove that a real JWT agrees, so
    the omission contradicted the plan's own statement of what each tier proves.

    Resolved by adding the case: obtain a sid-less offline access token, change or reset the password,
    present that same token, assert immediate rejection. With no `sid` on the token, a generation
    mismatch is the only possible cause, so one case exercises emission, the `float64` JSON round-trip,
    `GetIntClaim` parsing and middleware enforcement together.

26. **Atomic failure and audit behaviour were untested.** Round 3. Status: **Resolved**

    Valid. The plan's central safety promise is that the credential write, the generation increment and
    the sweep cannot half-apply, and every proposed handler test exercised the happy path.

    Resolved in stage 5 step 3: a representative site gets rollback cases with the helper failing during
    discovery and during revocation, plus a commit-failure case, each asserting no commit and **no new
    revocation event**. One case asserts the audit payload field by field, including that
    `preservedSessionIdentifier` is `""` rather than absent on the three sites that preserve nothing.
    `test/token-reuse-500` is the precedent for the shape.

27. **Seven coverage refinements, including one contradiction with my own executed output.**
    Round 3. Status: **Resolved**

    All valid; swept as one finding. Applied: the `dont-update` assertion now covers **all four** models
    rather than three, adding `RefreshToken`; every narrow method is exercised on all four engines rather
    than only the enabled one; `IncrementUserAuthStateGeneration` called twice must return successive
    values; promotion must touch only the named rows and only unrevoked tokens; **an empty promotion id
    list must be a no-op**, which is a real hazard rather than a formality since an empty `IN ()` is
    either a syntax error or a match-everything depending on the builder; the migration test asserts each
    expected index exists, because every behavioural query test stays green with an index omitted;
    `OldGeneration` and `NewGeneration` are asserted in the sweep tables; and the session documentation
    states the third-party access-token limitation.

    The contradiction was mine: stage 4 said "all five tokens revoked" where the executed sketch printed
    four, because the already-revoked token is neither re-revoked nor reported. Corrected, and the sketch
    now carries an explicit assertion on that count so the prose cannot drift from it again.

28. **No test asserted the generation actually persisted on new rows.** Round 4.
    Status: **Resolved**

    Valid, and the most consequential gap of the review rounds. Stage 2's tests covered access-token
    provenance, `sid` emission, claim parsing and `AuthContext` capture, but nothing asserted what
    generation lands on a newly created `codes`, `user_sessions` or `refresh_tokens` row. Confirmed
    nothing else would have caught it: stage 3's validator tests build
    `models.Code{AuthStateGeneration: N}` fixtures directly and never traverse issuance, and stage 1b's
    data tests exercise the narrow methods rather than the issuers.

    The failure mode is severe and silent. A missing stamp leaves the row at the column default of 0,
    which behaves correctly while the user is still at generation 0, and then the **first credential
    change locks that user out of every subsequent login**, because each new code compares 0 against
    their advanced generation. A feature meant to evict attackers would instead evict the account owner,
    and only after the feature had appeared to work.

    Resolved as stage 2 step 8, a six-row table asserting the models passed to `CreateCode`,
    `CreateUserSession` and `CreateRefreshToken`, executed like every other table here. Two properties
    of the fixture are load-bearing and stated in the step so they are not "simplified" later: the
    generations are **nonzero**, because a table written with 0 coincides with the column default and
    passes with the assignment missing, and the correct and incorrect sources are given **different**
    values, because equal ones make a wrong read indistinguishable. The rotation row uses a three-way
    conflict (parent 7, code 3, user 9) so a wrong read of either alternative is caught.
