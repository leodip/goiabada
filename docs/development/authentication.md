# Authentication and issuance

Change authorization ceremonies, session reuse and token issuance while preserving their security
invariants.

Paths in backticks are relative to the repository root unless a module directory is named. Read the
sections relevant to the change; [AGENTS.md](../../AGENTS.md) lists the common commands.

## OAuth2 Flows Supported

For the public protocol documentation, see `site/src/content/docs/`. Handler filenames below are
relative to `src/authserver/internal/handlers/`; service filenames are relative to
`src/authserver/internal/`.

### Authorization Code (with PKCE)
Primary flow for web/mobile apps. User authenticates via browser, receives code, exchanges for
tokens.
- Endpoint: `GET /auth/authorize` → `POST /auth/token` (grant_type=authorization_code)
- PKCE: always required for a public client; otherwise configurable globally
  (`Settings.PKCERequired`) or per-client (`Client.PKCERequired`)
- Supports `response_type=code` with optional `code_challenge` + `code_challenge_method`
- Implementation: `handler_authorize.go`, `authflow/authorization.go`, `issuance/code_issuer.go`;
  redeemed by `handler_token_authorization_code.go`,
  `protocolvalidation/token_grant_authorization_code.go`, `issuance/grant_authorization_code.go`

### Client Credentials
Server-to-server auth. No user context, client authenticates directly for access token.
- Endpoint: `POST /auth/token` (grant_type=client_credentials)
- Requires: `Client.ClientCredentialsEnabled = true`
- Auth methods: `client_secret_basic` (Authorization header) or `client_secret_post` (form body)
- Implementation: `handler_token_client_credentials.go`,
  `protocolvalidation/token_grant_client_credentials.go`, `issuance/grant_client_credentials.go`

### Client authentication
Every endpoint that authenticates its calling client (RFC 6749 section 2.3) does so the one way.
- Credentials: `client_authentication.go` reads them from the Authorization header or the form,
  never both, the header's values percent-decoded, and writes the Warn record of a refusal, naming
  the endpoint that refused. A refusal is a log record, not an audit event: the identifier is the
  caller's own and unproven
- Decision: `clientauth` takes the identifier and the secret as plain values and owns the
  refusals: an unknown or disabled client, or a confidential client's missing or wrong secret, is
  401 `invalid_client` with the Basic challenge; a public client that presents a secret is 400
  `invalid_request`; the secret is compared in constant time
- The token validator calls `FindClient` before it looks at the grant and `VerifySecret` at each
  grant's own point of authentication, so the token endpoint's answers keep their order (#437, #676)

### Access token claims (RFC 9068)
Every access token, from every grant, is an RFC 9068 JWT access token.
- `generateAccessTokenCore` and the client credentials grant sign it with the JOSE header
  `typ: at+jwt` (`issuance.AccessTokenHeaderType`) and the claim `client_id`; ID and refresh tokens
  keep the library's `JWT` header. The `typ: Bearer` claim stays
- The authorization code, refresh and password grants add `grant_id`, the identifier the grant's
  refresh token family shares (`FirstRefreshTokenJti`). The code exchange and the password grant fix
  it, as the first refresh token's jti, before they mint the access token; a refresh copies its
  parent's. The client credentials grant and the implicit flow issue no refresh token and no
  `grant_id`
- `offline_access` names `authserver` in `aud`, as the claim scopes do (RFC 9068 section 2.2.3)
- Departures from its SHOULDs, documented on the tokens page: a request naming several resources
  gets one token for all of them rather than `invalid_scope` (section 3; no RFC 8707), `groups` is
  an array of identifiers rather than SCIM objects (section 2.2.3.1), and the private claims have
  plain names (section 2.2.2 MAY) (#676)

### Access token liveness
One check decides whether an access token is one under RFC 9068 and still stands for live state.
- `liveness.AccessToken` checks the token first: its header `typ` is `at+jwt` (or
  `application/at+jwt`, without regard to case) and its `iss` is exactly the configured issuer, as
  RFC 9068 section 4 requires of a resource server. Then the client its `client_id` names exists, is
  the one the token was issued to, and is enabled. A new client may take a deleted client's
  identifier, so a token whose `iat` second is before the client's `created_at` second is refused,
  and one issued in that very second reads `deleted_clients` (written by `DeleteClient` in its
  transaction) and is refused when the identifier was deleted in or after that second, failing
  closed. Then it reads the user and the session the token names and returns a verdict: live, or
  the refusal. A token without `auth_time` is a client's and has no user to check. With `sid`, the
  session decides, its generation included, and the token's own generation claim is ignored; without
  `sid`, the token's claim decides, an absent one reading as 0. Every token past its header needs the
  settings, for the issuer
- Last, a token carrying `grant_id` is live only while its grant is: `IsRefreshTokenFamilyLive`
  answers whether the family has no revocation record and still has a member that is not revoked,
  in one indexed read. Every revocation that ends a grant writes the record in its transaction, for
  every family it reads: consent withdrawal, a client made public, a session's termination,
  authorization-code reuse containment, replay containment and `/auth/revoke`. A sweep alone misses
  the child of a rotation that claimed its parent before the sweep read the rows, so the record is
  what refuses that child's access token at once. A credential change ends access tokens through
  their generation instead. A rotation revokes the parent and inserts the child in one
  transaction, and a credential change promotes the preserved session's tokens, so both keep the
  grant live. A family whose rows are all gone is not live. A token
  without `grant_id` (client credentials, implicit) reads no grant; it is live only while its jti
  is not stored in `revoked_access_tokens` (`IsAccessTokenRevoked`, one indexed read), and one
  without a jti is refused unread
- An access token issued before #676 carries the header `typ: JWT` and is refused, and changing the
  issuer setting ends every outstanding access token at the auth server's own endpoints
- `RequireValidSession` calls it in front of `/userinfo` and the admin and account APIs, and owns
  the 401 `invalid_token` descriptions and the Warn record of each refusal; a revoked grant answers
  "The access token is invalid." as a refusal of the token or its client does, and so does a
  revoked jti; a fault is a 500,
  never a refusal (#106, #133, #676)

### Refresh Token
Exchange refresh token for new access/refresh tokens. Works with auth code and ROPC flows.
- Endpoint: `POST /auth/token` (grant_type=refresh_token)
- Offline tokens: Configurable idle timeout and max lifetime per client/globally
- Revocation: Old refresh token revoked on use, new one issued
- Liveness: `liveness.FindRefreshToken` reads the row with its code, user and client, and
  `liveness.RefreshToken` judges it: user enabled, the row's generation current, a password grant
  token's authentication instant, the code not revoked, no family revocation record, then the
  session (session-bound) or the maximum lifetime and the code's session owner (offline), and last
  the row's own revocation. The validator matches the client to the token between the two calls and
  keeps PKCE, which it answers before the family and session refusals, and the scope checks. A token
  refused only for its own revoked row goes on to the redemption, which contains its family (#676)
- Implementation: `handler_token_refresh_token.go`,
  `protocolvalidation/token_grant_refresh_token.go`, `liveness/refresh.go`,
  `issuance/grant_refresh_token.go`

### Token revocation (RFC 7009)
A client ends one of its grants by sending a token of it.
- Endpoint: `POST /auth/revoke`, form-encoded, CSRF-exempt, CORS for registered web origins, on a
  branch of its own whose faults answer 503
- Order: the client authenticates first through `clientauth` (a public client by `client_id`
  alone); the token parser refuses a malformed or foreign token before reading a key; the token
  says its type (an access token by its `at+jwt` header, a refresh token by its `typ` claim), and
  `token_type_hint` is never read
- Liveness before ownership: an access token is judged by `liveness.AccessToken`, a refresh token
  by `liveness.FindRefreshToken` and `liveness.RefreshToken`; a token that is not live is answered
  200 with nothing revoked or recorded, whatever client it names. A live token of another client is
  400 `invalid_grant`, "The token was issued to another client.", and `token_revocation_refused`;
  a refresh token's owner is read to tell a disabled or deleted owner's token (invalid) from a live
  one
- Refusal auditing: the handler uses `ratelimit.Gate`, as rate-limit refusals do, to record at most
  one `token_revocation_refused` per verified token owner client id per minute window per instance.
  The gate is shared across access and refresh tokens and callers: changing public client
  identifiers, tokens or hints cannot reset it. Every request is still refused and counted;
  successful revocations are audited independently
- Revocation: `revocation.RevokeGrantTx`, the sixth operation, records the family under
  `client_revoked` and revokes every member in one transaction; `revoked_grant` is written after the
  commit. It ends no session and no other grant
- A live access token without `grant_id` (client credentials, implicit) is revoked by its jti:
  `revocation.RevokeAccessToken` stores the jti with the token's `exp` in `revoked_access_tokens`,
  one statement on no transaction, and `revoked_access_token` is written only by the call that
  stored it. `liveness.AccessToken` refuses a token without `grant_id` while its jti is stored, or
  when it carries none, so a second revocation answers 200 as an invalid token; a token with
  `grant_id` never reads the table. The cleanup worker deletes a stored jti once its token has
  expired
- A fault reading the database or the keys answers 503 `temporarily_unavailable`, never 200.
  `goiabada_revocation_requests_total` counts each answer by outcome (#676)
- Implementation: `handler_revoke.go`, `revocation/revocation.go`, `revocationmetrics`

### Token introspection (RFC 7662)
An API, calling as a confidential client, asks whether a token is active.
- Endpoint: `POST /auth/introspect`, form-encoded, CSRF-exempt, no CORS; every other method is
  answered 405 with `Allow: POST` and `no-store` by `HandleIntrospectOtherMethods`, registered for
  the path on the same branch, whose faults answer 500 and count as `error`
- Order: the client authenticates first through `clientauth.AuthenticateConfidential`, which
  refuses a public client 401 `invalid_client` whatever it sent (section 4); the token parser
  refuses a malformed or foreign token before reading a key; `token_type_hint` is never read
- An access token is active when `liveness.AccessToken` finds it live and its `aud` names a
  resource on the caller's introspection resources (`clients_introspection_resources`, compared
  exactly); a refresh token only to its own client, compared before `liveness.RefreshToken` runs,
  so another client's token reads nothing of its grant. Introspection has no side effect: a rotated
  refresh token is answered inactive and triggers no replay containment
- Every other token is exactly `{"active": false}`. An active access token carries the token's own
  `scope`, `client_id`, `sub`, `aud`, `iss`, `exp`, `iat`, `nbf`, `jti` and `token_type`; a refresh
  token `scope`, its client's `client_id`, `sub`, `iss`, `exp`, `iat` and `jti`. Every answer carries
  `Cache-Control: no-store`; a fault answers 500, never inactive. No audit event;
  `goiabada_introspection_requests_total` counts each answer by outcome (#676)
- Implementation: `handler_introspect.go`, `clientauth`, `liveness`, `introspectionmetrics`

### Implicit Flow (Deprecated)
Legacy flow returning tokens directly in redirect URI fragment. **Deprecated in OAuth 2.1.**
- Endpoint: `GET /auth/authorize` with `response_type=token|id_token|id_token token`
- Disabled by default. Enable via `Settings.ImplicitFlowEnabled` or `Client.ImplicitGrantEnabled`
- Security risk: Tokens exposed in browser history/Referer headers
- Implementation: `handler_auth_issue.go`, `authflow/issuance.go`, `issuance/grant_implicit.go`,
  `protocolvalidation/authorize_validator.go`

### ROPC - Resource Owner Password Credentials (Deprecated)
Direct username/password exchange for tokens. **Deprecated in OAuth 2.1** due to credential
exposure.
- Endpoint: `POST /auth/token` (grant_type=password, username, password)
- Disabled by default. Enable via `Settings.ResourceOwnerPasswordCredentialsEnabled` or per-client
- Rate limited. Blocks users with 2FA enabled. Logs `audit.EventROPCAuthFailed` on failure
- Implementation: `handler_token_password.go`, `protocolvalidation/token_grant_password.go`,
  `issuance/grant_password.go`

### Dynamic Client Registration (RFC 7591)
Programmatic client registration for MCP clients, native apps, etc.
- Endpoint: `POST /connect/register`
- Disabled by default. Enable via `Settings.DynamicClientRegistrationEnabled`
- Creates public or confidential clients based on `token_endpoint_auth_method`
- Rate limited. Returns client_id and client_secret (if confidential)
- Implementation: `handler_dynamic_client_registration.go`

## Authentication Flow (Authorization Code)

The auth code flow uses a state machine tracked in `AuthContext` (stored in the server-side session
store, keyed by a cookie (#266)). A browser holds up to five ceremonies side by side, each its own
`AuthContext`, under the session key `AuthContexts` (`ceremony.Store`,
`ceremony.MaxHeldCeremonies`), so two tabs signing in to two applications both finish, and a link or
redirect from another site starts its own ceremony and ends none. `/auth/authorize` adds its
ceremony beside the others, a step's save makes its ceremony the most recently written, and an add
beyond five pushes out the least recently written. A rotation of the browser session's identifier,
at an accepted password or code and at `/auth/completed`'s rotations, is for the user the ceremony
authenticated and removes every held ceremony carrying another user (`heldRotation`), so a ceremony
someone abandoned after their password does not ride into the next user's session, where whoever
used the browser then could finish it as them. The key the one ceremony was held under before,
`AuthContext`, is never read, and the store's first write to a session removes it (#246).

### ACR Levels (Authentication Context Class Reference)
Defined in `src/authserver/internal/record/acr_level.go`:
- **`urn:goiabada:level1`** - Password only (single factor)
- **`urn:goiabada:level2_optional`** - Password + OTP if user has OTP enabled (skip if not)
- **`urn:goiabada:level2_mandatory`** - Password + OTP required (user must enroll if not already)

Target ACR determined by: the first level in the `acr_values` param of the authorize request, raised
to `Client.DefaultAcrLevel`, which is a floor `acr_values` never lowers (#240); with no
`acr_values`, the client's level

### Auth States (State Machine)
The values below are the string constants declared in
`src/authserver/internal/ceremony/auth_context.go`, and `AssertAgentDocs` in
`core/guard/agentdocs.go` holds this section's roster to them: a state declared there with no row
here, or a row here naming no constant, fails the core and both server unit tiers. There is no single order: a
ceremony's path depends on the target ACR, the session, and `prompt`.

| State | Assigned by | When |
|---|---|---|
| `requires_level_1` | `authflow.Authorization` | four conditions: a deferred error is parked; `prompt=login`; `id_token_hint` names another user; no valid session |
| | `authflow.Completion` | no reusable session and `!Level1AuthCompleted`, or the user's authentication generation moved on since the ceremony authenticated, or the ceremony's methods name `otp` from an authenticator the user no longer has, checked before any session is bound and again by the session write (restart route 1, through `Restart()`) |
| | `authflow.Issuance` | bound session gone, expired or foreign, or the user's authentication generation moved on since the ceremony authenticated, or the ceremony's methods name `otp` from an authenticator the user no longer has, checked again by the issuer, and not `prompt=none` (restart route 2, through `Restart()`) |
| `level1_password` | `authflow.SelectLevel1Method` | unconditional |
| `level1_password_completed` | `authflow.PasswordSubmission` | password verified, user enabled |
| `level1_existing_session` | `authflow.Authorization` | valid session, hint matches, user enabled. The SSO shortcut: password entry is skipped and `/auth/level1completed` accepts this state directly |
| `requires_level_2` | `authflow.Level1Completion` | target ACR above the owned session's ACR, or above level 1 with no owned session, or the session's `OtpConfigGeneration` differs from the user's and the target is above level 1, or the target is `level2_mandatory` and the user has no authenticator. A ceremony that verified the password itself (`Level1AuthCompleted`) counts no session, so it lands here whenever the target is above level 1 (#537) |
| `level2_otp` | `authflow.Level2Selection` | `level2_optional` with OTP enabled, or `level2_mandatory` (enrolment happens at `/auth/otp` if needed) |
| `authentication_completed` | `authflow.Level1Completion` | no step-up needed |
| | `authflow.Level2Selection` | `level2_optional` and no OTP enrolled, which is the skip that bypasses `/auth/otp` entirely |
| | `authflow.OTPSubmission` | OTP verified or enrolled |
| `requires_consent` | `authflow.Completion` | `prompt=consent`, or `client.ConsentRequired`, or `offline_access` in scope, or `authserver:manage-account` still in scope, the client not the admin console's, and no stored consent covering it (`userconsent.AlwaysOwed`, #509) |
| `ready_to_issue_code` | `authflow.SilentAuthentication` | every silent check passed, skipping every hop between |
| | `authflow.Completion` | no consent needed |
| | `authflow.ConsentPrompt` | scope already fully consented, no `offline_access`, no `prompt=consent` |
| | `authflow.ConsentSubmission` | approved with at least one scope the user still holds |

Every step handler takes the route boundary, `handlers.CeremonyBoundary` (`auth_ceremony.go`), and
every handler that answers a client with an error the client-error responder,
`handlers.ClientErrorResponder` (`client_error_responder.go`), which holds the emission gates, the
query, fragment and `form_post` encodings, the refusal interstitial and the `server_error` fallback
and clears nothing; the route table builds one of each. Every step but `/auth/authorize` begins with
the boundary's `beginStep`, which reads the request's settings before anything else (a request
without them is the 500 page carrying `reqctx.ErrNoSettings`, as it is at `/auth/authorize`, which
reads them first too), then loads the ceremony and gates its state as below. It first reads, in the
boundary's `loadAuthContext`, the ceremony the request names, through the one rule
`ceremony.RequestedId`: the `ceremony` query parameter on a GET, built into every redirect between
steps by `stepRedirect`, and the `ceremonyId` form field on a POST. A browser holding no ceremony at
all goes to the account page. An id missing, or naming a ceremony the browser does not hold while it
holds others, gets the "no longer active" page, 400, and the `auth_ceremony_mismatch` audit event,
whose details describe the ceremony the browser most recently wrote. Each route then gates on the
state it finds through `requireAuthState`, which answers 400 when it is not one it accepts (#246,
#437):

| Route | Method | Accepts | On mismatch |
|---|---|---|---|
| `/auth/authorize` | GET | anything, mints a new context, from the query or from a parked request | n/a |
| `/auth/authorize` | POST | parks the request, answers 303 to the GET | n/a |
| `/auth/level1` | GET | ceremony id first, then `requires_level_1` | 400, 400 |
| `/auth/pwd` | GET | ceremony id first, then `level1_password` | 400, 400 |
| `/auth/pwd` | POST | ceremony id first, then `level1_password` | 400, 400 |
| `/auth/level1completed` | GET | ceremony id first, then `level1_password_completed`, `level1_existing_session` | 400, 400 |
| `/auth/level2` | GET | ceremony id first, then `requires_level_2` | 400, 400 |
| `/auth/otp` | GET | ceremony id first, then `level2_otp` | 400, 400 |
| `/auth/otp` | POST | ceremony id first, then `level2_otp` | 400, 400 |
| `/auth/completed` | GET | ceremony id first, then `authentication_completed` | 400, 400 |
| `/auth/consent` | GET | ceremony id first, then `requires_consent` | 400, 400 |
| `/auth/consent` | POST | ceremony id first, then `requires_consent` | 400, 400 |
| `/auth/issue` | GET | ceremony id first, then `ready_to_issue_code` | 400, 400 |

### Flow Handlers (in order)
| Handler | File | Purpose |
|---------|------|---------|
| `/auth/authorize` | `handler_authorize.go`, `authflow/authorization.go`, `authflow/silent_authentication.go` | Entry point. `authflow.Authorization` creates the ceremony, validates the request, checks the existing session and routes it to level1 or SSO; a `prompt=none` request is answered by `authflow.SilentAuthentication`, without a page. A POST (`handler_authorize_post.go`, `authflow/authorization_parking.go`) only parks the request and redirects to the GET |
| `/auth/level1` | `handler_auth_level1.go`, `authflow/level1_selection.go` | Selects level1 auth method (currently only password) |
| `/auth/pwd` | `handler_auth_pwd.go`, `authflow/password.go` | Password login form. Verifies the password, rotates the browser session's identifier, records level 1 on the ceremony |
| `/auth/level1completed` | `handler_auth_level1.go`, `authflow/level1_completion.go` | Delivers a deferred authorization error if one is parked (see Deferred error redirects), else decides if level2 needed based on ACR and session state |
| `/auth/level2` | `handler_auth_level2.go`, `authflow/level2_selection.go` | Selects level2 auth method. If `level2_optional` + no OTP → skip to completed |
| `/auth/otp` | `handler_auth_otp.go`, `authflow/otp.go` | OTP verification (or enrollment if user doesn't have OTP yet). Rotates the browser session's identifier, records level 2 on the ceremony |
| `/auth/completed` | `handler_auth_completed.go`, `authflow/completion.go` | Final auth check (a user who is not the id_token_hint's refused, a disabled user refused, a moved-on generation restarted, all before any session is bound), session bump/create, scope filtering, consent check. The plan is one of three modes (`authflow/completion_decide.go`): reuse, which rotates the browser session's identifier before the bind when it raises the session; create, which confirms the ceremony, starts the session (`StartNewUserSession`, which writes nothing to the browser), then rotates and binds it to the browser session (`RegenerateSessionAndBind`), deletes it when that fails, and writes the device cookie only after; and restart |
| `/auth/consent` | `handler_consent.go`, `authflow/consent.go` | User consent screen (if required), and the submission weighed against the permissions the user holds now, recorded through `userconsent` |
| `/auth/issue` | `handler_auth_issue.go`, `authflow/issuance.go` | Final re-checks (redirect URI, client, flow, hint, session, user, scope), then issues the authorization code or the implicit tokens, redirects to client |

### AuthContext field rule
Every field on `AuthContext` is either request or attempt. The request is what `/auth/authorize`
accepted, including `RequestedScope`, the scope as asked for before any hop narrows `Scope` to what
a user holds; the attempt is everything an authentication writes. A restart keeps the request and
discards the attempt: `AuthContext.Restart()` zeroes every attempt field, puts `Scope` back from
`RequestedScope` and sets `requires_level_1`, so the second pass earns its own `amr`, scope and
consent (#140, #436). There are two restart routes: `authflow.Completion` when no session is
reusable and level 1 was never completed, or when the user's generation has moved on, or when the
ceremony names `otp` from an authenticator the user no longer has (#542), decided before it binds a
session (#522), and `authflow.Issuance` at `/auth/issue` when the bound session is gone, expired or
foreign, or the user's generation has moved on, or the ceremony names `otp` from an authenticator
the user no longer has, and the request is not `prompt=none`. The split is held by
`TestAuthContextFields_EveryFieldIsClassifiedOnce` in `ceremony`, which fails on a field in neither
list. Request fields are written only in `authflow.Authorization.Run`, which
`TestRequestFields_WrittenOnlyAtAuthorize` in `ceremony` holds with `go/types`. A bind that finds a
newer authentication already on the session is not a restart: it writes nothing
(`ErrStaleAuthentication`, #538) and `/auth/completed` answers it with the "no longer active" page,
saving no auth context: a newer sign-in's authentication has reached the session since this ceremony
adopted it. A restart would make it verify the password itself, so its bind would replace the
session's authentication, asking an SSO ceremony for a password nobody requested. A reuse arm that
rotates the browser session's identifier asks the same rule first (`AuthenticationIsStale`) and
answers the same page without rotating. Beyond that rule, every write a step after `/auth/authorize`
makes to the browser session lands only while the session still holds that step's ceremony (#579):
the ceremony store's save, clear and rotation read the session afresh, refuse when it does not hold
the ceremony (ended by another request of it, or pushed out by newer ones) or is gone (signed out,
expired, or rotated away by another request of the browser), apply only their own change to what
they read, touching no other ceremony but, at a rotation, those carrying another user, and write on
condition the stored row is unchanged, trying again at most three times in all when another write
lands between. A step so refused writes nothing and answers the "no longer active" page
(`ceremony.ErrCeremonyReplaced`), so the ceremonies the browser holds carry on. The create arm of
`/auth/completed` asks first (`ConfirmCeremony`), before it ends a foreign session or commits a new
one, and its rotation carries the same condition and every held ceremony. `/auth/authorize`'s add is
made the same way, on a fresh read and on condition, so a step's write landing meanwhile is kept,
and when the session it loaded is gone it starts a new one holding its ceremony alone. A request
`/auth/authorize` answers at once with an error stores nothing and removes nothing. Logout still
deletes the session whole, every ceremony with it; two requests of one ceremony stay
last-writer-wins between themselves, so a double-submitted consent form works. The
session-identifier middleware and the emailed-link marker write only their own key the same way, and
the marker's clear removes only the marker of the continuation that consumed it, so a flow finishing
after its marker expired leaves a newer link's in place.

### Deferred error redirects (#213)
`/auth/authorize` never redirects an unauthenticated browser to a client's `redirect_uri` on a
failed request, per RFC 9700 4.11.2. A validation failure is answered at once when the request is
silent (`prompt=none`, read from the raw parameter), when the browser holds a valid session and did
not ask for `prompt=login`, or when no redirect would be emitted anyway (the responder's
`RedirectWillBeEmitted` false). `authflow.Authorization` decides which (`decideAuthorizeRoute`).
Otherwise the error code and description are parked on `AuthContext.DeferredErrorCode` /
`DeferredErrorDescription`, the visitor goes to `/auth/level1`, and the redirect is emitted from
`/auth/level1completed` once the password is verified. That ceremony ends there and creates no
session.

One failure is answered before any of that and never redirects at all: a `response_mode` outside
`query`, `fragment`, `form_post` renders the refusal page at 400 with no error parameters, per OIDC
Core 3.1.2.6, since the server cannot encode a response in a mode it does not implement. The set has
one definition, `protocolvalidation.IsSupportedResponseMode`, shared by `authflow.Authorization` and
`ValidateRequest`.

A second response_mode rule, form_post's own, is answered on the same page for the same reason: the
redirect URI's scheme must be http or https, because the mode answers through an HTML form whose
action is the URI and `html/template`'s URL filter — the one guard standing between a stored
`javascript:` redirect URI and a live form action — rewrites every scheme outside http, https and
mailto to `#ZgotmplZ`, and a form cannot post to mailto either, so a private-use scheme (RFC 8252
7.1) used to get a form that posted the code to this server, and an error in that mode would go the
same way. `refuseUnaddressableAuthorizeRequest` refuses it after the unsupported mode, as
`AuthorizePageRefusalFormPostUnreachable`, its page naming `fragment` alone for an implicit request
(#121).

### Key Logic in Level1Completed
`authflow/level1_completion.go:Level1Completion.Run`, answered by
`handler_auth_level1.go:HandleAuthLevel1CompletedGet`:
- If a deferred error is parked → answer the client and stop (see above)
- If the ceremony verified the password itself (`Level1AuthCompleted`: `prompt=login`, an
  `id_token_hint` naming someone else, a restart) → the session counts for nothing, and the step-up
  is decided as with no session: target above level 1 → redirect to level2. See **Re-authentication
  over a session** below (#537)
- Otherwise the session is reused (the `level1_existing_session` SSO shortcut), and:
- If session ACR is `level1` and target is `level2_*` → redirect to level2
- If session ACR is `level2_optional` and target is `level2_mandatory` → redirect to level2
- If the target is `level2_mandatory` and the user has no authenticator now → redirect to level2,
  where they set one up. A removal lowers the user's sessions below level 3 (#542), and migration
  000062 ended the sessions stored before that, so no write leaves such a session now; the check is
  kept as a second line. Checked apart from the generation, because a `level2_optional` ceremony
  answers a moved generation for such a user by skipping the code and promoting it
- If the session's `OtpConfigGeneration` differs from the user's → re-auth level2 (user changed OTP
  settings). This block writes nothing: the obligation is discharged at `/auth/completed`
- Otherwise → auth completed

### Key Logic in Level2
`authflow/level2_selection.go:Level2Selection.Run`, its arm decided by `decideLevel2Arm`:
- If `level2_optional` + `user.OTPEnabled` → `/auth/otp`, the OTP form
- If `level2_optional` + no OTP → skip to auth completed
- If `level2_mandatory` → `/auth/otp`, the OTP form (user enrolls if needed)

### Session Reuse (SSO)
When user has valid session (`UserSession` in DB + session cookie):
- Session validated via `usersession.Manager.HasValidUserSession` (checks idle timeout, max
  lifetime, max_age param)
- If valid → uses existing `AcrLevel` and `AuthMethods` from session
- May still need level2 re-auth if target ACR higher than session ACR
- Reuse never lowers a session: `BumpUserSession` only raises its ACR and only adds methods (#537)
- Every whole-row session write takes the session's row first (`AcquireUserSessionRow`) and reads it
  after, in one transaction: `BumpUserSession`, and `BindUserSession`, which is `/auth/completed`'s
  reuse arm and also writes a replacing authentication and the auth time there rather than in a
  second write. Read without the lock, a concurrent removal's lowering was written back over (#542).
  The token endpoint and `prompt=none` bump with no methods and no level. A bind whose sign-in is
  older than the session's current `AuthTime`, or whose ceremony adopted the session and the row
  holds neither the `AuthTime` it adopted (`AdoptedAuthTime`, the SSO case, which enters no
  credential of its own) nor the ceremony's own credential instant (its own earlier bind, which a
  reload after a later failure binds again), compared at the column's microsecond, writes nothing
  and returns `ErrStaleAuthentication` (#538): a newer sign-in's level, methods and auth_time are
  not overwritten by an older ceremony that resumed after it, and `/auth/completed` answers that
  ceremony with the "no longer active" page, since a newer authentication already describes the
  session

## SSO and ACR/AMR Details

### AMR (Authentication Methods Reference)
Two methods tracked (`oidc/auth_method.go`): `pwd` (password), `otp` (time-based OTP). Stored as
space-separated string in `AuthContext.AuthMethods` and `UserSession.AuthMethods`. Output in tokens
as JSON array per OIDC spec: `"amr": ["pwd", "otp"]`

### UserSession Model
```
UserSession (DB)
├── SessionIdentifier (UUID stored in the server-side browser session, not directly in its cookie)
├── Started (for max lifetime check)
├── LastAccessed (for idle timeout check)
├── AuthMethods ("pwd" or "pwd otp")
├── AcrLevel ("urn:goiabada:level1" etc.)
├── AuthTime (when auth occurred: the last credential, a code's time after a step-up)
├── PasswordAuthTime (when the password was last entered; a removal lowers AuthTime to it)
├── AuthStateGeneration (snapshot of users.auth_state_generation)
├── OtpConfigGeneration (snapshot of users.otp_config_generation)
├── DeviceId (digest of the separate device cookie, for same-browser session replacement)
└── UserId
```

### Session Validity (`record/user_session.go`, `IsValid`)
Valid if ALL true:
1. `now <= LastAccessed + IdleTimeoutSeconds`
2. `now <= Started + MaxLifetimeSeconds`
3. If `max_age` param: `now <= AuthTime + max_age` (`Started` when `AuthTime` is zero)

### ACR Step-Up Logic (`ceremony/step_up.go`)
One rule, `StepUpOwed`, read by `authflow.Level1Completion` and `authflow.SilentAuthentication`.
Uses `record.AcrLevel.IsHigherThan()` for comparison (priority: level1=1, level2_optional=2,
level2_mandatory=3).

**With valid session:**
- Target ACR higher than session ACR → redirect to level2 (step-up)
- Target `level2_mandatory` and the user has no authenticator → redirect to level2 to set one up
  (`StepUpAuthenticatorMissing`; `prompt=none` answers "Additional authentication setup required")
- Session `OtpConfigGeneration` != user's + target requires level2 → re-prompt OTP
- Otherwise → SSO succeeds, bump session

**Without valid session:**
- Target > level1 → redirect to level2

### ACR in Token (`auth_context.go:SetAcrLevel`)
Token ACR = `max(targetACR, sessionACR)`, against the session the ceremony bound to. SSO reuse never
downgrades within a session. A ceremony that authenticated afresh has just written its target onto
that session, so its token ACR is the target (#537).

### Re-authentication over a session (#537)
A ceremony that verified the password itself is a **new authentication**, not an extension of the
browser's session. That is `AuthContext.Level1AuthCompleted`, set only by `RecordPasswordVerified`,
and it covers `prompt=login` over a valid session, an `id_token_hint` naming someone else, and a
restart. OIDC Core 1.0 section 3.1.2.3 says that with `prompt=login` the server "MUST reauthenticate
the End-User even if the End-User is already authenticated", and section 2 defines `acr`, `amr` and
`auth_time` as describing the same "authentication". So such a ceremony:

1. **Owes every factor its target needs.** `authflow.Level1Completion` passes no session to
`StepUpOwed`, so a level 3 target asks for the code (or enrolment), and a level 2 target asks for it
when the user has one, whatever the session already gave. Keycloak does the same ("the LoA from
previous authentications are not considered").
2. **Replaces the session's authentication** on `/auth/completed`'s reuse arm
(`reuseSessionPlan.replaceAuthentication`): the session takes the target level, this ceremony's
methods, its credential's instant and its password's, as the create arm would stamp a new session.
That can lower the session (`prompt=login` at a level 1 client over a level 3 session leaves it at
level 1, `pwd`), and the next level 3 request then steps up. The session row is kept, not replaced,
so other clients' session-bound refresh tokens keep working; their tokens carry the `acr`/`amr` of
their own codes.

Do not "fix" this back. Until #537 the session's code counted: the token said level 3 with `amr`
`["pwd"]` and a fresh `auth_time`, and `BumpUserSession` replaced the session's `pwd otp` with `pwd`
while keeping level 3, so every later SSO token contradicted itself (#239 finding F4). Merging the
methods back instead (`pwd otp` beside the fresh `auth_time`) claims a code that was never entered
at that time, which PR #238 decision 9 rejected. `max_age` already worked this way: a session
outside it is not valid, so the ceremony takes the create arm.

### OTP config generation
`users.otp_config_generation` is a per-user counter, advanced by one at every site that establishes
or removes an authenticator (`otpcredential.Establish` and `otpcredential.Remove`), inside the same
transaction as the write that changed it. `user_sessions.otp_config_generation` records the value
that session last satisfied, so a session owes a level 2 re-prompt whenever the two differ. Being
per user means one statement covers every session of that user.

A removal also lowers each of the user's sessions, in the same transaction and one statement
(`LowerUserSessionsToPassword`), to what a password alone reaches: `auth_methods` becomes `pwd`,
`level2_mandatory` becomes `level2_optional`, and `auth_time` goes back to `password_auth_time`, the
time the password was entered, since after a code `auth_time` is the code's and `["pwd"]` beside it
would claim a password entered then (OIDC Core 1.0 section 2). Without it a session that reached
level 3 went on claiming level 3 and `["pwd","otp"]` in every SSO token after the authenticator was
gone. `password_auth_time` is written whenever a sign-in verifies the password: the create arm, and
the reuse arm when it replaces the session's authentication (#537); a step-up leaves it. Migration
000062 added it and ended every stored session, whose password time could not be recovered.

A ceremony in flight adopted the session's methods before the lowering, so its claim to a code is
checked against the authenticator it came from (`otpcredential.OTPClaim`):
`AuthContext.OtpClaimGeneration` is the session's snapshot when it adopted the session, and the
generation the code was checked against or enrolled at when it entered one, and the claim stands
only while the user's `otp_config_generation` is still that and the user has an authenticator. A
removal, and a removal followed by a new enrolment, both move it. `/auth/completed` and
`/auth/issue` restart a ceremony whose claim no longer stands, rather than merging `otp` back into
the session or issuing it in a code; `prompt=none` there answers `login_required`. The session
writes (`BindUserSession`, `StartNewUserSession`) and both issuers ask again first in their
transactions, under the user's row lock (`OTPClaim.Recheck`), which a removal takes first, so a
removal landing after the handler's check either waits for the write and then lowers it, or is seen.
Tokens already issued, and the refresh tokens that renew them, keep their claims: ending the user's
sessions revokes those (#542 decision 1).

Both readers, `authflow.Level1Completion` and `authflow.SilentAuthentication`, only compare and
write nothing, so an abandoned ceremony spends no re-prompt. The snapshot is captured onto
`AuthContext` at `authflow.PasswordSubmission` and on every arm of `authflow.Level2Selection`, and
promoted once, at `/auth/completed`: `StartNewUserSession` writes it on the create arm, and
`PromoteUserSessionOtpConfigGeneration` on the reuse arm when the target ACR is above level 1. Both
columns are `dont-update` (#242).

### Scenario Summary

**Fresh login (no session):**
| Target ACR | User has OTP | Result |
|------------|--------------|--------|
| level1 | N/A | pwd only, ACR=level1, AMR=[pwd] |
| level2_optional | No | pwd only, ACR=level2_optional, AMR=[pwd] |
| level2_optional | Yes | pwd+otp, ACR=level2_optional, AMR=[pwd,otp] |
| level2_mandatory | No | pwd + forced OTP enrollment, ACR=level2_mandatory, AMR=[pwd,otp] |
| level2_mandatory | Yes | pwd+otp, ACR=level2_mandatory, AMR=[pwd,otp] |

**SSO (valid session exists):**
- Session ACR >= target ACR → SSO succeeds (keeps higher ACR in token), unless the target is
  `level2_mandatory` and the user has no authenticator now, who sets one up
- The user's authenticator removed → the session is already lowered to `level2_optional` and `pwd`,
  its `auth_time` the password's, and every later token says so (#542)
- Session ACR < target ACR → step-up required (prompt for OTP)
- Session `OtpConfigGeneration` != user's + target requires level2 → re-prompt OTP

**Re-authentication (`prompt=login` over the user's own valid session, #537):**
- Exactly the fresh login table above, whatever the session held: the same prompts, ACR and AMR
- The session then holds this sign-in's ACR, AMR and auth time; its ACR can be lower than before
  when the new target is lower.

## Rate limiting

Applied to credential checks and unauthenticated endpoints (login, OTP, ROPC, account password, OTP
and email changes, email verification and its resend, forgot/reset password, self-registration,
activation, DCR, and the authorization endpoint, both methods of which share one admission budget
per client block, #504). Credential checks count failures only, so a successful attempt spends
nothing; the email change counts every request beside its password check, since past the password
it says whether another account holds the address (#683). The limits counted by a user or by an
email apply whatever
`GOIABADA_AUTHSERVER_RATELIMITER_ENABLED` says: those counted by a user something has already
authenticated, the signing-in user or a token's subject (OTP, account password, email change, email
verification and its resend), since no stranger can spend them (#542), and those counted by an email anyone can
type (wrong passwords per account, 100 an hour shared by the sign-in form and the password grant,
and reset mails and registration notices per address), since only Goiabada can count them (#503).
The switch governs only the tiers that read the client's address, those counted by an IP address and
`pwd_account_net`, the 10 wrong passwords per 15 minutes for one email from one client block; with
it off the password check reserves the account-wide tier alone. The price is #89's lockout: 100
wrong passwords block an account's password sign-in for up to an hour, its remedy blocking the
attacker at the proxy or CDN (#503)

## Post-logout redirects

`src/authserver/internal/handlers/handler_logout.go` resolves a hintless sign-out's client through
`clientForPostLogoutRedirect`. An absent, unknown, unreadable or self-registered (`CreatedViaDCR`)
client earns no redirect. A self-registered client's chosen URIs do not establish a trusted target;
a confirmed `id_token_hint` can still earn its redirect (#682). An unauthenticated `client_id`
never scopes session teardown. See the [logout endpoint reference](../../site/src/content/docs/reference/endpoints/logout.mdx)
for the full confirmation and redirect rules.

## Standards

Goiabada implements published standards. When a change touches behavior one of them defines, read
the relevant section of the official text (rfc-editor.org, openid.net) rather than relying on
memory, and follow its MUST and SHOULD requirements. The main ones: OAuth 2.0 (RFC 6749) and bearer
tokens (RFC 6750), PKCE (RFC 7636), revocation (RFC 7009), introspection (RFC 7662), dynamic client
registration (RFC 7591), authorization server metadata (RFC 8414), JWT (RFC 7519) and JWK (RFC
7517), JWT access tokens (RFC 9068), the OAuth 2.0 Security Best Current Practice (RFC 9700), and
OpenID Connect Core 1.0 and Discovery 1.0.

Goiabada departs from three of RFC 9068's SHOULDs and MAYs, and the tokens page documents each:
a request whose scopes name several resources gets one token naming them all in `aud` (section 3,
since there is no RFC 8707 `resource` parameter; each scope still belongs to one resource in `aud`),
`groups` is an array of group identifiers rather than SCIM objects (section 2.2.3.1), and the
private claims `attributes`, `auth_state_generation`, `grant_id` and the `typ` claim have plain
names (section 2.2.2).

## API Routes

- `/auth/authorize` - OAuth2 authorization endpoint
- `/auth/token` - Token endpoint
- `/auth/revoke` - Token revocation endpoint (RFC 7009)
- `/auth/introspect` - Token introspection endpoint (RFC 7662)
- `/auth/logout` - Sign-out and post-logout redirect endpoint
- `/userinfo` - OIDC userinfo
- `/certs` - JWKS endpoint
- `/.well-known/openid-configuration` - OIDC discovery
- `/connect/register` - Dynamic Client Registration
- `/api/v1/admin/*` - Admin API; routes accept `authserver:manage` or their granular administrative
  scopes (read routes also accept `authserver:admin-read`); see
  `src/authserver/internal/server/routes.go`
- `/api/v1/account/*` - User self-service API (requires `authserver:manage-account` permission)
