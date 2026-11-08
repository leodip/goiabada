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
- Header: one or more spaces may follow `Basic` (RFC 9110 section 11.4); two or more Authorization
  fields are 400 `invalid_request` before any is read; a Basic header with no credentials, or ones
  that are not base64 or have no colon, is `clientauth.UnreadableBasicCredentials`, and one with
  nothing before the colon is `clientauth.BasicCredentialsNamingNoClient`: both 401 `invalid_client`
  with the challenge, and the body is not read in their place (RFC 6749 section 5.2). Another
  scheme, such as Bearer, is ignored (#707)
- Decision: `clientauth` takes the identifier and the secret as plain values and owns the
  refusals: an unknown or disabled client, or a confidential client's missing or wrong secret, is
  401 `invalid_client` with the Basic challenge; a public client that presents a secret is 400
  `invalid_request`; the secret is compared in constant time
- The token validator calls `FindClient` before it looks at the grant and `VerifySecret` at each
  grant's own point of authentication, so the token endpoint's answers keep their order (#437, #676)
- No limit: no rate limit bounds a client's secret check, at the token, revocation or
  introspection endpoint. Goiabada generates every secret with `securerandom.String(60)`, about 361
  bits, far past the 2^-128 guessing bound RFC 6749 section 10.10 sets for credentials not handled
  by end users, and one an administrator sets must also be at least 60 characters
  (`validateClientSecret`). A limit counted by client would protect nothing those secrets don't,
  and would let anyone who knows a confidential client's identifier, which every authorization
  request of a client signing users in carries, have its right secret refused and stop its users'
  sign-ins and refreshes. That departs from section 2.3.1's brute-force MUST, knowingly (#707)

### Access token claims (RFC 9068)
Every access token, from every grant, is an RFC 9068 JWT access token.
- One finishing step, `issuance.finishAccessToken`, ends every grant's access token, the client
  credentials grant's included: it writes the claims every access token carries (`iss`,
  `client_id`, `iat`, `nbf`, `jti`, `typ`, `exp`, `scope`), sets the JOSE header
  `typ: at+jwt` (`issuance.AccessTokenHeaderType`) and signs it. Each grant's builder decides only
  `sub`, `aud` and, for a user's grant, the claims of the sign-in. ID and refresh tokens keep the
  library's `JWT` header. The `typ: Bearer` claim stays on every access token, bound or not. A
  token issued for a request with a valid DPoP proof also carries `cnf.jkt`, the proof key's RFC
  7638 thumbprint, written by the same step, and its token response says `token_type: DPoP`
  (#42 decisions 2 and 3). Implicit-flow tokens are never bound
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

### DPoP at the token endpoint (RFC 9449)
- A request carrying a `DPoP` header is a DPoP request, on any of the four grants.
  `handlers.TokenDPoPNonce` heads the token route, ahead of the ROPC limiter, and sets one
  `DPoP-Nonce` header with a fresh nonce and `no-store`, so every answer to it carries one, the
  limiter's 400 and 429 and the handler's 400s and 500s included (sections 8 and 8.2). It is the
  only place the endpoint mints a nonce.
- The proof is checked once the form is parsed, before the client's credentials are read and
  `ValidateTokenRequest` authenticates the client, so the nonce round trip is never a
  client-authentication refusal or a charged password guess, however the credentials read (#42
  decision 7). `handlers.TokenProofs` holds the `dpop.Checker` for the public base URL,
  never the internal one, and the `dpop.Nonces`; `main` builds both, from
  `GOIABADA_AUTHSERVER_BASEURL` and the current session authentication key.
- Freshness comes from the nonce alone (decision 8). A nonce is a Unix-seconds timestamp and its
  HMAC-SHA256 tag under an HKDF-derived key, base64url: accepted for ten minutes after minting, and
  up to a minute before by an instance whose clock runs behind, by every instance sharing the key.
  The previous session key does not keep old nonces: a rotation costs a client one retry.
- `dpop.ErrNonceRequired` is answered `use_dpop_nonce` with a Debug record; `dpop.ErrInvalidProof`
  is `invalid_dpop_proof` with the Warn record `dpop proof refused at the token endpoint`. Both are
  400 and values of the token-refusal metric's error label. A valid proof's thumbprint goes to the
  grant's issuer, which binds the access token.
- Each proof is accepted once (section 11.1, #42 decision 9). Once `ValidateTokenRequest` has
  accepted the grant, just before the issuer mints, `TokenProofs.Replays` inserts the proof's
  `dpop.Proof.ReplayKey`, the SHA-256 hex of its normalized `htu`, a space and its `jti`, into
  `dpop_proofs` with its nonce's expiry (`dpop.Nonces.ExpiresAt`) plus `dpop.ReplayRecordGrace`,
  five minutes, so a sweep by one instance's clock never removes a record while an instance whose
  clock runs behind could still accept the proof. The nonce is judged again at that moment, by the
  clock then: one that expired while the grant was validated is `use_dpop_nonce`, so a request in
  flight across a sweep cannot record a spent proof as new. The primary key makes the insert atomic
  across requests and instances: a taken key is a replay, `invalid_dpop_proof` with the same Warn
  record. A request refused earlier records nothing, so its proof stays unspent. A
  store failure is a 500, and nothing is minted. The cleanup worker deletes expired rows on every
  poll, outside the claim.
- A public client's refresh-token family is bound to a proof key (section 5, #42 decision 11):
  `refresh_tokens.dpop_jkt` (000086) holds the thumbprint, NULL for an unbound family, tagged
  `dont-update` like `auth_state_generation`. `issuance.refreshTokenBinding` decides a new row's
  value: a rotation copies its parent's, never the request's; otherwise, for a family's first token
  and an unbound family's refresh, the request's thumbprint when the client, as the issuer loaded
  it, is public, and NULL for a confidential one. The handler passes the proof's thumbprint as
  `ValidateTokenRequestInput.DPoPThumbprint`; the refresh arm refuses a bound token whose request
  has no proof by its key `invalid_grant` (`BoundRefreshTokenMessage`), with the Warn record
  `refresh token refused for its dpop binding`, below client authentication and ownership and
  above every check of the token's state. It is above the redemption, so a revoked bound token
  without its key never triggers containment, and nothing is spent. The rotation re-checks on the
  row it holds and rolls back with `issuance.ErrRefreshTokenBindingMismatch`, so no rotation, however
  raced, mints from a bound token without its key or inserts an unbound child into a bound family.
  The binding is enforced whatever the client's current type; refresh tokens carry no `cnf`, and
  revocation and refresh-token introspection ignore the binding.
- An authorization request's `dpop_jkt` binds its code to a key (section 10, #42 decision 14).
  `ValidateRequest` refuses it `invalid_request` beside a response type that returns no code, or
  when it fails `isBase64URLSHA256`, the S256 challenge's validator; an empty value is absent, and a
  repeat is refused with the other repeated parameters. `AuthContext.DPoPJkt` is a request field,
  kept by `Restart`, so every step, the parked POST included, carries it to `codes.dpop_jkt`
  (000088), NULL for none and tagged `dont-update`. The code arm refuses a bound code whose request
  has no proof by its key `invalid_grant` (`BoundCodeMessage`), with the Warn record `authorization
  code refused for its dpop binding`, beside PKCE: below client authentication, above the reuse
  return and every check of the grant's state. The issuer has not claimed the code yet, so a
  refused attempt spends nothing, and `MarkCodeAsUsed` still lets exactly one redemption mint.
- The CORS middleware's global lists allow the `DPoP` request header and expose `DPoP-Nonce`, so a
  browser app can send a proof and read the nonce (section 8, #42 decision 15). Which origins are
  granted, and where, is unchanged.

### DPoP at the auth server's own resources (RFC 9449 section 7)
- `/userinfo` and every `/api/v1/*` route take an access token with the `DPoP` scheme as well as
  Bearer (#42 decision 10). `JwtAuthorizationHeaderToContext` reads the scheme: Bearer in the
  header or the form body, DPoP in the header only. A token carrying `cnf.jkt` sent by a Bearer
  method, and a token without it sent with DPoP, are 401 `invalid_token`; a stray `DPoP` header
  beside an unbound Bearer token is ignored.
- With the DPoP scheme the guard checks the proof through `middleware.ResourceProofs`, the token
  endpoint's `dpop.Checker` and replay store with no nonce judge, so `iat` must lie within 60
  seconds of the server's clock (decision 8). `ath` is the presented token's. A proof problem is
  401 `invalid_dpop_proof` (`INVALID_DPOP_PROOF` in the API envelope) with the Warn record `dpop
  proof refused at a resource`; a valid proof by another key than `cnf.jkt` is 401
  `invalid_token` (figure 16). An accepted proof goes on the context with
  `reqctx.WithDPoPProof`, which is what makes the guards behind challenge in the DPoP scheme.
- `RecordDPoPProof` is the last middleware on every bearer route, behind every guard and rate
  limiter, so only a request all of them admitted spends its proof, into `dpop_proofs` until
  `dpop.Proof.IssuedAtWindowEnds` (`iat` plus 60 seconds, rounded up to the second) plus
  `dpop.ReplayRecordGrace`. It judges `iat` again first, by the clock then, as the token endpoint
  judges the nonce. A replay is `invalid_dpop_proof`, a store failure a 500. The admin group mounts
  it in each route's `With`, after the route's scope guard, and the account group after each
  route's limiters; `TestInitRoutes_EveryBearerRouteRecordsTheDPoPProofAfterItsGuards` holds every
  route to it. The handler's own checks (body, session, current password, OTP code, existence)
  run after the record, so the writer it hands the handler releases the record
  (`ReleaseDPoPProof`) when the handler's first final status is a 4xx, before that status is
  written: a refused request leaves its proof unspent, and the client may resend it corrected. A
  success or a 5xx keeps the record. Recording before the handler, not at each handler's last
  check, keeps the proof single-use whatever the handler does: a concurrent use is a replay
  while the first request is in flight. A failed release is an Error record and leaves the proof
  spent.
- `htu` is compared with the path the client sent, `dpop.RequestPath` over `RequestURI`, at the
  token endpoint and the resources alike: `httpmw.StripTrailingSlash` rewrites `r.URL` before
  routing.
- Every 401 carries one `WWW-Authenticate` field line with `Bearer realm="goiabada"` first and
  `DPoP realm="goiabada", algs="…"` second (`dpop.SigningAlgorithms`), the error in the challenge
  of the scheme used; a request with no credential gets both with no error. A 400 or 403 carries
  the challenge of each scheme used, Bearer alone when none was, so every Bearer 400 and 403 is
  unchanged. Handlers behind the guards build theirs with `middleware.UnauthorizedChallenge` and
  `InsufficientScopeChallenge`, which read the scheme off the context.

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
- `RequireValidSession` calls it in front of `/userinfo`, the admin and account APIs and the
  admin console's browser session API (`/api/v1/sessions`), and owns
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
  alone); the token parser refuses a malformed or non-RS256 token before reading a key, and checks
  any other against the current key and then each stored one; the token says its type (an access token by its `at+jwt` header, a refresh token by its `typ` claim), and
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
  on no transaction (a lookup, then an insert a concurrent revocation's row refuses as a duplicate),
  and `revoked_access_token` is written only by the call that stored it. `liveness.AccessToken` refuses a token without `grant_id` while its jti is stored, or
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
  refuses a malformed or non-RS256 token before reading a key; `token_type_hint` is never read
- An access token is active when `liveness.AccessToken` finds it live and its `aud` names a
  resource on the caller's introspection resources (`clients_introspection_resources`, compared
  exactly); a refresh token only to its own client, compared before `liveness.RefreshToken` runs,
  so another client's token reads nothing of its grant, and while its issuing flow is enabled
  (`record.Client.IsRefreshIssuingFlowEnabled`). Active means live, not that a refresh would pass:
  the grant's consent, permission and scope-allowance re-checks run only at the token endpoint.
  Introspection has no side effect: a rotated refresh token is answered inactive and triggers no
  replay containment
- Every other token is exactly `{"active": false}`. An active access token carries the token's own
  `scope`, `client_id`, `sub`, `aud`, `iss`, `exp`, `iat`, `nbf`, `jti` and `token_type`, which is
  `DPoP` beside a `cnf` with the token's `jkt` when the token carries `cnf.jkt`
  (`issuance.AccessTokenThumbprint`, RFC 9449 section 6.2), `Bearer` otherwise; a refresh
  token `scope`, its client's `client_id`, `sub`, `iss`, `exp`, `iat` and `jti`. Every answer carries
  `Cache-Control: no-store`; a fault answers 500, never inactive. No audit event;
  `goiabada_introspection_requests_total` counts each answer by outcome (#676)
- Implementation: `handler_introspect.go`, `clientauth`, `liveness`, `introspectionmetrics`

### Back-channel logout (OpenID Connect Back-Channel Logout 1.0)
The auth server tells an app that a session it was on ended, by POSTing a logout token to the
client's back-channel logout URI (#784).
- Triggers: an end of a session still valid when it ended, judged by the idle timeout and maximum
  lifetime, never `max_age`. Expiry tells nobody (decision 1). Today these are:
  - the account and admin session ends and the cross-user handover at `/auth/completed`, through
    `revocation.TerminateUserSessionTx`, whose `live` argument is the caller's judgement;
  - a sign-in's removals in `usersession.StartNewUserSession` (`replaced_by_sign_in`,
    `same_device`, `session_cap`), each `Removal` carrying its `LogoutDeliveries`;
  - a sign-out at `/auth/logout`: a confirmed hint tells only the hint's client, for its part of the
    session; a hintless one ends the session in a transaction that reads every app first (decision 2);
  - a reused code's session, in `revocation.RevokeOnAuthCodeReuse`, whose `SessionLive` argument
    (`revocation.LiveUnder` over the settings) is the token endpoint's judgement
  - the credential sites, through `revocation.RevokeUserAuthStateTx`'s `LogoutNotice`, and the
    deletion of a user, through `revocation.UserWideDeliveries` inside the deletion's transaction,
    under `GetUserByIdForUpdate` and before `DeleteUser` cascades the sessions and grants away. Every
    deletion of a user must call it there
- Two shapes (decision 3). A user-wide end (`LogoutNotice.UserWide`: disabling or deleting the
  user, a password reset, an administrator setting the password) sends one `sub`-only token to each
  app with a URI on any stored session of the user, valid or not, or holding an unrevoked, unexpired
  refresh token (`GetUsableRefreshTokenClientIdsByUserId`, read before the sweep revokes them); an
  app with `backchannel_logout_session_required` gets `sub`+`sid` per valid session instead, and
  nothing for a grant alone. The user's own password change is session-specific: `sub`+`sid` per
  app on each ended valid session, never the kept one. The `recover` command is a user-wide end too
  (decision 11): `recovery.Run` builds the notice from the settings it reads, and the command
  delivers `Outcome.Revocation.LogoutDeliveries` itself after the commit, through
  `backchannel.NewCommandSender`'s `SendAndWait`, which runs them at once and waits; no job budget
  and no metric apply, and its `sent_logout_token` entries name the command under `command`. An
  unusable data key leaves the recovery committed and the apps untold, said on stderr
- Recipients are collected inside the end's transaction, under each ended session's row
  (`AcquireUserSessionRow`), before the deletion cascades the session's apps away. The apps and their
  clients are read with `GetCommittedUserSessionClients`, a locking read on MySQL, so a sign-in that
  added an app after the transaction's first read is still told; an ordinary read there answers
  InnoDB's snapshot. A row already gone names nobody. A termination, the hintless sign-out and a reused
  code take that session's row first and hold no users row: the subject is read before the
  transaction. A sign-in takes each session it removes after its own writes, and after the user's
  row when it rechecks an OTP claim. A user-wide end and a credential change take the
  user's row first (the generation increment, or `AcquireUserRow` for a deletion), then each of the
  user's sessions in id order, as the [data guide](data.md#transactions) sets out. The hinted
  sign-out runs no transaction: it reads the session and deletes the hinting app's row, and the
  session when that was its last app, each autocommitted, and tells that app after the delete. Each caller hands its deliveries to
  `backchannel.Sender.Send` after the commit, beside its audit events
- The token: `typ: logout+jwt`, RS256 under the current signing key's `kid`; `iss`, `aud` (the
  client identifier), `iat`, `exp` 120 seconds on, `jti`, the back-channel logout event with `{}`,
  `sub`, and `sid` for a session end; no `nonce` or `nbf` (decision 4). The typed header is what
  `issuance.HasIDTokenHeader` refuses as an `id_token_hint` (decision 12)
- Delivery: each one an after-response job, `ClassBackchannelLogout` or, for a client created
  through DCR, `ClassBackchannelLogoutSelfRegistered`. The URI is checked again with
  `urlmatch.CheckBackchannelLogoutURI` (http only for an administrator's confidential client), else
  `skipped`. At most three attempts at about 0, 15 and 60 seconds with jitter, each with a 5-second
  deadline, none that could outlive the token; the same token every time; no redirect followed. Any
  2xx is `delivered`; 408, 429, 5xx, a timeout and a connection failure are retried; another status
  is `refused`; a certificate failure, or no success after the last attempt, is `failed` (decision 5)
- Address guard (decision 7): a delivery to a client created through DCR, whoever set its URI, goes
  through `backchannel.newDeliveryClients`' guarded client: no proxy, and a `net.Dialer.Control`
  that refuses any dialed address `publicUnicast` rejects (loopback, RFC 1918, `fc00::/7`,
  link-local, unspecified, multicast, broadcast, and every IANA special-purpose block that is not
  globally reachable, with 6to4, IPv4-compatible and site-local; IPv4-mapped and NAT64
  `64:ff9b::/96` addresses are judged by the IPv4 address they carry). Control sees the resolved
  address, so DNS rebinding gains nothing. A refusal is final, `blocked`. An administrator's client
  uses a separate transport with the environment's proxy and reaches any address
- Each delivery counts on `goiabada_backchannel_logout_deliveries_total` by outcome, writes
  `sent_logout_token` when it finishes, and one Warn record when it was not delivered (decision 8)
- Discovery advertises `backchannel_logout_supported` and `backchannel_logout_session_supported`
- Implementation: `backchannel`, `revocation/revocation.go`, `authflow/completion.go`,
  `usersession/usersession_manager.go`, `handler_logout.go`, `handler_token.go`,
  `handler_api_account_sessions.go`, `handler_api_users_sessions.go`, `handler_api_users_crud.go`,
  `handler_api_account_password.go`, `accounthandlers/handler_reset_password.go`

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
- Rate limited. Blocks users with 2FA enabled, and users who owe the acceptance step a legal
  document for the client (`invalid_grant`, #622). Logs `audit.EventROPCAuthFailed` on failure
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
| `level1_password_completed` | `authflow.PasswordProof` | a password proven: verified at `/auth/pwd` with the user enabled (`authflow.PasswordSubmission`), or just chosen at registration without verification or at activation, carrying on the sign-in the Create an account link named while the browser holds it at `level1_password` (`accounthandlers.carryOnSignIn`, #622) |
| `level1_existing_session` | `authflow.Authorization` | valid session, hint matches, user enabled. The SSO shortcut: password entry is skipped and `/auth/level1completed` accepts this state directly |
| `requires_level_2` | `authflow.Level1Completion` | target ACR above the owned session's ACR, or above level 1 with no owned session, or the session's `OtpConfigGeneration` differs from the user's and the target is above level 1, or the target is `level2_mandatory` and the user has no authenticator. A ceremony that verified the password itself (`Level1AuthCompleted`) counts no session, so it lands here whenever the target is above level 1 (#537) |
| `level2_otp` | `authflow.Level2Selection` | `level2_optional` with OTP enabled, or `level2_mandatory` (enrolment happens at `/auth/otp` if needed) |
| `level2_recovery_codes` | `authflow.OTPSubmission` | OTP enrolled: the ceremony holds the new authenticator's recovery codes (`RecoveryCodes`) until `/auth/recovery-codes` first renders them; that render takes them off in one conditional write (`ceremony.Store.TakeRecoveryCodes`) and shows only what it took, so a reload or an overlapping load shows them no more (#257) |
| `authentication_completed` | `authflow.Level1Completion` | no step-up needed |
| | `authflow.Level2Selection` | `level2_optional` and no OTP enrolled, which is the skip that bypasses `/auth/otp` entirely |
| | `authflow.OTPSubmission` | OTP verified against the stored authenticator, or a recovery code accepted |
| | `authflow.ContinueAfterRecoveryCodes` | Continue on the recovery-codes page |
| `requires_legal_acceptance` | `authflow.Completion` | the user holds a requested scope and owes a legal document for the client: a must-accept document in effect for all apps or for the client whose current version the user has not accepted (`legaldocuments.Reader.Owed`); the admin console's client owes none (#622) |
| `requires_consent` | `authflow.Completion` | `prompt=consent`, or `client.ConsentRequired`, or `offline_access` in scope, or `authserver:manage-account` still in scope, the client not the admin console's, and no stored consent covering it (`userconsent.AlwaysOwed`, #509) or a client not remembering consent (`record.Client.RemembersConsent`, a public client with Remember consent off, whose stored consent is then not read, #711) |
| | `authflow.LegalAcceptance` | the same, decided once nothing is owed |
| `ready_to_issue_code` | `authflow.SilentAuthentication` | every silent check passed, skipping every hop between |
| | `authflow.Completion` | no consent needed |
| | `authflow.LegalAcceptance` | nothing owed any more, or the documents accepted, then decided as `authflow.Completion` decides it (`routeBoundCeremony`), consent included |
| | `authflow.ConsentPrompt` | scope already fully consented, the client remembering consent (#711), no `offline_access`, no `prompt=consent` |
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
| `/auth/recovery-codes` | GET | ceremony id first, then `level2_recovery_codes` | 400, 400 |
| `/auth/recovery-codes` | POST | ceremony id first, then `level2_recovery_codes` | 400, 400 |
| `/auth/completed` | GET | ceremony id first, then `authentication_completed` | 400, 400 |
| `/auth/legal-acceptance` | GET | ceremony id first, then `requires_legal_acceptance` | 400, 400 |
| `/auth/legal-acceptance` | POST | ceremony id first, then `requires_legal_acceptance` | 400, 400 |
| `/auth/consent` | GET | ceremony id first, then `requires_consent` | 400, 400 |
| `/auth/consent` | POST | ceremony id first, then `requires_consent` | 400, 400 |
| `/auth/issue` | GET | ceremony id first, then `ready_to_issue_code` | 400, 400 |

### Flow Handlers (in order)
| Handler | File | Purpose |
|---------|------|---------|
| `/auth/authorize` | `handler_authorize.go`, `authflow/authorization.go`, `authflow/silent_authentication.go` | Entry point. `authflow.Authorization` creates the ceremony, validates the request, checks the existing session and routes it to level1 or SSO; a `prompt=none` request is answered by `authflow.SilentAuthentication`, without a page. A POST (`handler_authorize_post.go`, `authflow/authorization_parking.go`) only parks the request and redirects to the GET |
| `/auth/level1` | `handler_auth_level1.go`, `authflow/level1_selection.go` | Selects level1 auth method (currently only password) |
| `/auth/pwd` | `handler_auth_pwd.go`, `authflow/password.go` | Password login form. Verifies the password, then `authflow.PasswordProof` rotates the browser session's identifier and records level 1 on the ceremony. Registration and activation reach the same operation when they carry on the sign-in the Create an account link named (`accounthandlers/sign_in_continuation.go`, #622), and redirect to `/auth/level1completed` |
| `/auth/level1completed` | `handler_auth_level1.go`, `authflow/level1_completion.go` | Delivers a deferred authorization error if one is parked (see Deferred error redirects), else decides if level2 needed based on ACR and session state |
| `/auth/level2` | `handler_auth_level2.go`, `authflow/level2_selection.go` | Selects level2 auth method. If `level2_optional` + no OTP → skip to completed |
| `/auth/otp` | `handler_auth_otp.go`, `authflow/otp.go` | OTP verification (or enrollment if user doesn't have OTP yet), or a recovery code in place of the code. Rotates the browser session's identifier, records level 2 on the ceremony. An enrolment goes on to `/auth/recovery-codes`, anything else to `/auth/completed` |
| `/auth/recovery-codes` | `handler_auth_recovery_codes.go`, `authflow/recovery_codes_step.go` | Shows an enrolment's recovery codes once, taking them off the ceremony in a save before the page renders; a reload says they were already shown. Its Continue (POST) moves the ceremony to `authentication_completed` and answers 303 to `/auth/completed` |
| `/auth/completed` | `handler_auth_completed.go`, `authflow/completion.go` | Final auth check (a user who is not the id_token_hint's refused, a disabled user refused, a moved-on generation restarted, all before any session is bound), session bump/create, scope filtering, consent check. The plan is one of three modes (`authflow/completion_decide.go`): reuse, which rotates the browser session's identifier before the bind when it raises the session; create, which confirms the ceremony, starts the session (`StartNewUserSession`, which writes nothing to the browser), then rotates and binds it to the browser session (`RegenerateSessionAndBind`), deletes it when that fails, and writes the device cookie only after; and restart |
| `/auth/legal-acceptance` | `handler_legal_acceptance.go`, `authflow/legal_acceptance.go` | The acceptance step (#622): lists the must-accept legal documents the user owes for the client, each unticked. Accept records the versions shown (`legaldocuments.RecordAcceptances`), shows the step again for an unticked box or a version published meanwhile, and goes on to consent or issuance; Decline answers `access_denied` and keeps the session. `prompt=none` answers `interaction_required` for what is owed, the password grant `invalid_grant`, and refresh is not checked |
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
- Only the page branch refreshes the browser session (`sessionstore.Refreshing`, in `pageChain`
  behind `middleware.NoStore`): a row more than ten seconds stale is touched there, and the
  session's cookie is sent again. A sign-in in progress gets the renewed 30 minutes its row has, so
  reloading a sign-in's pages does not leave its cookie expiring before the row. A signed-in
  session's cookie goes as `KeepSignedIn` answers now, with the row's new expiry or with neither
  Max-Age nor Expires. The second replaces a cookie that outlives the browser, written before an
  upgrade or a stricter setting, without waiting for a sign-in. The touch happens at the
  session's first read, before the handler, but the cookie is held until the final answer's
  headers go out (an informational status leaves it held, and a panic's 500 carries it) and
  dropped if the request wrote the session's cookie itself or the row no longer holds the contents
  the read found: another request of the browser that rotated, ended or rewrote the session and
  answered first would otherwise be undone by a cookie naming the removed row or built from the
  older contents, such as a Keep me signed in answer just replaced. Every answer on that branch is
  `no-store`, the router's 405 under a page group included, and the files, protocol and API branches
  read the session without touching it, so no reissued cookie rides on a cacheable answer (#743)
- Whether a signed-in cookie outlives the browser is the store's `KeepSignedIn` rule
  (`sessionbackend.NewKeepSignedIn`), asked per cookie write. Under Let each user choose it reads the
  password page's Keep me signed in answer from the browser session (`sessionkeys.KeepSignedIn`, a
  bool; no key counts as unticked). The answer travels on the ceremony (`AuthContext.KeepSignedIn`,
  written only by `RecordPasswordVerified`, nil when no box was shown), and `/auth/completed`
  records it only when the ceremony entered the password: the create arm in `RegenerateSessionAndBind`'s
  write, the reuse arm (`replaceAuthentication`) through `RecordKeepSignedIn` after the bind. A nil
  answer deletes the key; an SSO pass leaves it as it is (#743). Each record stamps the answer with
  its ceremony's `PasswordVerifiedAt` (`sessionkeys.KeepSignedInPasswordAt`), and `RecordKeepSignedIn`
  leaves an answer stamped later as it is, checked in its conditional write: two held ceremonies can
  bind in one order and record in the other, and the newer password entry's answer must stand. The
  create arm records its own answer whatever the stamp, since the session it binds started from
  that entry

## SSO and ACR/AMR Details

### AMR (Authentication Methods Reference)
Three methods tracked (`oidc/auth_method.go`): `pwd` (password), `otp` (time-based OTP) and
`recovery_code` (a recovery code entered in place of an authenticator code, Goiabada's own value,
#257). Stored as space-separated string in `AuthContext.AuthMethods` and `UserSession.AuthMethods`.
Output in tokens as JSON array per OIDC spec: `"amr": ["pwd", "otp"]`, or `["pwd", "recovery_code"]`
for a recovery-code sign-in. `AuthContext.ClaimsOTP` counts either second-factor method as a claim
the authenticator backs, tied to its `otp_config_generation`, so removing the authenticator lowers
a recovery-code session and restarts a ceremony in flight exactly as for a code (#542).

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
and email changes, account deletion, email verification and its resend, forgot/reset password, self-registration,
activation, DCR, and the authorization endpoint, both methods of which share one admission budget
per client block, #504). Credential checks count failures only, so a successful attempt spends
nothing. Two tiers count every request beside a credential check: the email change's, since past
the password it says whether another account holds the address (#683), and
`account_credential_change`, 10 an hour per account shared by the Account API's password change,
two-factor change and new set of recovery codes, mounted ahead of `account_password` so it counts
refused requests too. Without it nothing bounds how often one account succeeds at those changes,
and each sends a security notice (#724 decision 3). Account deletion is on `account_password`
alone, without `account_credential_change`: a wrong password, authenticator code or recovery code
each spends it, a blank password or a missing code spends nothing, and the last administrator is
refused before any credential is checked (#783 decision 4). The account's own data download counts
every request on `account_export`, mounted after its client and step-up guards (#782 decision 5).
The limits counted by a user or by an
email apply whatever
`GOIABADA_AUTHSERVER_RATELIMITER_ENABLED` says: those counted by a user something has already
authenticated, the signing-in user or a token's subject (OTP, account password, credential change,
email change, email verification and its resend, data download), since no stranger can spend them (#542), and those counted by an email anyone can
type (wrong passwords per account, 100 an hour shared by the sign-in form and the password grant,
and reset mails and registration notices per address), since only Goiabada can count them (#503).
The switch governs only the tiers that read the client's address, those counted by an IP address and
`pwd_account_net`, the 10 wrong passwords per 15 minutes for one email from one client block; with
it off the password check reserves the account-wide tier alone. The price is #89's lockout: 100
wrong passwords block an account's password sign-in for up to an hour, its remedy blocking the
attacker at the proxy or CDN (#503), or the optional Turnstile challenge (#642). While the challenge
is on, `RequirePasswordChallenge`, `RequireForgotPasswordChallenge` and `RequireRegistrationChallenge`
run ahead of their forms' limiters, after the forms' own availability refusals, so a submission
without a verified token spends no tier, those counted by an email and by a client block alike, and
no password is compared; the limiter itself is unchanged. The password grant shares `pwd_account`
and carries no challenge, so the lockout stays closed only while no public client has the grant
enabled (#642 decision 8). `internal/turnstile` refuses on Cloudflare's verdict or a missing token
and fails open on a configuration fault or no usable answer, so its worst case is the limiter alone.
A refused token spends no limiter budget, so the verifier caps the forms' checks in flight at 64; a
check that finds no free slot before its 3-second deadline fails open, logged with the reason `busy`.
Their transport's per-host cap of 64 also bounds the dials a canceled check leaves running in the
background; over HTTP/2 it is not a ceiling on every open connection. An administrator's check of a
secret key takes no slot and has its own transport, so a flood cannot block saving one.

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
registration (RFC 7591), authorization server metadata (RFC 8414), JWT (RFC 7519), JWS (RFC
7515), JWA (RFC 7518), JWK (RFC 7517) and JWK thumbprints (RFC 7638), JWT access tokens (RFC 9068),
DPoP (RFC 9449), the OAuth 2.0 Security Best Current Practice (RFC 9700), and OpenID Connect Core
1.0, Discovery 1.0 and Back-Channel Logout 1.0.

Every JWT the auth server or the admin console reads, its own tokens, the console's ID tokens and
DPoP proofs, first passes `oauth.CheckJWTStructure` in core, before its signature is checked (#709):
three segments of the unpadded base64url alphabet only, so `=`, CR, LF and whitespace are refused
(RFC 7515 sections 2 and 5.2); a header and payload of valid UTF-8 (RFC 7519 section 7.2); no
`crit` header, whatever its value, since Goiabada understands no extension (RFC 7515 section
4.1.11); and no `cty` of `JWT` or `application/jwt`, since it supports no nested JWT. Each reader
answers a refusal as it answers a malformed token. The console's ID-token reader also requires a
string `sub` of 1 to 255 characters and a numeric `iat` (OpenID Connect Core 1.0 section 2), refuses
an RSA key under 2048 bits or with an even, small or overlong exponent (RFC 7518 section 3.3), and
skips a key whose `use` is not `sig` or whose `alg` is not `RS256` (Core section 10.1).

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
  - `POST /api/v1/account/deletion` also requires a token issued to `admin-console-client`:
    `RequireAdminConsoleClient` answers any other client 403 `CLIENT_NOT_ALLOWED` with the
    `insufficient_scope` challenge, and is the route guard to reuse for another console-only
    route. It takes the password and, while two-factor authentication is on, an authenticator code
    or a recovery code. `DeleteUser` runs under the administrators' lock, which refuses the last
    enabled holder of `authserver:manage` there and in an earlier check made before the
    credentials. The credentials are checked against the first read of the user, so the row read
    under the deletion's lock must still hold the same password hash and, while two-factor is on,
    the authenticator generation the code was accepted for; a recovery code is claimed in the
    deletion's transaction (#783).
  - `GET /api/v1/account/export` mounts `RequireAdminConsoleClient`, then
    `RequireRecentAuthentication(300s, urn:goiabada:level2_optional)`, then the `account_export`
    tier (5 an hour per token user, every request counted), so a request either guard refuses
    spends nothing, then `RecordDPoPProof`. The step-up guard is RFC 9470 section 3: it refuses a
    token whose `auth_time` is older than the maximum age or whose `acr` ranks below the minimum,
    and fails closed on a missing or non-integer `auth_time` or an unknown `acr`, answering 401
    `INSUFFICIENT_USER_AUTHENTICATION` with `error="insufficient_user_authentication"`,
    `acr_values` and `max_age` on every refusal, in the challenge of the scheme used. It takes the
    age, the level and a clock, so it is the guard to reuse in front of another operation. A
    refresh keeps `auth_time`, so a refreshed token is as old as its sign-in. The answer is the admin export's builder and writer, and
    `exported_own_user_data` is written after it (#782). In the console, `render.IsStepUpRequired`
    recognises that 401 by its code and `render.IsSessionEnded` leaves it out, since the token and
    its session are still good. A page in front of the guard checks `IsStepUpRequired` before the
    API error classifier and sends the browser through the console's own sign-in with
    `prompt=login` and the level the operation asks for, never `max_age`, which would replace the
    session past the window: Your data asks for `urn:goiabada:level2_optional` and returns to
    `/account/data?signed_in_again=1`. The ordinary sign-in sends neither parameter. A step-up
    refusal that reaches `HandleAPIError`, `HandleAPIErrorWithCallback` or `HandleAPIErrorJSON` is
    that page's fault: each answers it with the 500 writer, whose log names the missing check, and
    leaves the user signed in.
