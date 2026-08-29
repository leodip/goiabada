# Goiabada - OAuth2/OIDC Authentication Server

## What It Is
Open-source authentication server in Go. OAuth2/OIDC compliant with SSO, 2FA, and admin console.

## Architecture (3 Go Modules)

```
src/
├── core/           # Shared: models, data layer, oauth, validators
├── authserver/     # OAuth2/OIDC endpoints, user auth flows
└── adminconsole/   # Admin UI for managing users/clients/permissions
```

- **Core** (`src/core/go.mod`): Database interface, models, JWT handling, OAuth logic
- **Auth Server** (`src/authserver/go.mod`): Main auth endpoints, token issuance
- **Admin Console** (`src/adminconsole/go.mod`): Admin management UI

## Key Directories

### Core (`src/core/`)
- `models/` - All domain models (Client, User, Permission, Group, etc.)
- `data/` - Database interface + implementations (commondb/, mysqldb/, postgresdb/, sqlitedb/, mssqldb/)
- `oauth/` - Token issuance, code issuance, JWT handling
- `validators/` - Input validation (authorize, token, email, password, etc.)
- `config/` - Configuration from environment variables
- `constants/` - Audit event names, resource identifiers

### Auth Server (`src/authserver/`)
- `internal/handlers/` - HTTP handlers (auth flows, token, userinfo, DCR)
- `internal/handlers/accounthandlers/` - User self-service handlers
- `internal/handlers/apihandlers/` - Admin API handlers
- `internal/server/routes.go` - All route definitions
- `web/template/` - HTML templates
- `tests/integration/` - Integration tests

### Admin Console (`src/adminconsole/`)
- `internal/handlers/` - Admin UI handlers
- `web/template/` - Admin UI templates

## Database Pattern

Single `Database` interface (`src/core/data/database.go`) with per-DB implementations:
- All methods accept `tx *sql.Tx` (nil = no transaction)
- Uses `sqlbuilder` for query building with DB-specific flavors
- Schema in `src/core/data/sqlitedb/schema.golden` (generated; see **Schema golden files** below)

**Supported**: SQLite, MySQL, PostgreSQL, SQL Server

## OAuth2 Flows Supported

For full documentation, see `site/` (Astro-based docs site).

### Authorization Code (with PKCE)
Primary flow for web/mobile apps. User authenticates via browser, receives code, exchanges for tokens.
- Endpoint: `GET /auth/authorize` → `POST /auth/token` (grant_type=authorization_code)
- PKCE: always required for a public client; otherwise configurable globally (`Settings.PKCERequired`) or per-client (`Client.PKCERequired`)
- Supports `response_type=code` with optional `code_challenge` + `code_challenge_method`
- Implementation: `handler_authorize.go`, `handler_token.go`, `oauth/code_issuer.go`

### Client Credentials
Server-to-server auth. No user context, client authenticates directly for access token.
- Endpoint: `POST /auth/token` (grant_type=client_credentials)
- Requires: `Client.ClientCredentialsEnabled = true`
- Auth methods: `client_secret_basic` (Authorization header) or `client_secret_post` (form body)
- Implementation: `handler_token.go` case "client_credentials"

### Refresh Token
Exchange refresh token for new access/refresh tokens. Works with auth code and ROPC flows.
- Endpoint: `POST /auth/token` (grant_type=refresh_token)
- Offline tokens: Configurable idle timeout and max lifetime per client/globally
- Revocation: Old refresh token revoked on use, new one issued
- Implementation: `handler_token.go` case "refresh_token", `oauth/token_issuer.go`

### Implicit Flow (Deprecated)
Legacy flow returning tokens directly in redirect URI fragment. **Deprecated in OAuth 2.1.**
- Endpoint: `GET /auth/authorize` with `response_type=token|id_token|id_token token`
- Disabled by default. Enable via `Settings.ImplicitFlowEnabled` or `Client.ImplicitGrantEnabled`
- Security risk: Tokens exposed in browser history/Referer headers
- Implementation: `handler_auth_issue.go`, `validators/authorize_validator.go`

### ROPC - Resource Owner Password Credentials (Deprecated)
Direct username/password exchange for tokens. **Deprecated in OAuth 2.1** due to credential exposure.
- Endpoint: `POST /auth/token` (grant_type=password, username, password)
- Disabled by default. Enable via `Settings.ResourceOwnerPasswordCredentialsEnabled` or per-client
- Rate limited. Blocks users with 2FA enabled. Logs `AuditROPCAuthFailed` on failure
- Implementation: `handler_token.go` case "password", `validators/token_validator.go`

### Dynamic Client Registration (RFC 7591)
Programmatic client registration for MCP servers, native apps, etc.
- Endpoint: `POST /connect/register`
- Disabled by default. Enable via `Settings.DynamicClientRegistrationEnabled`
- Creates public or confidential clients based on `token_endpoint_auth_method`
- Rate limited. Returns client_id and client_secret (if confidential)
- Implementation: `handler_dynamic_client_registration.go`

## Authentication Flow (Authorization Code)

The auth code flow uses a state machine tracked in `AuthContext` (stored in session cookie).

### ACR Levels (Authentication Context Class Reference)
Defined in `src/core/enums/enums.go`:
- **`urn:goiabada:level1`** - Password only (single factor)
- **`urn:goiabada:level2_optional`** - Password + OTP if user has OTP enabled (skip if not)
- **`urn:goiabada:level2_mandatory`** - Password + OTP required (user must enroll if not already)

Target ACR determined by: `acr_values` param in authorize request → falls back to `Client.DefaultAcrLevel`

### Auth States (State Machine)
Defined in `src/core/oauth/auth_context.go`. States transition in this order:

1. **`AuthStateInitial`** - Entry point at `/auth/authorize`
2. **`AuthStateRequiresLevel1`** - No valid session, needs level1 auth
3. **`AuthStateLevel1Password`** - User at password form
4. **`AuthStateLevel1PasswordCompleted`** - Password verified, deciding next step
5. **`AuthStateRequiresLevel2`** - Level2 auth needed (based on ACR)
6. **`AuthStateLevel2OTP`** - User at OTP form (or enrollment)
7. **`AuthStateLevel2OTPCompleted`** - OTP verified
8. **`AuthStateAuthenticationCompleted`** - All auth done, checking consent
9. **`AuthStateRequiresConsent`** - Showing consent screen (if `client.ConsentRequired` or `offline_access` scope)
10. **`AuthStateReadyToIssueCode`** - Ready to issue code and redirect to client

**Shortcut for existing session**: If user has valid session, flow goes `AuthStateInitial` → `AuthStateLevel1ExistingSession` → `AuthStateLevel1PasswordCompleted` (skipping password entry), then continues from step 4.

### Flow Handlers (in order)
| Handler | File | Purpose |
|---------|------|---------|
| `/auth/authorize` | `handler_authorize.go` | Entry point. Validates request, checks existing session, routes to level1 |
| `/auth/level1` | `handler_auth_level1.go` | Selects level1 auth method (currently only password) |
| `/auth/pwd` | `handler_auth_pwd.go` | Password login form. Validates credentials, creates session |
| `/auth/level1completed` | `handler_auth_level1.go` | Delivers a deferred authorization error if one is parked (see below), else decides if level2 needed based on ACR and session state |
| `/auth/level2` | `handler_auth_level2.go` | Selects level2 auth method. If `level2_optional` + no OTP → skip to completed |
| `/auth/otp` | `handler_auth_otp.go` | OTP verification (or enrollment if user doesn't have OTP yet) |
| `/auth/completed` | `handler_auth_completed.go` | Final auth check, scope filtering, consent check, session bump/create |
| `/auth/consent` | `handler_consent.go` | User consent screen (if required) |
| `/auth/issue` | `handler_auth_issue.go` | Issues authorization code, redirects to client |

### Deferred error redirects (#213)
`/auth/authorize` never redirects an unauthenticated browser to a client's `redirect_uri` on a failed
request, per RFC 9700 4.11.2. A validation failure is answered at once when the request is silent
(`prompt=none`, read from the raw parameter), when the browser holds a valid session and did not ask
for `prompt=login`, or when no redirect would be emitted anyway (`redirectWillBeEmitted` false).
Otherwise the error code and description are parked on `AuthContext.DeferredErrorCode` /
`DeferredErrorDescription`, the visitor goes to `/auth/level1`, and the redirect is emitted from
`/auth/level1completed` once the password is verified. That ceremony ends there and creates no
session.

One failure is answered before any of that and never redirects at all: a `response_mode` outside
`query`, `fragment`, `form_post` renders the refusal page at 400 with no error parameters, per OIDC
Core 3.1.2.6, since the server cannot encode a response in a mode it does not implement. The set has
one definition, `validators.IsSupportedResponseMode`, shared by the handler and `ValidateRequest`.

### Key Logic in Level1Completed
`handler_auth_level1.go:HandleAuthLevel1CompletedGet`:
- If a deferred error is parked → answer the client and stop (see above)
- If session ACR is `level1` and target is `level2_*` → redirect to level2
- If session ACR is `level2_optional` and target is `level2_mandatory` → redirect to level2
- If the session's `OtpConfigGeneration` differs from the user's → re-auth level2 (user changed OTP settings). This block writes nothing: the obligation is discharged at `/auth/completed`
- Otherwise → auth completed

### Key Logic in Level2
`handler_auth_level2.go:HandleAuthLevel2Get`:
- If `level2_optional` + `user.OTPEnabled` → show OTP form
- If `level2_optional` + no OTP → skip to auth completed
- If `level2_mandatory` → show OTP form (user enrolls if needed)

### Session Reuse (SSO)
When user has valid session (`UserSession` in DB + session cookie):
- Session validated via `userSessionManager.HasValidUserSession()` (checks idle timeout, max lifetime, max_age param)
- If valid → uses existing `AcrLevel` and `AuthMethods` from session
- May still need level2 re-auth if target ACR higher than session ACR

## SSO and ACR/AMR Details

### AMR (Authentication Methods Reference)
Two methods tracked (`enums.go`): `pwd` (password), `otp` (time-based OTP).
Stored as space-separated string in `AuthContext.AuthMethods` and `UserSession.AuthMethods`.
Output in tokens as JSON array per OIDC spec: `"amr": ["pwd", "otp"]`

### UserSession Model
```
UserSession (DB)
├── SessionIdentifier (UUID in browser cookie)
├── Started (for max lifetime check)
├── LastAccessed (for idle timeout check)
├── AuthMethods ("pwd" or "pwd otp")
├── AcrLevel ("urn:goiabada:level1" etc.)
├── AuthTime (when auth occurred)
├── OtpConfigGeneration (snapshot of users.otp_config_generation)
└── UserId
```

### Session Validity (`usersession.go:40-51`)
Valid if ALL true:
1. `now <= LastAccessed + IdleTimeoutSeconds`
2. `now <= Started + MaxLifetimeSeconds`
3. If `max_age` param: `now <= Started + max_age`

### ACR Step-Up Logic (`handler_auth_level1.go`)
Uses `enums.AcrLevel.IsHigherThan()` for comparison (priority: level1=1, level2_optional=2, level2_mandatory=3).

**With valid session:**
- Target ACR higher than session ACR → redirect to level2 (step-up)
- Session `OtpConfigGeneration` != user's + target requires level2 → re-prompt OTP
- Otherwise → SSO succeeds, bump session

**Without valid session:**
- Target > level1 → redirect to level2

### ACR in Token (`auth_context.go:SetAcrLevel`)
Token ACR = `max(targetACR, sessionACR)`. Never downgrades within a session.

### OTP config generation
`users.otp_config_generation` is a per-user counter, advanced by one at every site that establishes
or removes an authenticator (`EnableUserOTPTx` and `disableUserOTP`), inside the same transaction as
the write that changed it. `user_sessions.otp_config_generation` records the value that session last
satisfied, so a session owes a level 2 re-prompt whenever the two differ. Being per user means one
statement covers every session of that user.

Both readers, `HandleAuthLevel1CompletedGet` and `handlePromptNone`, only compare and write nothing,
so an abandoned ceremony spends no re-prompt. The snapshot is captured onto `AuthContext` at
`handler_auth_pwd` and on every arm of `HandleAuthLevel2Get`, and promoted once, at
`/auth/completed`: `StartNewUserSession` writes it on the create arm, and
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
- Session ACR >= target ACR → SSO succeeds (keeps higher ACR in token)
- Session ACR < target ACR → step-up required (prompt for OTP)
- Session `OtpConfigGeneration` != user's + target requires level2 → re-prompt OTP

## Configuration

All via environment variables with `GOIABADA_` prefix. Key ones:
- `GOIABADA_DB_TYPE` - sqlite/mysql/postgres/mssql
- `GOIABADA_AUTHSERVER_BASEURL` - Public URL
- `GOIABADA_ADMIN_EMAIL` / `GOIABADA_ADMIN_PASSWORD` - Initial admin

See `src/core/config/config.go` for all options.

## Testing

Three test types:

1. **Unit Tests** - Throughout codebase alongside source files (`*_test.go`)
   - Handler tests: `src/authserver/internal/handlers/*_test.go`
   - Core logic tests: `src/core/oauth/*_test.go`, `src/core/validators/*_test.go`

2. **Data Tests** - Database layer tests in `src/authserver/tests/data/`
   - Tests all CRUD operations for each model   

3. **Integration Tests** - Full API tests in `src/authserver/tests/integration/`
   - OAuth2 flows, DCR, Admin API, User management
   - Requires running server

**Best way to run all tests**: `./run-tests.sh` inside the dev container (from `src/authserver/`).

**gofmt guard**: every module's unit tier runs `TestGoSourcesAreGofmted`, which holds every Go
file under `src/` to gofmt's formatting through `core/testutil.AssertGofmted`. The walk is
repository-wide from each tier because `cmd/goiabada-setup` has no tier of its own. CI's Lint job
checks the same thing per module, where an unformatted file also costs that module its vet,
unparam and golangci-lint run.

**Schema golden files**: each engine's fully migrated catalog is recorded in
`src/core/data/<engine>db/schema.golden`, and the data tier compares a freshly migrated database
against the file for the engine it is running on. A migration therefore has one more step:
`cd src/core && go run ./cmd/schemadump` inside the dev container, which regenerates all four
files at once, and commit them. Skip it and CI goes red on every database job.

**Migration source rules**: the core tier runs `TestMigrationSource_TheFourCommittedDirectories`
in `src/core/data`, which holds the four `migrations/` directories to the rules decidable from the
text alone: naming, pairing, one number meaning one change, the collation pins on MySQL and SQL
Server, a named `CONSTRAINT` on every added SQL Server `DEFAULT` and a spelled-out `NULL` or
`NOT NULL` on every `ALTER COLUMN`, and each `schema.golden`'s recorded version. A migration
landing on fewer than four engines therefore owes a `-- parity: <engines> only. <why>` line in
every up.sql carrying it, and a `.down.sql` with no statement in it owes
`-- Migration NNNNNN down: intentional no-op.`

## Important Patterns

1. **Handler signature**: `HandleXxxGet/Post(dependencies...) http.HandlerFunc`
2. **Audit logging**: All security events logged via `auditLogger` (see `constants/constants.go` for event names)
3. **Rate limiting**: Applied to credential checks and unauthenticated endpoints (login, OTP, ROPC, account password and OTP changes, email verification, forgot/reset password, self-registration, activation, DCR). Credential checks count failures only, so a successful attempt spends nothing
4. **Permissions model**: Resources contain Permissions; Users/Groups/Clients can have Permissions
5. **Credential form fields**: A handler reads a credential-bearing field (`password`, `passwordConfirmation`, `currentPassword`, `newPassword`, `newPasswordConfirmation`, `otp`, `secretKey`, `base64Image`, `verificationCode`, `clientSecret`) and a form-binding marker (`ceremonyId`, `continuationId`) with `r.PostFormValue`, never `r.FormValue`. `r.FormValue` merges the URL query behind the request body, so the value would be accepted from the request target, where it reaches the browser's history, the `Referer` of anything the page loads, and the access log of every proxy, gateway and CDN in front of the deployment. Every such form is POST-only with a separate GET handler that renders it, so the query is never a submission. Enforced per module by `credential_read_lint_test.go` in each `internal/handlers` package; `handler_authorize.go` is exempt for `state` and `code`, which OIDC Core 3.1.2.1 requires the authorization endpoint to accept over GET as well as POST (#202)

## API Routes

- `/auth/authorize` - OAuth2 authorization endpoint
- `/auth/token` - Token endpoint
- `/userinfo` - OIDC userinfo
- `/certs` - JWKS endpoint
- `/.well-known/openid-configuration` - OIDC discovery
- `/connect/register` - Dynamic Client Registration
- `/api/v1/admin/*` - Admin API (requires `authserver:manage` permission)
- `/api/v1/account/*` - User self-service API (requires `authserver:manage-account` permission)

## Important Note
Do not make any changes until you have 95% confidence that you know what to build. Ask follow-up questions until you have that confidence.
