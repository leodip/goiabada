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
- Schema in `src/core/data/sqlitedb/schema.sql`

**Supported**: SQLite, MySQL, PostgreSQL, SQL Server

## OAuth2 Flows Supported

For full documentation, see `site/` (Astro-based docs site).

### Authorization Code (with PKCE)
Primary flow for web/mobile apps. User authenticates via browser, receives code, exchanges for tokens.
- Endpoint: `GET /auth/authorize` → `POST /auth/token` (grant_type=authorization_code)
- PKCE: Configurable globally (`Settings.PKCERequired`) or per-client (`Client.PKCERequired`)
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
| `/auth/level1completed` | `handler_auth_level1.go` | Decides if level2 needed based on ACR and session state |
| `/auth/level2` | `handler_auth_level2.go` | Selects level2 auth method. If `level2_optional` + no OTP → skip to completed |
| `/auth/otp` | `handler_auth_otp.go` | OTP verification (or enrollment if user doesn't have OTP yet) |
| `/auth/completed` | `handler_auth_completed.go` | Final auth check, scope filtering, consent check, session bump/create |
| `/auth/consent` | `handler_consent.go` | User consent screen (if required) |
| `/auth/issue` | `handler_auth_issue.go` | Issues authorization code, redirects to client |

### Key Logic in Level1Completed
`handler_auth_level1.go:HandleAuthLevel1CompletedGet`:
- If session ACR is `level1` and target is `level2_*` → redirect to level2
- If session ACR is `level2_optional` and target is `level2_mandatory` → redirect to level2
- If `Level2AuthConfigHasChanged` flag set on session → re-auth level2 (user changed OTP settings)
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

## Important Patterns

1. **Handler signature**: `HandleXxxGet/Post(dependencies...) http.HandlerFunc`
2. **Audit logging**: All security events logged via `auditLogger` (see `constants/constants.go` for event names)
3. **Rate limiting**: Applied to sensitive endpoints (password, OTP, ROPC, DCR, activation)
4. **Permissions model**: Resources contain Permissions; Users/Groups/Clients can have Permissions

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
