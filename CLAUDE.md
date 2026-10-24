# Goiabada - OAuth2/OIDC Authentication Server

## What It Is
Open-source authentication server in Go. OAuth2/OIDC compliant with SSO, 2FA, and admin console.

## Architecture (3 Go Modules)

```
src/
├── core/           # Shared: oauth, validators, kernel helpers
├── authserver/     # OAuth2/OIDC endpoints, user auth flows
└── adminconsole/   # Admin UI for managing users/clients/permissions
```

- **Core** (`src/core/go.mod`): JWT handling, OAuth logic, wire contract
- **Auth Server** (`src/authserver/go.mod`): Main auth endpoints, token issuance
- **Admin Console** (`src/adminconsole/go.mod`): Admin management UI

Which module owns what, and the rules that keep it that way, are in `ARCHITECTURE.md` at the
repository root. It is enforced rather than descriptive: see **Architecture guard** under Testing.

## Key Directories

### Core (`src/core/`)
- `adminpassword/` - The one rule for the first administrator's password, `Check`: at least 15 characters, at most bcrypt's 72 bytes, never `changeme`, never a password on `passwordblocklist`'s list, and never the admin email, its local part or the app name, or a derivative of them, the email and app name each caller seeds handed in beside the password (#550). The auth server's first start and the setup wizard both apply it, so the two cannot disagree on which passwords seed. A leaf of its own, importing only `core/errs` and `core/passwordblocklist`, a standard-library leaf, because in `inputvalidation` it linked `core/i18n`, `core/oauth`, TOML and JWT into the wizard. `core/guard`'s `imports_only_lint_test.go` holds it there through `AssertImportsOnly`, from that package because `go mod tidy` reads the tests of every package the wizard imports, so no test in a core package the wizard imports may import `core/guard`, which `AssertNoGuardInTestsReachedFrom` holds (#500)
- `api/` - The admin API wire contract: request and response DTOs, declarations only, importing no persistence model. The model-to-DTO mapping belongs to the auth server, in `internal/apimapping` (#350). One file per resource, each holding its requests beside its responses (#441)
- `boundedread/` - The one rule for a capped response body: read one byte past the cap and refuse the overrun rather than decode a prefix. Nine callers: the admin console's seven reads from the auth server, `internal/pinnedfetch`, which the generators download through, and the timezones generator's read of the decompressed tarball (#386, #432)
- `buildinfo/` - The build stamp both servers report, `Version`, `BuildDate` and `GitCommit`, which the release builds set with `-ldflags -X` and which read `development` in any other build. It left `core/constants` beside `builtin/` when that package split, because the linker writes these values rather than the two processes agreeing on them (#442)
- `builtin/` - The identifiers both processes must agree on: the `authserver` resource, the seven permissions on it, listed by `AuthServerPermissionIdentifiers()`, which returns a fresh copy on every call, the admin console's client identifier, and its session name in `session_name.go`. No context key and no other session key: each process declares its own, the auth server and the admin console alike their context keys in `internal/reqctx` and their session keys in `internal/sessionkeys`, and no row of `ARCHITECTURE.md`'s table here reads `kernel` any more. It was `core/constants` until #442 moved the build stamp to `buildinfo/` (#351, #385, #433, #440, #442)
- `cmd/` - `ownershipdump`, which regenerates `OWNERSHIP.md`'s table from the reference graph. It reads nothing but the source tree, so unlike `schemadump` it needs no container, and it refuses to invent a justification rather than fill the one cell a human owes (#385)
- `countries/` - Self-maintained ISO 3166-1 reference data: names, alpha-2 and alpha-3 codes, flag emoji and ITU-T E.164 calling codes, generated into `data_generated.go` from the datahub dataset. It replaced `github.com/biter777/countries` and deliberately depends on nothing (#272)
- There is no `enums/` here: the six auth-server-only enumerations it held went to the domains that own them — `AcrLevel`, `PasswordPolicy`, `ThreeStateSetting` and `KeyState` to `authserver/internal/record`, forced there because `internal/data` names them and imports nothing above it, `AuthMethod` to `ceremony` and since to `oidc` (#437), `TokenType` to `issuance` and `SMTPEncryption` to `emaildelivery` — leaving `Gender` as `core/gender`. A package named for a Go construct is what invites the next unrelated one in beside it (#385)
- `errs/` - The one way this tree constructs an error, and what pattern 7 below is about: one stack per error tree, the leftmost origin's, printed under `%+v`
- `gender/` - The three gender values the OIDC `gender` claim is written from, and the bound that says which integers name one. A fourth shared reference vocabulary beside `countries/`, `locales/` and `timezones/`: the auth server validates and stores a gender, the admin console renders and re-renders one, and both name the same three strings (#385)
- `guard/` - The tree-wide guards every module's unit tier runs, and the `Reporter` / `Run` pair they are written against. See **Guard shape** under Testing for what that shape is and what each guard owes. Test support compiled into no binary, holding guards and nothing else: it was `core/testutil` until #442, when `SkipWithoutIPv6Loopback`, the one helper in it that was no guard, left for `hostport/hostporttest`
- There is no renderer here: each application renders its own pages from its own `internal/render`, because the one shared renderer bound admin page data no auth server template could reach and parsed every template with a `FuncMap` of which the auth server calls four entries out of twenty-two (#385)
- `hashutil/` - SHA-256 over a string, and nothing else. It stayed here when password hashing went to `authserver/internal/passwordhash`, because both processes reach it independently: the auth server hashes authorization, verification and reset codes to locate rows, the admin console hashes the nonce it sends, and again to check the ID token's (#360, #427)
- `hostport/` - The one join of a configured host and port into an address: both servers' listeners, the three database connection strings and the SMTP dial go through `Join`, which brackets an IPv6 literal and reads `[::1]` as `::1`, per RFC 4038 section 5.1. A Sprintf'd `host:port` stopped either server at start on an IPv6 listen host, and a plain `net.JoinHostPort` would have broken `[::1]`, the one IPv6 spelling that worked before (#424). `hostporttest.SkipWithoutIPv6Loopback`, beside it, skips a test that listens on or dials an IPv6 literal on a machine with no `::1` (#442)
- `httpmw/` - The request middleware both processes mount: real IP, CSRF, security headers, the request logger, the panic recovery, which answers an empty 500 and writes one ERROR record with the request id and the stack, the one-trailing-slash strip, which rewrites `r.URL.Path` itself, and the cookie reset; and `statuswriter`, the writer the request logger and the HTTP metrics read a response's status through. They replaced chi's middleware package, which linked `net/http/pprof` and `expvar` into both servers (#462). Each application's own middleware - session, JWT, rate limiting - is in its `internal/middleware`
- `i18n/` - The internationalization layer: the embedded message catalogs and the runtime overrides that win over them, the `Locale` middleware early in every request chain, `WithLocale` as the one locale-setting primitive with a non-explicit call deferring to explicit intent already on the context, and the error-code vocabulary in `error_codes.md`. The six template helpers only the admin console renders with, the locale picker's label, the country, phone-country and timezone labels and the two date formatters, are that console's, unexported in its `internal/render`: they read nothing here but `T` and `CatalogTag`, and here they put CLDR's display tables into the auth server. Both servers' `<html lang>` and those CLDR labels read `CatalogTag`, the catalog the page was rendered from, and `LocaleTag`, the first preference asked for, is what an email's body copy is chosen from (#645). `Raw` stays, because it reads the catalog state this package keeps private (#442)
- `inputvalidation/` - Identifier validation and the angle-bracket predicate, the two rules both applications apply, to text an administrator or a registering client supplies. `IdentifierValidator.Validate` matches against a pattern compiled once, and the admin console names it through its own port. It was `core/validators` until #442. `ValidateNoAngleBrackets`, which wraps the predicate in an error only the auth server emits, is in `authserver/internal/accountvalidation` beside the other account validators — email, password, profile, address, phone — and the authorize and token validators are in `authserver/internal/protocolvalidation` (#344, #385, #442)
- `internal/refgraph/` - The reference-graph reader the tree-wide guards in `guard/` and `ownershipdump` in `cmd/` share: the import graph, which resolves against the module directories `sourceroot/` declares, build constraints, the tables `ARCHITECTURE.md` and `OWNERSHIP.md` hold as data, and the symbol census. It left `core/testutil`, now `guard/`, so that `ownershipdump` links neither `testing` nor testify (#431, #442)
- `internal/pinnedfetch/` - The download the reference-data generators share: a GET through an injectable doer, read through `boundedread`, and the SHA-256 check against the digest each generator pins in its source, whose refusal prints the digest received so updating a pin is edit, run, paste, run (#432)
- `issuerlength/` - The one bound on an issuer's length, `Check`: 60 UTF-16 code units, under the issuer column's 64. The auth server's start holds the base URL to it, since the first start seeds the base URL as the issuer, the general settings save every issuer, and the setup wizard the auth server URL it writes, so the three cannot disagree on which base URLs start and save. A leaf importing only `core/errs`, for `adminpassword/`'s reason, held there by `AssertImportsOnly` from `core/guard`'s `imports_only_lint_test.go` (#615)
- `locales/` - The locale identifiers and display names a user picks from. A shared reference vocabulary beside `countries/`, `timezones/` and `gender/`
- `localzone/` - The process's local time zone, resolved from `TZ` by `Install`, which both servers call before their first record: a dependency fixes the local zone during package initialization, before the embedded `time/tzdata` registers, so `TZ` was ignored on a host with no zone database. A name that is no zone, `Local`, or an absolute zone-file path that does not load stops the server with one stderr line and exit 2 (#331)
- `logging/` - The one `slog` handler, installed by both servers at startup, and the field helpers pattern 8 below is written about. Nothing else calls `slog.SetDefault`, `New`, `Default` or `With`, and a guard says so (#320). `RequestTargetForLog` is here beside `FieldForLog`, the one rendering of a request target for a record: the path escaped, every query value redacted but those an allowlist names, and the whole bounded. The request logger and the CSRF refusal in `httpmw/` and the auth server's API debug middleware call it (#159, #442)
- `metrics/` - The Prometheus metrics both servers expose, written here with no third-party dependency: counters, gauges and fixed-bucket histograms in a `Registry`, the text exposition format 0.0.4 its `Handler` writes under `Content-Type: text/plain; version=0.0.4; charset=utf-8`, `HTTPRequests`, the middleware recording requests by route, method and status, and `RegisterBuildInfo` and `RegisterRuntime`. Every label is declared with its closed value set (pattern 10 below), and `guard.AssertMetricsCatalog` holds each server's registry to the catalog table in the docs (#400)
- `oauth/` - The OAuth/OIDC values both processes share: token, JWT and JWKS types, the PKCE challenge helper, and the error response of RFC 6749 section 5.2. `ErrorDetail` is a comparable struct of code, description, HTTP status and WWW-Authenticate challenge, read through `Code()`, `Description()`, `HTTPStatus()` and `WWWAuthenticate()`, whose `Is` compares with `==`; `ConformErrorDescription` replaces every character RFC 6749 Appendix A.8 forbids in an `error_description` and bounds the result to 512 bytes, because a description interpolates request text and, since #213's deferral, is parked on an auth context every request of that ceremony then carries. Both were `core/customerrors`, the detail a map, until #442. The admin console's client of the protocol — JWKS parser, token client, authorize redirect — is `adminconsole/internal/oauthclient`; `response_type` parsing is the provider's and is in `authserver/internal/protocolvalidation` (#385). `IsWellFormedSpaceDelimited` and `SplitSpaceDelimited`, the one grammar and the one splitter of the five space-delimited request parameters (exactly one space between values, none at either end, and no other separator), are here because `core/i18n` reads `ui_locales` with them in a middleware both processes mount (#244)
- `passwordblocklist/` - The two whole-password checks the `nist` password policy is written to apply: `IsCommon`, whether a password, lowercased, is an entry of the built-in list of commonly used passwords, compared whole and never as a substring, and `IsTooClose`, whether it is one of the words it is given (the account's email, its local part, its username, the app name) or that word repeated, each read lowercased as is and with digits and symbols trimmed from both ends. The list is `data_generated.go`: the 16,043 entries of 15 characters or more and at most 72 bytes of the NCSC's top 100,000, Pwdb's top 1,000,000 and xato's top 1,000,000, their hashcat `$HEX[]` lines read as the passwords they encode, lowercased and de-duplicated, written by `generate/` from the three lists at a pinned SecLists commit, each checked against the SHA-256 it pins, its header naming each source and licence. A leaf importing the standard library alone, for `adminpassword/`'s reason, held there by `AssertImportsOnly` from `core/guard`'s `imports_only_lint_test.go` (#550)
- `passwordrules/` - The one wording of the stored password policy's rules, `Describe`: the sentence a page that sets a password shows under the field, built from `api.PasswordRulesResponse`, the rules as data the anonymous public settings carry, the length, the kinds of character required and whether common passwords and the account's words are refused. The auth server's registration, activation and reset forms and the admin console's change-password, new user and Authentication tab pages all call it, so the two applications cannot word the same rules differently; the auth server maps a policy to its rules in `internal/apimapping`, from what its validator applies (#550)
- `phonecountries/` - The phone country list a user picks a phone number's country from: one entry per country and E.164 calling code, built once from `countries/`, sorted by country name, with `ByUniqueID` its lookup. An entry's id, `<alpha3>_<index>`, is stored on the user row, so the order of a country's codes is stored data (#432). It left core for `authserver/internal/phonecountries` in #344, when no console code read it, and came back in #563 so the admin console's two phone pages can build their list from it instead of asking the admin API, which refuses a token carrying `authserver:manage-account` alone
- `requestid/` - The request id both servers carry: `Middleware` adopts an incoming `X-Request-Id` verbatim or mints `<hostname>/<10 base62>-<counter>`, exactly as chi's middleware did, and writes no response header; `FromContext` is how the log handler, the audit log, the error pages and the 500's `error_description` read it, and `NewContext` how a test plants one (#462)
- `routing/` - The router both servers register their routes on, built on `net/http.ServeMux`: `Use`, `With`, `Route`, the method verbs, `NotFound` and `Walk`, as chi's route tables used them. It decides once what every route follows: a group's middleware meets an unmatched path under it first, then the 404 of the router the group was created from, or a 405 with an empty body and an `Allow` naming every registered method, HEAD only where registered; a non-canonical path is a 404, never ServeMux's redirect; a route is named in chi's spelling, read by `RouteName` once reached and by `RouteFor` before routing, and two methods on one path may name its parameters differently, as the admin API's user-sessions routes do. `metrics.HTTPRequests` and `httpmw.BodyLimit` read routes from it. It replaced chi, which no module requires any more (#462)
- `securerandom/` - Random strings over `crypto/rand`, drawn by rejection sampling so an alphabet whose length does not divide 256 introduces no modulo bias: `String(n)` over the alphabet ids, secrets and security tokens are minted over, `StringFromAlphabet(n, alphabet)` over one the caller names, at most 256 bytes. Neither returns an error, because a CSPRNG failure ends the process (#211). It was `core/stringutil` until #442, which deleted the auth server's `randomstring` wrapper beside it
- `sessionstore/` - The server-side session store and its codec, which is where an `AuthContext` lives; the cookie carries the key and nothing else (#266). The one exception is `SealCookieValues`, `OpenCookieValues` and `ValuesCookie`: a short-lived state a browser carries itself, sealed under a key of its own so it never opens as a session cookie, which the admin console's sign-in handshake rides in from the authorize redirect to the callback, so an anonymous request to `/admin` or `/account` writes no row (#620). `Options` is the six cookie attributes this repository sets rather than an `http.Cookie`, so a MaxAge below zero is the one way to say "delete this" and there is no `Expires` beside it to disagree (#269). It holds the one session-key rule both configurations apply, `ParseKeys`, whose refusals name the variable each value was configured under (#434). `ConditionalStore` writes a session on condition nothing wrote it since a fresh read, which the auth server's store is built with and the admin console's is not, so the console's browser session stays last-writer-wins (#579). `GetFresh` loads the session as stored now, past the request's memo and writing nothing, which the admin console's refresh re-reads through under its per-session lock (#621)
- `sourceroot/` - The one declaration of the four module directories, `ModuleDirs`, and the ascent that finds the source root from them, `FindSourceRoot`, which the tree-wide guards (through `guard.SourceRoot`), `ownershipdump` and the auth server's `schemadump` root their walks with. It left `core/internal/refgraph` because Go's internal rule kept `schemadump` from reading it there, which is how the same four directories came to be declared twice (#480)
- `timezones/` - The IANA zone table a user's zone is picked from, one row per country and zone, generated from the tzdata release and SHA-256 its generator pins. Nothing loads it at startup; a test checks every zone loads (#49, #432)

### Auth Server (`src/authserver/`)
- `internal/handlers/` - HTTP handlers (auth flows, token, userinfo, DCR). A ceremony handler keeps only the HTTP side of its step: the route boundary (`CeremonyBoundary`, `auth_ceremony.go`), its `internal/authflow` operation called with a per-request browser adapter (`browserSession`, `browser_session.go`), and the response its result names, written through the client-error responder (`ClientErrorResponder`) or a step redirect. The device cookie is read and written here (`device_cookie.go`). `doubled_services.go` declares, whole, the six services the route table hands straight to the operations, which no handler takes, so mockery generates the doubles the handler tests build every operation from (#580)
- `internal/handlers/accounthandlers/` - Pages reached without a session: self-registration and its activation link, forgot password and its reset link (#435)
- `internal/handlers/apihandlers/` - Admin API handlers
- `internal/{ceremony,issuance,signingkeys}/` - Provider-side issuance: codes, tokens, key rotation, ceremony context
- `internal/authflow/` - The ceremony steps' operations, one per step: its loads, the decision it applies, its database and browser-session writes, and a typed result its handler answers from. It cannot reach HTTP (`import_lint_test.go` refuses `net/http`, `core/routing`, `core/httpmw`, `core/requestid`, `internal/handlers`, `internal/middleware` and `internal/reqctx`): what the request carries arrives as plain values, every browser-session write goes through a port the handler satisfies with a per-request adapter (`handlers.browserSession`), and the handler writes the response after the operation returns. Every ceremony route has one: `/auth/authorize` (`Authorization` on the GET, which creates the ceremony and routes it with `decideAuthorizeRoute`, after `ResolveParked` swaps in a parked request; `AuthorizationParking` on the POST), `/auth/level1` (`SelectLevel1Method`), `/auth/level1completed` (`Level1Completion`), `/auth/level2` (`Level2Selection`), `/auth/pwd` (`PasswordPrompt` on the GET and beside a refusal, `PasswordSubmission` on the POST), `/auth/otp` (`OTPPrompt` on the GET, `OTPSubmission` on the POST), `/auth/completed` (`Completion`), `/auth/consent` (`ConsentPrompt` on the GET, `ConsentSubmission` on the POST), `/auth/issue` (`Issuance`) and a `prompt=none` request at `/auth/authorize` (`SilentAuthentication`, with `decideSilentAuthentication`, which `Authorization` hands it to). The handlers keep what reads the request and writes the response: `/auth/authorize`'s parameter parse, its settings read and its `ui_locales` swap of the request's localizer among them (#580)
- `internal/{permissions,usercreation,usersession,useragent,emaildelivery,otp,imageupload,uithemes}/` - Application services and leaf helpers: permissions, user creation, sessions, email, OTP, image uploads, themes
- `internal/revocation/` - The five revocation operations, their results, reason constants and audit helpers. No handler package owns revocation orchestration or its transactions any more (#387)
- `internal/recovery/` - The `recover` subcommand's operation, `Run`: for one named, enabled user, a manage grant, a password held to the stored policy and the authenticator's removal, each only as asked, in one transaction with the #106 revocation sweep, the user, the authenticator and the sessions and refresh tokens swept read under the user's row, taken first, and the held grant under the manage permission's, taken after it, where the Admin API's grant saves take that row first and never the user's, so a save and a recovery can deadlock, as they do on MySQL, and `RunInTransaction` reruns the one the engine rolls back (#301), and the audit events after the commit naming the command under `command`. The command in `cmd/goiabada-authserver` parses, refuses a schema other than its head, and prints; the data tier runs `Run` on every engine (#498)
- `internal/reqctx/` - The five request-scoped values (settings, session identifier, bearer token, validated token, and the credential reservation a failures-only rate-limit tier holds), each written by one middleware and read through a typed accessor; services take theirs as parameters, and the context-value guard holds every module file to them with no exemption (#433, #439)
- `internal/otpcredential/` - The stored TOTP credential: establish, remove, verify a stored or a supplied code, and the seed's encryption at rest. A removal also lowers the user's sessions to what a password alone reaches, in the same transaction and one statement (#542). `OTPClaim` is here too: a sign-in's claim to a one-time code stands only while the user still has the authenticator it came from, which `/auth/completed` and `/auth/issue` ask, and the session writes and both issuers ask again under the user's row lock (`Recheck`, #542). `internal/otp` underneath stays the stateless primitive (#387)
- `internal/userclaims/` - The one stored-user-to-OIDC-claims conversion, serving `/userinfo` and issuance from the same mapper, with the two places those two disagree — the base URLs, the auth server's that `picture` is built on and the admin console's that `profile` is (#527), and which include flag filters groups and attributes — as inputs rather than merged away. `updated_at` was a third until it turned out to be a defect: it rides with the `profile` scope at every site now, which is what OIDC Core 5.4 and this repository's own docs site both say it is, where issuance used to emit it for any scope beyond a lone `openid` and, in an access token, for a lone `openid` too, because the audience loop extends the scope slice before the claim block reads it (#387, #422)
- `internal/userconsent/` - The stored consent a user gives a client: `Record` reads the row and creates or rewrites it with the scope the consent screen granted, replacing it whole. The handler parses, decides and answers (#437)
- `internal/authorizerequest/` - The authorization request a POST to `/auth/authorize` parks for the GET it is answered with: `Park` stores it under a one-time handle (only its digest is kept), `Consume` takes it once. The POST touches nothing of the browser's own session, because a cross-site POST arrives without the Lax cookie (#246, #437)
- `internal/afterresponse/` - The work a handler hands off so its response does not wait for it: `Go` runs a job under the request's context detached from its cancellation, so its records keep the request id, and `Wait`, called by the server once the listeners have drained, waits for the jobs in flight. Forgot-password's code store, audit record and mail run here, so every well-formed request answers alike, and so does the self-service email change's notice to the previous address, which never fails the change (#404). At most 64 jobs of each `Class` run at once, recovery, registration and the account notice each against a budget of its own, so the two public forms cannot fill the slot the authenticated notice needs; past that `Go` drops the job with one Warn record on the request's id, never running it inline, and a dropped job is never counted in flight (#485, #394 review)
- `internal/emaillinks/` - The emailed-link round trip for password reset and activation: build the link, mark it followed, redeem it once. Beside `emaildelivery`, which sends it (#387)
- `internal/{encryption,passwordhash,oidc,rsakey,urlmatch,uuid}/` - The authserver-only utilities #360 moved out of `core`: AES and bcrypt, discovery metadata, RSA key generation, redirect-URI and origin predicates, UUIDs (#360); `oidc` also holds the grant type list every grant-type reader consults and the `amr` values (#437); the encrypted id_token_hint's JWE, keyed from a client secret and sharing nothing with the data cipher, left `encryption` for `internal/idtokenhint` (#434)
- `internal/record/` - The persistence records (Client, User, Permission, Group, etc.), one struct per table: no cryptography, no claim construction, and nothing imported but the standard library, `core/builtin` and `core/errs` (#359, #387, #442)
- `internal/data/` - The composition-only `Database` interface, `commondb/`, the four engine adapters, and the generated `Database` mock that every narrow port is tested through (#354, #359, #386)
- `internal/data/datafactory/` - Database composition: engine selection, config mapping, the email-case pre-flight, which the migrator runs under its lock on its own connection (#542), the startup data tasks, which refuse a start whose data key opens none of the stored data (#353, #438, #542)
- `internal/bootstrap/` - The first run: which of the three bootstrap modes applies, and the seed, whose 18 writes commit in one transaction with the bootstrap file published only after it (#424). A seed that loses an empty database to another instance seeding it at once (a unique key, and the database now reads as seeded) carries on as a later start would (#542)
- `internal/server/routes.go` - All route definitions
- `web/template/` - HTML templates
- `tests/integration/` - Integration tests

### Admin Console (`src/adminconsole/`)
- `internal/handlers/` - Admin UI handlers
- `internal/apiclient/` - The admin API client: `AuthServerClient`, its methods behind the one deadlined, bounded executor, and `APIError`. There is no interface over it: each handler declares an unexported port beside the function taking it, and each test fake implements the port of the handler it is passed to, embedding no interface, so a method a handler starts calling that a fake lacks fails to compile rather than panicking at test time. `TestAuthServerClient_TheCharacterizationCoversEveryMethod` holds every exported method to a wire characterization row. One file per resource the methods call, with no `_client.go` suffix, and a test beside the file of the method it tests; `layout_test.go` holds both (#386, #441)
- `internal/publicsettings/` - The auth server's public settings every page renders with: `Client` reads `/api/public/settings` under its own timeout and bound, and `Cache` serves the answer for a TTL, every request arriving during a fetch sharing that one fetch with no lock held across it, and an `Invalidate` never undone by a fetch that started before it. It was `internal/cache`, and the client `apiclient.SettingsClient`, until #441
- `internal/reqctx/` - The two request-scoped values, the signed-in administrator's token set and the auth server's public settings, each written by one middleware and read through a typed accessor over an unexported key; an absent value is `ErrNoJwtInfo` or `ErrNoSettings` rather than a panic. The twin of the auth server's, and the context-value guard holds the module to it with no exemption (#440, #462)
- `internal/sessionbackend/` - The HTTP backend of `core/sessionstore` over the auth server's browser-session endpoint, the twin of the auth server's package of the same name, and its `TokenSource` port, which `oauthclient.SessionTokenSource` implements as a cache over the token client's client-credentials grant. It left `apiclient` in #441
- `internal/sessionkeys/` - The two keys of the console's browser session, the token set and its expiry, and the six of its sealed sign-in handshake. Stored data: a live session carries the two spellings, so renaming one signs every administrator out at deploy, and renaming one of the six fails the sign-ins in flight at the deploy. The six stay declared because they key the sealed map and the callback deletes the stale copies a session written before #620 can hold. It was `internal/constants` until the context keys left for `reqctx` (#440, #620)
- `web/template/` - Admin UI templates

## Database Pattern

Single `Database` interface (`src/authserver/internal/data/database.go`) with per-DB implementations:
- All methods accept `ctx context.Context` then `tx *sql.Tx` (nil = no transaction); the context reaches `BeginTx`, `QueryContext` and `ExecContext` (#386)
- Uses `sqlbuilder` for query building with DB-specific flavors
- Nothing above the data layer takes the whole interface: each handler, middleware and service declares an unexported port beside the function that takes it, naming only what that file calls (#386)
- Schema in `src/authserver/internal/data/sqlitedb/schema.golden` (generated; see **Schema golden files** below)
- Migrations are applied by Goiabada's own runner in `src/authserver/internal/data/migrator/`, built per engine by each `NewMigrator()`

**Supported**: SQLite, MySQL, PostgreSQL, SQL Server

## OAuth2 Flows Supported

For full documentation, see `site/` (Astro-based docs site).

### Authorization Code (with PKCE)
Primary flow for web/mobile apps. User authenticates via browser, receives code, exchanges for tokens.
- Endpoint: `GET /auth/authorize` → `POST /auth/token` (grant_type=authorization_code)
- PKCE: always required for a public client; otherwise configurable globally (`Settings.PKCERequired`) or per-client (`Client.PKCERequired`)
- Supports `response_type=code` with optional `code_challenge` + `code_challenge_method`
- Implementation: `handler_authorize.go`, `authflow/authorization.go`, `issuance/code_issuer.go`; redeemed by `handler_token_authorization_code.go`, `protocolvalidation/token_grant_authorization_code.go`, `issuance/grant_authorization_code.go`

### Client Credentials
Server-to-server auth. No user context, client authenticates directly for access token.
- Endpoint: `POST /auth/token` (grant_type=client_credentials)
- Requires: `Client.ClientCredentialsEnabled = true`
- Auth methods: `client_secret_basic` (Authorization header) or `client_secret_post` (form body)
- Implementation: `handler_token_client_credentials.go`, `protocolvalidation/token_grant_client_credentials.go`, `issuance/grant_client_credentials.go`

### Refresh Token
Exchange refresh token for new access/refresh tokens. Works with auth code and ROPC flows.
- Endpoint: `POST /auth/token` (grant_type=refresh_token)
- Offline tokens: Configurable idle timeout and max lifetime per client/globally
- Revocation: Old refresh token revoked on use, new one issued
- Implementation: `handler_token_refresh_token.go`, `protocolvalidation/token_grant_refresh_token.go`, `issuance/grant_refresh_token.go`

### Implicit Flow (Deprecated)
Legacy flow returning tokens directly in redirect URI fragment. **Deprecated in OAuth 2.1.**
- Endpoint: `GET /auth/authorize` with `response_type=token|id_token|id_token token`
- Disabled by default. Enable via `Settings.ImplicitFlowEnabled` or `Client.ImplicitGrantEnabled`
- Security risk: Tokens exposed in browser history/Referer headers
- Implementation: `handler_auth_issue.go`, `authflow/issuance.go`, `issuance/grant_implicit.go`, `protocolvalidation/authorize_validator.go`

### ROPC - Resource Owner Password Credentials (Deprecated)
Direct username/password exchange for tokens. **Deprecated in OAuth 2.1** due to credential exposure.
- Endpoint: `POST /auth/token` (grant_type=password, username, password)
- Disabled by default. Enable via `Settings.ResourceOwnerPasswordCredentialsEnabled` or per-client
- Rate limited. Blocks users with 2FA enabled. Logs `audit.EventROPCAuthFailed` on failure
- Implementation: `handler_token_password.go`, `protocolvalidation/token_grant_password.go`, `issuance/grant_password.go`

### Dynamic Client Registration (RFC 7591)
Programmatic client registration for MCP clients, native apps, etc.
- Endpoint: `POST /connect/register`
- Disabled by default. Enable via `Settings.DynamicClientRegistrationEnabled`
- Creates public or confidential clients based on `token_endpoint_auth_method`
- Rate limited. Returns client_id and client_secret (if confidential)
- Implementation: `handler_dynamic_client_registration.go`

## Authentication Flow (Authorization Code)

The auth code flow uses a state machine tracked in `AuthContext` (stored in the server-side session store, keyed by a cookie (#266)). A browser holds up to five ceremonies side by side, each its own `AuthContext`, under the session key `AuthContexts` (`ceremony.Store`, `ceremony.MaxHeldCeremonies`), so two tabs signing in to two applications both finish, and a link or redirect from another site starts its own ceremony and ends none. `/auth/authorize` adds its ceremony beside the others, a step's save makes its ceremony the most recently written, and an add beyond five pushes out the least recently written. A rotation of the browser session's identifier, at an accepted password or code and at `/auth/completed`'s rotations, is for the user the ceremony authenticated and removes every held ceremony carrying another user (`heldRotation`), so a ceremony someone abandoned after their password does not ride into the next user's session, where whoever used the browser then could finish it as them. The key the one ceremony was held under before, `AuthContext`, is never read, and the store's first write to a session removes it (#246).

### ACR Levels (Authentication Context Class Reference)
Defined in `src/authserver/internal/record/acr_level.go`:
- **`urn:goiabada:level1`** - Password only (single factor)
- **`urn:goiabada:level2_optional`** - Password + OTP if user has OTP enabled (skip if not)
- **`urn:goiabada:level2_mandatory`** - Password + OTP required (user must enroll if not already)

Target ACR determined by: the first level in the `acr_values` param of the authorize request, raised to `Client.DefaultAcrLevel`, which is a floor `acr_values` never lowers (#240); with no `acr_values`, the client's level

### Auth States (State Machine)
The values below are the string constants declared in `src/authserver/internal/ceremony/auth_context.go`, and
`AssertAgentDocs` in `core/guard/agentdocs.go` holds this section's roster to them: a state
declared there with no row here, or a row here naming no constant, fails every module's unit tier.
There is no single order: a ceremony's path depends on the target ACR, the session, and `prompt`.

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
and clears nothing; the route table builds one of each. Every step but `/auth/authorize` begins
with the boundary's `beginStep`, which reads the request's settings before anything else (a request
without them is the 500 page carrying `reqctx.ErrNoSettings`, as it is at `/auth/authorize`, which
reads them first too), then loads the ceremony and gates its state as below. It first reads, in
the boundary's `loadAuthContext`, the ceremony the request names, through the one rule
`ceremony.RequestedId`: the `ceremony` query parameter on a GET, built into every redirect between
steps by `stepRedirect`, and the `ceremonyId` form field on a POST. A browser holding no ceremony at
all goes to the account page. An id missing, or naming a ceremony the browser does not hold while
it holds others, gets the "no longer active" page, 400, and the `auth_ceremony_mismatch` audit
event, whose details describe the ceremony the browser most recently wrote.
Each route then gates on the state it finds through `requireAuthState`, which answers 400 when it is
not one it accepts (#246, #437):

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
| `/auth/level1completed` | `handler_auth_level1.go`, `authflow/level1_completion.go` | Delivers a deferred authorization error if one is parked (see below), else decides if level2 needed based on ACR and session state |
| `/auth/level2` | `handler_auth_level2.go`, `authflow/level2_selection.go` | Selects level2 auth method. If `level2_optional` + no OTP → skip to completed |
| `/auth/otp` | `handler_auth_otp.go`, `authflow/otp.go` | OTP verification (or enrollment if user doesn't have OTP yet). Rotates the browser session's identifier, records level 2 on the ceremony |
| `/auth/completed` | `handler_auth_completed.go`, `authflow/completion.go` | Final auth check (a user who is not the id_token_hint's refused, a disabled user refused, a moved-on generation restarted, all before any session is bound), session bump/create, scope filtering, consent check. The plan is one of three modes (`authflow/completion_decide.go`): reuse, which rotates the browser session's identifier before the bind when it raises the session; create, which confirms the ceremony, starts the session (`StartNewUserSession`, which writes nothing to the browser), then rotates and binds it to the browser session (`RegenerateSessionAndBind`), deletes it when that fails, and writes the device cookie only after; and restart |
| `/auth/consent` | `handler_consent.go`, `authflow/consent.go` | User consent screen (if required), and the submission weighed against the permissions the user holds now, recorded through `userconsent` |
| `/auth/issue` | `handler_auth_issue.go`, `authflow/issuance.go` | Final re-checks (redirect URI, client, flow, hint, session, user, scope), then issues the authorization code or the implicit tokens, redirects to client |

### AuthContext field rule
Every field on `AuthContext` is either request or attempt. The request is what `/auth/authorize`
accepted, including `RequestedScope`, the scope as asked for before any hop narrows `Scope` to what a
user holds; the attempt is everything an authentication writes. A restart keeps the request and
discards the attempt: `AuthContext.Restart()` zeroes every attempt field, puts `Scope` back from
`RequestedScope` and sets `requires_level_1`, so the second pass earns its own `amr`, scope and
consent (#140, #436). There are two restart routes: `authflow.Completion` when no session is
reusable and level 1 was never completed, or when the user's generation has moved on, or when the
ceremony names `otp` from an authenticator the user no longer has (#542), decided before
it binds a session (#522), and `authflow.Issuance` at `/auth/issue` when the
bound session is gone, expired or foreign, or the user's generation has moved on, or the ceremony names `otp` from an authenticator the user no longer has, and the request is not `prompt=none`. The split is held by
`TestAuthContextFields_EveryFieldIsClassifiedOnce` in `ceremony`, which fails on a field in neither
list. Request fields are written only in `authflow.Authorization.Run`, which
`TestRequestFields_WrittenOnlyAtAuthorize` in `ceremony` holds with `go/types`. A bind that finds a
newer authentication already on the session is not a restart: it writes nothing
(`ErrStaleAuthentication`, #538) and `/auth/completed` answers it with the "no longer active"
page, saving no auth context: a newer sign-in's authentication has reached the session since this
ceremony adopted it. A restart would make it verify the password itself, so its bind would
replace the session's authentication, asking an SSO ceremony for a password nobody requested. A
reuse arm that rotates the browser session's identifier asks the same rule first
(`AuthenticationIsStale`) and answers the same page without rotating. Beyond that rule, every write
a step after `/auth/authorize` makes to the browser session lands only while the session still
holds that step's ceremony (#579): the ceremony store's save, clear and rotation read the session
afresh, refuse when it does not hold the ceremony (ended by another request of it, or pushed out
by newer ones) or is gone (signed out, expired, or rotated away by another request of the browser),
apply only their own change to what they read, touching no other ceremony but, at a rotation,
those carrying another user, and write on condition the stored row is unchanged, trying again at
most three times in all when another write lands between. A step so refused writes nothing and answers the "no longer active" page
(`ceremony.ErrCeremonyReplaced`), so the ceremonies the browser holds carry on. The create arm of
`/auth/completed` asks first (`ConfirmCeremony`), before it ends a foreign session or commits a new
one, and its rotation carries the same condition and every held ceremony. `/auth/authorize`'s add
is made the same way, on a fresh read and on condition, so a step's write landing meanwhile is
kept, and when the session it loaded is gone it starts a new one holding its ceremony alone. A
request `/auth/authorize` answers at once with an error stores nothing and removes nothing. Logout
still deletes the session whole, every ceremony with it; two requests of one ceremony stay
last-writer-wins between themselves, so a double-submitted consent form works. The
session-identifier middleware and the emailed-link marker write only their own key the same way, and
the marker's clear removes only the marker of the continuation that consumed it, so a flow finishing
after its marker expired leaves a newer link's in place.

### Deferred error redirects (#213)
`/auth/authorize` never redirects an unauthenticated browser to a client's `redirect_uri` on a failed
request, per RFC 9700 4.11.2. A validation failure is answered at once when the request is silent
(`prompt=none`, read from the raw parameter), when the browser holds a valid session and did not ask
for `prompt=login`, or when no redirect would be emitted anyway (the responder's `RedirectWillBeEmitted` false).
`authflow.Authorization` decides which (`decideAuthorizeRoute`).
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
`authflow/level1_completion.go:Level1Completion.Run`, answered by `handler_auth_level1.go:HandleAuthLevel1CompletedGet`:
- If a deferred error is parked → answer the client and stop (see above)
- If the ceremony verified the password itself (`Level1AuthCompleted`: `prompt=login`, an `id_token_hint` naming someone else, a restart) → the session counts for nothing, and the step-up is decided as with no session: target above level 1 → redirect to level2. See **Re-authentication over a session** below (#537)
- Otherwise the session is reused (the `level1_existing_session` SSO shortcut), and:
- If session ACR is `level1` and target is `level2_*` → redirect to level2
- If session ACR is `level2_optional` and target is `level2_mandatory` → redirect to level2
- If the target is `level2_mandatory` and the user has no authenticator now → redirect to level2, where they set one up. A removal lowers the user's sessions below level 3 (#542), and migration 000062 ended the sessions stored before that, so no write leaves such a session now; the check is kept as a second line. Checked apart from the generation, because a `level2_optional` ceremony answers a moved generation for such a user by skipping the code and promoting it
- If the session's `OtpConfigGeneration` differs from the user's → re-auth level2 (user changed OTP settings). This block writes nothing: the obligation is discharged at `/auth/completed`
- Otherwise → auth completed

### Key Logic in Level2
`authflow/level2_selection.go:Level2Selection.Run`, its arm decided by `decideLevel2Arm`:
- If `level2_optional` + `user.OTPEnabled` → `/auth/otp`, the OTP form
- If `level2_optional` + no OTP → skip to auth completed
- If `level2_mandatory` → `/auth/otp`, the OTP form (user enrolls if needed)

### Session Reuse (SSO)
When user has valid session (`UserSession` in DB + session cookie):
- Session validated via `userSessionManager.HasValidUserSession()` (checks idle timeout, max lifetime, max_age param)
- If valid → uses existing `AcrLevel` and `AuthMethods` from session
- May still need level2 re-auth if target ACR higher than session ACR
- Reuse never lowers a session: `BumpUserSession` only raises its ACR and only adds methods (#537)
- Every whole-row session write takes the session's row first (`AcquireUserSessionRow`) and reads it after, in one transaction: `BumpUserSession`, and `BindUserSession`, which is `/auth/completed`'s reuse arm and also writes a replacing authentication and the auth time there rather than in a second write. Read without the lock, a concurrent removal's lowering was written back over (#542). The token endpoint and `prompt=none` bump with no methods and no level. A bind whose sign-in is older than the session's current `AuthTime`, or whose ceremony adopted the session and the row holds neither the `AuthTime` it adopted (`AdoptedAuthTime`, the SSO case, which enters no credential of its own) nor the ceremony's own credential instant (its own earlier bind, which a reload after a later failure binds again), compared at the column's microsecond, writes nothing and returns `ErrStaleAuthentication` (#538): a newer sign-in's level, methods and auth_time are not overwritten by an older ceremony that resumed after it, and `/auth/completed` answers that ceremony with the "no longer active" page, since a newer authentication already describes the session

## SSO and ACR/AMR Details

### AMR (Authentication Methods Reference)
Two methods tracked (`oidc/auth_method.go`): `pwd` (password), `otp` (time-based OTP).
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
├── AuthTime (when auth occurred: the last credential, a code's time after a step-up)
├── PasswordAuthTime (when the password was last entered; a removal lowers AuthTime to it)
├── OtpConfigGeneration (snapshot of users.otp_config_generation)
└── UserId
```

### Session Validity (`record/user_session.go`, `IsValid`)
Valid if ALL true:
1. `now <= LastAccessed + IdleTimeoutSeconds`
2. `now <= Started + MaxLifetimeSeconds`
3. If `max_age` param: `now <= AuthTime + max_age` (`Started` when `AuthTime` is zero)

### ACR Step-Up Logic (`ceremony/step_up.go`)
One rule, `StepUpOwed`, read by `authflow.Level1Completion` and `authflow.SilentAuthentication`. Uses `record.AcrLevel.IsHigherThan()` for comparison (priority: level1=1, level2_optional=2, level2_mandatory=3).

**With valid session:**
- Target ACR higher than session ACR → redirect to level2 (step-up)
- Target `level2_mandatory` and the user has no authenticator → redirect to level2 to set one up (`StepUpAuthenticatorMissing`; `prompt=none` answers "Additional authentication setup required")
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
   `StepUpOwed`, so a level 3 target asks for the code (or enrolment), and a level 2 target asks for
   it when the user has one, whatever the session already gave. Keycloak does the same ("the LoA from
   previous authentications are not considered").
2. **Replaces the session's authentication** on `/auth/completed`'s reuse arm
   (`reuseSessionPlan.replaceAuthentication`): the session takes the target level, this ceremony's
   methods, its credential's instant and its password's, as the create arm would stamp a new session. That can lower
   the session (`prompt=login` at a level 1 client over a level 3 session leaves it at level 1, `pwd`),
   and the next level 3 request then steps up. The session row is kept, not replaced, so other clients'
   session-bound refresh tokens keep working; their tokens carry the `acr`/`amr` of their own codes.

Do not "fix" this back. Until #537 the session's code counted: the token said level 3 with `amr`
`["pwd"]` and a fresh `auth_time`, and `BumpUserSession` replaced the session's `pwd otp` with `pwd`
while keeping level 3, so every later SSO token contradicted itself (#239 finding F4). Merging the
methods back instead (`pwd otp` beside the fresh `auth_time`) claims a code that was never entered at
that time, which PR #238 decision 9 rejected. `max_age` already worked this way: a session outside it
is not valid, so the ceremony takes the create arm.

### OTP config generation
`users.otp_config_generation` is a per-user counter, advanced by one at every site that establishes
or removes an authenticator (`otpcredential.Establish` and `otpcredential.Remove`), inside the same
transaction as the write that changed it. `user_sessions.otp_config_generation` records the value
that session last satisfied, so a session owes a level 2 re-prompt whenever the two differ. Being per user means one
statement covers every session of that user.

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
checked against the authenticator it came from (`otpcredential.OTPClaim`): `AuthContext.OtpClaimGeneration`
is the session's snapshot when it adopted the session, and the generation the code was checked against
or enrolled at when it entered one, and the claim stands only while the user's `otp_config_generation`
is still that and the user has an authenticator. A removal, and a removal followed by a new enrolment,
both move it. `/auth/completed` and `/auth/issue` restart a ceremony whose claim no longer stands,
rather than merging `otp` back into the session or issuing it in a code; `prompt=none` there answers
`login_required`. The session writes (`BindUserSession`, `StartNewUserSession`) and both issuers ask
again first in their transactions, under the user's row lock (`OTPClaim.Recheck`), which a removal
takes first, so a removal landing after the handler's check either waits for the write and then
lowers it, or is seen. Tokens already issued, and the refresh tokens that renew them, keep their
claims: ending the user's sessions revokes those (#542 decision 1).

Both readers, `authflow.Level1Completion` and `authflow.SilentAuthentication`, only compare and write nothing,
so an abandoned ceremony spends no re-prompt. The snapshot is captured onto `AuthContext` at
`authflow.PasswordSubmission` and on every arm of `authflow.Level2Selection`, and promoted once, at
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
- Session ACR >= target ACR → SSO succeeds (keeps higher ACR in token), unless the target is `level2_mandatory` and the user has no authenticator now, who sets one up
- The user's authenticator removed → the session is already lowered to `level2_optional` and `pwd`, its `auth_time` the password's, and every later token says so (#542)
- Session ACR < target ACR → step-up required (prompt for OTP)
- Session `OtpConfigGeneration` != user's + target requires level2 → re-prompt OTP

**Re-authentication (`prompt=login` over the user's own valid session, #537):**
- Exactly the fresh login table above, whatever the session held: the same prompts, ACR and AMR
- The session then holds this sign-in's ACR, AMR and auth time, lower than before if the target was

## Configuration

All via environment variables with `GOIABADA_` prefix. Key ones:
- `GOIABADA_DB_TYPE` - sqlite/mysql/postgres/mssql
- `GOIABADA_AUTHSERVER_BASEURL` - Public URL
- `GOIABADA_ADMIN_EMAIL` / `GOIABADA_ADMIN_PASSWORD` - Initial admin

See `src/authserver/internal/config/config.go` and `src/adminconsole/internal/config/config.go` for all options; each binary loads only its own.
Each `main` loads it once, through its own `config.Load(fs, args)`, refusing a malformed numeric or boolean variable on one stderr line with exit 2, and hands the result to `server.NewServer`; the route table gives each handler the values it uses (the base URL it redirects to, the auth server's) when it builds it. Neither binary keeps a configuration global, and nothing reads one at request time (#434, #441).

## Testing

Three test types:

1. **Unit Tests** - Throughout codebase alongside source files (`*_test.go`)
   - Handler tests: `src/authserver/internal/handlers/*_test.go`
   - Provider tests: `src/authserver/internal/{ceremony,issuance,signingkeys}/*_test.go`
   - Ceremony step operations: `src/authserver/internal/authflow/*_test.go`, its decisions' tables, the completion plan's constructor lint and its import lint; the steps' behaviour is pinned by the handler tests, which build each operation through one builder per handler (`ceremony_handler_builders_test.go`) from the same doubles, those of `handlers/doubled_services.go` among them
   - Core logic tests: `src/core/oauth/*_test.go`, `src/core/inputvalidation/*_test.go`
   - Validator tests: `src/authserver/internal/{protocol,account}validation/*_test.go`

2. **Data Tests** - Database layer tests in `src/authserver/tests/data/`
   - Tests all CRUD operations for each model   

3. **Integration Tests** - Full API tests in `src/authserver/tests/integration/`
   - OAuth2 flows, DCR, Admin API, User management
   - Requires running server

**Best way to run all tests**: `./run-tests.sh` inside the dev container (from `src/authserver/`).

**Test fixtures**: tests draw random values from `authserver/internal/fake`, a test-only package
over `crypto/rand` that replaced a third-party faker in #272 and left `internal/testutil` in #442.
Reach for it rather than adding a dependency the next time a test needs a random string.

**Settings row in the integration tier**: every integration test runs against one server and one
settings row, which the server reads on every request, so a value a test leaves there is what every
later test runs against. A test that changes the row, through the admin API or directly, calls
`restoreSettings(t)` or `changeSettings(t, edit)` from `tests/integration/settings_helpers_test.go`
before its first change; each registers a `t.Cleanup` that writes the whole row back except
`last_cleanup_at`, which the background worker owns. `TestMain` compares the row at the end of the
run with the row at its start and fails the tier naming each changed field, so a test that forgets
fails the run instead of the tests after it (#433).

**Fresh test databases**: every data and integration run starts from an empty database, as CI's
fresh service containers always did. `run-tests.sh` removes the SQLite files, and on mysql,
postgres and mssql it drops `goiabada_data` or `goiabada_integration` through `cmd/droptestdb`,
which refuses every other name, so the server or the data tier recreates and migrates it and the
integration server seeds it. The drop itself is each engine package's `DropDatabase`, the one
spelling `schemadump` and the data tier's fixtures use too (#433).

**Dev stack secrets**: the dev stack's data key and its MySQL, PostgreSQL and SQL Server passwords
come from `src/.devcontainer/.env`, which `src/.devcontainer/generate-env.sh` writes with fresh
values (and fills in when one is missing) and `.gitignore` keeps out of git; Compose hands them to
the databases and the devcontainer. `run-tests.sh` and `schemadump` read them from the environment
and refuse with one line naming a missing one, so outside the devcontainer, or in a container
created before #627, run the script and recreate the stack with its volumes (#501).

**Transaction stub**: a unit test that needs the mock database to answer `RunInTransaction`
uses `datamocks.ExpectRunInTransaction`, hand-written beside the generated mock in
`authserver/internal/data/mocks` and reachable from every caller without a new import, with
`ExpectRunInTransactionThenFail` for a commit the engine refuses and `ExpectRunInTransactionRefused`
for a transaction that never opens. It hands the body the transaction the caller names and refuses a
nil one: every `Database` method takes the transaction it runs under and a call made outside any
transaction passes nil, so a stub handing over nil makes a write inside the transaction
indistinguishable from one moved back outside it, and the test passes either way. That was seven
divergent copies of the same 58 lines, two of them handing over nil, until they were merged into one
here, folded into #387 (PR #422).

**Race detector**: `./run-tests.sh --type modules --race` runs the three module tiers under
`go test -race`, and CI's `Unit / race` job does the same beside the plain unit jobs. The
detector needs cgo, so the dev container ships gcc and pins `CGO_ENABLED=0` for everything
except that leg, which sets it to 1 for itself. Code whose correctness is a locking argument
(`authserver/internal/ratelimit`, whose failures-only limiter holds the in-flight count since #439, the concurrent transactions of #301) is
covered there and nowhere else; the data and integration tiers do not run under it.

**Guard shape**: every tree-wide guard splits in two, and a new one is written the same way. A
*finder* walks the tree and returns findings; a *reporting half* turns them into `Errorf` and turns
a walk that reached nothing into `Fatalf`. The reporting half takes a `guard.Reporter` --
`Helper`, `Errorf`, `Fatalf`, the measured surface of `*testing.T`, and an interface rather than a
`testing.TB` parameter because `testing.TB` cannot be implemented outside the testing package. The
exported `Assert*` keeps its `*testing.T` and delegates, so no caller moves. Both halves are then
driven from a rule test: the finder directly, the reporting half through `guard.Run`, which
runs it on its own goroutine so a recorded `Fatalf` ends it in `runtime.Goexit` the way the real one
does. Every guard follows this: those in `core/guard`, the newest
`AssertNoLiteralStackSecrets`, which refuses a data key or database password supplied by literal in
any runnable file -- workflows, Compose and other YAML, devcontainer and editor configurations,
Dockerfiles, Makefiles, env files (`.env` and `.env.*` among them, unless git tracks no copy of
it and the repository's `.gitignore` files, its own directory's or a parent's, read as git reads
them, keep it out of the repository), shell scripts, Go mains and Markdown code blocks -- and the
published sample key and passwords anywhere outside the refusal and its tests (#501), and before it
`AssertNoStaleDeferredBodyCloses`, which refuses a deferred func-literal close of a response
body reading a variable the same function reassigns after the defer is registered, in a later
statement, a nested closure or the next iteration of a loop, so only the last response is closed
(#591), and before it
`AssertNoGuardInTestsReachedFrom`, which refuses a test importing `core/guard`, directly or
through first-party production code, in any package a module reaches, called over the setup
wizard because `go mod tidy` reads those tests and would put TOML in its `go.sum` (#500),
and before it
`AssertImportsOnly`, which holds one package's production files to importing the standard library
and an allowlist its caller names, which #387 wrote as `record`'s own lint, holding that package
to `core/builtin` and `core/errs`, before #500 moved it here when `core/adminpassword` became the
second package held to one, to `core/errs` alone, so the setup wizard links nothing more to reach
the admin password rule, and before it
`AssertNoParentImport`, which holds each child handler package a caller names to naming no import
of its parent, which the auth server calls over `apihandlers` and `accounthandlers` and the admin
console over its six, and which #387 wrote as that server's own lint before #440 moved it here for
both applications, and before it
`AssertContextValuesThroughAccessors`, which refuses a `context.WithValue` or a context `Value`
read in a production file outside the module's accessor package, resolved with `go/types`, and
which each application calls with its own `internal/reqctx` and no exemption, the admin
console's last, `internal/handlertest`'s write of chi's route context, gone once it set path
values with `r.SetPathValue` (#433, #440, #462), and
`AssertNoAgreementPointers`, which
refuses a comment pointing at an issue's agreement or a probe file instead of stating the fact
with its issue number (#428), plus `authserver/internal/data`'s
begin-transaction, benign-sentinel, page-offset, id-list-bound, transaction-pass-through and
SQL-context lints, the auth server's API error-code and audit-catalog lints, its discarded-error lint
in `internal/server`, which refuses `_` in the error position of a hash, encryption or
key-generation call (#409) and resolves the data cipher's methods by receiver type with `go/types` (#434),
its admin-route classification lint beside it, which holds every admin write route, and every admin read
whose handler applies a ceiling of the administrative policy, to a row naming the ceilings its handler applies
or why it needs none, in both directions (#402),
and its write-once lint in `internal/ceremony`, which refuses a write to an `AuthContext` request field
outside `authflow.Authorization.Run`, resolved with `go/types` (#436). `AssertImportsOnly` and
`AssertNoParentImport` both parse imports with `go/parser` rather than matching text, because an
alias binds a different name to the same path and one of the 39 production files did exactly that.
`git grep -n 'func assert.*\(r Reporter\|r guard\.Reporter\)' -- '*.go'` lists them; no count is
kept here, because the one that was drifted each time a guard was added (#442). Each owes three
cases: a tree that must fail, a tree that must pass, and the walk that reached nothing. One of
`core/guard`'s, `AssertNotCalledArity`, owes a fourth: a
test that measures testify's matching against testify, because a guard whose premise is a reading
of a dependency stops meaning anything the moment that dependency changes and nothing says so
(#421). Without the last two the first proves nothing, and without
the reporting half under test a defect in the five lines that report disables the guard across
every module with nothing going red -- which is what blinding `AssertNoDeadInterfaces` demonstrated on `8883642d`
(#333).

**gofmt guard**: every module's unit tier runs `TestGoSourcesAreGofmted`, which holds every Go
file under `src/` to gofmt's formatting through `core/guard.AssertGofmted`. The walk is
repository-wide from each tier because `cmd/goiabada-setup`'s own tier calls none of the tree-wide
guards. CI's Lint job checks the same thing per module, where an unformatted file also costs that
module its vet, unparam and golangci-lint run.

**Architecture guard**: `ARCHITECTURE.md` at the repository root records the allowed module edges,
the intended final owner of every top-level `core` package, why each symbol in `core/builtin`
is still there, the temporary exceptions to those rules, the third-party modules the admin
console must not compile, and the packages no shipped binary may link. Its five tables are
data, not prose: `AssertArchitecture` in `core/guard/architecture.go` parses them and checks four
against the real import graph and the built-in identifiers table against every production reference
to `core/builtin`; all three module unit tiers call it. The check runs in both directions,
which is what makes the document a burn-down list rather than a wish — an edge the tables do not
allow is a failure, and so is an exception left standing for an edge that no longer exists, so the
issue that removes an edge has to remove its row with it (#332). A new top-level `core` package
fails the tier until the table says where it belongs, and so does a new symbol in `core/builtin`,
whose row has to name the strongest of `kernel`, `both-apps`, `moving` and `contract` that the
reference graph backs (#351). A sixth table lives in `src/core/OWNERSHIP.md`, one row per exported
symbol any `core` package declares: `core/guard.AssertSymbolOwnership` reads it from the same
three tiers, four justifications are computed from the reference graph and three are asserted with
a note the guard requires (#385). Rule 9 walks the production closure of the three shipped mains,
the auth server, the admin console and the setup wizard, and refuses `testing` and everything under
it, `net/http/httptest` and every testify package, so a production import of a test helper or mock
fails the unit tier rather than reaching a release, and `net/http/pprof` and `expvar`, which register
the process's profiles and variables on Go's default mux the moment they are linked (#462); the three mains are `shippedMains` in
`architecture.go`, and the guard fails when one is not found (#331). It reads each main with the
`production` tag set because all three release builds set it, the setup wizard's since #463, and
`TestReleaseBuilds_TheRealReleaseBuildsSetProduction` in core's tier holds them to it: every
`go build` in the servers' cross-compile script, the two server Dockerfiles and the wizard's
cross-compile script sets `production`, the mains they build are exactly `shippedMains`, and both
scripts' `build_platform` calls equal `releaseTargets` as a set (#463). Beside it,
`TestReleaseBuilds_TheRealStampsNameVariables` holds every `-ldflags -X` target in the same four
files, the servers' script's `$LDFLAGS` read from its one assignment, to naming a package-level string
variable a production build declares, `main.` resolved against the main its `go build` compiles: the
linker ignores an `-X` that names nothing, so a path a move leaves behind would build with exit 0 and
ship binaries reporting `development` (#442).

**Dead-interface guard**: the auth server and admin console unit tiers each run
`TestHandlers_NoDeadInterfaces` over their own `internal/handlers` package, holding every interface
it declares to having at least one reference somewhere in that module, production or test, through
`core/guard.AssertNoDeadInterfaces`; the core and setup tiers never execute it, because those two
handler packages are the only call sites. The walk is recursive, so the auth server's has always
covered `apihandlers` and `accounthandlers` and the ports #387 gave them, and its call names
`internal/{revocation,emaillinks,otpcredential,userclaims,userconsent,authorizerequest,bootstrap,authflow,recovery}` beside it, because a package that
declares a port nobody reaches is the same defect wherever it sits (#387, #437, #580, #498). Liveness is `go/types` object identity and not a matching
spelling — a shadowed name and a same-named type in another package each count as nothing, which is
how the census behind #333 first read `TCPConnectionTester` as live — and structural satisfaction
does not count at all, since an interface no code names is what dead means here (#333).

**Vacuous-assertion guard**: all three module unit tiers run `TestNotCalledArity` over the whole
source root, holding every testify `AssertNotCalled` to carrying one matcher per parameter of the
method it names, through `core/guard.AssertNotCalledArity`. testify matches a recorded call on
the method name *and* the whole argument list, so `AssertNotCalled(t, "Log")` against a three-parameter
`Log` compares lists that can never be equal and passes whatever the subject did; the compiler sees
a variadic call and says nothing. Forty-one such sites shipped, one of them false since #241. The
receiver is resolved with `go/types` rather than by spelling, because one method name can sit on two
doubles at two arities (`CreateUser` is 3 on `Database` and 2 on `UserCreator`), and four shapes are
reported rather than skipped: a method named through anything but a string literal, an unresolvable
receiver, a name the double does not declare, and a variadic method. It does not widen to
`AssertCalled`, whose arity mismatch fails loudly, or to `.On(...)`, where a stub matching nothing
panics (#421).

**Schema golden files**: each engine's fully migrated catalog is recorded in
`src/authserver/internal/data/<engine>db/schema.golden`, and the data tier compares a freshly
migrated database against the file for the engine it is running on. A migration therefore has one
more step: `cd src/authserver && go run ./cmd/schemadump` inside the dev container, which
regenerates all four files at once, and commit them. Skip it and CI goes red on every database job.

**Core symbol ownership table**: `src/core/OWNERSHIP.md` has one row per exported symbol every
`core` package declares, so adding or moving one has one more step:
`cd src/core && go run ./cmd/ownershipdump`, and commit it. It refuses to invent a justification,
so the answer is to move the symbol or to write `test-support`, `contract` or `moving` with the
reason. The lint tier runs it and fails on a tree it changed.

**Generated mocks**: the `*_mock.go` files are written by mockery, at the version `versions.yaml`
pins as `tools.mockery`, and committed. Regenerate with `src/authserver/generate-mocks.sh` inside
the dev container, which refuses to run on any other version rather than stamp one that did not
produce the output. Each generated file opens with `src/mockery-header.txt`, inlined by
`template-data.boilerplate-file` in the two `.mockery.yaml` files and written from the pin by
`./version-manager.sh update`, so a clone reads which generator wrote the tree instead of having to
install one to find out. That is checked in both halves, because they catch different things: every
module's unit tier runs `TestGeneratedMocksArePinned`, which holds the pin, the header and every
generated file to each other through `core/guard.AssertGeneratedMocksArePinned` and needs no
generator; the lint tier and CI's Lint job run the generator itself and fail on a tree it changed,
which is the only thing that catches an interface newly named in a config. Keying on mockery's own
`Code generated ... DO NOT EDIT` marker rather than on the filename is what leaves the countries
and timezones tables, which have generators of their own, out of it (#338).

**Lint tier**: `./run-tests.sh --type lint` runs golangci-lint and `unparam -exported` over the
four modules with the commands CI's Lint job uses, then regenerates the Tailwind CSS and the mocks
and fails if either differs from what is committed; `all` includes it. It fails rather than skips
when a binary is missing, and refuses `--race`. It is where `sloglint` holds most of the logging
convention (pattern 8), which is why it is a tier of the script and not CI-only (#320), and where
`gosec` holds shipping code to every rule, each false positive suppressed inline with its reason,
which `nolintlint` requires (#426), and where the rest of `.golangci.yml`'s set holds the tree, each measured before it was enabled and listed with why in that file: among them `testifylint`, under which an error assertion is `require`, never `assert`, and `errorlint`, `rowserrcheck`, `sqlclosecheck` and `noctx`. The two
regeneration checks are here because each was CI-only and nothing local could see it: a template
class that never reached `main.css` (#328) and sixteen mocks stale against their own pin (#338).
`unparam` joined them for the same reason: #385 moved an exported parse into the module whose two
call sites discard its result, and only CI could see the finding (#385).

**Migration source rules**: the authserver internal tier runs
`TestMigrationSource_TheFourCommittedDirectories` in `src/authserver/internal/data`, which holds the
four `migrations/` directories to the rules decidable from the text alone: naming, pairing, one
number meaning one change, the collation pins on MySQL and SQL Server, a named `CONSTRAINT` on
every added SQL Server `DEFAULT` and a spelled-out `NULL` or
`NOT NULL` on every `ALTER COLUMN`, and each `schema.golden`'s recorded version. A migration
landing on fewer than four engines therefore owes a `-- parity: <engines> only. <why>` line in
every up.sql carrying it, and a `.down.sql` with no statement in it owes
`-- Migration NNNNNN down: intentional no-op.`

## Important Patterns

1. **Handler signature**: `HandleXxxGet/Post(dependencies...) http.HandlerFunc`
2. **Audit logging**: All security events logged via `auditLogger` (see `authserver/internal/audit/events.go` for event names)
3. **Rate limiting**: Applied to credential checks and unauthenticated endpoints (login, OTP, ROPC, account password, OTP and email changes, email verification and its resend, forgot/reset password, self-registration, activation, DCR, and the authorization endpoint, both methods of which share one admission budget per client block, #504). Credential checks count failures only, so a successful attempt spends nothing. The limits counted by a user or by an email apply whatever `GOIABADA_AUTHSERVER_RATELIMITER_ENABLED` says: those counted by a user something has already authenticated, the signing-in user or a token's subject (OTP, account password, email verification and its resend), since no stranger can spend them (#542), and those counted by an email anyone can type (wrong passwords per account, 100 an hour shared by the sign-in form and the password grant, and reset mails and registration notices per address), since only Goiabada can count them (#503). The switch governs only the tiers that read the client's address, those counted by an IP address and `pwd_account_net`, the 10 wrong passwords per 15 minutes for one email from one client block; with it off the password check reserves the account-wide tier alone. The price is #89's lockout: 100 wrong passwords block an account's password sign-in for up to an hour, its remedy blocking the attacker at the proxy or CDN (#503)
4. **Permissions model**: Resources contain Permissions; Users/Groups/Clients can have Permissions
5. **Credential form fields**: A handler reads a credential-bearing field (`password`, `passwordConfirmation`, `currentPassword`, `newPassword`, `newPasswordConfirmation`, `otp`, `secretKey`, `base64Image`, `verificationCode`, `clientSecret`) and a form-binding marker (`ceremonyId`, `continuationId`) with `r.PostFormValue`, never `r.FormValue`. `r.FormValue` merges the URL query behind the request body, so the value would be accepted from the request target, where it reaches the browser's history, the `Referer` of anything the page loads, and the access log of every proxy, gateway and CDN in front of the deployment. Every such form is POST-only with a separate GET handler that renders it, so the query is never a submission. Enforced by `core/guard.AssertNoCredentialQueryFallback`, which carries the walk and the four merged-form accessors it refuses, called from a `credential_read_lint_test.go` in each `internal/handlers` package and from `core/httpmw`; each caller owns its own name list, because the lists must differ. The auth server's adds the four token-endpoint credentials (`code`, `code_verifier`, `refresh_token`, `client_secret`) and `access_token`, which `JwtAuthorizationHeaderToContext` in `authserver/internal/middleware` reads lawfully from a form body per OIDC Core 1.0 5.3.1; the kernel's is `access_token` alone, and since #385 moved that read out of core it refuses the read coming back rather than holding a site. Only `state` is exempt, at `/auth/authorize`, which OIDC Core 3.1.2.1 requires the authorization endpoint to accept over GET as well as POST; `code` is not, being an authorization *response* value the client returns in the request entity-body (RFC 6749 4.1.2, 4.1.3) (#202, #333)
6. **Transactions**: exist for atomicity, and every one is opened through `RunInTransaction`, which reruns the body when the engine aborts it as a deadlock victim (bounded, then the error surfaces); `begin_transaction_lint_test.go` in `src/authserver/internal/data` refuses a bare `BeginTransaction` in production code. No lock order is imposed. One property is kept on purpose (#139): a termination deletes the session row first, and issuance takes that row before inserting its code, or before signing the implicit grant's tokens, in one transaction, so a code or a token can never slip between a termination's sweep and its commit. A second is kept the same way (#131): a refresh rotation takes the user's row first (`AcquireUserRow`), as a credential change does through its write and its generation increment, so a rotation's child is never stamped from a token a revocation has already moved past, and a revocation's sweep never misses a child. A third is kept the same way (#542): a sign-in's claim to a one-time code is checked on the user under the user's row (`otpcredential.OTPClaim.Recheck`), first in the transaction that binds it to a session or issues it, and a removal takes the user's row first and lowers the sessions in the same transaction, so a code is never bound or issued after the removal of the authenticator it came from. Concurrent transactions on the same account can still deadlock on MySQL, PostgreSQL or SQL Server; the loser is rolled back with nothing half applied and rerun. SQLite has one connection and cannot deadlock. Do not add ordering to prevent a deadlock; add a test that forces it and shows the retry resolves it (#301). A commit that fails for any other reason is never rerun, since the server may have committed before the failure reached it, and comes back tagged `data.ErrCommitOutcomeUnknown`, which the rotate endpoint answers as 409 `ROTATION_OUTCOME_UNKNOWN`; a commit whose context is already done is never asked of the driver, is rolled back and carries no tag, while one cancelled with its COMMIT in flight carries it, even when the driver answers with the context's own error, as pgx and go-mssqldb do (#371)
7. **Error handling**: every error this tree constructs goes through `core/errs` (`New`, `Errorf`, `Wrap`, `Wrapf`, `WithStack`, `Join`), which captures one stack per error tree, the origin's, and prints it under `%+v`; a package-level sentinel is the one exception and stays on stdlib `errors.New`, because a stack captured at init would masquerade as the origin of everything wrapping it. Match with `errors.Is` / `errors.As`, never a bare type assertion and never the error's text. `errorlint` in `.golangci.yml` holds the first half; the few places that mean the error value itself carry a `//nolint:errorlint` saying why: `core/errs`'s own tree walk, the migrator's `IsNoChange` and `IsNilVersion`, whose identity is the whole test (#268), and the migrate command's `reportStop`. `TestNoLegacyErrors` in `core/guard/errors_lint.go`, called from all three module tiers and walking the whole of `src/`, refuses `github.com/pkg/errors`, stdlib `errors.New`/`errors.Join`/`fmt.Errorf` in production code, and `errs.WithStack(errs.New(...))` and any `errs` constructor in a package-level var, which is the sentinel rule enforced rather than merely stated (#279). In the admin console a handler answers either a page or JSON, never both: `NotFound`/`InternalServerError`/`HandleAPIError` render HTML, and `JSONNotFound`/`JSONBadRequestBody`/`JSONError`/`HandleAPIErrorJSON` answer the same statuses as JSON. Mixing them makes the browser's `response.json()` throw on that branch alone; `TestHandlers_AjaxHandlersDoNotUsePageWriters` in `adminconsole/internal/handlers/ajax_writer_lint_test.go` refuses it. Which of the two a handler picks is the only decision it makes about an `apiClient` failure: `HandleAPIError`, `HandleAPIErrorWithCallback` and `HandleAPIErrorJSON` turn the auth server's status into the console's, and `TestHandlers_ApiClientErrorsReachTheClassifier` refuses a guard that answers one itself or catches every status as a rejected value (#279). In the auth server the type makes the choice: `internal/handlers` declares the page and JSON writers as two ports, `PageRenderer` and `JSONWriter`, and hands the token, userinfo, JWKS and discovery endpoints only the second, so a page writer there does not compile; `routes.go` registers them, registration and the APIs on the branches of `initMiddleware` whose settings and session middleware answer their own faults, and a panic, as JSON too (#435)
8. **Logging**: `core/logging` owns the one `slog` handler, installed by both servers at startup. Every message is a lowercase string literal with no `component:` prefix and no `failed to` or `error ` opener, the one verb being "unable to"; values ride as snake_case attributes, one fixed name per concept, `error` for an error, `client_identifier` for the wire string against `client_id` for the row id. `request_id` is the handler's, injected from the context, so a site with a `context.Context` or `*http.Request` in scope at any depth uses the `*Context` variant. Error means someone must act, Warn a refused or handled request, Info lifecycle and configuration, Debug per-request tracing. Two guards hold it. `sloglint`, enabled in `.golangci.yml` and run by `./run-tests.sh --type lint` and CI's Lint job over type-checked code, holds the lowercase message, the snake_case keys, the refused `err` and `request_id`, and the `*Context` rule; a function that hands its caller's key/value run to a record is registered there under `custom-funcs` so the keys are read at its call sites. `TestSlogConvention` in `core/guard/slog_lint.go`, called from all three module tiers, holds what sloglint cannot express: that the message is a literal at the call rather than a constant, the refused message openers, `slog.SetDefault`/`New`/`Default`/`With` outside the handler's own files, a `...` spread into a record or a forwarder outside the functions `slogSpreadSites` lists, that list against `custom-funcs`, and a plain `slog.Debug`/`Info`/`Warn`/`Error` in any production package outside the directories `slogNoRequestDirs` lists, the ones with no request above them: the mains and composition (both `config` and `server` packages, `datafactory`, `migrator`, the four engine adapters, `bootstrap`), `cleanup`, the developer tools and generators, test support, and the setup wizard. Each entry is one directory and not its subtree, so a package created anywhere else, beneath a listed one included, is checked from its first commit (#442). The plain-record rule admits the functions `slogPlainSites` names, each with the reason no context reaches it: the admin console's template function `addUrlParam` and the `convertToString` it calls, `core/i18n`'s startup records in `loadOverrideCatalogs` and `orEmpty`, and `StaticFS` and `TemplateFS` in each application's `web` package. That rule is what refuses a new helper written without a context after sloglint has admitted it. `AssertRequestPathContext` and `AssertAuditLogContext` share the same scope, and `requestContextOwners` admits `core/i18n`'s `WithLocale`, whose background context is the fallback for a nil one. A package holding both startup and request work, like `core/i18n` with its locale middleware, stays in scope with its startup functions admitted by name. A request-path helper therefore takes a `context.Context`; a helper with neither a context nor a request is a startup or template site. No request-path writer is left carrying no `request_id`: the audit path was the last but one until #328 gave `AuditLogger.Log` a context, and `commondb`'s transaction and statement records were the last until #386 gave every `Database` method one. Level is not decidable and is pinned per site through `logtest.CaptureSlog(t)`, the one way a test reads records (#320)
9. **Multi-row writes and list saves**: a request that writes more than one row validates the whole request first, bounds and duplicates included, so a refusal writes nothing; then writes in one `RunInTransaction` whose body reads what it needs on the transaction, returns each failure through `errs.Wrap` and writes no response, since a deadlock victim's body is rerun; then answers, audit events after the commit. A save replacing a whole list is the common case, and there are seven: a client's redirect URIs and web origins, user, group, client and resource permissions, and a user's groups. Each requires the list as its caller loaded it (`expectedRedirectURIs` and its siblings; absent or `null` is a 400, `[]` means an empty list was loaded), reads the stored rows on the transaction, and answers 409 `CONCURRENT_UPDATE` with nothing written when they differ from it as a set; otherwise it applies `replaceSet`'s plan, which deletes every row whose key is not wanted and every extra copy of one that is, so a duplicate left by an overlap is repaired by the next save. A unique-key race answers the same 409, through the one failure writer `writeListSaveFailure`. No list save takes a row lock: overlapping saves merge item by item, and the data tier's `list_save_test.go` shows it on MySQL, PostgreSQL and SQL Server. A row lock is for one row read, decided on and written back with a security consequence, which today means #245's public/confidential switch (`AcquireClientRow`), #139's issuance (`AcquireUserSessionRow`), #131's refresh rotation (`AcquireUserRow`), #542's session writes (`AcquireUserSessionRow`) and one-time code claims (`AcquireUserRow`), and #407's settings section saves (`AcquireSettingsRow`), each of which reads the settings row again under it and writes its own section onto what it read, through `apihandlers.saveSettingsSection`, so a save of another section committed meanwhile is not written back over (#428)
10. **Metric labels**: a metric label takes only values from a closed set declared when its family is registered with `core/metrics`, through `metrics.Enum` (listed in the catalog) or `metrics.Described` (named there in words, for the status codes, the route table or the build stamp), and a value outside the set is recorded as `other`, so no family can exceed the product of its sets whatever the requests. Nothing taken from a request or from the database reaches a label without being mapped into a declared set first: no user id, subject, email, username, session identifier, client identifier, IP address, raw path, query, user agent or error description. `client_identifier` is never a label, because with dynamic client registration on anyone can mint identifiers. The route label is the router's own table read once at startup, `unmatched` for a request no route answered, read off the request through `routing.RouteName` in `core/routing` by `metrics.HTTPRequests` in `core/metrics/http.go`; the method label is a standard verb or `other`; the status label is the exact code. Each server's unit tier holds every family it registers, name, type, labels and value sets, to the catalog table on the docs' Monitoring page through `core/guard.AssertMetricsCatalog`, in both directions, so a new family or label fails until the docs describe it (#400)

## UI conventions

Both servers draw their pages with `ui.css`, Goiabada's design tokens and components, and Tailwind
utilities for layout (#617). The file is one copy in each application's `web/tailwindcss/`, which
`TestUICSS_IsTheAuthServersCopy` holds byte-identical; edit one, copy it over the other, and
regenerate both `main.css`. Every class a page names has a rule in the served
`main.css` (`core/guard.AssertClassesAreDrawn`), so a misspelt or leftover class fails the unit tier.

- **Themes**: automatic (the settings' empty value: each visitor's device decides), light and
  dark. The layouts write `data-theme` for light and dark alone. A color is a token, `bg-surface`,
  `text-ink-muted`, `border-line`, never a raw value, and every pair a component draws text or a
  boundary on is in `TestThemeContrast_EveryPairMeetsWCAGAA`, at WCAG AA in both themes.
- **Components**: `page-header` with `page-eyebrow`, `page-title`, `page-lead` and `page-actions`;
  `panel`, `panel-body` (several, each under a `panel-title`, for a panel in sections),
  `panel-footer`; `button`, with `-primary` for a form's one main action, `-danger`, `-quiet`,
  `-sm`, `-icon` and `-block`; `field`, holding `field-label`, a `control`, `field-hint` and
  `field-error`; `input-row` for a control and the button acting on it; `choice`, `switch`,
  `option-card`, `check-list` of `check-row`; `detail-list`, a `dl` of a record's facts;
  `notice` with `-danger`, `-positive`, `-caution` or `-note`; `tag`; `table-scroll` around a
  `data-table`; `tab-bar` and `tab-item`, one underlined row while the tabs fit and rows of pills
  where they do not, which `shell.js` decides, so a bar never scrolls sideways; `pager`; `dialog`; `empty-state`; `spinner`;
  `text-link`. The auth server's card adds `auth-title`, `auth-lead`, `auth-status` with a
  `status-icon` (`-danger`, `-positive`, `-caution`, `-note`), `auth-actions` for two answers side
  by side, `auth-steps`, `auth-qr`, `secret-key` with `secret-key-row`, `code-hint`,
  `auth-address`, `auth-section-title`, `identity-row` and `link-list` of `link-row`; the console's
  pages without a menu (home, the error pages, sign-out) draw the same card. An uploaded image is an
  `image-upload` with an `image-preview` (`-square` for a logo), cropped in the `crop_dialog`
  partial: a `crop-area` the cropper draws in, and `crop-controls` whose `crop-slider`s do what
  dragging does, so a crop needs neither a pointer nor a drag.
- **Markup**: `core/guard.AssertWellFormedTemplates` holds every page to well-formed HTML and to
  the accessibility rules readable from a template: every element closed explicitly and in order,
  what a branch opens closed in it, quoted attributes, no nesting a browser repairs, a label for
  every control, alt on every image, a name on every link and button, one `<h1>`, no skipped
  heading level.
- **Scripts**: no executable script in a template, no `on…` attribute, no `javascript:` URL. Page
  behaviour lives in static files, `static/utils.js`, the console's `static/shell.js` and
  `static/pages/<page>.js`, attached with `addEventListener`. A template hands a script data in a
  JSON data block, `<script type="application/json" id="…">{{ . }}</script>`, or in `data-`
  attributes, and text by message ID: through `T`, except the console's `js.*` strings, which carry
  client-side placeholders and go through `i18n.Raw` in `JSBootstrap`. ES2020 at most, with no build
  step, for the declared floor: Chrome and Edge 111, Safari 16.4, Firefox 128.
  `core/guard.AssertScriptSyntax` parses every static script with acorn under Node, both pinned in
  `versions.yaml`, so each module's unit tier needs `node` on the path, as the dev container and the
  test jobs have it. The auth server's pages work with JavaScript off; the console says it needs it.
  In the console a script answers an action in a live region the page draws empty, through
  `showNotice`, not in a dialog, its failures too (`sendAjaxRequest`'s `statusRegion`); a removal
  asks first in a `modal_dialog` of type `confirm`, whose
  second button names the action; a button marked `data-copy-target` copies, a long `select`
  marked `data-searchable` becomes a `combobox` that filters as the person types, the select kept
  hidden to post the value, an element marked `data-duration-for` says the seconds typed in a field
  as a duration, and a form marked `data-confirm-dialog` asks before a save whose consequences need
  saying, every one in one `modal_dialog` of type `confirm_change`, each from a control marked
  `data-confirm` against the value stored when the page was drawn (`data-stored-value`,
  `data-stored-checked`), as `shell.js` wires them; a form a script saves calls `confirmChanges`.
  A script that shows something following a control's value shows it again on `pageshow`, since a
  browser restoring the form, as on Back, fires no change, and a script asking the server about a
  choice drops an answer to any request but its latest, a failure included, through
  `sendAjaxRequest`'s `current`; one asking the server to validate values applies the values it
  sent, never the fields as they are when the answer arrives, and drops the answer once the person
  has typed past them. A row's own action, a removal or an addition saved at once, is a button
  marked `data-action-url`, which `static/pages/row-actions.js` posts, asking first when the
  button carries `data-confirm`; a search that finds users to add is `#userSearchForm`, which
  `static/pages/user-search.js` turns into a search as the person types and never lets submit.
- **Accessibility**: WCAG 2.2 AA on every page, in every state and both themes. An error is a
  `notice-danger` with `role="alert"`, a success a `notice-positive` with `role="status"`; a table
  wider than its place scrolls inside `table-scroll`, a labelled region with `tabindex="0"`; an icon
  is `aria-hidden="true"`, and a button showing one alone carries `sr-only` text; targets are at
  least 24 pixels. A refusal about one field marks it `aria-invalid="true"` and names the notice in
  its `aria-describedby`, under the same `{{if .error}}` the notice renders under, which the guard
  reads as one branch; a handler whose form has several fields says which in `errorField`, and in
  the console reads it off the admin API's error code through `render.ErrorField`, or, for the
  API's `VALIDATION_ERROR`, which names no field, the first required field sent blank through
  `render.ErrorFieldOrBlank`. No
  template rebinds `$`, which the guard refuses, since it reads `$` as the data the template was
  called with.
- **Page patterns**: every page is one of a few shapes, built the same way each time, and the first
  page of each shape is its reference. A list (`admin_users.html`): the page header with the main
  action, a GET search form if the list searches, a `data-table-stack` table whose first cell links
  to the record and whose last holds the row's other actions as links, a `notice` or `empty-state`
  for nothing found, and the paginator only past one page. A settings form
  (`admin_settings_sessions.html`): eyebrow, title and lead, one `panel` holding the notices at its
  top and the fields in a `form-grid`, each field's help visible under it, and Save in the
  `panel-footer`; a longer one (`admin_settings_general.html`) in sections, each a `panel-body`
  under a `panel-title`, and the settings a switch governs hidden while it is off rather than
  disabled (`admin_settings_email.html`). An action on the whole page that changes what is stored
  (`admin_settings_keys.html`, Rotate keys) is a form posted from `page-actions`, asked first in a
  `confirm_change` dialog, which answers with the page again. A choice among a few options (`admin_settings_ui_theme.html`): `option-card`s in
  a fieldset with a legend; several of many (`consent.html`): a `check-list` of `check-row`s in a
  fieldset with a legend. A confirmation that deletes or removes says so on its buttons: "Cancel",
  and the action in `button-danger`. On the auth server, a form (`auth_pwd.html`): the title, an
  `auth-lead` saying what the page asks when the title does not, the notice at the top of the form,
  the fields, and one `button-block` primary button; a page that reports (`auth_error.html`): an
  `auth-status` with a `status-icon` in the outcome's tone, the title and the icon centered, the
  message left-aligned, an address it names in an `auth-address`, and at most one action, a
  `button-block`. A list whose rows a person ends or revokes (`account_user_sessions.html`): each
  row's button asks in a `confirm` dialog with the row's own sentence in `data-confirm`, and on
  success gives way to a `tag` saying so, which takes its focus unless the person moved it elsewhere
  meanwhile, while the page's live region says it too; a row added the same way from a search
  (`admin_groups_members_add.html`) acts at once, with no
  dialog, since one Remove undoes it. A home of destinations (the console's `index.html`): a `link-list`. A record with tabs
  (`admin_clients_settings.html`): a header linking back to the list in the eyebrow, the record's
  identifier as the title, the `tab-bar`, one partial per kind of record (`client_header`,
  `user_header`, `group_header`, `resource_header`), then each tab one `panel`, its sections `panel-body`s
  under a `panel-title`, its yes or no settings a `check-list` whose rows say what each does, and
  Save in the `panel-footer`. A create form (`admin_clients_new.html`): the same back link, title
  and lead, one `panel`, and Cancel beside the create action. A delete confirmation page
  (`admin_clients_delete.html`): a lead saying what the deletion takes with it, the record in a
  `detail-list`, its identifier typed to confirm, and Cancel beside the action in `button-danger`. A
  list edited in the page and saved whole (`admin_clients_redirect_uris.html`): a field and its Add
  in an `input-row`, refused at the field, the rows drawn as stored, each with a Remove naming its
  row, a change announced, and Save sending the list beside the list as drawn; where a row's Edit
  loads it into those fields (`admin_resources_permissions.html`), the row is marked `data-editing`
  while the edit lasts, its Edit giving way to a `tag` saying so. A new shape gets its reference page
  and a line here when its first page is built.
- **Wording**: the glossary's terms (`site/src/content/docs/concepts/glossary.mdx`): sign in and sign
  out, client, one-time code, two-factor authentication, auth server. Client and application are one
  thing with a name per reader. Wherever an administrator or a developer reads, the console's admin
  pages, the admin API's messages and the docs, it is a client, which is OAuth's word and the API's.
  Wherever the person signing in reads, the auth server's pages and the console's account pages, it
  is an application, since that person never registered one; a page quoting such a screen quotes it
  as it reads. No page calls it both, though a parameter's name, such as `client_id`, stays as it
  is. On an administrator's page "app" names a kind of software, such as a single-page app or a
  mobile app, and never a client: a sentence about what uses a client says that ("anything that
  signs in with this client"). Every sentence is true when it is read, its tense included: a
  question asked before an action says what will happen ("The key will be deleted"), a notice after
  it what was done, and help about standing behaviour the present. Sentence case; a
  button says what it does ("Save", "New user"); a page title reads "Page – app name". Both catalogs
  change together, a message ID is kept, and a renamed one goes in the release notes, since
  operators' override catalogs are keyed by it.

## Standards

Goiabada implements published standards. When a change touches behavior one of them defines, read the relevant section of the official text (rfc-editor.org, openid.net) rather than relying on memory, and follow its MUST and SHOULD requirements. The main ones: OAuth 2.0 (RFC 6749) and bearer tokens (RFC 6750), PKCE (RFC 7636), revocation (RFC 7009), introspection (RFC 7662), dynamic client registration (RFC 7591), authorization server metadata (RFC 8414), JWT (RFC 7519) and JWK (RFC 7517), the OAuth 2.0 Security Best Current Practice (RFC 9700), and OpenID Connect Core 1.0 and Discovery 1.0.

## API Routes

- `/auth/authorize` - OAuth2 authorization endpoint
- `/auth/token` - Token endpoint
- `/userinfo` - OIDC userinfo
- `/certs` - JWKS endpoint
- `/.well-known/openid-configuration` - OIDC discovery
- `/connect/register` - Dynamic Client Registration
- `/api/v1/admin/*` - Admin API (requires `authserver:manage` permission)
- `/api/v1/account/*` - User self-service API (requires `authserver:manage-account` permission)
