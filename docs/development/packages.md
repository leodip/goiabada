# Package responsibilities

Locate the owner and the rationale for a package before moving responsibilities between modules.

Paths in backticks are relative to the repository root unless a module directory is named. Read the
sections relevant to the change; [AGENTS.md](../../AGENTS.md) lists the common commands.

### Core (`src/core/`)
- `adminpassword/` - The one rule for the first administrator's password, `Check`: at least 15
  characters, at most bcrypt's 72 bytes, never `changeme`, never a password on `passwordblocklist`'s
  list, and never the admin email, its local part or the app name, or a derivative of them, the
  email and app name each caller seeds handed in beside the password (#550). The auth server's first
  start and the setup wizard both apply it, so the two cannot disagree on which passwords seed. A
  leaf of its own, importing only `core/errs` and `core/passwordblocklist`, a standard-library leaf,
  because in `inputvalidation` it linked `core/i18n`, `core/oauth`, TOML and JWT into the wizard.
  `core/guard`'s `imports_only_lint_test.go` holds it there through `AssertImportsOnly`, from that
  package because `go mod tidy` reads the tests of every package the wizard imports, so no test in a
  core package the wizard imports may import `core/guard`, which `AssertNoGuardInTestsReachedFrom`
  holds (#500)
- `api/` - The admin API wire contract: request and response DTOs, declarations only, importing no
  persistence model. The model-to-DTO mapping belongs to the auth server, in `internal/apimapping`
  (#350). One file per resource, each holding its requests beside its responses (#441)
- `boundedread/` - The one rule for a capped response body: read one byte past the cap and refuse
  the overrun rather than decode a prefix. Used by the console's API executor, public-settings
  client, session backend, token client and JWKS parser; by `internal/pinnedfetch`, which the
  generators download through; and by the timezones generator for the decompressed tarball (#386,
  #432)
- `buildinfo/` - The build stamp both servers report, `Version`, `BuildDate` and `GitCommit`, which
  the release builds set with `-ldflags -X` and which read `development` in any other build. It left
  `core/constants` beside `builtin/` when that package split, because the linker writes these values
  rather than the two processes agreeing on them (#442)
- `builtin/` - The identifiers both processes must agree on: the `authserver` resource, the seven
  permissions on it, listed by `AuthServerPermissionIdentifiers()`, which returns a fresh copy on
  every call, the admin console's client identifier, and its session name in `session_name.go`. No
  context key and no other session key: each process declares its own, the auth server and the admin
  console alike their context keys in `internal/reqctx` and their session keys in
  `internal/sessionkeys`, and no row of `ARCHITECTURE.md`'s table here reads `kernel` any more. It
  was `core/constants` until #442 moved the build stamp to `buildinfo/` (#351, #385, #433, #440,
  #442)
- `cmd/` - `ownershipdump`, which regenerates `OWNERSHIP.md`'s table from the reference graph. It
  reads nothing but the source tree, so unlike `schemadump` it needs no container, and it refuses to
  invent a justification rather than fill the one cell a human owes (#385). Beside it,
  `imagescanreport`, which the weekly Image scan workflow runs over Trivy's, Grype's and
  govulncheck's JSON for each published image to write the one `security` issue: a finding with a
  fixed version, or a Go finding govulncheck reports reachable, merged across scanners and
  identifiers into one entry per advisory, the rest to the run's log, and the same bytes for the
  same scans, since the workflow compares the report with the issue's body (#520)
- `countries/` - Self-maintained ISO 3166-1 reference data: names, alpha-2 and alpha-3 codes, flag
  emoji and ITU-T E.164 calling codes, generated into `data_generated.go` from the datahub dataset.
  It replaced `github.com/biter777/countries` and deliberately depends on nothing (#272)
- There is no `enums/` here: the six auth-server-only enumerations it held went to the domains that
  own them — `AcrLevel`, `PasswordPolicy`, `ThreeStateSetting` and `KeyState` to
  `authserver/internal/record`, forced there because `internal/data` names them and imports nothing
  above it, `AuthMethod` to `ceremony` and since to `oidc` (#437), `TokenType` to `issuance` and
  `SMTPEncryption` to `emaildelivery` — leaving `Gender` as `core/gender`. A package named for a Go
  construct is what invites the next unrelated one in beside it (#385)
- `errs/` - The one way this tree constructs an error, with the convention in [Error
  handling](conventions.md#error-handling): one stack per error tree, the leftmost origin's, printed
  under `%+v`
- `gender/` - The three gender values the OIDC `gender` claim is written from, and the bound that
  says which integers name one. A fourth shared reference vocabulary beside `countries/`, `locales/`
  and `timezones/`: the auth server validates and stores a gender, the admin console renders and
  re-renders one, and both name the same three strings (#385)
- `guard/` - The tree-wide guards the core and both server unit tiers run, and the `Reporter` /
  `Run` pair they are written against. See [Guard shape](guards.md#guard-shape) for what that shape
  is and what each guard owes. Test support compiled into no binary, holding guards and nothing
  else: it was `core/testutil` until #442, when `SkipWithoutIPv6Loopback`, the one helper in it that
  was no guard, left for `hostport/hostporttest`
- There is no renderer here: each application renders its own pages from its own `internal/render`,
  because the one shared renderer bound admin page data no auth server template could reach and
  parsed every template with a `FuncMap` of which the auth server calls four entries out of
  twenty-two (#385)
- `hashutil/` - SHA-256 over a string, and nothing else. It stayed here when password hashing went
  to `authserver/internal/passwordhash`, because both processes reach it independently: the auth
  server hashes authorization, verification and reset codes to locate rows, the admin console hashes
  the nonce it sends, and again to check the ID token's (#360, #427)
- `hostport/` - The one join of a configured host and port into an address: both servers' listeners,
  the three database connection strings and the SMTP dial go through `Join`, which brackets an IPv6
  literal and reads `[::1]` as `::1`, per RFC 4038 section 5.1. A Sprintf'd `host:port` stopped
  either server at start on an IPv6 listen host, and a plain `net.JoinHostPort` would have broken
  `[::1]`, the one IPv6 spelling that worked before (#424). `hostporttest.SkipWithoutIPv6Loopback`,
  beside it, skips a test that listens on or dials an IPv6 literal on a machine with no `::1` (#442)
- `httpmw/` - The request middleware both processes mount: real IP, CSRF, security headers, the
  request logger, the panic recovery, which answers an empty 500 and writes one ERROR record with
  the request id and the stack, the one-trailing-slash strip, which rewrites `r.URL.Path` itself,
  and the cookie reset; and `statuswriter`, the writer the request logger and the HTTP metrics read
  a response's status through. They replaced chi's middleware package, which linked `net/http/pprof`
  and `expvar` into both servers (#462). Each application's own middleware - session, JWT, rate
  limiting - is in its `internal/middleware`
- `i18n/` - The internationalization layer: the embedded message catalogs and the runtime overrides
  that win over them, the `Locale` middleware early in every request chain, `WithLocale` as the one
  locale-setting primitive with a non-explicit call deferring to explicit intent already on the
  context, and the error-code vocabulary in `error_codes.md`. The six template helpers only the
  admin console renders with, the locale picker's label, the country, phone-country and timezone
  labels and the two date formatters, are that console's, unexported in its `internal/render`: they
  read nothing here but `T` and `CatalogTag`, and here they put CLDR's display tables into the auth
  server. Both servers' `<html lang>` and those CLDR labels read `CatalogTag`, the catalog the page
  was rendered from, and `LocaleTag`, the first preference asked for, is what an email's body copy
  is chosen from (#645). `Raw` stays, because it reads the catalog state this package keeps private
  (#442)
- `inputvalidation/` - Identifier validation and the angle-bracket predicate, the two rules both
  applications apply, to text an administrator or a registering client supplies.
  `IdentifierValidator.Validate` matches against a pattern compiled once, and the admin console
  names it through its own port. It was `core/validators` until #442. `ValidateNoAngleBrackets`,
  which wraps the predicate in an error only the auth server emits, is in
  `authserver/internal/accountvalidation` beside the other account validators — email, password,
  profile, address, phone — and the authorize and token validators are in
  `authserver/internal/protocolvalidation` (#344, #385, #442)
- `internal/refgraph/` - The reference-graph reader the tree-wide guards in `guard/` and
  `ownershipdump` in `cmd/` share: the import graph, which resolves against the module directories
  `sourceroot/` declares, build constraints, the tables `ARCHITECTURE.md` and `OWNERSHIP.md` hold as
  data, and the symbol census. It left `core/testutil`, now `guard/`, so that `ownershipdump` links
  neither `testing` nor testify (#431, #442)
- `internal/pinnedfetch/` - The download the reference-data generators share: a GET through an
  injectable doer, read through `boundedread`, and the SHA-256 check against the digest each
  generator pins in its source, whose refusal prints the digest received so updating a pin is edit,
  run, paste, run (#432)
- `issuerlength/` - The one bound on an issuer's length, `Check`: 60 UTF-16 code units, under the
  issuer column's 64. The auth server's start holds the base URL to it, since the first start seeds
  the base URL as the issuer, the general settings save every issuer, and the setup wizard the auth
  server URL it writes, so the three cannot disagree on which base URLs start and save. A leaf
  importing only `core/errs`, for `adminpassword/`'s reason, held there by `AssertImportsOnly` from
  `core/guard`'s `imports_only_lint_test.go` (#615)
- `locales/` - The locale identifiers and display names a user picks from. A shared reference
  vocabulary beside `countries/`, `timezones/` and `gender/`
- `localzone/` - The process's local time zone, resolved from `TZ` by `Install`, which both servers
  call before their first record: a dependency fixes the local zone during package initialization,
  before the embedded `time/tzdata` registers, so `TZ` was ignored on a host with no zone database.
  A name that is no zone, `Local`, or an absolute zone-file path that does not load stops the server
  with one stderr line and exit 2 (#331)
- `logging/` - The one `slog` handler, installed by both servers at startup, and the field helpers
  described in [Logging](conventions.md#logging). Nothing else calls `slog.SetDefault`, `New`,
  `Default` or `With`, and a guard says so (#320). `RequestTargetForLog` is here beside
  `FieldForLog`, the one rendering of a request target for a record: the path escaped, every query
  value redacted but those an allowlist names, and the whole bounded. The request logger and the
  CSRF refusal in `httpmw/` and the auth server's API debug middleware call it (#159, #442)
- `loopback/` - The one answer to "is this the loopback interface", `IsHost`: `127.0.0.1`, `::1`
  and `localhost`, exact after case folding, with a numeric port or IPv6 brackets accepted, so
  `localhost.attacker.com` is not loopback. `IsPlainHTTPOff` builds RFC 9700 section 2.6's rule on
  it: an `http` URI on any other host. The auth server's redirect-URI matching grants loopback port
  flexibility by `IsHost`, and its redirect-URI intakes refuse by `IsPlainHTTPOff`. A
  standard-library leaf, for `adminpassword/`'s reason, held there by `AssertImportsOnly` from
  `core/guard`'s `imports_only_lint_test.go` (#590)
- `metrics/` - The Prometheus metrics both servers expose, written here with no third-party
  dependency: counters, gauges and fixed-bucket histograms in a `Registry`, the text exposition
  format 0.0.4 its `Handler` writes under `Content-Type: text/plain; version=0.0.4; charset=utf-8`,
  `HTTPRequests`, the middleware recording requests by route, method and status, and
  `RegisterBuildInfo` and `RegisterRuntime`. Every label is declared with its closed value set; see
  [Metric labels](conventions.md#metric-labels), and `guard.AssertMetricsCatalog` holds each
  server's registry to the catalog table in the docs (#400)
- `oauth/` - The OAuth/OIDC values both processes share: token, JWT and JWKS types, the PKCE
  challenge helper, and the error response of RFC 6749 section 5.2. `ErrorDetail` is a comparable
  struct of code, description, HTTP status and WWW-Authenticate challenge, read through `Code()`,
  `Description()`, `HTTPStatus()` and `WWWAuthenticate()`, whose `Is` compares with `==`;
  `ConformErrorDescription` replaces every character RFC 6749 Appendix A.8 forbids in an
  `error_description` and bounds the result to 512 bytes, because a description interpolates request
  text and, since #213's deferral, is parked on an auth context every request of that ceremony then
  carries. Both were `core/customerrors`, the detail a map, until #442. The admin console's client
  of the protocol — JWKS parser, token client, authorize redirect — is
  `adminconsole/internal/oauthclient`; `response_type` parsing is the provider's and is in
  `authserver/internal/protocolvalidation` (#385). `IsWellFormedSpaceDelimited` and
  `SplitSpaceDelimited`, the one grammar and the one splitter of the five space-delimited request
  parameters (exactly one space between values, none at either end, and no other separator), are
  here because `core/i18n` reads `ui_locales` with them in a middleware both processes mount (#244)
- `passwordblocklist/` - The two whole-password checks the `nist` password policy is written to
  apply: `IsCommon`, whether a password, lowercased, is an entry of the built-in list of commonly
  used passwords, compared whole and never as a substring, and `IsTooClose`, whether it is one of
  the words it is given (the account's email, its local part, its username, the app name) or that
  word repeated, each read lowercased as is and with digits and symbols trimmed from both ends. The
  list is `data_generated.go`: the 16,043 entries of 15 characters or more and at most 72 bytes of
  the NCSC's top 100,000, Pwdb's top 1,000,000 and xato's top 1,000,000, their hashcat `$HEX[]`
  lines read as the passwords they encode, lowercased and de-duplicated, written by `generate/` from
  the three lists at a pinned SecLists commit, each checked against the SHA-256 it pins, its header
  naming each source and licence. A leaf importing the standard library alone, for
  `adminpassword/`'s reason, held there by `AssertImportsOnly` from `core/guard`'s
  `imports_only_lint_test.go` (#550)
- `passwordrules/` - The one wording of the stored password policy's rules, `Describe`: the sentence
  a page that sets a password shows under the field, built from `api.PasswordRulesResponse`, the
  rules as data the anonymous public settings carry, the length, the kinds of character required and
  whether common passwords and the account's words are refused. The auth server's registration,
  activation and reset forms and the admin console's change-password, new user and Authentication
  tab pages all call it, so the two applications cannot word the same rules differently; the auth
  server maps a policy to its rules in `internal/apimapping`, from what its validator applies (#550)
- `phonecountries/` - The phone country list a user picks a phone number's country from: one entry
  per country and E.164 calling code, built once from `countries/`, sorted by country name, with
  `ByUniqueID` its lookup. An entry's id, `<alpha3>_<index>`, is stored on the user row, so the
  order of a country's codes is stored data (#432). It left core for
  `authserver/internal/phonecountries` in #344, when no console code read it, and came back in #563
  so the admin console's two phone pages can build their list from it instead of asking the admin
  API, which refuses a token carrying `authserver:manage-account` alone
- `requestid/` - The request id both servers carry: `Middleware` adopts an incoming `X-Request-Id`
  verbatim or mints `<hostname>/<10 base62>-<counter>`, exactly as chi's middleware did, and writes
  no response header; `FromContext` is how the log handler, the audit log, the error pages and the
  500's `error_description` read it, and `NewContext` how a test plants one (#462)
- `routing/` - The router both servers register their routes on, built on `net/http.ServeMux`:
  `Use`, `With`, `Route`, the method verbs, `NotFound` and `Walk`, as chi's route tables used them.
  It decides once what every route follows: a group's middleware meets an unmatched path under it
  first, then the 404 of the router the group was created from, or a 405 with an empty body and an
  `Allow` naming every registered method, HEAD only where registered; a non-canonical path is a 404,
  never ServeMux's redirect; a route is named in chi's spelling, read by `RouteName` once reached
  and by `RouteFor` before routing; a path's parameters have one name for every method registered on
  it, and a method naming them otherwise, or in another order, panics at registration, as OpenAPI
  requires of one path (#651). `metrics.HTTPRequests` and `httpmw.BodyLimit` read routes from it. It
  replaced chi, which no module requires any more (#462)
- `securerandom/` - Random strings over `crypto/rand`, drawn by rejection sampling so an alphabet
  whose length does not divide 256 introduces no modulo bias: `String(n)` over the alphabet ids,
  secrets and security tokens are minted over, `StringFromAlphabet(n, alphabet)` over one the caller
  names, at most 256 bytes. Neither returns an error, because a CSPRNG failure ends the process
  (#211). It was `core/stringutil` until #442, which deleted the auth server's `randomstring`
  wrapper beside it
- `sessionstore/` - The server-side session store and its codec, which is where an `AuthContext`
  lives; the cookie carries the key and nothing else (#266). The one exception is
  `SealCookieValues`, `OpenCookieValues` and `ValuesCookie`: a short-lived state a browser carries
  itself, sealed under a key of its own so it never opens as a session cookie, which the admin
  console's sign-in handshake rides in from the authorize redirect to the callback, so an anonymous
  request to `/admin` or `/account` writes no row (#620). `Options` is the six cookie attributes
  this repository sets rather than an `http.Cookie`, so a MaxAge below zero is the one way to say
  "delete this" and there is no `Expires` beside it to disagree (#269). It holds the one session-key
  rule both configurations apply, `ParseKeys`, whose refusals name the variable each value was
  configured under (#434). `ConditionalStore` writes a session on condition nothing wrote it since a
  fresh read, which the auth server's store is built with and the admin console's is not, so the
  console's browser session stays last-writer-wins (#579). `GetFresh` loads the session as stored
  now, past the request's memo and writing nothing, which the admin console's refresh re-reads
  through under its per-session lock (#621)
- `sourceroot/` - The one declaration of the four module directories, `ModuleDirs`, and the ascent
  that finds the source root from them, `FindSourceRoot`, which the tree-wide guards (through
  `guard.SourceRoot`), `ownershipdump` and the auth server's `schemadump` root their walks with. It
  left `core/internal/refgraph` because Go's internal rule kept `schemadump` from reading it there,
  which is how the same four directories came to be declared twice (#480)
- `timezones/` - The IANA zone table a user's zone is picked from, one row per country and zone,
  generated from the tzdata release and SHA-256 its generator pins. Nothing loads it at startup; a
  test checks every zone loads (#49, #432)

### Auth Server (`src/authserver/`)
- `internal/handlers/` - HTTP handlers (auth flows, token, userinfo, DCR). A ceremony handler keeps
  only the HTTP side of its step: the route boundary (`CeremonyBoundary`, `auth_ceremony.go`), its
  `internal/authflow` operation called with a per-request browser adapter (`browserSession`,
  `browser_session.go`), and the response its result names, written through the client-error
  responder (`ClientErrorResponder`) or a step redirect. The device cookie is read and written here
  (`device_cookie.go`). `doubled_services.go` declares, whole, the six services the route table
  hands straight to the operations, which no handler takes, so mockery generates the doubles the
  handler tests build every operation from (#580)
- `internal/handlers/accounthandlers/` - Pages reached without a session: self-registration and its
  activation link, forgot password and its reset link (#435)
- `internal/handlers/apihandlers/` - Admin API handlers
- `internal/{ceremony,issuance,signingkeys}/` - Provider-side issuance: codes, tokens, key rotation,
  ceremony context
- `internal/authflow/` - The ceremony steps' operations, one per step: its loads, the decision it
  applies, its database and browser-session writes, and a typed result its handler answers from. It
  cannot reach HTTP (`import_lint_test.go` refuses `net/http`, `core/routing`, `core/httpmw`,
  `core/requestid`, `internal/handlers`, `internal/middleware` and `internal/reqctx`): what the
  request carries arrives as plain values, every browser-session write goes through a port the
  handler satisfies with a per-request adapter (`handlers.browserSession`), and the handler writes
  the response after the operation returns. Every ceremony route has one: `/auth/authorize`
  (`Authorization` on the GET, which creates the ceremony and routes it with `decideAuthorizeRoute`,
  after `ResolveParked` swaps in a parked request; `AuthorizationParking` on the POST),
  `/auth/level1` (`SelectLevel1Method`), `/auth/level1completed` (`Level1Completion`),
  `/auth/level2` (`Level2Selection`), `/auth/pwd` (`PasswordPrompt` on the GET and beside a refusal,
  `PasswordSubmission` on the POST), `/auth/otp` (`OTPPrompt` on the GET, `OTPSubmission` on the
  POST), `/auth/recovery-codes` (`RecoveryCodesPrompt` on the GET, `ContinueAfterRecoveryCodes` on
  the POST), `/auth/completed` (`Completion`), `/auth/consent` (`ConsentPrompt` on the GET,
  `ConsentSubmission` on the POST), `/auth/issue` (`Issuance`) and a `prompt=none` request at
  `/auth/authorize` (`SilentAuthentication`, with `decideSilentAuthentication`, which
  `Authorization` hands it to). The handlers keep what reads the request and writes the response:
  `/auth/authorize`'s parameter parse, its settings read and its `ui_locales` swap of the request's
  localizer among them (#580)
-
  `internal/{permissions,usercreation,usersession,useragent,emaildelivery,otp,imageupload,uithemes}/`
  - Application services and leaf helpers: permissions, user creation, sessions, email, OTP, image
  uploads, themes
- `internal/clientauth/` - Client authentication from plain values, the client identifier and the
  secret presented: the lookup, the secret check and their refusals' wording and shape, shared by
  every endpoint that authenticates its caller. Reading the credentials off a request and logging a
  refusal stay in `internal/handlers`. It also declares `ChallengeRealm`, the realm the Basic and
  Bearer challenges share, as the lowest package that writes a challenge (#676)
- `internal/introspectionmetrics/` - `goiabada_introspection_requests_total`, the introspection
  endpoint's answers by outcome, a closed set (#676)
- `internal/liveness/` - Whether a token the auth server issued is still live. An access token:
  its header is `at+jwt` and its `iss` the configured issuer (RFC 9068 section 4); its client exists
  and is enabled; its user exists and is enabled; its `sid` session exists, belongs to the user, is within its
  bounds and on the user's generation; or, without `sid`, its own generation is current; and, with
  `grant_id`, its refresh token family has no revocation record and a member not revoked. A refresh
  token: `FindRefreshToken` reads its row and what it names, and `RefreshToken` judges the state the
  refresh grant checks, leaving ownership, PKCE and scope to the grant's validator. Each returns a
  verdict and leaves the answer and the log record to the caller: the bearer guard
  `RequireValidSession`, the refresh grant, revocation and introspection, so they cannot disagree.
  `Subject` is the one reading of a token's subject, which `reqctx` answers through (#676)
- `internal/revocation/` - The six revocation operations, their results, reason constants and audit
  helpers, the sixth, `RevokeGrantTx`, ending one grant at its client's request at `/auth/revoke`
  (#676). No handler package owns revocation orchestration or its transactions any more (#387)
- `internal/revocationmetrics/` - `goiabada_revocation_requests_total`, the revocation endpoint's
  answers by outcome, a closed set (#676)
- `internal/recovery/` - The `recover` subcommand's operation, `Run`: for one named, enabled user, a
  manage grant, a password held to the stored policy and the authenticator's removal, each only as
  asked, in one transaction with the #106 revocation sweep, the user, the authenticator and the
  sessions and refresh tokens swept read under the user's row, taken first, and the held grant under
  the manage permission's, taken after it, where the Admin API's grant saves take that row first and
  never the user's, so a save and a recovery can deadlock, as they do on MySQL, and
  `RunInTransaction` reruns the one the engine rolls back (#301), and the audit events after the
  commit naming the command under `command`. The command in `cmd/goiabada-authserver` parses,
  refuses a schema other than its head, and prints; the data tier runs `Run` on every engine (#498)
- `internal/reqctx/` - The five request-scoped values (settings, session identifier, bearer token,
  validated token, and the credential reservation a failures-only rate-limit tier holds), each
  written by one middleware and read through a typed accessor; services take theirs as parameters,
  and the context-value guard holds every module file to them with no exemption (#433, #439)
- `internal/otpcredential/` - The stored TOTP credential: establish, remove, verify a stored or a
  supplied code, and the seed's encryption at rest. A removal also lowers the user's sessions to
  what a password alone reaches, in the same transaction and one statement (#542). `OTPClaim` is
  here too: a sign-in's claim to a one-time code stands only while the user still has the
  authenticator it came from, which `/auth/completed` and `/auth/issue` ask, and the session writes
  and both issuers ask again under the user's row lock (`Recheck`, #542). `internal/otp` underneath
  stays the stateless primitive (#387)
- `internal/userclaims/` - The one stored-user-to-OIDC-claims conversion, serving `/userinfo` and
  issuance from the same mapper, with the two places those two disagree — the base URLs, the auth
  server's that `picture` is built on and the admin console's that `profile` is (#527), and which
  include flag filters groups and attributes — as inputs rather than merged away. `updated_at` was a
  third until it turned out to be a defect: it rides with the `profile` scope at every site now,
  which is what OIDC Core 5.4 and this repository's own docs site both say it is, where issuance
  used to emit it for any scope beyond a lone `openid` and, in an access token, for a lone `openid`
  too, because the audience loop extends the scope slice before the claim block reads it (#387,
  #422)
- `internal/userconsent/` - The stored consent a user gives a client: `Record` reads the row and
  creates or rewrites it with the scope the consent screen granted, replacing it whole. The handler
  parses, decides and answers (#437)
- `internal/authorizerequest/` - The authorization request a POST to `/auth/authorize` parks for the
  GET it is answered with: `Park` stores it under a one-time handle (only its digest is kept),
  `Consume` takes it once. The POST touches nothing of the browser's own session, because a
  cross-site POST arrives without the Lax cookie (#246, #437)
- `internal/afterresponse/` - The work a handler hands off so its response does not wait for it:
  `Go` runs a job under the request's context detached from its cancellation, so its records keep
  the request id, and `Wait`, called by the server once the listeners have drained, waits for the
  jobs in flight. Forgot-password's code store, audit record and mail run here, so every well-formed
  request answers alike, and so does the self-service email change's notice to the previous address,
  which never fails the change (#404). At most 64 jobs of each `Class` run at once, recovery,
  registration and the account notice each against a budget of its own, so the two public forms
  cannot fill the slot the authenticated notice needs; past that `Go` drops the job with one Warn
  record on the request's id, never running it inline, and a dropped job is never counted in flight
  (#485, #394 review)
- `internal/emaillinks/` - The emailed-link round trip for password reset and activation: build the
  link, mark it followed, redeem it once. Beside `emaildelivery`, which sends it (#387)
- `internal/{encryption,passwordhash,oidc,rsakey,urlmatch,uuid}/` - The authserver-only utilities
  #360 moved out of `core`: AES and bcrypt, discovery metadata, RSA key generation, redirect-URI and
  origin predicates, UUIDs (#360); `oidc` also holds the grant type list every grant-type reader
  consults and the `amr` values (#437); the encrypted id_token_hint's JWE, keyed from a client
  secret and sharing nothing with the data cipher, left `encryption` for `internal/idtokenhint`
  (#434)
- `internal/record/` - The persistence records (Client, User, Permission, Group, etc.), one struct
  per table: no cryptography, no claim construction, and nothing imported but the standard library,
  `core/builtin` and `core/errs` (#359, #387, #442)
- `internal/data/` - The composition-only `Database` interface, `commondb/`, the four engine
  adapters, and the generated `Database` mock that every narrow port is tested through (#354, #359,
  #386)
- `internal/data/datafactory/` - Database composition: engine selection, config mapping, the
  email-case pre-flight, which the migrator runs under its lock on its own connection (#542), the
  startup data tasks, which refuse a start whose data key opens none of the stored data (#353, #438,
  #542)
- `internal/bootstrap/` - The first run: which of the three bootstrap modes applies, and the seed,
  whose 18 writes commit in one transaction with the bootstrap file published only after it (#424).
  A seed that loses an empty database to another instance seeding it at once (a unique key, and the
  database now reads as seeded) carries on as a later start would (#542)
- `internal/server/routes.go` - All route definitions
- `web/template/` - HTML templates
- `tests/integration/` - Integration tests

### Admin Console (`src/adminconsole/`)
- `internal/handlers/` - Admin UI handlers
- `internal/apiclient/` - The admin API client: `AuthServerClient`, its methods behind the one
  deadlined, bounded executor, and `APIError`. There is no interface over it: each handler declares
  an unexported port beside the function taking it, and each test fake implements the port of the
  handler it is passed to, embedding no interface, so a method a handler starts calling that a fake
  lacks fails to compile rather than panicking at test time.
  `TestAuthServerClient_TheCharacterizationCoversEveryMethod` holds every exported method to a wire
  characterization row. One file per resource the methods call, with no `_client.go` suffix, and a
  test beside the file of the method it tests; `layout_test.go` holds both (#386, #441)
- `internal/publicsettings/` - The auth server's public settings every page renders with: `Client`
  reads `/api/public/settings` under its own timeout and bound, and `Cache` serves the answer for a
  TTL, every request arriving during a fetch sharing that one fetch with no lock held across it, and
  an `Invalidate` never undone by a fetch that started before it. It was `internal/cache`, and the
  client `apiclient.SettingsClient`, until #441
- `internal/reqctx/` - The two request-scoped values, the signed-in administrator's token set and
  the auth server's public settings, each written by one middleware and read through a typed
  accessor over an unexported key; an absent value is `ErrNoJwtInfo` or `ErrNoSettings` rather than
  a panic. The twin of the auth server's, and the context-value guard holds the module to it with no
  exemption (#440, #462)
- `internal/sessionbackend/` - The HTTP backend of `core/sessionstore` over the auth server's
  browser-session endpoint, the twin of the auth server's package of the same name, and its
  `TokenSource` port, which `oauthclient.SessionTokenSource` implements as a cache over the token
  client's client-credentials grant. It left `apiclient` in #441
- `internal/sessionkeys/` - The two keys of the console's browser session, the token set and its
  expiry, and the six of its sealed sign-in handshake. Stored data: a live session carries the two
  spellings, so renaming one signs every administrator out at deploy, and renaming one of the six
  fails the sign-ins in flight at the deploy. The six stay declared because they key the sealed map
  and the callback deletes the stale copies a session written before #620 can hold. It was
  `internal/constants` until the context keys left for `reqctx` (#440, #620)
- `web/template/` - Admin UI templates

## Configuration

Each application loads its own configuration from environment variables with the `GOIABADA_` prefix,
then parses its command-line flags. A flag overrides its environment value where a flag is
registered. Key environment variables:
- `GOIABADA_DB_TYPE` - sqlite/mysql/postgres/mssql
- `GOIABADA_AUTHSERVER_BASEURL` - Public URL
- `GOIABADA_ADMIN_EMAIL` / `GOIABADA_ADMIN_PASSWORD` - Initial admin

See `src/authserver/internal/config/config.go` and `src/adminconsole/internal/config/config.go` for
all options; each binary loads only its own. Each `main` loads it once, through its own
`config.Load(fs, args)`, refusing a malformed numeric or boolean variable on one stderr line with
exit 2, and hands the result to `server.NewServer`; the route table gives each handler the values it
uses (the base URL it redirects to, the auth server's) when it builds it. Neither binary keeps a
configuration global, and nothing reads one at request time (#434, #441).
