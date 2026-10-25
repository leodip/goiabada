# Application conventions

Apply the shared handler, error, logging and metrics conventions when changing application code.

Paths in backticks are relative to the repository root unless a module directory is named. Read the
sections relevant to the change; [AGENTS.md](../../AGENTS.md) lists the common commands.

## Handler signature

`HandleXxxGet/Post(dependencies...) http.HandlerFunc`

## Audit logging

All security events logged via `auditLogger` (see `authserver/internal/audit/events.go` for event
names)

## Permissions model

Resources contain Permissions; Users/Groups/Clients can have Permissions

## Credential form fields

A handler reads a credential-bearing field (`password`, `passwordConfirmation`, `currentPassword`,
`newPassword`, `newPasswordConfirmation`, `otp`, `secretKey`, `base64Image`, `verificationCode`,
`clientSecret`) and a form-binding marker (`ceremonyId`, `continuationId`) with `r.PostFormValue`,
never `r.FormValue`. `r.FormValue` merges the URL query behind the request body, so the value would
be accepted from the request target, where it reaches the browser's history, the `Referer` of
anything the page loads, and the access log of every proxy, gateway and CDN in front of the
deployment. Every such form is POST-only with a separate GET handler that renders it, so the query
is never a submission. Enforced by `core/guard.AssertNoCredentialQueryFallback`, which carries the
walk and the four merged-form accessors it refuses, called from a `credential_read_lint_test.go` in
each `internal/handlers` package and from `core/httpmw`; each caller owns its own name list, because
the lists must differ. The auth server's adds the four token-endpoint credentials (`code`,
`code_verifier`, `refresh_token`, `client_secret`) and `access_token`, which
`JwtAuthorizationHeaderToContext` in `authserver/internal/middleware` reads lawfully from a form
body per OIDC Core 1.0 5.3.1; the kernel's is `access_token` alone, and since #385 moved that read
out of core it refuses the read coming back rather than holding a site. Only `state` is exempt, at
`/auth/authorize`, which OIDC Core 3.1.2.1 requires the authorization endpoint to accept over GET as
well as POST; `code` is not, being an authorization *response* value the client returns in the
request entity-body (RFC 6749 4.1.2, 4.1.3) (#202, #333)

## Error handling

Every error this tree constructs goes through `core/errs` (`New`, `Errorf`, `Wrap`, `Wrapf`,
`WithStack`, `Join`), which captures one stack per error tree, the origin's, and prints it under
`%+v`; a package-level sentinel is the one exception and stays on stdlib `errors.New`, because a
stack captured at init would masquerade as the origin of everything wrapping it. Match with
`errors.Is` / `errors.As`, never a bare type assertion and never the error's text. `errorlint` in
`.golangci.yml` holds the first half; the few places that mean the error value itself carry a
`//nolint:errorlint` saying why: `core/errs`'s own tree walk, the migrator's `IsNoChange` and
`IsNilVersion`, whose identity is the whole test (#268), and the migrate command's `reportStop`.
`TestNoLegacyErrors` in `core/guard/errors_lint.go`, called from all three module tiers and walking
the whole of `src/`, refuses `github.com/pkg/errors`, stdlib `errors.New`/`errors.Join`/`fmt.Errorf`
in production code, and `errs.WithStack(errs.New(...))` and any `errs` constructor in a
package-level var, which is the sentinel rule enforced rather than merely stated (#279). In the
admin console a handler answers either a page or JSON, never both:
`NotFound`/`InternalServerError`/`HandleAPIError` render HTML, and
`JSONNotFound`/`JSONBadRequestBody`/`JSONError`/`HandleAPIErrorJSON` answer the same statuses as
JSON. Mixing them makes the browser's `response.json()` throw on that branch alone;
`TestHandlers_AjaxHandlersDoNotUsePageWriters` in
`adminconsole/internal/handlers/ajax_writer_lint_test.go` refuses it. Which of the two a handler
picks is the only decision it makes about an `apiClient` failure: `HandleAPIError`,
`HandleAPIErrorWithCallback` and `HandleAPIErrorJSON` turn the auth server's status into the
console's, and `TestHandlers_ApiClientErrorsReachTheClassifier` refuses a guard that answers one
itself or catches every status as a rejected value (#279). In the auth server the type makes the
choice: `internal/handlers` declares the page and JSON writers as two ports, `PageRenderer` and
`JSONWriter`, and hands the token, userinfo, JWKS and discovery endpoints only the second, so a page
writer there does not compile; `routes.go` registers them, registration and the APIs on the branches
of `initMiddleware` whose settings and session middleware answer their own faults, and a panic, as
JSON too (#435)

## Logging

`core/logging` owns the one `slog` handler, installed by both servers at startup. Every message is a
lowercase string literal with no `component:` prefix and no `failed to` or `error ` opener, the one
verb being "unable to"; values ride as snake_case attributes, one fixed name per concept, `error`
for an error, `client_identifier` for the wire string against `client_id` for the row id.
`request_id` is the handler's, injected from the context, so a site with a `context.Context` or
`*http.Request` in scope at any depth uses the `*Context` variant. Error means someone must act,
Warn a refused or handled request, Info lifecycle and configuration, Debug per-request tracing. Two
guards hold it. `sloglint`, enabled in `.golangci.yml` and run by `./run-tests.sh --type lint` and
CI's Lint job over type-checked code, holds the lowercase message, the snake_case keys, the refused
`err` and `request_id`, and the `*Context` rule; a function that hands its caller's key/value run to
a record is registered there under `custom-funcs` so the keys are read at its call sites.
`TestSlogConvention` in `core/guard/slog_lint.go`, called from all three module tiers, holds what
sloglint cannot express: that the message is a literal at the call rather than a constant, the
refused message openers, `slog.SetDefault`/`New`/`Default`/`With` outside the handler's own files, a
`...` spread into a record or a forwarder outside the functions `slogSpreadSites` lists, that list
against `custom-funcs`, and a plain `slog.Debug`/`Info`/`Warn`/`Error` in any production package
outside the directories `slogNoRequestDirs` lists, the ones with no request above them: the mains
and composition (both `config` and `server` packages, `datafactory`, `migrator`, the four engine
adapters, `bootstrap`), `cleanup`, the developer tools and generators, test support, and the setup
wizard. Each entry is one directory and not its subtree, so a package created anywhere else, beneath
a listed one included, is checked from its first commit (#442). The plain-record rule admits the
functions `slogPlainSites` names, each with the reason no context reaches it: the admin console's
template function `addUrlParam` and the `convertToString` it calls, `core/i18n`'s startup records in
`loadOverrideCatalogs` and `orEmpty`, and `StaticFS` and `TemplateFS` in each application's `web`
package. That rule is what refuses a new helper written without a context after sloglint has
admitted it. `AssertRequestPathContext` and `AssertAuditLogContext` share the same scope, and
`requestContextOwners` admits `core/i18n`'s `WithLocale`, whose background context is the fallback
for a nil one. A package holding both startup and request work, like `core/i18n` with its locale
middleware, stays in scope with its startup functions admitted by name. A request-path helper
therefore takes a `context.Context`; a helper with neither a context nor a request is a startup or
template site. No request-path writer is left carrying no `request_id`: the audit path was the last
but one until #328 gave `AuditLogger.Log` a context, and `commondb`'s transaction and statement
records were the last until #386 gave every `Database` method one. Level is not decidable and is
pinned per site through `logtest.CaptureSlog(t)`, the one way a test reads records (#320)

## Metric labels

A metric label takes only values from a closed set declared when its family is registered with
`core/metrics`, through `metrics.Enum` (listed in the catalog) or `metrics.Described` (named there
in words, for the status codes, the route table or the build stamp), and a value outside the set is
recorded as `other`, so no family can exceed the product of its sets whatever the requests. Nothing
taken from a request or from the database reaches a label without being mapped into a declared set
first: no user id, subject, email, username, session identifier, client identifier, IP address, raw
path, query, user agent or error description. `client_identifier` is never a label, because with
dynamic client registration on anyone can mint identifiers. The route label is the router's own
table read once at startup, `unmatched` for a request no route answered, read off the request
through `routing.RouteName` in `core/routing` by `metrics.HTTPRequests` in `core/metrics/http.go`;
the method label is a standard verb or `other`; the status label is the exact code. Each server's
unit tier holds every family it registers, name, type, labels and value sets, to the catalog table
on the docs' Monitoring page through `core/guard.AssertMetricsCatalog`, in both directions, so a new
family or label fails until the docs describe it (#400)
