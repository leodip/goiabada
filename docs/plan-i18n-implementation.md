# i18n Localization — Implementation Plan

Companion to `plan-i18n-localization.md`. Where the design doc says **what and why**, this plan says **how, in what order, with what file changes and tests**. Section references like "§6.X" point back to the design doc.

Status: draft for review.
Scope: 8 PRs, sequenced per design §6.6, English-fallback at every step.

## How to use this document

- Each PR has its own section with: goal, files added, files modified, public APIs introduced, test plan, acceptance criteria.
- A reviewer for any individual PR should read **only** the introduction plus that PR's section. Cross-PR concerns are surfaced explicitly.
- Anything that says "see design §X.Y" is intentional — the design doc is the authoritative source for *why*.

---

## 0. Pre-work and global decisions

These need a yes/no before PR 1 opens.

| Decision | Default | Owner |
|---|---|---|
| Country canonical code: **alpha-2** (recommended) vs alpha-3 | alpha-2 | project owner |
| Locale picker label format: **`Native (English)`** vs native-only | `Native (English)` | project owner |
| Reference-data v1 scope: **all three** (countries, timezones, phone) vs defer timezones | all three | project owner |
| `GOIABADA_I18N_OVERRIDES_DIR` env var name | as documented | project owner |
| API version bump strategy for §6.3 breaking change | **Default: stay on `/api/v1/`, announce via CHANGELOG only** (rationale below). Alternative `/v1` → `/v2` is materially larger PR 1 scope (route duplication, dual-contract maintenance) | project owner — confirm before PR 1 opens |

Until these are confirmed, PR 1 cannot land in final form.

**API versioning — why the default is "stay on `/api/v1/`".** The breaking change in §6.3 affects only the **error response shape** of admin/account endpoints. Success responses, request shapes, endpoint paths, and authentication are all unchanged. Goiabada's admin/account API consumers are predominantly the bundled adminconsole (which we update in PR 1) plus self-hosters' own scripts, who follow the CHANGELOG. Maintaining a `/api/v2/` route tree alongside `/api/v1/` for a deprecation window means duplicating every admin/account route and its error-emit path, doubling the surface PR 1 has to touch and adding ongoing maintenance until `v1` retires. CHANGELOG-only announcement is proportional to the change size.

If the project owner instead picks `/api/v2/`, PR 1's scope expands materially: every admin/account route gets a `/v2/` mirror, the dual-shape error helper has to know which version emitted the request, and the adminconsole client gains a path-version flag. This implementation plan assumes the default path; the alternative would warrant a separate scope review before PR 1 opens.

Suggested: confirm in the PR description when PR 1 opens; the §0 decisions show up explicitly in the diff and aren't worth blocking on up front.

---

## 1. Repository layout introduced

After PR 1, the new tree:

```
src/core/
├── i18n/
│   ├── i18n.go                  # bundle, T(), Localizer(), middleware glue
│   ├── middleware.go            # MiddlewareLocalePhase1, Phase2 helpers
│   ├── error.go                 # LocalizedError type, EnglishFallback()
│   ├── error_codes.go           # const ErrCodeXxx = "..." declarations
│   ├── error_codes.md           # human doc of every code, args, English msg
│   ├── system_entities.go       # registry: built-in entity ID -> catalog key prefix
│   ├── overrides.go             # GOIABADA_I18N_OVERRIDES_DIR loader
│   ├── catalogs/
│   │   ├── active.en.toml       # source of truth (English)
│   │   └── active.pt-BR.toml    # added in PR 8
│   └── reference/
│       └── en/
│           ├── countries.toml
│           ├── timezones.toml
│           └── phone_countries.toml
└── ...

scripts/i18n/
├── gen-reference.sh             # CLDR -> reference TOML bundles for any locale
└── lint-error-codes.sh          # CI: code↔catalog parity check
```

Adminconsole and authserver get no new top-level dirs; existing files are modified.

---

## 2. Public APIs introduced

The full surface that PR 1 establishes. Subsequent PRs only consume these; they do not extend the API except where noted.

```go
// Package src/core/i18n

// --- Bundle and lookup ---

// LoadBundle loads embedded catalogs and merges runtime overrides from
// GOIABADA_I18N_OVERRIDES_DIR. Called once at startup from main.
func LoadBundle() (*Bundle, error)

// T translates a key for the localizer carried on ctx. If the key is missing
// in the resolved locale, falls back to the English catalog. If still missing,
// returns the key itself (so missing keys are visible in the UI during dev).
// Args may be a map[string]any for templated messages.
func T(ctx context.Context, key string, args ...any) string

// Localizer returns the *i18n.Localizer attached to ctx by Phase 1 / Phase 2.
// Returns the English localizer if none is attached (test contexts, background
// jobs that never went through middleware).
func Localizer(ctx context.Context) *i18n.Localizer

// --- Locale resolution helpers ---

// MiddlewareLocalePhase1 is the global middleware. See design §6.12 step 4.
func MiddlewareLocalePhase1(authHelper AuthHelper) func(http.Handler) http.Handler

// MiddlewareLocalePhase2Adminconsole is the route-level middleware for
// adminconsole's authenticated chains (baseAuth, accountAuth, adminAuth).
// See design §6.16.
func MiddlewareLocalePhase2Adminconsole() func(http.Handler) http.Handler

// RefineLocalizerWithUser is the authserver per-handler refinement helper.
// Returns a NEW *http.Request with an updated context. Dropping the return
// value silently leaves the localizer at Phase 1 state. See design §3.2 / §6.12.
func RefineLocalizerWithUser(r *http.Request, user *models.User) *http.Request

// RefineLocalizerContext is the context-shaped form of the same logic, for
// background workers. See design §3.2.
func RefineLocalizerContext(ctx context.Context, user *models.User) context.Context

// RefineLocalizerWithUILocales is used by handler_authorize.go after
// capturing a form-body ui_locales. Returns a new request. See design §6.1.
func RefineLocalizerWithUILocales(r *http.Request, uiLocales []string) *http.Request

// SanitizeUILocales applies the §6.1 rules: trim, BCP47 shape filter,
// cap 10 tags / 256 bytes. Returns the filtered list.
func SanitizeUILocales(raw string) []string

// IsMachineRequest classifies a request as Surface B (machine) vs Surface A
// (browser) per design §6.13. Used at middleware error-emit sites.
func IsMachineRequest(r *http.Request) bool

// --- Errors ---

// LocalizedError carries a key plus args; the message is rendered on demand.
// Implements error. EnglishFallback() returns the rendered English message
// for protocol response paths that must stay English.
type LocalizedError struct {
    Code string         // one of error_codes.go constants
    Args map[string]any // substituted into the message at render time
}

func NewLocalizedError(code string, args map[string]any) *LocalizedError
func (e *LocalizedError) Error() string             // returns EnglishFallback()

// EnglishFallback renders the English catalog template for e.Code with e.Args
// substituted. "Fallback" means it does not require a request-bound localizer
// (English is the always-available source-of-truth catalog) — it does NOT
// mean args are dropped. Used at protocol response boundaries where the
// response must stay English regardless of caller locale (§6.2). Args are
// fully substituted; e.g., a "max length" code with Args{"max": 60} renders
// "...no longer than 60 characters." in English.
func (e *LocalizedError) EnglishFallback() string

// Localize renders against the locale carried on ctx (or English if none),
// with e.Args substituted.
func (e *LocalizedError) Localize(ctx context.Context) string

// --- System entity helper (for §6.10) ---

// SystemEntityDisplay returns the localized display name for a built-in
// entity (admin client, authserver resource, system permission). For
// user-created entities (not in the registry), returns the DB value
// verbatim. Used in templates via the funcmap.
func SystemEntityDisplay(ctx context.Context, kind, identifier, dbFallback string) string
func SystemEntityDescription(ctx context.Context, kind, identifier, dbFallback string) string
```

Template funcmap additions (registered in `src/core/handlerhelpers/template_funcs.go`):

```
T              // i18n.T
TPlural        // pluralized variant when needed
SysName        // i18n.SystemEntityDisplay
SysDesc        // i18n.SystemEntityDescription
DirAttr        // returns "ltr" or "rtl" for the active locale (deferred use)
```

---

## 3. PR 1 — Infrastructure + login page proven end-to-end

**Goal.** Land the i18n machinery, prove it works on one page (login), establish patterns for every later PR. This is the largest and most foundational PR; subsequent ones are mostly mechanical extraction.

**Scope summary.**

- New `src/core/i18n/` package with the public API in §2.
- Funcmap hook.
- Phase 1 middleware (global, both modules).
- Phase 2 middleware (adminconsole only) wired into route chains.
- `RefineLocalizerWithUser` helper for authserver handlers.
- `AuthContext.UILocales` field, sanitization, capture from authorize handler.
- `profile` scope added to adminconsole's JWT request (§6.15).
- `/unauthorized` wrapped with `baseAuth`.
- API error contract migration to flat shape (§6.3).
- Country-code canonicalization refactor (§6.17 prework).
- One end-to-end localized page: login (`/auth/pwd`).
- English catalog skeleton with login-page keys.

**Files added.**

| Path | Purpose |
|---|---|
| `src/core/i18n/i18n.go` | Bundle, `T`, `Localizer`, embedded FS via `//go:embed catalogs/* reference/*` |
| `src/core/i18n/middleware.go` | `MiddlewareLocalePhase1`, `MiddlewareLocalePhase2Adminconsole`, refinement helpers |
| `src/core/i18n/error.go` | `LocalizedError` type, `EnglishFallback`, `Localize` |
| `src/core/i18n/error_codes.go` | Code constants (initially small set; PR 4 expands) |
| `src/core/i18n/error_codes.md` | Doc of every code |
| `src/core/i18n/system_entities.go` | Registry skeleton; populated more in PR 3 / PR 5 |
| `src/core/i18n/overrides.go` | `GOIABADA_I18N_OVERRIDES_DIR` loader |
| `src/core/i18n/catalogs/active.en.toml` | Login-page keys, scope description keys (§6.9), error code keys for the login flow |
| `src/core/i18n/catalogs/active.pt-BR.toml` | **Minimal stub** — only the login-page keys translated. Lets PR 1's canary tests assert end-to-end multi-step localization without standing up the full pt-BR translation. PR 8 expands this file to cover the entire English catalog. |
| `src/core/i18n/i18n_test.go` | Bundle load, T fallback chain, override merge |
| `src/core/i18n/middleware_test.go` | Phase 1 precedence, Phase 2 override, explicit-intent suppression |
| `src/core/i18n/sanitize_test.go` | `ui_locales` bounds and BCP47 filter |

**Files modified.**

| Path | Change |
|---|---|
| `go.mod`, `go.sum` (in each of the 3 modules) | Add `github.com/nicksnyder/go-i18n/v2` and `golang.org/x/text` |
| `src/core/oauth/auth_context.go` | Add `UILocales []string` field; serialize/deserialize in existing JSON marshalling |
| `src/core/handlerhelpers/auth_helper.go` | No signature change; `GetAuthContext(r *http.Request)` already exists. Add helper to set `UILocales` if needed |
| `src/core/handlerhelpers/template_funcs.go` | Register `T`, `TPlural`, `SysName`, `SysDesc`, `DirAttr` in `templateFuncMap` |
| `src/authserver/internal/server/server.go` (around `:202`) | Insert `MiddlewareLocalePhase1` between `MiddlewareSessionIdentifier` and the rest. Order per §6.12 |
| `src/adminconsole/internal/server/server.go` | Register `MiddlewareLocalePhase1` globally (root router) before any route-level chain |
| `src/adminconsole/internal/server/routes.go` (around `:59`, `:79`) | Insert `MiddlewareLocalePhase2Adminconsole` into `baseAuth`, `accountAuth`, `adminAuth` immediately after JWT validation. Wrap `/unauthorized` with `baseAuth`. Audit and explicitly mark every public route as "Phase 1 OK" or "needs baseAuth" |
| `src/core/middleware/middleware_jwt.go` (around `:310`) | Add `profile` to scope set requested by adminconsole |
| `src/authserver/internal/handlers/handler_authorize.go` (around `:91`) | Capture `r.FormValue("ui_locales")` → `SanitizeUILocales` → store on `AuthContext.UILocales`. Call `r = i18n.RefineLocalizerWithUILocales(r, captured)` before any browser-visible response |
| `src/authserver/internal/handlers/handler_auth_pwd.go` | First localized handler. Loads user on POST; calls `r = i18n.RefineLocalizerWithUser(r, user)`; renders with `r` |
| `src/authserver/web/template/auth_pwd.html` | Convert every English literal to `{{ T $.ctx "auth.pwd.<key>" }}` |
| `src/authserver/web/template/layouts/auth_layout.html` | Layout-level strings (header, footer) become `{{ T }}` calls — only touch the parts visible on the login page in PR 1; others come in PR 2. (No bind-map manipulation here; `ctx` is injected by the renderer per the line below.) |
| `src/core/handlerhelpers/http_helper.go` (around `:72`) | **Renderer-level `ctx` injection.** The current renderer injects `app`/`settings` fields only; templates have no way to add into the Go bind map themselves. Add `data["ctx"] = r.Context()` (or merge an `i18nCtx` object) into the bind map immediately before `template.Execute`. This is the single canonical injection point — every template that uses `{{ T $.ctx ... }}` relies on this happening here. Adminconsole uses the same helper, so a single change covers both modules. If adminconsole has a separate render path, it gets the same treatment. |
| `src/authserver/internal/handlers/apihandlers/api_common.go` (around `:12`) | New flat error shape from §6.3. Add helper `EmitError(w, status, category, code, args, fallback)` |
| `src/core/api/responses.go` (around `:380`) | Update internal API response builder to new shape |
| `src/adminconsole/internal/apiclient/auth_server_client.go` (around `:141`) | Parse new shape (read `error_code` and `error_args`) |
| `src/adminconsole/internal/handlers/api_error_helper.go` (around `:20`) | Read `error_code` + `error_args`, localize via `T` |
| Admin/account API handlers across `src/authserver/internal/handlers/apihandlers/` | Migrate every `EmitError`/equivalent call to the new shape (mechanical) |
| `src/adminconsole/web/template/account_address.html` (around `:74`) | Form posts canonical country code (alpha-2 if that's the decision) |
| `src/adminconsole/web/template/admin_users_address.html` (around `:69`) | **Same country dropdown on the admin-user-edit surface.** Easy to miss; it shares the country-select pattern with `account_address.html` and must be migrated together to keep stored values consistent |
| `src/core/validators/address_validator.go` (around `:51`) | Lookup by canonical alpha-2; reject anything else (including the alpha-3 codes the form used to post) |
| Admin-user CRUD handlers in `src/adminconsole/internal/handlers/adminuserhandlers/` (or wherever admin-user POST handling lives — verify path during scope) | Accept and validate the canonical code on admin-user form submission, mirroring the account-side change |
| `src/core/data/{sqlite,mysql,postgres,mssql}db/migrations/000019_canonicalize_address_country_alpha2.{up,down}.sql` | **New data-only migration** that converts existing alpha-3 values (the form's old shape) to alpha-2 via a CASE statement keyed by `address_country`. Pairs are sourced from `biter777/countries.All()` (the lib already pinned in `core/go.mod`); a small one-shot generator was used to emit the four files and then discarded — the SQL header retains a provenance note. Down migration is an intentional no-op (conversion is one-way — pre-migration state contained a mix of alpha-3, alpha-2 and free-form names, so blind reverse would corrupt rows that were already alpha-2). The four DB dialects use identical SQL (CASE WHEN is portable). Schema unchanged → no `schema.sql` snapshot updates needed. |
| Any OpenAPI / API spec docs that reference country shape | Update to document the canonical code value. If admin API endpoints accept country in request bodies, update request/response schemas accordingly |

**APIs introduced.** All of §2 except `SystemEntityDescription` (used starting in PR 3).

**Test plan.**

Unit tests:
- Bundle loads embedded catalogs correctly.
- `T` returns English when locale not registered.
- `T` returns key string when neither locale nor English has it (visible-miss policy).
- Override directory merges over embedded; logs once per overridden key.
- `SanitizeUILocales`: empty, garbage, too-many-tags, too-many-bytes, mixed valid/invalid.
- Phase 1 precedence: query → AuthContext → Accept-Language → English (table-driven).
- Phase 1 reads `AuthContext.UILocales` from session via existing `GetAuthContext(r)`.
- Phase 2 (adminconsole) reads `locale` claim from JWT; falls back to Phase 1 when claim missing.
- Phase 2 skips override when current request has `ui_locales` query.
- Phase 2 skips override when `AuthContext.UILocales` is set (the §6.4 mid-flow rule).
- `RefineLocalizerWithUser` returns a new request; the original request's context is unchanged.
- `RefineLocalizerWithUser(r, user)` with `User.Locale = ""` is a no-op (stay on Phase 1).
- `RefineLocalizerWithUILocales` round-trips through context retrieval.
- `IsMachineRequest`: matches each surface-B endpoint; returns false for browser paths.

Integration / handler tests:
- Login page in `Accept-Language: en-US`: renders English.
- Login page in `Accept-Language: pt-BR` with no pt-BR catalog yet: renders English (graceful fallback).
- Login page with `?ui_locales=pt-BR` and a stub pt-BR catalog: renders pt-BR.
- POST `/auth/authorize` with `ui_locales=pt-BR` in form body: AuthContext stores it; redirect to `/auth/pwd` renders pt-BR.
- Multi-step: hit `/auth/authorize?ui_locales=pt-BR`, follow redirect to `/auth/pwd`, submit credentials, follow redirect to `/auth/consent`. All three pages render in pt-BR. **This is the canary test that proves §6.1 works.**
- Adminconsole login: token contains `locale` claim (verifies §6.15 step 1).
- Adminconsole user with stored `Locale = pt-BR` lands on a localized dashboard (will render English until PR 3 lands a localized adminconsole page; assertion is on the localizer attached to context, not visible text).
- Admin API endpoint that errors: returns flat-shape JSON `{error, error_code, error_args, error_description}`.
- Adminconsole consumer of that endpoint: `api_error_helper` returns localized text for `error_code`.
- Address form submits canonical country code; validator accepts; round-trip through DB preserves it.

Regression tests:
- Middleware composition order: assert `MiddlewareSettings → MiddlewareCookieReset → MiddlewareSessionIdentifier → MiddlewareLocalePhase1 → ...` in authserver chain.
- Middleware composition order in adminconsole: Phase 1 global, Phase 2 inside each authenticated chain.
- Existing protocol error responses unchanged: `/auth/token` with bad credentials returns identical English JSON to pre-PR.
- Existing OIDC discovery, JWKS unchanged.

**Acceptance criteria.**

- [ ] PR opens with §0 decisions confirmed in the description.
- [ ] `/auth/pwd` renders in English by default and in pt-BR when `ui_locales=pt-BR` is supplied (catalog stub for pt-BR shipped with this PR for the login page only).
- [ ] Multi-step auth flow preserves `ui_locales` end-to-end (canary test green).
- [ ] Adminconsole token includes `locale` claim.
- [ ] `/unauthorized` page renders in the user's stored locale.
- [ ] Admin/account API responses use new flat shape; adminconsole reads it correctly.
- [ ] CHANGELOG entry for the API breaking change.
- [ ] All existing tests pass (no regressions on protocol endpoints).
- [ ] `./run-tests.sh` clean (per CLAUDE.md).
- [ ] Country canonicalization refactor lands in this PR; address form round-trip works.

---

## 4. PR 2 — Authserver template extraction

**Goal.** Extract every English literal in authserver templates into the catalog. After this PR, authserver UI pages all consume `T`.

**Scope summary.**

- 24 template files under `src/authserver/web/template/` (login already done in PR 1, so 23 remaining).
- All bind maps gain `ctx` (or use the renderer-injection helper from PR 1).
- New catalog keys under `auth.<page>.<key>` and `account.<page>.<key>`.
- Strict-`len(bind)` test assertions updated (per project memory).

**Files modified.**

- All `.html` files under `src/authserver/web/template/` and subdirectories.
- Each handler in `src/authserver/internal/handlers/` and `src/authserver/internal/handlers/accounthandlers/` that builds a bind map: ensure `ctx` is included.
- `src/core/i18n/catalogs/active.en.toml`: add ~hundreds of keys.

**Files NOT touched in this PR.**

- Email templates (PR 6).
- Admin API handlers' error messages — that's PR 4.
- JS files (PR 7).
- Adminconsole templates (PR 3).

**Conventions.**

- Key naming: `auth.<page_short_name>.<element>`. Examples: `auth.pwd.title`, `auth.pwd.field.email_label`, `auth.consent.button.allow`.
- Every page's H1 / page title gets `auth.<page>.title` and `auth.<page>.page_title` (HTML `<title>` may differ).
- Strings shared across templates (e.g., "Cancel", "Save") go under `common.button.cancel` etc. — finite set, prevents key explosion.
- Parameters use go-i18n `TemplateData`. Example: `auth.pwd.error.too_many_attempts = "Too many attempts. Try again in {{.minutes}} minutes."`.

**Test plan.**

- Update affected handler unit tests to expect `ctx` in bind map (per project memory: handler tests use strict `len(bind)`).
- Snapshot test per page (English): rendered HTML matches a fixture. Catches accidental literal preservation.
- Visual sanity: render every authserver page in `Accept-Language: en` and diff against pre-PR baseline.

**Acceptance criteria.**

- [ ] No literal English strings in any `.html` file under `src/authserver/web/template/` (CI lint: grep for non-`{{ T }}` text content).
- [ ] All 23 (+1 from PR 1) page snapshot tests pass.
- [ ] `active.en.toml` keys validated by code↔catalog parity script.

---

## 5. PR 3 — Adminconsole template extraction

**Goal.** Same as PR 2 but for adminconsole's 85 templates.

**Scope summary.**

- 85 template files under `src/adminconsole/web/template/`.
- Layout templates (`layouts/admin_layout.html`, etc.) — extract once, applies everywhere.
- System entity rendering (§6.10) wired up here: any place that reads admin-client / authserver-resource / system-permission name from DB now goes through `SysName` / `SysDesc` template helpers, with the registry covering exactly the seeder's built-in identifiers.
- Sub-PRs allowed if review surface gets too big (suggested split: layouts + admin sections in one, account sections in another).

**Files added.**

| Path | Purpose |
|---|---|
| `src/core/i18n/system_entities.go` (expanded) | Populate registry with seeder's identifiers |
| `src/core/i18n/catalogs/active.en.toml` | New keys under `admin.*`, `system.client.*`, `system.resource.*`, `system.permission.*` |

**Files modified.**

- All `.html` under `src/adminconsole/web/template/`.
- Adminconsole handlers building bind maps: include `ctx`.
- Templates rendering admin client / authserver resource names: replace direct DB-value rendering with `{{ SysName $.ctx "client" .Identifier .DisplayName }}` (the third arg is the DB fallback for user-created entities).

**Test plan.**

- Adminconsole handler test files (per project memory: most don't exist; this PR may add `test_main_test.go` parity for the bigger handlers).
- Snapshot tests for each adminconsole page in English.
- System entity tests: built-in identifier renders catalog value; user-created identifier renders DB value verbatim.
- Test that the registry keys match what the seeder produces (lockstep).

**Acceptance criteria.**

- [ ] No literal English strings in `.html` files under `src/adminconsole/web/template/`.
- [ ] System entity rendering verified for the admin client and authserver resource on the relevant pages.
- [ ] Snapshot tests cover all 85 pages.
- [ ] Code↔catalog parity check passes.

---

## 6. PR 4 — UI validator + handler error/flash migration

**Goal.** Move every UI-facing error and flash message into the `LocalizedError` model with stable error codes; protocol validators stay English (§6.2).

**Scope summary.**

- UI validators under `src/core/validators/` migrate to `LocalizedError` returns.
- Protocol validators (`authorize_validator.go`, `token_validator.go`, plus DCR/revoke/introspect validators) stay untouched.
- Shared validators (e.g., email): return `LocalizedError`; protocol callsites call `err.EnglishFallback()` before constructing OAuth error response.
- Handler error returns and flash messages migrate.
- `error_codes.go` and `error_codes.md` populated with the full taxonomy.
- §6.13 surface comments added at every error-emit site.
- `IsMachineRequest` consumer wired into `middleware_jwt.go:125` and `api_auth.go:21`.
- CI lint script for code↔catalog parity (`scripts/i18n/lint-error-codes.sh`).

**Files added.**

| Path | Purpose |
|---|---|
| `scripts/i18n/lint-error-codes.sh` | Asserts every `validator.*` / `handler.*` catalog key has a matching code constant and vice versa |

**Files modified.**

- UI validators: `address_validator.go`, `email_validator.go`, `password_validator.go`, `phone_validator.go`, `identifier_validator.go`, plus any other validator file used outside protocol paths. Inventory before migration to confirm classification.
- All authserver handlers under `src/authserver/internal/handlers/` (browser-flow ones) and `src/authserver/internal/handlers/accounthandlers/`: convert flash and error messages to `LocalizedError`.
- All adminconsole handlers under `src/adminconsole/internal/handlers/`: same.
- Admin API handlers: emit `LocalizedError` via the API shape from PR 1.
- `src/core/middleware/middleware_jwt.go:125`: split error path with `IsMachineRequest`; browser → localized HTML, machine → §6.3 shape.
- `src/authserver/internal/middleware/api_auth.go:21`: machine path, English §6.3 shape.
- `src/core/handlerhelpers/http_helper.go:43`: localized HTML for browser surface A.
- Every emit site gets a `// i18n surface: A | B | C` comment per §6.13.

**Files NOT touched.**

- Protocol validators (`authorize_validator.go`, `token_validator.go`, etc.).
- Protocol response constructors (`/auth/token` etc.).

**Test plan.**

- Per migrated validator: existing tests updated to assert on `LocalizedError.Code` and `Args`, not on rendered string.
- Add a "render in pt-BR catalog stub" test for each major error code group, asserting the localized output appears.
- Protocol validator regression: feed bad input to `/auth/token`, assert response is byte-identical to pre-PR (no localization slipped in).
- CI lint runs in this PR's pipeline; failing parity blocks merge.
- `IsMachineRequest` table-driven tests covering every surface-B endpoint plus a representative surface-A path.
- `middleware_jwt.go` failure: hit a protected browser route without auth → localized HTML page; hit an API route without auth → English JSON in §6.3 shape.

**Acceptance criteria.**

- [ ] `error_codes.md` lists every defined code.
- [ ] CI lint passes (no orphan codes, no orphan keys).
- [ ] Protocol error responses byte-identical to pre-PR (regression suite).
- [ ] Every error-emit site has a surface comment.
- [ ] Adminconsole shows localized validation messages from authserver API responses.

---

## 7. PR 5 — Reference-data dropdowns

**Goal.** Localize country, timezone, and phone-country labels; localize the locale picker.

**Scope summary.**

- CLDR-derived per-locale reference bundles (English baseline ships in PR 1; this PR fills out the wiring and adds the generator script).
- Locale picker `Native (English)` rendering (§6.11).
- Built-in system entity rendering already wired in PR 3; no further work here unless gaps surface.
- Country canonicalization already done in PR 1.
- Optional scope reduction (§6.17): if effort pressure, defer timezones to a follow-up.

**Files added.**

| Path | Purpose |
|---|---|
| `scripts/i18n/gen-reference.sh` | Reads CLDR data, emits `reference/<locale>/{countries,timezones,phone_countries}.toml` |
| `src/core/i18n/reference/<locale>/*.toml` | English baseline already in PR 1; future locales added here |

**Files modified.**

- `src/core/locales/locales.go`: add `NativeName` field to the locale struct; static table populated from CLDR.
- Account-side templates:
  - `src/adminconsole/web/template/account_profile.html` (around `:114` for timezones, `:123` for locale picker): use localized labels.
  - `src/adminconsole/web/template/account_address.html` (around `:74`): country dropdown localized.
  - `src/adminconsole/web/template/account_phone.html` (around `:31`): phone-country localized.
- **Admin-user-edit equivalents** (the same surfaces administrators see when editing other users — easy to miss):
  - `src/adminconsole/web/template/admin_users_profile.html` (around `:128` for locale picker; also timezone if present): localized labels.
  - `src/adminconsole/web/template/admin_users_address.html` (country dropdown): localized labels (the form-field migration to canonical code already happened in PR 1; this PR adds localized display).
  - `src/adminconsole/web/template/admin_users_phone.html` (around `:26`, currently renders `.Name` from phone countries): switch to localized phone-country labels.
- New template helper `RefData(ctx, kind, key)` returning the localized label for the active locale.

**Test plan.**

- Generator script: run for `pt-BR`, verify output files match a checked-in golden.
- Locale picker renders `Native (English)` for every locale in the list (table-driven).
- Country dropdown in pt-BR renders Portuguese country names — assert on **both** `account_address.html` and `admin_users_address.html`.
- Phone country dropdown renders `Brasil (+55)` in pt-BR — assert on **both** `account_phone.html` and `admin_users_phone.html`.
- Locale picker pt-BR rendering — assert on **both** `account_profile.html` and `admin_users_profile.html`.
- Round-trip: form post in pt-BR submits canonical country code; validator accepts. Run round-trip on both account-side and admin-side surfaces.

**Acceptance criteria.**

- [ ] `gen-reference.sh` documented; running it for any locale produces complete bundles.
- [ ] All affected templates render localized labels — both account-side (3 files) and admin-user-edit equivalents (3 files).
- [ ] Locale picker shows native names on both account profile and admin user profile.
- [ ] No drift between displayed label and stored canonical code.

---

## 8. PR 6 — Email pipeline + recipient locale

**Goal.** Emails render in the recipient's locale, not the request initiator's. Email templates moved to catalog. Email rendering audit completed (§6.8).

**Scope summary.**

- Email rendering function signature change: `recipientLocale` is required.
- Audit every email-send call site.
- Fix cross-module template references discovered (e.g., `email_newuser_set_password.html` referenced from authserver).
- Either move templates to a shared `src/core/web/template/emails/` FS or move the call site.
- Remove `email_test.html` if confirmed unused; otherwise wire it up.
- Email templates converted to `T`.
- Subjects move into the catalog under `email.<template>.subject`.
- Production-FS render tests (§6.5).

**Files modified.**

- All `.html` under `src/authserver/web/template/emails/` (4 files) and `src/adminconsole/web/template/emails/` (2 files), pending audit findings.
- Every email-send call site: pass `recipient.Locale` (or English fallback) explicitly.
- Email rendering helper (current location TBD by audit): take `recipientLocale string` as required argument; construct localizer from it independent of request context.
- `src/authserver/internal/handlers/apihandlers/handler_api_settings_email.go:247`: decide on `email_test.html` (use it or remove).
- `src/authserver/internal/handlers/apihandlers/handler_api_users_crud.go:431`: fix the cross-FS reference identified in §6.8.

**Test plan.**

- Per email template: render with `recipientLocale = "pt-BR"` against a stub catalog; assert localized output appears, asserts subject is localized.
- Production-FS test: each email-send call site is exercised in a test that uses the actual embedded template FS (not a test-only FS), so missing-template / wrong-FS bugs fail in CI.
- Audit results documented in PR description (which templates are real, which were dead).

**Acceptance criteria.**

- [ ] §6.8 audit completed and findings actioned (cross-module references resolved, dead templates removed or wired up).
- [ ] Every email-send site passes `recipientLocale` explicitly.
- [ ] Production-FS render test fixture is green for every confirmed template.
- [ ] §2 inventory in the design doc updated to reflect post-audit reality.

---

## 9. PR 7 — JS bootstrap

**Goal.** Localize user-facing JS strings.

**Scope summary.**

- 3 JS files: `src/authserver/web/static/utils.js`, `src/adminconsole/web/static/utils.js`, `src/adminconsole/web/static/image-upload.js`.
- Per-page `window.i18n = { ... }` bootstrap object rendered server-side via the layout template.
- JS reads from `window.i18n[key]` — small helper `t(key)` in each utils.js.

**Files modified.**

- `utils.js` (both modules): replace literal strings with `t(...)` lookups; add the helper function.
- `image-upload.js`: same.
- Layout templates: emit `<script>window.i18n = {...}</script>` block with the keys used by JS on that page.
- Catalog: add the small set of JS keys under `js.<context>.<key>`.

**Test plan.**

- Per JS-using page: bootstrap object includes the keys referenced by `t(...)` calls in the loaded JS.
- A simple browser test (or DOM-rendered HTML assertion) verifying the bootstrap object structure.

**Acceptance criteria.**

- [ ] No literal English in user-facing JS strings.
- [ ] Bootstrap object emitted on every page that uses localized JS.

---

## 10. PR 8 — pt-BR canary + final acceptance

**Goal.** Translate the entire English catalog into pt-BR, regenerate pt-BR reference bundles, run the full canary acceptance pass.

**Scope summary.**

- **Expand `active.pt-BR.toml`** (the login-page stub from PR 1) to cover every key in `active.en.toml`.
- Run `gen-reference.sh pt-BR` → check in `reference/pt-BR/{countries,timezones,phone_countries}.toml`.
- End-to-end browser testing.
- Document the missing-key behavior (key string visible in UI), document how to add a new locale.

**Files added.**

- `src/core/i18n/reference/pt-BR/*.toml`.
- `docs/i18n-add-language.md` (or equivalent README section): step-by-step for adding a new locale.

**Files modified.**

- `src/core/i18n/catalogs/active.pt-BR.toml`: expanded from PR 1's login-page stub to cover the entire English catalog.

**Test plan.**

- The §3.2 / §6.1 mid-flow canary test, now with a real pt-BR catalog rather than the PR 1 stub.
- Full browser session in pt-BR: registration, login, account profile, admin operations, error scenarios. Manual + automated where feasible.
- Email send with `recipientLocale = "pt-BR"`: every template renders in Portuguese.
- Locale change end-to-end: user changes locale in adminconsole → log out / log back in → UI is pt-BR.
- Adminconsole API errors: pt-BR users see localized messages; English users see English.
- Protocol responses unchanged (regression).

**Acceptance criteria.**

- [ ] Every English key has a pt-BR translation.
- [ ] No "[missing key]" markers visible in the pt-BR UI on any page exercised in testing.
- [ ] Reference bundles ship for pt-BR.
- [ ] Add-a-language doc reviewed and accurate.
- [ ] CHANGELOG entry: pt-BR support added.

---

## 11. Cross-cutting concerns

These don't belong to a single PR; they apply across the rollout.

### 11.1 Protocol error preservation

A regression suite runs in every PR (added in PR 1) that:

- Hits the protocol endpoints currently registered in authserver — `/auth/token`, `/auth/authorize` (error redirect path), `/connect/register`, `/userinfo`, `/.well-known/openid-configuration`, `/certs` — with bad / boundary input.
- Asserts response is byte-identical to a pre-i18n baseline (or otherwise spec-conformant where the response is non-deterministic, e.g., timestamps).
- Lives in `src/authserver/tests/integration/protocol_errors_test.go` (or similar).
- **Note on `/auth/revoke` and `/auth/introspect`:** these RFC 7009 / RFC 7662 endpoints are not registered in authserver today (verified against `src/authserver/internal/server/routes.go`). They are intentionally omitted from the suite. If/when they are added, the regression suite gains a case for each at that point.

If any PR breaks this suite, the breaking change is in protocol territory and must be reverted or reclassified.

### 11.2 Catalog hygiene

- `active.en.toml` is the source of truth for keys. Other locales mirror its structure.
- CI lint (added PR 4) refuses orphan keys (in catalog but no code constant) and orphan codes (constant but no catalog entry).
- A separate check (cheap script) flags translations that contain English literals copied verbatim — common translator mistake.

### 11.3 Missing-key policy

- If a key is missing in the resolved locale: fall back to English.
- If a key is missing in English too (programmer error): return the literal key string (e.g., `"auth.pwd.title"` shows up on the page). Visible-miss is intentional during dev. CI catches this when the lint runs after PR 4.

### 11.4 Documentation deliverables

- `CLAUDE.md` gains a short "Localization" subsection pointing at `plan-i18n-localization.md` for design and this file for implementation.
- `README.md` gains an "Adding a language" section landing in PR 8 with the TOML / generator workflow.
- Release notes / `CHANGELOG.md` entries:
  - PR 1: API breaking change (admin/account error shape).
  - PR 1: `profile` scope now requested by adminconsole; `locale` claim now in tokens.
  - PR 8: pt-BR available; `GOIABADA_I18N_OVERRIDES_DIR` documented.

### 11.5 Test environment

- Tests run inside the dev container per project convention (`./run-tests.sh` in `src/authserver/`). Confirm i18n catalogs are picked up by all three modules' test runners.
- Integration tests under `src/authserver/tests/integration/` exercise full flows; pt-BR canary tests join this suite in PR 8.

### 11.6 Rollback story

Every PR is independently revertable because every step keeps English working. If pt-BR reveals a structural issue at PR 8, reverting PR 8 leaves the product fully English and the i18n machinery in place — no rollback through the entire rollout. If a structural issue is found earlier (e.g., Phase 2 misbehaves under load), PR 4–7 can be reverted without losing PR 1's foundation.

---

## 12. Open implementation questions

Items where the design doc gave us latitude and an implementation choice still needs to be made by the implementer (or surfaced in PR review):

- **Country canonical code** — alpha-2 vs alpha-3. PR 1 must pick. Design doc (§6.17) says "suggested: alpha-2". Resolve in PR 1 review.
- **Locale picker label format** — `Native (English)` vs native-only with tooltip. Design (§6.11) recommends the former; revisit if it's noisy in pt-BR.
- **Reference-data scope** — keep timezones in v1 vs defer (§6.17 scope reduction). Default: keep.
- **API version bump** — bump major (`/api/v1/` → `/api/v2/`) vs CHANGELOG-only announcement. Design (§6.3) accepted the breaking change but didn't specify versioning. Pragmatic call.
- **Email FS unification** — moving email templates to `src/core/web/template/emails/` shared FS, or fixing call sites individually. Decided in PR 6 based on §6.8 audit findings.
- **Adminconsole template extraction split** — single PR vs sub-PRs for the 85 templates. PR 3 author's call once they see review velocity.

---

## 13. Done definition

The implementation is complete when:

- All 8 PRs have merged.
- The §1 acceptance criterion holds: an English-speaking developer can switch their browser's `Accept-Language` to pt-BR and see every screen, email, and error message in Portuguese, with no code changes between the two languages.
- Protocol responses are byte-identical to pre-i18n for spec-defined error paths.
- A documented self-hoster path exists for adding a third language without touching Go code (drop catalog + reference bundles in `GOIABADA_I18N_OVERRIDES_DIR`).
- CHANGELOG and CLAUDE.md updated.
- The full test suite passes via `./run-tests.sh`.
