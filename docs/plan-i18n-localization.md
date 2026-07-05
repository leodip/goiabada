# Localization (i18n) — Feasibility & Proposal

Status: draft for review
Scope: both `authserver` and `adminconsole`

## 1. Goal

Make every user-facing string in Goiabada translatable, so the product can be served in languages other than English with minimal code changes — primarily catalog edits, plus a regeneration of CLDR-derived reference-data bundles (country, timezone, phone-country labels) for the new locale.

Concretely, after this work:

- All visible UI text (login, registration, account self-service, consent, OTP, admin console, validation errors, flash messages) is loaded from a translation catalog, not hardcoded.
- A user's language is resolved per request from (in order) the OIDC `ui_locales` parameter, an in-flight `AuthContext` carrying `ui_locales` across the multi-step authorize flow, the authenticated user's stored locale, the `Accept-Language` header, and finally an English fallback. Detailed precedence and middleware shape live in §3.2 and §6.4.
- Adding a new language is largely a content task: edit/translate the catalog, regenerate the reference-data bundle from CLDR using the provided script (or skip if the language reuses an existing reference-data set), ship. No new Go code is required for the i18n machinery; reference-data regeneration is a documented one-shot per locale.
- Emails are rendered in the recipient's locale.
- The OIDC `locale` claim and the UI locale stay consistent.

Out of scope for this proposal: actually translating into specific languages (that's a follow-up content task), RTL layout polish (deferred until the first RTL language is added), and locale-aware number/date formatting (separate concern, noted below).

What "done" looks like for a reviewer: an English-speaking developer can switch their browser's `Accept-Language` to a second language we've translated and see every screen, email, and error message in that language, with no code changes between the two languages.

## 2. Context

All user-facing content in Goiabada is currently hardcoded in English, spread across:

- HTML templates (109 files: 24 in `src/authserver/web/template/`, 85 in `src/adminconsole/web/template/`)
- Email templates (6 files exist on disk: 4 in `src/authserver/web/template/emails/`, 2 in `src/adminconsole/web/template/emails/`; the authoritative list of *actually rendered* templates is settled by the audit in §6.8 — at least one cross-module reference and one apparently unused template have been flagged)
- Handler error and flash messages (~99 handler files, built with `errors.New(...)` / `fmt.Errorf(...)` and assigned to bind maps)
- Validator error messages (16 files in `src/core/validators/`, returned via `customerrors.NewErrorDetail("", "...")`)
- JS strings (`utils.js` in both modules, `image-upload.js` in adminconsole)

Audit log constants are internal and out of scope.

### What already helps us

- Single template funcmap layer at `src/core/handlerhelpers/template_funcs.go` — natural insertion point for a translation helper.
- Locale list at `src/core/locales/locales.go` (500+ locale codes with display names) — suggests this was anticipated.
- Templates use `html/template`, which composes cleanly with funcmap-based translation.
- No existing i18n library to migrate away from, no conflicting framework.

### What makes it non-trivial

- Validator and handler errors **are** the user-facing message today. The error contract has to change, or we have to look up English-as-key. This is the central design decision.
- No automated extraction tool covers Go templates plus Go literals. Initial extraction is a manual, grep-assisted pass.
- Parameterized and pluralized strings ("3 failed attempts") need template-side rework, not just lookup.
- RTL support (Arabic, Hebrew, etc.) implies CSS/layout work beyond strings.
- Email pipeline must carry the recipient's locale through to render time.

Rough order of magnitude: a few thousand individual strings once labels in templates are counted.

## 3. Proposed Solution

### 3.1 Library

Use [`github.com/nicksnyder/go-i18n/v2`](https://github.com/nicksnyder/go-i18n).

- De facto standard in the Go ecosystem.
- CLDR-backed pluralization.
- Message catalogs in TOML, JSON, or YAML.
- Lightweight, no runtime server, no codegen required.
- Integrates with `html/template` via a single funcmap entry.

### 3.2 Locale resolution

Resolve the request's `*i18n.Localizer` in **two phases** (full rationale in §6.4 and §6.12; multi-step auth flow handling in §6.1).

**Phase 1 — early middleware (pre-identity).** Global. Runs before any auth/JWT middleware on both modules. Establishes a tentative localizer using:

1. Explicit `ui_locales` query parameter on the current request (per OIDC spec, space-separated ordered list).
2. `AuthContext.UILocales` if a multi-step authorize flow is in progress (see §6.1; the list is captured at `/auth/authorize` and read on each subsequent step).
3. `Accept-Language` header.
4. English fallback.

**Phase 2 — implementation differs by module.** Refines the localizer to the user's stored locale once identity is known. Per §6.4, §6.12, §6.16:

- **Adminconsole:** Phase 2 is route-level **middleware**, slotted into each authenticated route chain (`baseAuth`, `accountAuth`, `adminAuth`) immediately after JWT validation. JWT carries the `locale` claim (requires `profile` scope, see §6.15), so no DB lookup.
- **Authserver:** Phase 2 is a **per-handler refinement helper**, not middleware. Authserver has no global middleware that loads `User`, so a global Phase 2 middleware would have no `User` to read. Each handler that loads a `User` calls the helper immediately after the load and **uses the returned request for downstream rendering**. Go contexts are immutable, so the helper must return a new `*http.Request` (with an updated `context.Context`) — passing in `r` and ignoring the result would leave the localizer unchanged. Canonical signature and call site:
   ```go
   r = i18n.RefineLocalizerWithUser(r, user)
   // RefineLocalizerWithUser is a thin wrapper; internally it does:
   //   ctx := i18n.RefineLocalizerContext(r.Context(), user)
   //   return r.WithContext(ctx)
   ```
   The two helpers (`RefineLocalizerWithUser` taking `*http.Request`, `RefineLocalizerContext` taking `context.Context`) are distinct functions because Go cannot overload by parameter type. Handlers should always use the request-shaped form; the context-shaped form exists for code paths that already have a bare `context.Context` (e.g., background workers).
   All downstream calls (template rendering, redirects, error helpers) must use the returned `r`. Pre-login handlers (no `User` available) skip the helper entirely and stay on Phase 1's localizer.

In both modules, Phase 2 applies the override **only when explicit intent is absent**. "Explicit intent" means **either** the current request supplied a `ui_locales` query parameter **or** an in-flight `AuthContext.UILocales` is set (the multi-step authorize flow's persisted form of the same intent). When explicit intent is present, Phase 1's result wins. This prevents Phase 2 from silently swapping the locale mid-flow when the user authenticates partway through `/auth/pwd` → `/auth/otp` → `/auth/consent`.

Phase 1 always attaches its localizer to `context.Context`. Phase 2 (where applicable) replaces it on the same key, so handlers and templates always read the most-refined localizer available.

### 3.3 Template integration

Register a `T` function in the existing `templateFuncMap`:

```go
// in template_funcs.go
"T": func(ctx context.Context, key string, args ...any) string {
    return localize(ctx, key, args...)
},
```

Templates become:

```html
<h2>{{ T $.ctx "register.title" }}</h2>
<span class="label-text">{{ T $.ctx "register.email" }}</span>
```

Bind maps gain a `ctx` entry on every render (or we wrap the renderer to inject it). Pluralization and parameters use go-i18n's standard `TemplateData` mechanism.

### 3.4 Go-side messages — the core design call

Validators and handlers currently return formatted English. Two options:

**Option A — Message keys (clean, invasive)**

Validators and handlers return a structured error carrying a key plus parameters. Translation happens at the render boundary (handler → template, or API response serializer).

```go
return customerrors.NewLocalizedError("validator.address.locality_too_long", map[string]any{"max": 60})
```

Pros: clean separation, no English in business code, easy to swap languages.
Cons: invasive — touches every validator and many handlers; API consumers downstream must accept that error messages are now localized.

**Option B — English-as-key (pragmatic, fragile)**

Keep `errors.New("Please ensure the locality is no longer than 60 characters.")` as-is. At render time, look up that exact string in the catalog; if missing, return it verbatim.

Pros: minimal code change, ship incrementally.
Cons: any rewording silently breaks the lookup; parameterized messages (`fmt.Errorf("user %s not found", x)`) defeat lookup unless they're refactored anyway.

**Recommendation: A.** The mechanical pain is worth it. B accumulates silent breakage and we'd still end up doing A for parameterized messages. We can mitigate A's churn by introducing the new error type alongside the old one and migrating module-by-module.

**Decided: Option A.**

**Important constraint — protocol errors stay English.** OAuth2 (RFC 6749), OIDC, and DCR (RFC 7591) errors are part of the wire protocol consumed by OAuth clients, not end users. These must NOT be localized:

- `error` field: standardized codes (`invalid_request`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`, `access_denied`, `server_error`, `temporarily_unavailable`, etc.). Never translate.
- `error_description` field: human-readable but consumed by client developers/logs. Keep English, machine-stable wording.
- Endpoints affected: `/auth/authorize` (error redirects), `/auth/token`, `/connect/register`, `/userinfo`, `/auth/revoke`, `/auth/introspect`, plus any future protocol endpoints.

Implementation rule: localized errors apply to the **UI rendering path** (templates, flash messages, validator output displayed in forms). Protocol response paths construct errors directly with English string literals and never go through the localizer. Keep the two paths visibly distinct in code (e.g., separate `LocalizedError` and `OAuthProtocolError` types) so it's hard to accidentally translate a spec error.

### 3.5 JS strings

Expose translations to JS via a per-page bootstrap object rendered server-side:

```html
<script>
  window.i18n = {
    "session.expired.title": "{{ T $.ctx "session.expired.title" }}",
    "session.expired.body": "{{ T $.ctx "session.expired.body" }}"
  };
</script>
```

Avoids a separate JSON endpoint and keeps the locale resolution server-side. Three JS files = small surface.

### 3.6 Emails

Carry the **recipient's** locale (not the request initiator's) through to the email rendering function as an explicit required parameter — see §6.5 for the full rule and rationale. Email templates use the same `T` helper. Subject lines move into the catalog.

### 3.7 Catalog layout

```
src/core/i18n/
├── i18n.go               # bundle init, localizer factory, T function
├── middleware.go         # locale resolution, ctx attachment
└── catalogs/
    ├── active.en.toml    # English baseline (source of truth)
    ├── active.es.toml
    └── active.pt-BR.toml
```

Keys grouped by domain, e.g., `auth.pwd.title`, `validator.address.locality_too_long`, `email.activate.subject`. English catalog is the source of truth and what reviewers edit; other languages are translations of it.

### 3.8 Date and number formatting

Out of scope for the string translation effort but worth flagging: use `golang.org/x/text/message` and `golang.org/x/text/date` when we need locale-aware numbers/dates. Independent of go-i18n.

### 3.9 RTL

Add `dir="{{ T $.ctx "_dir" }}"` to the `<html>` tag (resolves to `ltr` or `rtl` per locale). Audit Tailwind classes for `left-`/`right-` that should become logical (`start-`/`end-`). Defer until a first RTL language is added.

## 4. Suggested Phasing

1. **Infrastructure.** Library, locale resolution middleware, funcmap hook, English baseline catalog scaffold. Prove on one page end-to-end (login). Decide on key naming convention. **Includes country-code canonicalization** (per §6.17): pick alpha-2 vs alpha-3, standardize forms, validator, and any DB column. This is a prerequisite refactor for step 6 (reference-data dropdowns) and is small and contained, so it ships with the foundational PR.
2. **Authserver templates.** 24 files, all user-visible. Extract strings, populate English catalog.
3. **Adminconsole templates.** 85 files. Larger but lower-risk (admins, internal users).
4. **Validators.** Introduce localized error type, migrate validators one file at a time.
5. **Handlers.** Migrate error/flash strings using the localized error type.
6. **Reference-data dropdowns.** CLDR-derived country, timezone, and phone-country label maps per §6.17. Depends on step 1's canonicalization. Generator script for new locales lands here.
7. **Emails.** Plumb locale through email rendering.
8. **JS.** Bootstrap object on relevant pages.
9. **Second language end-to-end.** pt-BR (per §5 q2), the canary to validate the full pipeline.
10. **RTL** (deferred until needed).

Steps 2 and 3 can run partially in parallel with 4–5 since they touch disjoint files. Step 6 can begin as soon as step 1 lands.

## 5. Decisions

These items started as open questions; all are now settled. Kept as a running log so reviewers can see what was decided and why. Detailed implementation refinements live in §6.

1. **Error contract: Option A (message keys + parameters), with protocol responses staying English.** Decided. Validators and handlers return structured `LocalizedError{Key, Args}`; translation happens at the render boundary. OAuth/OIDC/DCR protocol responses are explicitly carved out per §6.2 (English, machine-stable). Admin/account API adopts a new `{error, error_code, error_args, error_description}` shape — accepted breaking change, see §6.3.
2. **First non-English language: pt-BR (Brazilian Portuguese).** Decided. Used as the canary to validate the full pipeline end-to-end. English remains the source of truth; pt-BR is the first translation target and the test case for parameterized strings, pluralization, and the locale-resolution chain.
3. **Translator workflow: in-repo TOML files, PR-based.** Decided. Catalogs live under `src/core/i18n/catalogs/` and are edited like any other source file. Translation changes go through normal PR review. If/when external translators become the bottleneck, revisit and consider Weblate Hosted (free for open-source) or Crowdin, syncing into the same in-repo files via webhook.
4. **UI locale and OIDC `locale` claim share the same User field.** Decided. One `User.Locale` field drives both the Goiabada UI rendering and the `locale` claim returned in ID tokens / `/userinfo`. The OIDC `ui_locales` request parameter still lets relying parties override the UI locale per request without touching the stored preference. If a real need for divergent UI vs. claim locales ever surfaces, a second field can be added then.
5. **Adminconsole scope: translate everything.** Decided. Both authserver and adminconsole are fully localized — no English-only screens, no second-class surfaces. Self-hosters in non-English-speaking regions get a consistent localized product end-to-end. The phasing in §4 already sequences authserver templates before adminconsole templates, so we still get an early validation point without dropping admin from scope.
6. **Effort estimate accepted.** Realistic scope is roughly 5–7 weeks of focused work for one developer to ship both modules fully localized in English + pt-BR. Rough breakdown:
   - Infrastructure (library, middleware, funcmap hook, `LocalizedError` type, base catalog, one page proven end-to-end): ~3–5 days
   - Authserver template extraction (24 files): ~3–5 days
   - Adminconsole template extraction (85 files): ~1.5–2 weeks
   - Validator migration (16 files): ~2–3 days
   - Handler error/flash migration (~99 files): ~1–2 weeks
   - Email templates + locale plumbing: ~1–2 days
   - JS bootstrap: ~1 day
   - pt-BR translation pass + review: ~3–5 days
   - Buffer for surprises: ~1 week

   **Delivery model: phased PRs (revised — see §6.6).** Originally agreed as one big PR; revised during review because review/regression risk on 109 templates, 16 validators, ~99 handlers, emails, JS, and tests in a single merge is too high. Each phase from §4 ships as its own PR behind English fallback, with pt-BR translation as the final canary PR.

## 6. Review Refinements

Resolutions to issues raised during developer review of this plan.

### 6.1 `ui_locales` must survive the multi-step auth flow (High)

**Issue.** The OAuth authorize flow spans multiple requests: `/auth/authorize` → `/auth/pwd` → `/auth/otp` → `/auth/consent` → `/auth/issue`. The locale-resolution middleware as originally described would only see `ui_locales` on the entry request. Every subsequent screen would silently fall back to `Accept-Language` or English, breaking the user's stated preference mid-flow.

**Resolution.**

- Add a field to `AuthContext` (`src/core/oauth/auth_context.go`) that stores the **ordered `ui_locales` list** as received on the authorize request, after sanitization. Raw-shape list (not a pre-resolved single locale) preserves OIDC fallback semantics: if pt-BR is unavailable but the user passed `ui_locales=pt-BR es`, Spanish is still picked up.
- **Sanitize before storing.** `AuthContext` is serialized into the session via `auth_helper.go:71` and persisted in cookie-backed/chunked storage (`src/core/sessionstore/chunked_cookie_store.go:20`). An attacker-controlled `ui_locales` query could otherwise bloat session cookies or cause save failures. Apply on input:
  - Trim whitespace around each tag.
  - Drop entries that don't match a permissive BCP 47 shape (e.g., `^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$`). Don't try to validate against a registry; just reject obvious garbage.
  - Cap the number of tags retained (suggested: 10) — preserve order, drop the tail.
  - Cap total stored bytes (suggested: 256) — drop the tail if the cap would be exceeded.
  - If sanitization leaves nothing, store an empty list and treat it as "no `ui_locales` was present" downstream.
- Locale-resolution responsibilities are split across the two phases (per §3.2):
  - **Phase 1 (global middleware, every request).** Establishes a tentative localizer from, in order:
    1. Explicit `ui_locales` query parameter on the current request
    2. `AuthContext.UILocales` if an auth flow is in progress (session cookie carries it)
    3. `Accept-Language` header
    4. English fallback
  - **Phase 2 (adminconsole route-level middleware; authserver per-handler refinement).** Where identity is established, refines to the user's stored locale (`User.Locale` for authserver, `locale` claim from JWT for adminconsole), **unless** explicit intent (request `ui_locales` or `AuthContext.UILocales`) is present — in which case Phase 1's result wins.
- **Capture `ui_locales` from query OR form on `/auth/authorize`.** The endpoint is registered for both GET and POST (`src/authserver/internal/server/routes.go:95`); the handler reads other authorize params via `r.FormValue(...)` (`src/authserver/internal/handlers/handler_authorize.go:91`), which checks query first then parsed form body. `ui_locales` follows the same convention: if an RP POSTs the authorize request with `ui_locales` in the form body, that value is captured. Specific responsibilities:
  - **Phase 1 middleware reads `r.URL.Query().Get("ui_locales")` only.** It must NOT call `r.ParseForm()` or `r.FormValue(...)`, since those consume the request body and would interfere with the authorize handler's own parsing on POST. For non-authorize endpoints, query-only is fine: only `/auth/authorize` accepts `ui_locales` from a body.
  - **The authorize handler captures from the form** (`r.FormValue("ui_locales")` covers query and form), sanitizes per the rules above, and stores into `AuthContext.UILocales`. From this point onward, every subsequent request in the auth flow gets the value via Phase 1's `AuthContext.UILocales` lookup.
  - **For the current authorize request itself**, if the captured form value differs from what Phase 1 already saw on the query string (typical case: query had nothing, form had a value), the handler refines the current request's localizer with the just-captured list before rendering any browser-visible response (e.g., the level1 password page). Pattern: `r = i18n.RefineLocalizerWithUILocales(r, capturedList)`. The helper has the same return-the-new-request shape as `RefineLocalizerWithUser` (per §3.2), and the same rule applies: drop the return value and the refinement is lost.
- **Do not** persist `ui_locales` on `UserSession`. `ui_locales` is a per-authorize-request hint from the relying party; storing it on the long-lived session would leak an RP-specific preference into unrelated future SSO requests, contradicting §5 q4 ("override per request without touching stored preference"). `AuthContext.UILocales` already covers the full duration of the multi-step auth transaction, which is the only window where cross-request persistence is needed. After the authorize flow completes, the value is naturally discarded with `AuthContext`.

### 6.2 Protocol validators vs UI validators (High)

**Issue.** §3.4 stated that validators migrate to `LocalizedError`. But `authorize_validator.go` and `token_validator.go` produce strings that flow into OAuth/OIDC `error_description` on `/auth/authorize` redirects and `/auth/token` JSON responses. Wholesale migration would localize protocol responses, contradicting §3.4's rule that protocol errors stay English.

**Resolution.** Split validators by **audience**, not by file location:

- **Protocol validators** — output reaches OAuth/OIDC clients via spec-defined error fields. Stay English, keep existing error types. Examples: `authorize_validator.go`, `token_validator.go`, validators feeding `/connect/register`, `/auth/revoke`, `/auth/introspect`.
- **UI validators** — output reaches end users via rendered templates or admin forms. Return `LocalizedError{Key, Args}`. Examples: `address_validator.go`, `email_validator.go`, `password_validator.go`, `phone_validator.go`, `identifier_validator.go` when used by account self-service or admin CRUD.

For validators shared across both paths (e.g., email validation hits both account registration and DCR), the validator returns `LocalizedError`, and protocol call sites extract the English fallback string before constructing the OAuth error response. Convention: at every protocol response boundary, code calls `err.EnglishFallback()` (or equivalent) rather than going through the localizer.

§3.4's "validators migrate to `LocalizedError`" should be read as "**UI** validators migrate". Protocol validators are explicitly out of scope for translation.

### 6.3 Admin console API error contract (High)

**Issue.** Admin UI renders error messages from authserver API responses (`src/adminconsole/internal/handlers/api_error_helper.go:20` reads `apiErr.Message`). If authserver API responses stay English, the admin UI shows English even after i18n. If authserver localizes API responses by request locale, all API consumers get localized strings unpredictably.

**Current shape.** Admin/account API errors today are nested:

```json
{
  "error": {
    "code": "...",
    "message": "..."
  }
}
```

(see `src/authserver/internal/handlers/apihandlers/api_common.go:12`).

**Resolution — new flat error shape (breaking change, accepted).** Admin/account API responses move to:

```json
{
  "error": "validation_failed",
  "error_code": "validator.address.locality_too_long",
  "error_args": {"max": 60},
  "error_description": "Please ensure the locality is no longer than 60 characters."
}
```

- `error` — short machine-readable category (e.g., `validation_failed`, `not_found`, `permission_denied`). Stable, English.
- `error_code` plus `error_args` — the localizable payload. Adminconsole's `api_error_helper` localizes `error_code` using its own request locale.
- `error_description` — English human-readable text for non-localizing consumers (logs, curl, scripts).
- Applies to the **admin API surface** (`/api/v1/admin/*` and `/api/v1/account/*`). Protocol endpoints (`/auth/token`, `/auth/authorize`, `/connect/register`, `/userinfo`, `/auth/revoke`, `/auth/introspect`) keep their RFC-defined error shape unchanged.

**This is a breaking change** to the admin/account API response shape. Accepted by the project owner. Implementation tasks:

- Update `api_common.go` and all admin/account handlers to emit the new shape.
- Update `src/adminconsole/internal/handlers/api_error_helper.go` and any other consumer in adminconsole to read the new fields.
- Call out the breaking change in release notes / CHANGELOG and bump the API version accordingly so external consumers know to update.
- Migrate any integration tests that assert on the old nested shape.

Net effect: localized errors are produced once (in `core/validators` or handlers), serialized over the API as `{error, error_code, error_args, error_description}`, and rendered by whichever module owns the user-facing surface.

### 6.4 Two-phase locale resolution (Medium)

**Issue.** §3.2 described a single locale-resolution middleware that consults the authenticated user's stored locale. But early-chain middleware does not have identity yet — authserver attaches a session identifier later, and adminconsole identity comes from JWT/session middleware further down the stack. A locale middleware running early can't read `User.Locale`.

**Resolution.** Resolve locale in two phases:

- **Phase 1 — early middleware (pre-identity).** Always runs. Resolves from: explicit `ui_locales` query param → `AuthContext.UILocales` (if present in session, see §6.1) → `Accept-Language` → English. Sets a tentative localizer on the request context.
- **Phase 2 — post-identity refinement.** Runs after identity is established. Implementation form differs by module (middleware in adminconsole, per-handler refinement helper in authserver — see the per-module bullets below). Overrides the locale with the user's stored locale, **unless** explicit request intent is present — defined as **either** a `ui_locales` query parameter on the current request **or** an in-flight `AuthContext.UILocales` (the persisted form of `ui_locales` across the multi-step authorize transaction, per §6.1). Treating `AuthContext.UILocales` as equivalent to a live query parameter is critical: without this rule, Phase 2 would override the RP's stated `ui_locales` with `User.Locale` the moment the user authenticates inside the flow (e.g., on `/auth/pwd` submit), reintroducing the very mid-flow locale switch §6.1 was added to prevent.

Per-module specifics:

- **Adminconsole.** JWT/userinfo carries the `locale` claim only when the `profile` scope is granted (see `src/core/oauth/token_issuer.go:597`). Adminconsole already authenticates via Goiabada itself, so:
  - The adminconsole OAuth client must request the `profile` scope (in addition to whatever it requests today) so the `locale` claim reaches it.
  - Phase 2 reads `locale` from the JWT/session — no DB lookup.
  - **Fallback when the claim is missing** (older tokens, scope misconfiguration, third-party admin client without `profile`): fall through to phase 1's result (`Accept-Language` → English). Never silently default to English when a phase 1 signal exists.
  - **Staleness window.** When a user changes their locale, the new value reaches adminconsole only after the access/ID token is refreshed. This is acceptable — the admin's own UI catches up on next refresh, no cross-user impact. Document this limitation. If tighter consistency is wanted later, the option is to force a token refresh on locale-change via prompt=login or by triggering a session bump; not in scope for this work.
- **Authserver.** No global middleware loads `User` — `MiddlewareSessionIdentifier` only sets `ContextKeySessionIdentifier` (`src/authserver/internal/middleware/middleware_session_identifier.go:51`); handlers load users individually (e.g., `src/authserver/internal/handlers/handler_consent.go:82`). So **Phase 2 in authserver is a per-handler refinement, not middleware**: each handler calls `r = i18n.RefineLocalizerWithUser(r, user)` immediately after loading its `User`, and uses the returned `r` for everything downstream. The helper must return a new `*http.Request` because Go contexts are immutable; dropping the return value would silently leave the localizer at its Phase 1 state (see §3.2 and §6.12 step 6 for the canonical signature). The helper applies the override rule against `User.Locale`. No staleness — it's a live DB read on the same `User` the handler already had to load. Handlers that don't have a `User` (pre-login steps before identity is established) skip the helper and stay on phase 1's localizer.

### 6.5 Email recipient locale and inventory correction (Medium)

**Issue.** Email rendering currently runs in the HTTP request's context, so the localizer would resolve to the *initiator's* locale (e.g., the admin who triggered "set password" at `src/authserver/internal/handlers/apihandlers/handler_api_users_crud.go:431`), not the *recipient's*. Also the original inventory missed 2 email templates in adminconsole.

**Inventory correction.** There are **6** email templates total, not 4:

- `src/authserver/web/template/emails/` (4): `email_register_activate.html`, `email_register_confirmation.html`, `email_forgot_password.html`, `email_verification.html`
- `src/adminconsole/web/template/emails/` (2): `email_test.html`, `email_newuser_set_password.html`

**Resolution.**

- Email rendering takes `recipientLocale` as an **explicit required parameter**. Never pulled from request context. The function signature changes; every caller must supply `recipient.Locale` (or fall back to English) before invoking the renderer.
- The localizer used inside email rendering is constructed from `recipientLocale` — independent of any request-bound localizer.
- Email subjects move into the catalog alongside body strings, keyed under `email.<template_name>.subject` and `email.<template_name>.body.*`.
- Add a unit test fixture that, for each email template confirmed by the §6.8 audit, asserts that rendering with a non-default locale produces output in that locale. The fixture must use the **production** template FS (the same one used at runtime), not a test-only FS, so missing-template / wrong-FS bugs surface here.

### 6.6 Delivery model revised: phased PRs (Medium)

**Issue.** §5 q6 committed to a single big PR. Reviewer flagged that 109 templates, 16 validators, ~99 handlers, JS, emails, tests, and catalogs in one merge is a review and regression risk. Bisecting any regression introduced anywhere in that surface area would be painful, and a problem found late could block the entire effort.

**Resolution.** Revert to phased delivery. Each phase merges as its own PR, behind English fallback so partial work is never user-visible as broken. The pt-BR canary lands near the end after all infrastructure and extraction is done.

PR sequence:

1. **Infrastructure + login page proven end-to-end.** Library, two-phase locale middleware, funcmap hook, `LocalizedError`, API error contract, `AuthContext.UILocales` field, base catalog, login page fully migrated as the working example. Pattern is locked here. **Also includes country-code canonicalization** (per §6.17): decide alpha-2 vs alpha-3, standardize form fields, validator, and DB column. Prerequisite for PR 5.
2. **Authserver template extraction** (24 files).
3. **Adminconsole template extraction** (85 files). Can be split further if it grows unwieldy.
4. **UI validator migration plus handler error/flash migration** (protocol validators stay untouched per §6.2).
5. **Reference-data dropdowns** (per §6.17). CLDR-derived country, timezone, phone-country label bundles, generator script, and template wiring. Depends on PR 1's canonicalization.
6. **Email pipeline plus recipient locale plumbing** (per §6.5).
7. **JS bootstrap.**
8. **pt-BR canary.** Translation pass over the full English catalog plus regenerated pt-BR reference-data bundles. End-to-end browser testing in pt-BR.

This **supersedes the "one big PR" wording in §5 q6**. Each PR is independently reviewable and revertable; English remains the working fallback throughout.

### 6.7 Catalog deployment: embedded plus runtime override (Low)

**Issue.** §1 (Goal) originally said "drop in a translated catalog file, ship". With `//go:embed` baking catalogs into the binary (the simplest go-i18n setup), adding a language requires a rebuild and release. There's also a second blocker on "drop in and ship" that was glossed over: §6.17's reference-data bundles (CLDR-derived country, timezone, phone-country labels) are *not* catalog entries, so a new locale needs both the catalog and the reference-data bundle.

**Resolution.** Hybrid override path covering both file types:

- **Default behaviour: embedded catalogs and reference data.** Catalogs under `src/core/i18n/catalogs/active.*.toml` and reference-data bundles under `src/core/i18n/reference/<locale>/` are embedded via `//go:embed`. This is the canonical set, ships with each release, version-controlled.
- **Runtime override path.** New env var `GOIABADA_I18N_OVERRIDES_DIR` points to a directory with this layout:
  ```
  $GOIABADA_I18N_OVERRIDES_DIR/
    catalogs/active.<locale>.toml
    reference/<locale>/countries.toml
    reference/<locale>/timezones.toml
    reference/<locale>/phone_countries.toml
  ```
  At startup, the bundle loads embedded files first, then walks the override directory and merges anything found on top. A new locale that ships only override files works end-to-end without a rebuild.
- Conflicts: override files win, by design. Logged at startup so operators can see what was overridden.
- The reference-data file format is a flat key-value table (e.g., `countries.toml` keyed by canonical country code → localized name). Format is documented; a small generator script (`scripts/i18n/gen-reference.sh` or similar) produces these from CLDR for any locale, so adding a language stays a content/data task and not a code task.

This honours the §1 goal — self-hosters can ship a new language without a release cycle — while keeping the default deployment simple and version-controlled.

### 6.8 Email rendering audit and ownership (High)

**Issue.** The plan says 6 email templates exist (4 authserver + 2 adminconsole), but actual rendering paths are not consistent with that split:

- `src/authserver/internal/handlers/apihandlers/handler_api_users_crud.go:431` references `email_newuser_set_password.html`, but that file only exists under adminconsole. Authserver's template FS is `src/authserver/web/template` only (`src/authserver/internal/server/server.go:63`), so this either fails at runtime or relies on something not visible in the obvious load path.
- `email_test.html` appears unused — the test-email handler at `src/authserver/internal/handlers/apihandlers/handler_api_settings_email.go:247` sends a hardcoded string, not a rendered template.

If the i18n work just translates "the templates that exist on disk" without auditing which are actually rendered, we ship translations for unused files and may leave the live cross-module rendering path broken or untranslated.

**Resolution.** Add an **email rendering audit** as a prerequisite step inside Phase 5 (email pipeline PR):

- For every call site that triggers an email send, record: (a) template file referenced, (b) which template FS it loads from, (c) whether it actually exists in that FS, (d) whether the path is exercised in tests.
- Fix any cross-module template references found. Either move the template into the rendering module's FS or introduce a shared `core/web/template/emails/` FS embedded by both modules.
- Remove or wire up `email_test.html` — don't carry it forward as dead weight.
- The unit test fixture in §6.5 must use the **production** template FS (same one used at runtime), not a test-only FS, so wrong-FS bugs surface in CI.
- The §2 / §6.5 inventory becomes authoritative only after this audit. Treat the "6 files" count as provisional until then.

### 6.9 Consent scope descriptions (High)

**Issue.** Consent screen content is generated in Go, not templates:

- OIDC scope descriptions: `oidc.GetIdTokenScopeDescription` returns English literals from `src/core/oidc/oidc.go:19`, used at `src/authserver/internal/handlers/handler_consent.go:42`.
- Permission scope descriptions: built inline as `fmt.Sprintf("Permission %v on resource %v", ...)` at `handler_consent.go:50`.

The original plan covered handler error/flash messages but not these — consent would remain partially English even after templates, validators, JS, and emails localize.

**Resolution.**

- **OIDC scope descriptions move to the catalog.** Keys: `consent.scope.openid.description`, `consent.scope.email.description`, `consent.scope.profile.description`, `consent.scope.address.description`, `consent.scope.phone.description`, `consent.scope.offline_access.description`. `GetIdTokenScopeDescription` becomes a function that takes a localizer (or `context.Context`) and returns the localized string. The English source lives in the English catalog.
- **Permission scope descriptions move to a templated catalog message.** Replace `fmt.Sprintf("Permission %v on resource %v", ...)` with a localized message keyed `consent.scope.permission_template`, parameterized as `{permission, resource}`. English template: `"Permission {{.permission}} on resource {{.resource}}"`.
- This depends on §6.10 for whether the `permission` and `resource` substitutions are themselves localized strings or raw identifiers.

### 6.10 Built-in system display names and descriptions (High)

**Issue.** The seeder creates English `DisplayName` / `Description` for the built-in admin console client, the authserver resource, and system permissions (`src/core/data/database_seeder.go:84`+). These render directly in user-facing pages, e.g., `src/authserver/web/template/layouts/auth_layout.html:45` and `src/adminconsole/web/template/admin_resources.html:42`. Without addressing them, built-in system data stays English on visible screens.

**Resolution — catalog-backed for built-ins, DB values for user-created.**

- **Built-in system entities** (admin console client, authserver resource, the canonical system permissions seeded at install) are recognized by their stable identifiers. UI helpers render their display name/description via catalog keys: `system.client.<identifier>.display_name`, `system.resource.<identifier>.description`, `system.permission.<identifier>.description`.
- A small registry (e.g., `src/core/i18n/system_entities.go`) maps known system entity identifiers to catalog key prefixes. The registry covers exactly what the seeder creates — finite list, easy to maintain.
- The seeded English values stay in the DB as **fallbacks** when a catalog key is missing.
- **User-created clients/resources/permissions** render their DB `DisplayName` / `Description` verbatim, untranslated. Localizing user-authored content is not in scope: admins write their own text in their own language and we don't translate that for them.
- Permission scope description in §6.9 then composes: the *template* is localized, and the *permission/resource substitutions* are localized only if the entity is in the system registry; otherwise the raw DB string is used.

This is a real scope boundary worth confirming explicitly: **v1 localizes built-in system data only**. User-created entity text stays in whatever language the admin entered.

### 6.11 Locale picker labels (Medium)

**Issue.** `locales.Get()` returns English display names from `src/core/locales/locales.go:1`. Templates render them as-is, e.g., `src/adminconsole/web/template/account_profile.html:123`, `src/adminconsole/web/template/admin_users_profile.html:128`. The locale picker — the very UI that lets a user choose their language — is itself English.

**Resolution — native names with English fallback.**

- Add a `NativeName` field to the locale struct in `src/core/locales/locales.go`, populated from CLDR data (one-shot static table; the locale list is maintained in-tree anyway).
- Locale dropdowns render `Native (English)` format — e.g., `Português (Brasil) (Portuguese, Brazilian)`. Users who recognize neither column have a chance with the other. This is the convention used by Wikipedia, Wikimedia, GitHub language pickers, etc.
- No catalog ballooning: native names are static reference data, not translated strings. The catalog stays focused on UI text.
- If the `(English)` parenthetical is judged too noisy, fall back to native-only with a tooltip showing English. Defer that polish.

### 6.12 Middleware ordering (Medium)

**Issue.** Phase 1 locale middleware reads `AuthContext.UILocales` from the session, so it must run after session-cookie handling. But authserver currently runs `MiddlewareSettings` → `MiddlewareCookieReset` → `MiddlewareSessionIdentifier` (`src/authserver/internal/server/server.go:202`), and `MiddlewareCookieReset` (`src/core/middleware/middleware_cookie_reset.go:12`) safely handles invalid cookies before any session read. Putting i18n middleware in the wrong slot would either bypass cookie-reset safety or read stale/uninitialized session state.

**Resolution.** Specify the canonical order. The list below is the **authserver** chain (global middleware); adminconsole's chain is route-level and is detailed in §6.16.

1. `MiddlewareSettings` — global settings load. Required by everything below.
2. `MiddlewareCookieReset` — invalid cookies are handled before any session read.
3. `MiddlewareSessionIdentifier` — sets `ContextKeySessionIdentifier` from the session cookie when valid. **Important:** this does *not* place the full `AuthContext` on `context.Context`. `AuthContext` is read on demand from the session store via `AuthHelper.GetAuthContext` (`src/core/handlerhelpers/auth_helper.go:35`), which takes a `*http.Request` and reads `SessionKeyAuthContext`.
4. **`MiddlewareLocalePhase1` (new).** Resolves the tentative localizer in this order:
   1. `?ui_locales` query parameter on the current request.
   2. `AuthContext.UILocales` — loaded by calling the existing `AuthHelper.GetAuthContext(r)` with the `*http.Request` (same call signature handlers use today, so we don't introduce a new way to read `AuthContext`). "Not found" / no-active-flow errors are swallowed; the middleware just falls through to the next signal.
   3. `Accept-Language` header.
   4. English fallback.
   Sets the tentative localizer on `context.Context`.
5. (No global auth/JWT middleware in authserver. Identity is not established at the chain level — handlers load `User` individually.)
6. Handler runs. **Phase 2 in authserver is a per-handler refinement, not middleware.** Each handler that loads a `User` calls the helper and assigns the returned request back: `r = i18n.RefineLocalizerWithUser(r, user)`. Go contexts are immutable, so the helper must return a new `*http.Request` (with an updated `context.Context`); call sites that drop the return value would leave the localizer at its Phase 1 state. The helper applies the §3.2 / §6.4 override rule against `User.Locale` (skipping override when explicit intent is present per §6.1). All downstream calls in the handler — template rendering, redirects, error helpers — must use the returned `r`. Handlers without a `User` (pre-login steps) skip the helper and stay on Phase 1's localizer. This puts the lookup cost only where a `User` was already going to be loaded, instead of forcing a new global middleware to do its own lookup on every request.
7. Template rendering reads the (refined or tentative) localizer from `context.Context`.

PR Phase 1 (§6.6) lands `MiddlewareLocalePhase1` and the `RefineLocalizerWithUser` helper. Tests required: a regression test asserting middleware composition order; a unit test covering Phase 1 reading `AuthContext.UILocales` mid-flow even when no handler runs (e.g., a redirect inside an early middleware); a unit test asserting `RefineLocalizerWithUser` honours explicit-intent precedence.

**A note on session-read cost.** Phase 1 calls `AuthHelper.GetAuthContext(r)`, which reads `SessionKeyAuthContext` from the session. This is **not** a fresh session-store roundtrip on every request: by the time Phase 1 runs, `MiddlewareSessionIdentifier` has already triggered the session decode (cookie unmarshalling, signature verification), and gorilla/sessions caches the decoded session on the request. Phase 1's helper call is effectively a map lookup against the cached session, plus a possible nil-check. Cost is negligible.

Alternatives considered and rejected:

- **A separate `MiddlewareAuthContextLoader` that always places `AuthContext` on `context.Context`.** Same effective cost as Phase 1 calling the helper directly (session is already cached either way). Rejected for a different reason: it would introduce a new context key and a new "the right way to read AuthContext" convention, when handlers already use `AuthHelper.GetAuthContext(r)` everywhere. Keeping Phase 1 on the existing helper means no new convention to learn or migrate to.
- **A global `MiddlewareLocalePhase2` for authserver that loads `UserSession` → `User` itself.** Would unify the model with adminconsole but adds two DB roundtrips per authenticated request just for locale, with no other consumer. Per-handler refinement keeps the cost colocated with code that was loading `User` anyway.
- **Restricting Phase 1's `AuthContext` lookup to authserver auth-flow paths only.** Considered as a way to skip the cached-session read on unrelated routes. Rejected because the read is already free against the cached session, and route-prefix gating would add fragility (every new auth-flow route needing a maintenance update).

### 6.13 Classifying non-template error response surfaces (Medium)

**Issue.** Many user-visible response surfaces sit outside handlers/templates and emit English directly:

- `src/core/middleware/middleware_settings.go:21`
- `src/core/middleware/middleware_jwt.go:125`
- `src/authserver/internal/middleware/api_auth.go:21`
- `src/core/handlerhelpers/http_helper.go:43`

Some of these reach browser users (should localize), some reach API/protocol clients (should stay English). Without a classification, the migration risks either localizing protocol responses or leaving browser-visible failures English. A naive prefix rule ("`/auth/*` is protocol") breaks down: `/auth/pwd`, `/auth/otp`, `/auth/consent`, `/auth/level1`, `/auth/level2`, `/auth/completed`, `/auth/issue` (browser intermediate steps under `routes.go`) all share the `/auth/` prefix with the protocol endpoints `/auth/token` and (the RP-redirect-error path of) `/auth/authorize`. There are also non-`/api/v1` machine endpoints to classify: `/api/public/settings` (consumed by `src/adminconsole/internal/apiclient/settings_client.go:40`), `/.well-known/openid-configuration`, `/certs`, `/client/logo/*`, `/userinfo/picture/*`.

**Resolution — classify by response surface, not by route prefix.**

Three response-surface categories. Endpoints are classified by which surfaces they emit; an endpoint can emit more than one (a single endpoint can take both a protocol path and a browser path depending on what happens during the request).

**Surface A — Localized HTML.** Browser-visible error pages, rendered HTML responses, redirects to error pages. Locale middleware has already run (§6.12), so the localizer is available. Examples:

- Authserver browser-flow handlers: `/auth/pwd`, `/auth/otp`, `/auth/level1`, `/auth/level1completed`, `/auth/level2`, `/auth/completed`, `/auth/consent`, `/auth/issue` — every page the user actually sees during the auth flow.
- Authserver account self-service pages.
- Adminconsole UI pages (everything not under `/api/`).
- `http_helper.go` general error responses returned to browsers.
- Panic recovery / 500 page rendered to a browser.

**Surface B — English structured machine response.** JSON / binary / spec-defined responses to machine consumers. Stay English. Examples:

- OAuth/OIDC protocol endpoints: `/auth/token`, `/auth/authorize` *when emitting an OAuth error redirect to the RP*, `/auth/revoke`, `/auth/introspect`, `/connect/register`, `/userinfo`, `/userinfo/picture/*`.
- OIDC discovery and JWKS: `/.well-known/openid-configuration`, `/certs`.
- Admin/account API: `/api/v1/admin/*`, `/api/v1/account/*` — uses the `{error, error_code, error_args, error_description}` shape from §6.3.
- Other public machine endpoints: `/api/public/settings`, `/client/logo/*` (binary; errors are JSON or plain HTTP status).

Note: `/auth/authorize` is a hybrid. Validation failures that redirect back to the RP with `error=...&error_description=...` are surface B (English, per RFC 6749). Successful validation that renders an internal browser step (e.g., level1 password page) is surface A (localized). The handler itself decides which surface it's emitting; classification is per response, not per endpoint.

**Surface C — English bootstrap fallback.** Surfaces that fire so early in the middleware chain that the locale is not yet established, or where the failure prevents the locale subsystem from working. Stay English by necessity. Examples:

- `middleware_settings.go` failure (settings load is required before locale middleware can resolve).
- Panic that occurs before locale middleware runs.

Per-emit-site classification for the originally listed files:

| File | Surface |
|---|---|
| `middleware_settings.go:21` | C — English bootstrap fallback. |
| `middleware_jwt.go:125` (browser request) | A — Localized HTML. Locale middleware ran already (§6.12 step 4). |
| `middleware_jwt.go:125` (API request) | B — English structured response in §6.3 shape. |
| `api_auth.go:21` | B — English structured response (admin/account API shape). |
| `http_helper.go:43` | A — Localized HTML via standard error page renderer. |
| Panic recovery / 500 page | A if locale established, else C. |

How code distinguishes browser vs API request inside a middleware (for `middleware_jwt.go`-style cases): match the request path against the surface-B endpoint list, or check the `Accept` header. The PR introducing Phase 4 adds a small helper `IsMachineRequest(r *http.Request) bool` that codifies the rule once.

PR Phase 4 (validator/handler error migration) adds a one-line classification comment at every emit site (`// i18n surface: A`, `B`, or `C`) and converts surface-A surfaces to the localized error renderer. Surface B and C surfaces stay English but get the comment so future readers know it's intentional.

### 6.14 API error code taxonomy (Medium)

**Issue.** The new `{error, error_code, error_args, error_description}` shape (§6.3) only does useful work if `error_code` values are stable and specific enough to be catalog keys. Today the API uses coarse codes like `VALIDATION_ERROR` and `INTERNAL_ERROR` (`src/authserver/internal/handlers/apihandlers/api_common.go:12`, `src/core/api/responses.go:380`, parsed by adminconsole at `src/adminconsole/internal/apiclient/auth_server_client.go:141`). A migration that just changes the JSON shape without redefining codes will produce a localizable container with nothing meaningfully localizable inside it.

**Resolution.** Define the taxonomy as part of Phase 4:

- **`error`** — coarse, stable category. Kept as a small enumerated set: `validation_failed`, `not_found`, `permission_denied`, `unauthenticated`, `conflict`, `rate_limited`, `internal_error`. English. Machine-readable.
- **`error_code`** — specific, stable, dotted path identifying the exact failure. Examples: `validator.user.email_already_in_use`, `validator.client.identifier_invalid_format`, `handler.user.cannot_delete_self`, `handler.client.cannot_delete_system_client`. Maps 1:1 to catalog keys.
- **`error_args`** — parameters substituted into the localized message at render time.
- **`error_description`** — the rendered English message. Stable for non-localizing consumers and as a debugging aid in logs.

Operational practices:

- Code constants live in `src/core/i18n/error_codes.go` (or similar); handler/validator code references constants, never string literals. Renames are mechanical.
- A document `src/core/i18n/error_codes.md` lists every defined code with its English message and arg shape. Adding a new error means adding a code first, then using it.
- CI lint: every catalog key beginning with `validator.` or `handler.` must have a corresponding code constant; every code constant must have a catalog entry. Prevents drift.
- Existing coarse codes (`VALIDATION_ERROR`, `INTERNAL_ERROR`, etc.) move to the `error` field as the new category. Specific codes go in `error_code`. Old single-code consumers see the category and have something to log against.

### 6.15 Adminconsole `profile` scope and locale claim — explicit checklist (Low)

**Issue.** The plan says adminconsole must request the OAuth `profile` scope so the JWT carries the `locale` claim (§6.4). But adminconsole's current scope construction at `src/core/middleware/middleware_jwt.go:310` omits `profile`, while the token issuer only emits `locale` under `profile` scope (`src/core/oauth/token_issuer.go:597`). This is easy to silently miss in implementation and would cause Phase 2 in adminconsole to always fall back to phase 1.

**Resolution.** Lift the requirement into an explicit PR Phase 1 checklist:

- [ ] Adminconsole client request includes `profile` scope (`src/core/middleware/middleware_jwt.go:310` adjusted to add `profile` to the requested scope set).
- [ ] Verified that `src/core/oauth/token_issuer.go:597` emits `locale` claim when the granted scopes include `profile`.
- [ ] Phase 2 middleware in adminconsole reads the `locale` claim from the validated JWT.
- [ ] Phase 2 in adminconsole falls back to phase 1's localizer when the `locale` claim is missing (older sessions, scope misconfiguration, etc.) — never silently jumps to English.
- [ ] Integration test: adminconsole login completes and the resulting access/ID token contains the `locale` claim.
- [ ] Integration test: change `User.Locale` via the account API → log out and log back in → adminconsole UI reflects the new locale.
- [ ] Documented staleness window: locale changes propagate to adminconsole only on next token refresh / re-login. Acceptable for v1.

### 6.16 Adminconsole route-level Phase 2 placement (Medium)

**Issue.** §6.12 described the middleware chain as if it were global. That's accurate for authserver, but adminconsole's JWT identity is established by **route-level** middleware, not global: `baseAuth`, `accountAuth`, and `adminAuth` are assembled in `src/adminconsole/internal/server/routes.go:59`. Phase 2 cannot be slotted into a single global place. Worse, `/unauthorized` is not wrapped with `baseAuth` (`src/adminconsole/internal/server/routes.go:79`), even though authenticated-but-forbidden users land there via redirect from `src/core/middleware/middleware_jwt.go:285` — so Phase 2 wouldn't fire on the page where users see "you're not allowed", and that page would render in Phase 1's locale rather than the user's stored locale.

**Resolution.**

- **Phase 2 is inserted into each route-level chain** that establishes identity: `baseAuth`, `accountAuth`, `adminAuth`. It runs immediately after JWT validation within that chain, mirroring §6.12's step 6 but at chain scope.
- **Phase 1 stays global** in adminconsole (registered on the root router), exactly as in authserver. It runs before any route-level chain, so every request — including ones that don't authenticate at all — gets a tentative localizer.
- **`/unauthorized` is wrapped with `baseAuth`.** Authenticated users are the only ones who see it (per the redirect at `middleware_jwt.go:285`), so wrapping it through baseAuth establishes identity, fires Phase 2, and lets the page render in the user's locale. The wrap is safe because baseAuth tolerates missing-permission cases — the whole point of the page is that the user is authenticated but not authorized.
- **Other public-but-user-relevant pages.** Audit logout confirmation, generic error pages, and similar routes during PR Phase 1. For each, decide: (a) wrap in baseAuth (page is reached by authenticated users, deserves their stored locale), or (b) accept Phase 1 fallback (page is reached by anonymous users or both — Accept-Language is fine). Document the decision per route in the routes file.

PR Phase 1 checklist gains: confirm `baseAuth`/`accountAuth`/`adminAuth` each include Phase 2 immediately after JWT validation, confirm `/unauthorized` is wrapped, confirm any audited public pages have an explicit decision.

### 6.17 Other reference-data dropdowns (Medium)

**Issue.** §6.11 covered the locale picker, but other reference-data dropdowns are also rendered with English labels:

- Time zones: `src/core/timezones/timezones.go:39` → `src/adminconsole/web/template/account_profile.html:114`
- Country names: `biter777/countries` → `src/adminconsole/web/template/account_address.html:74`
- Phone country labels: `src/core/phonecountries/phone_countries.go:19` → `src/adminconsole/web/template/account_phone.html:31`

Without addressing these, a user whose UI is localized to pt-BR still sees country/timezone dropdowns full of English labels.

**Resolution — localize each to the active UI locale, no parenthetical English.** Unlike the locale picker (where the user may not yet know the UI's language), these dropdowns appear when the UI is already in the user's chosen language; showing English in parentheses adds clutter for no benefit.

Source data:

- **Country names.** CLDR provides localized country names for every supported locale. **Pre-work required before labels can be wired up consistently.** The codebase currently mixes country representations: `src/adminconsole/web/template/account_address.html:74` posts ISO 3166-1 alpha-3 codes; `src/core/validators/address_validator.go:51` looks up by country *Name* via `countries.ByName(input.AddressCountry)`. Localized labels keyed off one representation while the validator reads another would silently corrupt or reject submissions. PR Phase 1 picks the canonical stored representation (suggested: alpha-2, the international standard, but alpha-3 is acceptable if migration cost outweighs the benefit) and standardizes form fields, validator, and any DB column on it. Localized labels are then keyed by the canonical code. This normalization is a contained refactor; doing it before label work prevents drift between stored value and displayed label.
- **Phone country labels.** Country-name portion uses the same CLDR country map as above. Dialing code is numeric and locale-independent. The label format `Brazil (+55)` becomes `Brasil (+55)` in pt-BR.
- **Time zones.** CLDR provides localized timezone display names (e.g., `America/Sao_Paulo` → `Horário de Brasília`). Larger dataset; same per-locale static-map pattern. Technical IDs (`America/Sao_Paulo`) remain unchanged as the canonical value.

For v1 (en + pt-BR), ship the pt-BR maps for all three. Adding a future locale requires generating these maps as part of the locale-rollout work, alongside the catalog translation.

**Scope reduction option (if effort pressure during implementation):** localize country names and phone country labels in v1, defer timezone label localization to a follow-up. Timezones are the largest dataset and many users navigate them by recognizing the technical ID anyway. This keeps the visible dropdowns on the most-used profile pages localized while deferring the heaviest data work.

These maps are static reference data, not catalog entries — they live alongside `src/core/locales/locales.go` rather than in `active.<locale>.toml`. The catalog stays focused on UI text.

## 7. Bottom Line

Technically very feasible. No architectural blockers. The right library exists, the right hook point exists, the locale data exists. The substantive work is the volume of strings and the validator/handler error contract decision.
