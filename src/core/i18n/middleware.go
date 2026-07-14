package i18n

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// AuthContextReader matches the subset of *handlerhelpers.AuthHelper that
// MiddlewareLocale needs to look up an in-flight authorize transaction.
// Adminconsole passes nil because it has no AuthContext concept (identity
// comes from JWT, handled separately by MiddlewareLocaleFromJWT).
type AuthContextReader interface {
	GetAuthContext(r *http.Request) (*oauth.AuthContext, error)
}

const (
	bcp47ShapePattern = `^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$`
	maxUILocaleTags   = 10
	maxUILocaleBytes  = 256
)

var bcp47ShapeRe = regexp.MustCompile(bcp47ShapePattern)

// SanitizeUILocales filters and bounds an OIDC ui_locales value: trims each
// tag, drops entries that don't match a permissive BCP 47 shape, caps at
// 10 tags and 256 total bytes (preserving order, dropping the tail when
// caps trip). Bounds prevent attacker-controlled input from bloating the
// session cookie.
//
// Returning nil means "no usable ui_locales was supplied" — callers should
// treat that as if the parameter was absent.
func SanitizeUILocales(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	bytesUsed := 0
	for _, tag := range strings.Fields(raw) {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if !bcp47ShapeRe.MatchString(tag) {
			continue
		}
		if bytesUsed+len(tag) > maxUILocaleBytes {
			break
		}
		out = append(out, tag)
		bytesUsed += len(tag)
		if len(out) >= maxUILocaleTags {
			break
		}
	}
	return out
}

// MiddlewareLocale returns the global locale-resolution middleware. It
// runs early in the request chain (before identity is established) and
// attaches a tentative localizer to the request context. authHelper may
// be nil (adminconsole), in which case the AuthContext step is skipped.
//
// Resolution order:
//
//  1. ?ui_locales= query parameter on the current request (no form parsing).
//  2. AuthContext.UILocales (authserver flows in progress).
//  3. Accept-Language header.
//  4. English fallback.
//
// When the source is (1) or (2) the localizer is marked as carrying
// "explicit intent" — RefineLocalizerWithUser and MiddlewareLocaleFromJWT
// honor that mark by skipping their override. This prevents user-locale
// refinement from clobbering an explicit per-request preference.
//
// Runs even if LoadBundle hasn't been called — in that case it becomes a
// no-op and Localizer falls back to a synthetic English localizer.
func MiddlewareLocale(authHelper AuthContextReader) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := resolveLocale(r.Context(), r, authHelper)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func resolveLocale(ctx context.Context, r *http.Request, authHelper AuthContextReader) context.Context {
	bundle := defaultBundle
	if bundle == nil {
		return ctx
	}

	// (1) Query parameter. Do NOT call r.ParseForm / r.FormValue — that
	// would consume the body and interfere with handlers that do their
	// own form parsing on POST.
	if raw := r.URL.Query().Get("ui_locales"); raw != "" {
		if tags := SanitizeUILocales(raw); len(tags) > 0 {
			return attachLocale(ctx, bundle.localizerFor(tags), tags[0], true)
		}
	}

	// (2) AuthContext.UILocales — authserver flows in progress.
	// gorilla/sessions caches the decoded session on the request via the
	// registry, so this is effectively a map lookup, not a fresh decode.
	if authHelper != nil {
		if ac, err := authHelper.GetAuthContext(r); err == nil && ac != nil && len(ac.UILocales) > 0 {
			return attachLocale(ctx, bundle.localizerFor(ac.UILocales), ac.UILocales[0], true)
		}
	}

	// (3) Accept-Language. go-i18n parses the header per RFC 7231.
	if al := r.Header.Get("Accept-Language"); al != "" {
		return attachLocale(ctx, bundle.localizerFor([]string{al}), al, false)
	}

	// (4) English fallback.
	return attachLocale(ctx, bundle.english, "en", false)
}

// MiddlewareLocaleFromJWT reads the locale claim from the JWT info already
// on the request context (set by JwtSessionHandler) and refines the
// localizer to it, unless the request carries explicit locale intent. Used
// by adminconsole's authenticated route chains to honor each user's stored
// locale preference.
//
// Falls through to the existing localizer when the claim is missing
// (older tokens, scope misconfiguration, third-party admin client without
// the profile scope) — never silently jumps to English.
func MiddlewareLocaleFromJWT() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if hasExplicitIntent(ctx) {
				next.ServeHTTP(w, r)
				return
			}
			locale := localeClaimFromJwt(ctx)
			if locale == "" {
				next.ServeHTTP(w, r)
				return
			}
			bundle := defaultBundle
			if bundle == nil {
				next.ServeHTTP(w, r)
				return
			}
			ctx = attachLocale(ctx, bundle.localizerFor([]string{locale}), locale, false)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func localeClaimFromJwt(ctx context.Context) string {
	v := ctx.Value(constants.ContextKeyJwtInfo)
	if v == nil {
		return ""
	}
	jwtInfo, ok := v.(oauth.JwtInfo)
	if !ok || jwtInfo.IdToken == nil {
		return ""
	}
	return strings.TrimSpace(jwtInfo.IdToken.GetStringClaim("locale"))
}

// RefineLocalizerWithUser is the authserver per-handler refinement helper.
// It returns a NEW *http.Request with an updated context. Go contexts are
// immutable: dropping the return value silently leaves the localizer
// unchanged.
//
// Canonical use:
//
//	r = i18n.RefineLocalizerWithUser(r, user)
//	// every downstream call (rendering, redirects, error helpers) MUST
//	// use the returned r.
//
// The override is suppressed when explicit request intent is present
// (current ?ui_locales or in-flight AuthContext.UILocales) — this is the
// rule that prevents user-locale refinement from clobbering an RP's stated
// ui_locales the moment the user authenticates inside the multi-step flow.
func RefineLocalizerWithUser(r *http.Request, user *models.User) *http.Request {
	return r.WithContext(RefineLocalizerContext(r.Context(), user))
}

// RefineLocalizerContext is the context-shaped form of RefineLocalizerWithUser
// for code paths that already have a bare context.Context (background workers,
// tests). Same override-suppression rule applies.
func RefineLocalizerContext(ctx context.Context, user *models.User) context.Context {
	if user == nil {
		return ctx
	}
	locale := strings.TrimSpace(user.Locale)
	if locale == "" {
		return ctx
	}
	if hasExplicitIntent(ctx) {
		return ctx
	}
	bundle := defaultBundle
	if bundle == nil {
		return ctx
	}
	return attachLocale(ctx, bundle.localizerFor([]string{locale}), locale, false)
}

// RefineLocalizerWithUILocales is used by handler_authorize.go after
// capturing a form-body ui_locales (which the global locale middleware
// cannot see — it only reads the query string to avoid consuming the POST
// body). Returns a new *http.Request. The same return-value-must-be-assigned
// rule from RefineLocalizerWithUser applies.
func RefineLocalizerWithUILocales(r *http.Request, uiLocales []string) *http.Request {
	if len(uiLocales) == 0 {
		return r
	}
	bundle := defaultBundle
	if bundle == nil {
		return r
	}
	ctx := attachLocale(r.Context(), bundle.localizerFor(uiLocales), uiLocales[0], true)
	return r.WithContext(ctx)
}

// attachLocale stores the localizer plus the primary resolved language tag
// (the first preference used to build the localizer; "en" for the bundle's
// English fallback). The tag is used by the CLDR-backed display helpers
// (RefCountry/RefPhoneCountry/RefTimezone).
func attachLocale(ctx context.Context, loc *i18n.Localizer, tag string, explicit bool) context.Context {
	ctx = context.WithValue(ctx, ctxKeyLocalizer, loc)
	ctx = context.WithValue(ctx, ctxKeyLocaleTag, primaryTag(tag))
	ctx = context.WithValue(ctx, ctxKeyExplicitIntent, explicit)
	return ctx
}

// primaryTag extracts the first language tag from a possibly multi-tag
// string ("en-US,en;q=0.9,fr;q=0.8" → "en-US"; "pt-BR" → "pt-BR";
// "en" → "en"). The display helpers need a single tag, not the full
// preference list.
func primaryTag(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "en"
	}
	if i := strings.IndexAny(s, ",;"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if s == "" {
		return "en"
	}
	return s
}

func hasExplicitIntent(ctx context.Context) bool {
	if v := ctx.Value(ctxKeyExplicitIntent); v != nil {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// EmailContext returns a context configured to render in the recipient's
// locale, decoupled from the originating request's locale. Used at
// email-send sites: the recipient cares about reading the email in their
// language, not the locale of whoever triggered the send (an admin issuing
// a welcome email, a server-side cron job, etc.).
//
// parent is the originating request context. EmailContext overlays the
// recipient-locale localizer on top of it, preserving every other context
// value the caller may need downstream (Settings, JWT info, audit
// metadata, request-id). Pass nil when there is genuinely no parent
// context (background workers); in that case context.Background() is used.
//
// recipientLocale is the BCP 47 tag (e.g. "pt-BR"). An empty string falls
// back to English. The returned context can be attached to a request via
// r.WithContext(...) before calling RenderTemplateToBuffer.
func EmailContext(parent context.Context, recipientLocale string) context.Context {
	if parent == nil {
		parent = context.Background()
	}
	bundle := defaultBundle
	if bundle == nil {
		return parent
	}
	tag := strings.TrimSpace(recipientLocale)
	if tag == "" {
		return attachLocale(parent, bundle.english, "en", false)
	}
	return attachLocale(parent, bundle.localizerFor([]string{tag}), tag, false)
}

// IsMachineRequest classifies a request by response surface: returns true
// for machine surfaces (admin/account API, OAuth/OIDC protocol endpoints,
// OIDC discovery, JWKS, public machine endpoints), false for browser HTML
// surfaces. Used at middleware error-emit sites to fork between localized
// HTML and English JSON envelopes.
func IsMachineRequest(r *http.Request) bool {
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/api/v1/"),
		strings.HasPrefix(p, "/api/public/"),
		p == "/auth/token",
		p == "/connect/register",
		p == "/userinfo",
		strings.HasPrefix(p, "/userinfo/"),
		strings.HasPrefix(p, "/.well-known/"),
		p == "/certs",
		strings.HasPrefix(p, "/client/logo/"):
		return true
	}
	return false
}
