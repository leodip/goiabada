package i18n

import (
	"context"
	"net/http"
	"regexp"
	"strings"
)

// UILocalesReader supplies locale preferences from an in-flight authorize
// transaction. Adminconsole passes nil because it has no such transaction
// state (identity comes from JWT, which adminconsole refines from in a
// middleware of its own over WithLocale).
type UILocalesReader interface {
	UILocales(r *http.Request) []string
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
// attaches a tentative localizer to the request context. uiLocalesReader may
// be nil (adminconsole), in which case the in-flight UI-locales step is skipped.
//
// Resolution order:
//
//  1. ?ui_locales= query parameter on the current request (no form parsing).
//  2. UI locales from an authserver flow in progress.
//  3. Accept-Language header.
//  4. English fallback.
//
// When the source is (1) or (2) the localizer is marked as carrying
// "explicit intent", which a non-explicit WithLocale call honors by leaving it
// alone. This prevents user-locale refinement from clobbering an explicit
// per-request preference.
//
// Runs even if LoadBundle hasn't been called — in that case it becomes a
// no-op and Localizer falls back to a synthetic English localizer.
func MiddlewareLocale(uiLocalesReader UILocalesReader) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := resolveLocale(r.Context(), r, uiLocalesReader)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ResolveRequestLocale attaches a tentative localizer to ctx from the request
// alone: ?ui_locales, then Accept-Language, then English. It is exactly what
// MiddlewareLocale does when authHelper is nil.
//
// It exists for a middleware that answers a request before MiddlewareLocale has
// run and so has no localizer to reach for. MiddlewareCsrf is the case: it is
// mounted on the root router, above the branch that carries the locale
// middleware, so that a route registered outside that branch cannot escape the
// origin check. Moving it down to gain a localizer would trade a fail-safe
// default for a translated 403.
//
// This is not a substitute for the middleware. The context it returns reaches
// the one response the caller is about to write, never the handlers below, so a
// caller that has a localizer already must use that one.
func ResolveRequestLocale(ctx context.Context, r *http.Request) context.Context {
	return resolveLocale(ctx, r, nil)
}

func resolveLocale(ctx context.Context, r *http.Request, uiLocalesReader UILocalesReader) context.Context {
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

	// (2) UI locales from an authserver flow in progress.
	// sessionstore.Get caches the loaded session on the request, so this is
	// effectively a map lookup, not a fresh load.
	if uiLocalesReader != nil {
		if tags := uiLocalesReader.UILocales(r); len(tags) > 0 {
			return attachLocale(ctx, bundle.localizerFor(tags), tags[0], true)
		}
	}

	// (3) Accept-Language, parsed per RFC 9110 section 12.5.4 and matched
	// against the loaded catalogs (see Bundle.localizerFor).
	if al := r.Header.Get("Accept-Language"); al != "" {
		return attachLocale(ctx, bundle.localizerFor([]string{al}), al, false)
	}

	// (4) English fallback.
	return attachLocale(ctx, bundle.english, "en", false)
}

// WithLocale attaches the translator for the locale the caller is asking for, and
// is the whole of core/i18n's locale-setting surface: every policy about which
// locale a process wants, and where it reads it from, belongs to that process.
//
// The tags are preferences, best first, and all the usable ones — non-empty
// after trimming — are matched together, the way an Accept-Language list is. An
// empty tag is skipped rather than ending the search, so a caller can write a
// preference ahead of a fallback and get the fallback only when the preference
// is absent: WithLocale(ctx, true, user.Locale, "en"). Matching is
// Bundle.localizerFor's, which means a tag no catalog matches still resolves,
// to English, while the tag itself is recorded as asked for. When no tag is
// usable, or LoadBundle has not run, ctx is returned unchanged.
//
// explicit marks the locale as a stated per-request preference: an RP's
// ui_locales, or an email rendered in its recipient's language rather than in
// the language of whoever triggered the send. A call with explicit false leaves
// an explicit locale already on ctx untouched, which is what stops user-locale
// refinement clobbering what the request asked for; a call with explicit true
// always wins.
//
// Go contexts are immutable, so the returned context is the whole of the
// effect. On a request that means
//
//	r = r.WithContext(i18n.WithLocale(r.Context(), false, user.Locale))
//	// every downstream call (rendering, redirects, error helpers) MUST use
//	// the returned r.
//
// Dropping the return value silently leaves the localizer unchanged.
func WithLocale(ctx context.Context, explicit bool, tags ...string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	bundle := defaultBundle
	if bundle == nil {
		return ctx
	}
	if !explicit && hasExplicitIntent(ctx) {
		return ctx
	}

	usable := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag = strings.TrimSpace(tag); tag != "" {
			usable = append(usable, tag)
		}
	}
	if len(usable) == 0 {
		return ctx
	}
	// The whole list reaches the matcher, not just usable[0]: ui_locales
	// arrives as "fr pt-BR" and today resolves pt-BR, because fr has no
	// catalog and the matcher reads the list as one preference order.
	// Matching only the first tag would answer English there, silently
	// discarding the RP's second choice (#385).
	return attachLocale(ctx, bundle.localizerFor(usable), usable[0], explicit)
}

// attachLocale stores the localizer plus the primary resolved language tag
// (the first preference used to build the localizer; "en" for the bundle's
// English fallback). The tag is used by the CLDR-backed display helpers
// (RefCountry/RefPhoneCountry/RefTimezone).
func attachLocale(ctx context.Context, loc *Translator, tag string, explicit bool) context.Context {
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
