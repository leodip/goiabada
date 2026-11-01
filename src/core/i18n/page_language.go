package i18n

import (
	"context"
	"strings"

	"golang.org/x/text/language"
)

// WithPageLanguage attaches a user's page language: the language they chose for Goiabada's own
// pages, stored as the tag of one of the loaded catalogs, or empty for Automatic (#631).
//
// A tag that names a loaded catalog wins over every source the request carries: ?ui_locales, a
// sign-in's ui_locales and Accept-Language, which the locale middleware resolved before identity
// was known, and any later WithLocale call, explicit or not, such as an authorize or sign-out
// handler applying the ui_locales it was sent. OIDC Core 1.0 section 3.1.2.1 and RP-Initiated
// Logout 1.0 section 2 make ui_locales a preference the provider may decline, and the user's own
// choice answers the same question better.
//
// Empty, or a tag that names no loaded catalog, is Automatic: the language the request asks for. A
// stored tag whose catalog an operator has since removed therefore follows the request, not
// English. The tag is compared exactly, as IsCatalogTag compares it; it is a stored value, not a
// preference to match. On a context with no page language, Automatic returns ctx unchanged, and a
// later WithLocale still applies.
//
// A later WithPageLanguage replaces an earlier one, so a caller applies the user it knows best last,
// and that user's Automatic replaces the earlier user's choice too: the page is then drawn in the
// language the request asks for, as it would have been with no choice applied, including what any
// WithLocale call made while the choice was on the context asked for (decision 5).
//
// As with WithLocale, the returned context is the whole of the effect. Unlike WithLocale, it has
// no nil-context fallback: its callers draw a page, so they always hold the request's context.
func WithPageLanguage(ctx context.Context, pageLanguage string) context.Context {
	b := current()
	tag, ok := b.catalogTag(pageLanguage)
	if !ok {
		if !hasPageLanguage(ctx) {
			return ctx
		}
		return restoreRequestLanguage(ctx)
	}
	beneath := requestLanguageOf(ctx)
	ctx = attachLocale(ctx, &translator{bundle: b, tag: tag}, pageLanguage, true, true)
	return context.WithValue(ctx, ctxKeyRequestLanguage, beneath)
}

// requestLanguage is the language a request asks for: the values attachLocale stores, as ctx held
// them, nil where it held none.
type requestLanguage struct {
	localizer, localeTag, explicitIntent any
}

// requestLanguageOf returns the language the request on ctx asks for: the one kept beneath a page
// language while one is on ctx, else ctx's own.
func requestLanguageOf(ctx context.Context) requestLanguage {
	if hasPageLanguage(ctx) {
		if beneath, ok := ctx.Value(ctxKeyRequestLanguage).(requestLanguage); ok {
			return beneath
		}
	}
	return requestLanguage{
		localizer:      ctx.Value(ctxKeyLocalizer),
		localeTag:      ctx.Value(ctxKeyLocaleTag),
		explicitIntent: ctx.Value(ctxKeyExplicitIntent),
	}
}

// restoreRequestLanguage replaces the page language on ctx with the language the request asks for.
// A value absent beneath it is restored as absent, so each reader falls back as it would have.
func restoreRequestLanguage(ctx context.Context) context.Context {
	beneath := requestLanguageOf(ctx)
	ctx = context.WithValue(ctx, ctxKeyLocalizer, beneath.localizer)
	ctx = context.WithValue(ctx, ctxKeyLocaleTag, beneath.localeTag)
	ctx = context.WithValue(ctx, ctxKeyExplicitIntent, beneath.explicitIntent)
	return context.WithValue(ctx, ctxKeyPageLanguage, false)
}

// CatalogTags returns the tags of the catalogs this process has loaded, which are the languages a
// user can choose as their page language: English first, then the built-in catalogs, then any an
// operator's override directory adds, in load order. An override of a built-in catalog adds no
// entry. The slice is the caller's own.
func CatalogTags() []string {
	tags := current().tags
	out := make([]string, len(tags))
	for i, t := range tags {
		out[i] = t.String()
	}
	return out
}

// IsCatalogTag reports whether tag is exactly the tag of a catalog this process has loaded, as
// CatalogTags lists it. A tag that only matches one ("pt" or "pt-br" for pt-BR) is not one, and
// nor is the tag of a catalog that is no longer loaded: as a page language, either counts as
// Automatic.
func IsCatalogTag(tag string) bool {
	_, ok := current().catalogTag(tag)
	return ok
}

// catalogTag finds the loaded catalog whose tag is exactly s.
func (b *bundle) catalogTag(s string) (language.Tag, bool) {
	if s == "" {
		return language.Tag{}, false
	}
	for _, t := range b.tags {
		if t.String() == s {
			return t, true
		}
	}
	return language.Tag{}, false
}

// WithRecipientLanguage attaches the language an email to an existing user is written in, subject
// and body alike: their page language when it names a loaded catalog, else their language and
// region (locale, the OIDC locale claim), else English (#631). An email has no browser to follow, so
// Automatic falls back to the locale rather than to the request.
//
// It replaces whatever ctx carries, a page language included. The request that sends an email may be
// drawn for someone else, the user of a signed-in browser asking to reset another account, or an
// administrator creating a user, and its language is the reader's of that page, never the
// recipient's. The locale is matched as WithLocale matches it and recorded as asked for, so a
// regional tag still picks its own copy of the body (LocaleTag) and a tag with no catalog falls back
// to English.
func WithRecipientLanguage(ctx context.Context, pageLanguage, locale string) context.Context {
	b := current()
	if tag, ok := b.catalogTag(pageLanguage); ok {
		return attachLocale(ctx, &translator{bundle: b, tag: tag}, pageLanguage, true, false)
	}
	tags := []string{"en"}
	if locale = strings.TrimSpace(locale); locale != "" {
		tags = []string{locale, "en"}
	}
	return attachLocale(ctx, b.localizerFor(tags), tags[0], true, false)
}
