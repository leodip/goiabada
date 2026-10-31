package i18n

import (
	"context"

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
// choice answers the same question better. A later WithPageLanguage replaces an earlier one, so a
// caller applies the user it knows best last.
//
// Empty, or a tag that names no loaded catalog, is Automatic and returns ctx unchanged: the
// language the request resolved stands, and a later WithLocale still applies. A stored tag whose
// catalog an operator has since removed therefore follows the request, not English. The tag is
// compared exactly, as IsCatalogTag compares it; it is a stored value, not a preference to match.
//
// As with WithLocale, the returned context is the whole of the effect. Unlike WithLocale, it has
// no nil-context fallback: its callers draw a page, so they always hold the request's context.
func WithPageLanguage(ctx context.Context, pageLanguage string) context.Context {
	b := current()
	tag, ok := b.catalogTag(pageLanguage)
	if !ok {
		return ctx
	}
	return attachLocale(ctx, &translator{bundle: b, tag: tag}, pageLanguage, true, true)
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
