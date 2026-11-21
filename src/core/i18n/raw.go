package i18n

import (
	"context"
)

// Raw returns the un-templated catalog string for key against the locale
// carried on ctx, falling back to English, then to the key itself. Unlike T()
// it does not execute the string as a template, so {{param}} placeholders are
// preserved for client-side substitution (used by the JS bootstrap).
//
// It resolves the locale exactly as T() does, off the translator the locale
// middleware attached, so a page and its JS strings can never disagree about
// which locale they are in. Without a translator on the context — a bare test
// context, say — it resolves from LocaleTag(ctx) through the same matcher
// (#273).
func Raw(ctx context.Context, key string) string {
	if m, ok := rawLocalizer(ctx).lookup(key); ok {
		return m.raw
	}
	return key
}

// RawCounted returns the un-templated forms of the counted phrase key that a script chooses among
// with its own plural rules, keyed by catalog key, against the locale Raw resolves: each form
// "<key>.<category>" the page's own catalog holds, never one English supplies, and "<key>.other" as
// Raw answers it, so a catalog without the family hands over English's other form by the ordinary
// fallback. The script then renders the other form for a category it finds no key for, which is
// TCount's order (#665 decision 1).
func RawCounted(ctx context.Context, key string) map[string]string {
	l := rawLocalizer(ctx)
	forms := map[string]string{key + ".other": Raw(ctx, key+".other")}
	for _, category := range pluralCategoryNames {
		if form := key + "." + category; l.owns(form) {
			forms[form] = l.bundle.messages[l.tag][form].raw
		}
	}
	return forms
}

// rawLocalizer is the translator Raw and RawCounted read: the one the locale middleware attached to
// ctx, else the one LocaleTag(ctx) matches.
func rawLocalizer(ctx context.Context) *translator {
	if ctx != nil {
		if v, ok := ctx.Value(ctxKeyLocalizer).(*translator); ok {
			return v
		}
	}
	return builtIn().localizerFor([]string{LocaleTag(ctx)})
}
