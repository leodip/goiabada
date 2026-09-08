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
// which locale they are in. Without a translator on the context — the
// EmailContext and bare-test-context cases — it resolves from LocaleTag(ctx)
// through the same matcher (#273).
func Raw(ctx context.Context, key string) string {
	var loc *Translator
	if ctx != nil {
		if v, ok := ctx.Value(ctxKeyLocalizer).(*Translator); ok {
			loc = v
		}
	}
	if loc == nil {
		if defaultBundle == nil {
			return key
		}
		loc = defaultBundle.localizerFor([]string{LocaleTag(ctx)})
	}
	if m, ok := loc.lookup(key); ok {
		return m.raw
	}
	return key
}
