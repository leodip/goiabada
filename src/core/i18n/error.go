package i18n

import (
	"context"

	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// LocalizedError carries a stable error code and template arguments. The
// rendered message is produced on demand at the response boundary —
// localized for browser surfaces, English-only for protocol surfaces.
//
// The Code field MUST be one of the constants in error_codes.go. Args is
// keyed by the placeholder names used in the catalog template
// (e.g. {"max": 60} renders against "...{{.max}}...").
type LocalizedError struct {
	Code string
	Args map[string]any
}

// NewLocalizedError is the canonical constructor. Args may be nil for
// codes whose catalog message takes no parameters.
func NewLocalizedError(code string, args map[string]any) *LocalizedError {
	return &LocalizedError{Code: code, Args: args}
}

// Error returns the English rendering, satisfying the error interface.
// Equivalent to EnglishFallback().
func (e *LocalizedError) Error() string { return e.EnglishFallback() }

// EnglishFallback renders the English catalog template for e.Code with
// e.Args substituted. "Fallback" means it does not require a request-bound
// localizer (English is always available as the source-of-truth catalog) —
// it does NOT mean args are dropped. Used at protocol response boundaries
// that must stay English regardless of caller locale (see design §6.2).
//
// If LoadBundle hasn't run, or the code is missing from the English
// catalog, returns e.Code so the gap is visible.
func (e *LocalizedError) EnglishFallback() string {
	if defaultBundle == nil {
		return e.Code
	}
	return localize(defaultBundle.english, e.Code, e.Args)
}

// Localize renders e against the locale carried on ctx, with e.Args
// substituted. Falls back to EnglishFallback() if the key is missing in
// the resolved locale.
func (e *LocalizedError) Localize(ctx context.Context) string {
	loc := Localizer(ctx)
	out, err := loc.Localize(buildConfig(e.Code, e.Args))
	if err != nil {
		return e.EnglishFallback()
	}
	return out
}

func localize(loc *i18n.Localizer, code string, args map[string]any) string {
	out, err := loc.Localize(buildConfig(code, args))
	if err != nil {
		return code
	}
	return out
}

func buildConfig(code string, args map[string]any) *i18n.LocalizeConfig {
	cfg := &i18n.LocalizeConfig{MessageID: code}
	if len(args) > 0 {
		cfg.TemplateData = args
	}
	return cfg
}
