package handlerhelpers

import (
	"context"
	"html/template"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/i18n"
)

// templateFuncMap is the four functions this application's templates call, counted by grepping
// every declared key against src/authserver/web/template. The admin console's copy of this file
// declares twenty-two, these four among them.
//
// The one map both binaries parsed with lived in core until #385 and held all twenty-two, so
// eighteen functions no auth server page can reach -- five console page predicates, the JS
// bootstrap block, the reference-data formatters -- were parsed into every template this server
// renders. Adding an entry here means an auth server template calls it; adding one the console
// alone calls means adding it there.
var templateFuncMap = template.FuncMap{
	// T translates key against the localizer carried on ctx. ctx is the
	// request context, injected into bind maps by RenderTemplateToBuffer
	// (see http_helper.go), so templates write {{ T $.ctx "auth.pwd.title" }}.
	//
	// Variadic kv pairs build a map[string]any for parameterized messages:
	//   {{ T $.ctx "validator.address.locality_too_long" "max" 60 }}
	// Each odd-indexed value is a key (must be a string); the next value is
	// the substitution. Pairs are dropped silently if mistyped.
	"T": func(ctx context.Context, key string, kv ...any) string {
		if len(kv) == 0 {
			return i18n.T(ctx, key)
		}
		args := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			k, ok := kv[i].(string)
			if !ok {
				continue
			}
			args[k] = kv[i+1]
		}
		return i18n.T(ctx, key, args)
	},
	// Lang resolves the active locale's BCP 47 tag for the <html lang="...">
	// attribute, so the document advertises the language it actually renders
	// in (screen readers, hyphenation, translation tools). Falls back to "en".
	"Lang": func(ctx context.Context) string { return i18n.LocaleTag(ctx) },

	// https://dev.to/moniquelive/passing-multiple-arguments-to-golang-templates-16h8
	"args": func(els ...any) []any {
		return els
	},
	"versionComment": func() template.HTML {
		//nolint:gosec // G203: build-time constants stamped by the linker, never request input
		return template.HTML("<!-- version: " + constants.Version + "; build date: " + constants.BuildDate + "; git commit: " + constants.GitCommit + "-->")
	},
}
