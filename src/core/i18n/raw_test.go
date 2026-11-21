package i18n

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRaw_PreservesPlaceholdersAndLocalizes(t *testing.T) {
	en := ctxFor("en")
	pt := ctxFor("pt-BR")

	// A parameterized JS key: the {{detail}} placeholder must survive verbatim
	// for client-side tFormat(). T() leaks the key here; Raw() must not.
	raw := Raw(en, "js.error.unexpected")
	assert.Contains(t, raw, "{{detail}}", "Raw must preserve the client-side placeholder")
	assert.NotEqual(t, "js.error.unexpected", raw, "Raw must not leak the key")
	assert.Equal(t, "js.error.unexpected", T(en, "js.error.unexpected"),
		"documents why Raw exists: T() leaks the key for {{param}} messages")

	// Localizes like T for plain (non-parameterized) keys.
	assert.Equal(t, "Erro", Raw(pt, "js.error.error_title"))
	assert.NotEmpty(t, Raw(en, "js.error.error_title"))

	// Miss policy: an unknown key returns the key itself.
	assert.Equal(t, "no.such.key.zzz", Raw(en, "no.such.key.zzz"))
}

// TestRaw_ResolvesTheLocaleTheSameWayTAsDoes is the case that fails under the
// old Raw, which indexed the catalogs by the request's primary tag string:
// "pt" and "pt-PT" matched no catalog, so the page rendered in pt-BR while the
// JS bootstrap strings came back in English (#273).
func TestRaw_ResolvesTheLocaleTheSameWayTAsDoes(t *testing.T) {
	for _, tc := range []struct {
		acceptLanguage string
		wantRaw        string
		wantT          string
	}{
		{"pt-BR", "Erro", "Entrar"},
		{"pt", "Erro", "Entrar"},
		{"pt-PT", "Erro", "Entrar"},
		// The primary tag is nl-NL, which matches no catalog, while the
		// matcher takes the second range: the page is pt-BR, so the JS
		// strings must be too.
		{"nl-NL,pt;q=0.8", "Erro", "Entrar"},
		// English outranks pt-BR here, and both surfaces must say so.
		{"en-US,pt-BR;q=0.5", "Error", "Sign in"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/auth/pwd", nil)
		req.Header.Set("Accept-Language", tc.acceptLanguage)

		var gotRaw, gotT string
		Locale(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			gotRaw = Raw(r.Context(), "js.error.error_title")
			gotT = T(r.Context(), "auth.pwd.title")
		})).ServeHTTP(httptest.NewRecorder(), req)

		assert.Equalf(t, tc.wantRaw, gotRaw, "Raw for Accept-Language %q", tc.acceptLanguage)
		assert.Equalf(t, tc.wantT, gotT, "T for Accept-Language %q", tc.acceptLanguage)
	}
}

func TestRaw_NoLocalizerOnContextResolvesFromLocaleTag(t *testing.T) {
	// A bare test context carries the tag but no translator.
	ctx := context.WithValue(context.Background(), ctxKeyLocaleTag, "pt-BR")
	assert.Equal(t, "Erro", Raw(ctx, "js.error.error_title"))
}

// A script's counted phrase gets the forms the page's own catalog holds and its other form, and never
// a form English holds for a category the page's catalog leaves out: the script would choose it over
// the catalog's own other form, which is not TCount's order.
func TestRawCounted_HandsOverTheCatalogsOwnFormsAndItsOtherForm(t *testing.T) {
	b := counted(map[string]map[string]string{
		"en": {
			"pairs.one":     "{{count}} pair",
			"pairs.few":     "{{count}} pairs (en few)",
			"pairs.other":   "{{count}} pairs",
			"clients.one":   "{{count}} client",
			"clients.other": "{{count}} clients",
		},
		"pl": {"pairs.one": "{{count}} para", "pairs.many": "{{count}} par", "pairs.other": "{{count}} pary", "pairs.none": "Brak par"},
	})
	pl, en := ctxForBundle(b, "pl"), ctxForBundle(b, "en")
	assert.Equal(t, map[string]string{"pairs.one": "{{count}} para", "pairs.many": "{{count}} par", "pairs.other": "{{count}} pary"},
		RawCounted(pl, "pairs"), "pl's own forms, its placeholders unexecuted, and neither English's few nor the sentence for nothing")
	assert.Equal(t, map[string]string{"clients.other": "{{count}} clients"}, RawCounted(pl, "clients"),
		"pl has no form of the family, so English's other form, by the ordinary fallback")
	assert.Equal(t, map[string]string{"pairs.one": "{{count}} pair", "pairs.few": "{{count}} pairs (en few)", "pairs.other": "{{count}} pairs"},
		RawCounted(en, "pairs"))
	assert.Equal(t, map[string]string{"nothing.other": "nothing.other"}, RawCounted(pl, "nothing"),
		"a family no catalog has hands over its other form's key, the visible miss Raw answers")
}

// The built-in catalogs hand over their own one and other forms of the combobox's match count, each
// with the {{count}} placeholder the script fills, resolved as Raw resolves a locale.
func TestRawCounted_TheBuiltInCombobox(t *testing.T) {
	assert.Equal(t, map[string]string{"js.combobox.results.one": "{{count}} résultat", "js.combobox.results.other": "{{count}} résultats"},
		RawCounted(ctxFor("fr-CA"), "js.combobox.results"))
	assert.Equal(t, map[string]string{"js.combobox.results.one": "{{count}} resultado", "js.combobox.results.other": "{{count}} resultados"},
		RawCounted(context.WithValue(context.Background(), ctxKeyLocaleTag, "pt"), "js.combobox.results"),
		"a context with no translator resolves from its locale tag")
}
