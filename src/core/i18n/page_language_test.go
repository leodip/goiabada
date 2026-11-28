package i18n

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A user's page language is the language they chose for Goiabada's own pages. It wins over every
// source a request carries, and each case here names the source that loses as well as the one that
// wins, beside its Automatic twin, which keeps today's answer (#631 decision 4).

// throughLocale runs the locale middleware, with an optional in-flight ui_locales reader standing in
// for a sign-in's, over a request and returns the context it handed down.
func throughLocale(t *testing.T, reader UILocalesReader, target, acceptLanguage string) context.Context {
	t.Helper()

	req := httptest.NewRequest("GET", target, nil)
	if acceptLanguage != "" {
		req.Header.Set("Accept-Language", acceptLanguage)
	}
	var ctx context.Context
	Locale(reader)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
	})).ServeHTTP(httptest.NewRecorder(), req)
	require.NotNil(t, ctx)
	return ctx
}

func TestWithPageLanguage_WinsOverEveryRequestSource(t *testing.T) {
	tests := []struct {
		name           string
		reader         UILocalesReader
		target         string
		acceptLanguage string
		automatic      string
	}{
		{"over ?ui_locales", nil, "/auth/pwd?ui_locales=es", "en", "Iniciar sesión"},
		{"over a sign-in's ui_locales", &stubUILocalesReader{locales: []string{"es"}}, "/auth/pwd", "en", "Iniciar sesión"},
		{"over Accept-Language", nil, "/auth/pwd", "es", "Iniciar sesión"},
		{"over ?ui_locales, a sign-in's ui_locales and Accept-Language together",
			&stubUILocalesReader{locales: []string{"fr"}}, "/auth/pwd?ui_locales=es", "de", "Iniciar sesión"},
		{"over the English fallback", nil, "/auth/pwd", "", "Sign in"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := throughLocale(t, tt.reader, tt.target, tt.acceptLanguage)

			chosen := WithPageLanguage(base, "pt-BR")
			assert.Equal(t, "Entrar", T(chosen, "auth.pwd.title"))
			assert.Equal(t, "pt-BR", CatalogTag(chosen))
			assert.Equal(t, "pt-BR", LocaleTag(chosen))

			automatic := WithPageLanguage(base, "")
			assert.Equal(t, tt.automatic, T(automatic, "auth.pwd.title"), "Automatic keeps today's answer")
			assert.Equal(t, base, automatic, "Automatic leaves the context as the request resolved it")
		})
	}
}

// English is one of the languages a user can choose, not a synonym for Automatic: choosing it beats
// a request asking for Portuguese.
func TestWithPageLanguage_EnglishIsAChoice(t *testing.T) {
	base := throughLocale(t, nil, "/auth/pwd?ui_locales=pt-BR", "pt-BR")
	require.Equal(t, "Entrar", T(base, "auth.pwd.title"))

	chosen := WithPageLanguage(base, "en")
	assert.Equal(t, "Sign in", T(chosen, "auth.pwd.title"))
	assert.Equal(t, "en", CatalogTag(chosen))
}

// An authorize or sign-out handler applies its own ui_locales with an explicit WithLocale after the
// middleware; once the user's page language is on the context, that later request does not move it,
// and neither does a non-explicit refinement. On Automatic the handler's ui_locales still wins.
func TestWithPageLanguage_ALaterWithLocaleDoesNotOverrideIt(t *testing.T) {
	base := throughLocale(t, nil, "/auth/authorize", "en")
	chosen := WithPageLanguage(base, "pt-BR")

	explicit := WithLocale(chosen, true, SanitizeUILocales("es")...)
	assert.Equal(t, "Entrar", T(explicit, "auth.pwd.title"), "a handler's own ui_locales loses to the choice")
	assert.Equal(t, "pt-BR", CatalogTag(explicit))
	assert.Equal(t, "pt-BR", LocaleTag(explicit))

	refined := WithLocale(chosen, false, "fr")
	assert.Equal(t, "Entrar", T(refined, "auth.pwd.title"), "a non-explicit refinement loses to the choice")

	// Its Automatic twin: the handler's ui_locales is applied as it is today.
	automatic := WithLocale(WithPageLanguage(base, ""), true, SanitizeUILocales("es")...)
	assert.Equal(t, "Iniciar sesión", T(automatic, "auth.pwd.title"))
	assert.Equal(t, "es", CatalogTag(automatic))

	// And WithLocale still protects that explicit request from a later non-explicit refinement, as
	// it did before page languages existed.
	assert.Equal(t, "Iniciar sesión", T(WithLocale(automatic, false, "fr"), "auth.pwd.title"))
}

// A later page language replaces an earlier one: the auth server applies the browser session's
// user's choice and then the sign-in's user's, who wins as the person signing in now (decision 5).
func TestWithPageLanguage_ALaterChoiceReplacesAnEarlierOne(t *testing.T) {
	base := throughLocale(t, nil, "/auth/otp", "en")

	ctx := WithPageLanguage(WithPageLanguage(base, "de"), "fr")
	assert.Equal(t, "Connexion", T(ctx, "auth.pwd.title"))
	assert.Equal(t, "fr", CatalogTag(ctx))
}

// A later user on Automatic, or whose stored tag's catalog has gone, replaces an earlier user's
// choice with the language the request asks for: the browser session's user chose German, the
// sign-in's user chose nothing, and the page follows the request's ?ui_locales=es, a sign-in's
// ui_locales or the browser, not the session user (decisions 2, 3 and 5).
func TestWithPageLanguage_ALaterAutomaticGivesTheRequestsLanguageBack(t *testing.T) {
	tests := []struct {
		name           string
		reader         UILocalesReader
		target         string
		acceptLanguage string
		want           string
		catalog        string
		explicit       bool
	}{
		{"?ui_locales", nil, "/auth/pwd?ui_locales=es", "en", "Iniciar sesión", "es", true},
		{"a sign-in's ui_locales", &stubUILocalesReader{locales: []string{"it"}}, "/auth/pwd", "en", "Accedi", "it", true},
		{"Accept-Language", nil, "/auth/pwd", "fr", "Connexion", "fr", false},
		{"the English fallback", nil, "/auth/pwd", "", "Sign in", "en", false},
	}
	for _, tt := range tests {
		for _, automatic := range []string{"", "sv"} {
			t.Run(tt.name+"/"+automatic, func(t *testing.T) {
				base := throughLocale(t, tt.reader, tt.target, tt.acceptLanguage)
				ctx := WithPageLanguage(WithPageLanguage(base, "de"), automatic)

				assert.Equal(t, tt.want, T(ctx, "auth.pwd.title"), "the session user's German loses")
				assert.Equal(t, tt.catalog, CatalogTag(ctx))
				assert.Equal(t, LocaleTag(base), LocaleTag(ctx))
				assert.Equal(t, tt.explicit, hasExplicitIntent(ctx))

				// The request's language is back, so a later handler's own ui_locales applies again.
				assert.Equal(t, "Entrar", T(WithLocale(ctx, true, "pt-BR"), "auth.pwd.title"))
			})
		}
	}
}

// A handler's own ui_locales applied while a choice is on the context does not move the choice, but
// it is what the request asks for: once a later user on Automatic replaces the choice, it stands,
// and a non-explicit refinement beneath the choice still defers to it.
func TestWithPageLanguage_AWithLocaleBeneathAChoiceSurvivesALaterAutomatic(t *testing.T) {
	base := throughLocale(t, nil, "/auth/authorize", "en")

	chosen := WithLocale(WithPageLanguage(base, "de"), true, SanitizeUILocales("es")...)
	require.Equal(t, "Anmelden", T(chosen, "auth.pwd.title"))
	chosen = WithLocale(chosen, false, "fr")
	require.Equal(t, "Anmelden", T(chosen, "auth.pwd.title"))

	ctx := WithPageLanguage(chosen, "")
	assert.Equal(t, "Iniciar sesión", T(ctx, "auth.pwd.title"))
	assert.Equal(t, "es", CatalogTag(ctx))
	assert.Equal(t, "es", LocaleTag(ctx))

	// With no handler's ui_locales, the non-explicit refinement beneath the choice is what stands.
	refined := WithPageLanguage(WithLocale(WithPageLanguage(base, "de"), false, "fr"), "")
	assert.Equal(t, "Connexion", T(refined, "auth.pwd.title"))
}

// A value that names no built-in catalog counts as Automatic, a language Goiabada doesn't ship
// included: the request's own language stands, not English, and a later explicit request still
// applies.
func TestWithPageLanguage_AValueNamingNoCatalogIsAutomatic(t *testing.T) {
	base := throughLocale(t, nil, "/auth/pwd?ui_locales=es", "en")

	for _, value := range []string{"sv", "nl", "pt", "pt-br", " pt-BR", "pt_BR", "pt-BR-x-y"} {
		t.Run(value, func(t *testing.T) {
			ctx := WithPageLanguage(base, value)
			assert.Equal(t, base, ctx, "%q names no catalog, so the context is unchanged", value)
			assert.Equal(t, "Iniciar sesión", T(ctx, "auth.pwd.title"))
			assert.Equal(t, "Connexion", T(WithLocale(ctx, true, "fr"), "auth.pwd.title"),
				"%q is Automatic, so a later explicit request still applies", value)
		})
	}
}

// CatalogTags lists the catalogs built into Goiabada, English first, and nothing else.
func TestCatalogTags_ListsTheBuiltInCatalogs(t *testing.T) {
	assert.Equal(t, []string{"en", "de", "es", "fr", "id", "it", "ja", "pl", "pt-BR", "ru", "zh-Hans"}, CatalogTags())
}

// The list is the caller's own: changing it changes nothing the next caller sees.
func TestCatalogTags_ReturnsACopy(t *testing.T) {
	tags := CatalogTags()
	require.NotEmpty(t, tags)
	tags[0] = "xx"
	assert.Equal(t, "en", CatalogTags()[0])
}

// The built-in catalogs are the ones compiled in, and a tag names one only when it is spelt exactly as
// its catalog is: a page language and a brand's footer link label are both checked against them.
func TestIsCatalogTag(t *testing.T) {
	for _, tag := range []string{"en", "de", "es", "fr", "id", "it", "ja", "pl", "pt-BR", "ru", "zh-Hans"} {
		assert.True(t, IsCatalogTag(tag), "%q is a built-in catalog", tag)
	}
	for _, tag := range []string{"", "sv", "nl", "pt", "pt-br", "PT-BR", " pt-BR", "pt-BR ", "en-US", "EN", "fr-CA", "in", "id-ID", "ID", "pl-PL", "PL", "ru-RU", "RU", "ja-JP", "JA", "jpn", "zh", "zh-CN", "zh-hans", "ZH-HANS", "zh-Hans-CN", "zh-Hant", "zh-TW"} {
		assert.False(t, IsCatalogTag(tag), "%q names no built-in catalog", tag)
	}
}
