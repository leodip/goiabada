package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/httpmw"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
)

// pageLanguageSeen sends one request carrying cookies through the chain a signed-in console page
// goes through: the locale middleware, CookieReset, SessionHandler and PageLanguage, as
// applicationChain and routes.go mount them. It reports the sign-in title the page below would
// draw, and the catalog it would draw it from, which is what <html lang> names.
func (h *sessionHarness) pageLanguageSeen(target, acceptLanguage string, cookies []*http.Cookie) (title, catalog string) {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Accept-Language", acceptLanguage)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	page := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		title = i18n.T(r.Context(), "auth.pwd.title")
		catalog = i18n.CatalogTag(r.Context())
	})
	chain := i18n.Locale(nil)(httpmw.CookieReset(h.store, sessionTestName)(
		h.middleware(h.parser).SessionHandler()(PageLanguage(h.store, sessionTestName)(page))))
	chain.ServeHTTP(httptest.NewRecorder(), req)
	return title, catalog
}

// signedInWithPageLanguage is a signed-in session holding the page language copy the sign-in, or
// the profile page, wrote; absent leaves the key out, as in a session signed in before #631.
func signedInWithPageLanguage(pageLanguage string, present bool) map[string]any {
	values := signedIn(notDue())
	if present {
		values[sessionkeys.PageLanguage] = pageLanguage
	}
	return values
}

// The stored ID token carries a locale claim of German in every row, which the console no longer
// reads: Language and region steers no console page (#631 decision 2).
var verifiedStoredWithLocale = &oauth.JwtToken{TokenBase64: storedIDTokenRaw,
	Claims: map[string]any{"sub": "the-admin", "locale": "de"}}

// A user's page language, copied into the console's session, wins over ?ui_locales and the
// browser on every signed-in page; Automatic, its twin, keeps the request's order: ?ui_locales,
// then Accept-Language, then English (#631 decisions 2, 4 and 7). A tag that names no loaded
// catalog counts as Automatic (decision 3).
func TestPageLanguage_TheChoiceWinsOverTheRequestAndAutomaticFollowsIt(t *testing.T) {
	for _, tc := range []struct {
		name           string
		pageLanguage   string
		present        bool
		target         string
		acceptLanguage string
		wantTitle      string
		wantCatalog    string
	}{
		{"chosen, over ui_locales and the browser", "pt-BR", true,
			"/admin/users?ui_locales=es", "en", "Entrar", "pt-BR"},
		{"Automatic, ui_locales wins over the browser", "", true,
			"/admin/users?ui_locales=es", "en", "Iniciar sesión", "es"},
		{"chosen, over the browser", "fr", true,
			"/admin/users", "it", "Connexion", "fr"},
		{"Automatic, the browser, not the locale claim", "", true,
			"/admin/users", "it", "Accedi", "it"},
		{"no copy in the session, the browser", "", false,
			"/admin/users", "it", "Accedi", "it"},
		{"a tag with no catalog, the request", "ja", true,
			"/admin/users?ui_locales=es", "en", "Iniciar sesión", "es"},
		{"a tag that only matches a catalog, the request", "pt-br", true,
			"/admin/users", "en", "Sign in", "en"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSessionHarness(t)
			h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).
				Return(verifiedStoredWithLocale, nil)
			cookies := h.seed(signedInWithPageLanguage(tc.pageLanguage, tc.present))

			title, catalog := h.pageLanguageSeen(tc.target, tc.acceptLanguage, cookies)

			assert.Equal(t, tc.wantTitle, title)
			assert.Equal(t, tc.wantCatalog, catalog)
		})
	}
}

// A session that holds a page language but no signed-in user, one signed out after its ID token
// stopped verifying, draws its pages in the request's language: the copy is the signed-in user's,
// and an anonymous page has none.
func TestPageLanguage_ASignedOutSessionFollowsTheRequest(t *testing.T) {
	h := newSessionHarness(t)
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).
		Return(nil, assert.AnError)
	cookies := h.seed(signedInWithPageLanguage("pt-BR", true))

	title, catalog := h.pageLanguageSeen("/admin/users", "it", cookies)

	assert.Equal(t, "Accedi", title)
	assert.Equal(t, "it", catalog)
}

// A browser with no session at all is the anonymous request: nothing to read, and the request's
// language stands.
func TestPageLanguage_NoSessionFollowsTheRequest(t *testing.T) {
	h := newSessionHarness(t)

	title, catalog := h.pageLanguageSeen("/admin/users?ui_locales=de", "en", nil)

	assert.Equal(t, "Anmelden", title)
	assert.Equal(t, "de", catalog)
}
