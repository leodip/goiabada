package renderintegration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/middleware"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// My Account's Profile form offers the Page language, and the console draws the user's next page in
// what they saved there, over ?ui_locales and the browser (#631 decisions 4, 7 and 10).

// storedProfileAPI is the Account API as the profile page reaches it: one stored profile, which a
// save changes as the auth server would, the page language left as stored when the update names
// none. A refusal, when set, answers every save.
type storedProfileAPI struct {
	pageLanguage string
	refusal      error
}

func (a *storedProfileAPI) GetAccountProfile(context.Context, string) (*api.UserResponse, error) {
	return &api.UserResponse{Id: 7, Email: "someone@example.com", Locale: "de", PageLanguage: a.pageLanguage}, nil
}

func (a *storedProfileAPI) UpdateAccountProfile(_ context.Context, _ string,
	request *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	if a.refusal != nil {
		return nil, a.refusal
	}
	if request.PageLanguage != nil {
		a.pageLanguage = *request.PageLanguage
	}
	return a.GetAccountProfile(context.Background(), "")
}

func newPageLanguageStore(t *testing.T) *sessionstore.ServerSideStore {
	t.Helper()
	store, err := sessionstore.NewServerSideStore(sessiontest.NewMemoryBackend(), sessionkeys.JWT, false,
		sessionstore.BrowserSessionCookie, sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		}, nil)
	require.NoError(t, err)
	return store
}

// pageLanguageBrowser is one signed-in browser: the cookies it holds, and the console's locale
// chain, as applicationChain and routes.go mount it around an account page.
type pageLanguageBrowser struct {
	t       *testing.T
	store   *sessionstore.ServerSideStore
	cookies map[string]*http.Cookie
}

func (b *pageLanguageBrowser) serve(handler http.Handler, method, target string, form url.Values) *httptest.ResponseRecorder {
	b.t.Helper()
	options := []handlertest.Option{handlertest.WithAccessToken(),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test", UITheme: "dark"})}
	if form != nil {
		options = append(options, handlertest.WithForm(form))
	}
	req := handlertest.Request(method, target, options...)
	req.Header.Set("Accept-Language", "en-US")
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	i18n.Locale(nil)(middleware.PageLanguage(b.store, builtin.AdminConsoleSessionName)(handler)).ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		b.cookies[c.Name] = c
	}
	return rec
}

// htmlLangRe reads the language a page is marked in.
var htmlLangRe = regexp.MustCompile(`<html lang="([^"]+)"`)

func htmlLang(t *testing.T, page string) string {
	t.Helper()
	m := htmlLangRe.FindStringSubmatch(page)
	require.NotNil(t, m, "the page is marked with a language")
	return m[1]
}

// The user saves a page language, and the page the save redirects to is drawn and marked in it, an
// address asking for Spanish and a browser asking for English notwithstanding; the profile's
// Language and region, German, plays no part. Saving Automatic gives ?ui_locales back, and then the
// browser.
func TestRender_AccountProfile_TheSavedPageLanguageDrawsTheNextPage(t *testing.T) {
	store := newPageLanguageStore(t)
	profiles := &storedProfileAPI{}
	httpHelper := render.New(web.TemplateFS(), web.StaticFS())
	get := accounthandlers.HandleProfileGet(httpHelper, store, profiles)
	post := accounthandlers.HandleProfilePost(httpHelper, store, profiles, "https://console.example")
	browser := &pageLanguageBrowser{t: t, store: store, cookies: map[string]*http.Cookie{}}

	save := func(pageLanguage string) {
		t.Helper()
		rec := browser.serve(post, http.MethodPost, "/account/profile",
			url.Values{"username": {"someone"}, "pageLanguage": {pageLanguage}})
		require.Equal(t, http.StatusFound, rec.Code)
	}
	open := func(target string) string {
		t.Helper()
		rec := browser.serve(get, http.MethodGet, target, nil)
		require.Equal(t, http.StatusOK, rec.Code)
		return rec.Body.String()
	}

	save("pt-BR")
	page := open("/account/profile")
	assert.Equal(t, "pt-BR", htmlLang(t, page))
	assert.Contains(t, page, "Perfil salvo.")
	assert.Equal(t, "pt-BR", htmlLang(t, open("/account/profile?ui_locales=es")), "the choice wins over ?ui_locales")

	save("")
	page = open("/account/profile")
	assert.Equal(t, "en", htmlLang(t, page), "Automatic follows the browser")
	assert.Contains(t, page, "Profile saved.")
	assert.Equal(t, "es", htmlLang(t, open("/account/profile?ui_locales=es")), "Automatic follows ?ui_locales")
}

// pageLanguageSelectRe captures the Page language select's opening tag and its options.
var pageLanguageSelectRe = regexp.MustCompile(`(?s)(<select[^>]*id="pageLanguage"[^>]*>)(.*?)</select>`)

// The select is labelled, offers Automatic first and then every built-in catalog, each named in
// itself and in English as Language and region names it, selects the stored choice, and is
// described by the agreed hint, all in the page's language (decision 10).
func TestRender_AccountProfile_ThePageLanguageSelect(t *testing.T) {
	store := newPageLanguageStore(t)
	profiles := &storedProfileAPI{pageLanguage: "es"}

	out := servePage(t, accounthandlers.HandleProfileGet(render.New(web.TemplateFS(), web.StaticFS()), store, profiles),
		http.MethodGet, "/account/profile")

	assert.Contains(t, out, `<label class="field-label" for="pageLanguage">Idioma das páginas</label>`)
	m := pageLanguageSelectRe.FindStringSubmatch(out)
	require.NotNil(t, m, "the Page language select is drawn")
	assert.Contains(t, m[1], `name="pageLanguage"`)
	assert.Contains(t, m[1], `aria-describedby="pageLanguageHint"`)
	assert.NotContains(t, m[1], "aria-invalid")
	options := regexp.MustCompile(`<option value="([^"]*)"( selected)?>([^<]*)</option>`).FindAllStringSubmatch(m[2], -1)
	var drawn []string
	for _, o := range options {
		drawn = append(drawn, o[1]+"|"+o[2]+"|"+o[3])
	}
	assert.Equal(t, []string{
		"||Automático",
		"en||en – English",
		"de||de – Deutsch (German)",
		"es| selected|es – español (Spanish)",
		"fr||fr – français (French)",
		"it||it – italiano (Italian)",
		"pt-BR||pt-BR – português (Brasil) (Portuguese (Brazil))",
	}, drawn)
	assert.Contains(t, out, `<p class="field-hint" id="pageLanguageHint">O idioma destas páginas, das páginas de entrada `+
		`depois que você digita sua senha e dos e-mails enviados a você. Automático usa o idioma que o aplicativo `+
		`ou o seu navegador pede e, nos e-mails, o seu idioma e região.</p>`)
}

// A page language the auth server refuses marks the select, which names the notice beside its hint;
// the choice is drawn again as Automatic, the refused value naming no option.
func TestRender_AccountProfile_ARefusedPageLanguageIsTheFieldMarked(t *testing.T) {
	profiles := &storedProfileAPI{refusal: &apiclient.APIError{Code: i18n.ErrCodeProfilePageLanguageInvalid,
		Message: "Escolha um idioma da lista.", StatusCode: http.StatusBadRequest}}

	out := serveRefusal(t, accounthandlers.HandleProfilePost(render.New(web.TemplateFS(), web.StaticFS()),
		newPageLanguageStore(t), profiles, "https://console.example"),
		"/account/profile", url.Values{"username": {"someone"}, "pageLanguage": {"xx"}})

	m := pageLanguageSelectRe.FindStringSubmatch(out)
	require.NotNil(t, m, "the Page language select is drawn")
	assert.Contains(t, m[1], `aria-invalid="true"`)
	assert.Contains(t, m[1], `aria-describedby="profile-error pageLanguageHint"`)
	assert.Contains(t, m[2], `<option value="" selected>Automático</option>`)
	assert.Contains(t, out, "Escolha um idioma da lista.")
	assert.NotContains(t, inputRe("username").FindString(out), "aria-invalid")
}
