package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A user's page language is the language of every auth server page drawn for a known user: the
// user of the sign-in in progress once it has verified the password or adopted a session, else the
// user of the browser's signed-in session, and on the reset page the user the link names (#631
// decision 5). It wins over the ui_locales an application sends on the authorization and on the
// sign-out, and over the browser's Accept-Language (decision 4). A page where no user is known
// keeps ui_locales, then the browser, then English (decision 6), and so does every page of a user
// on Automatic.
//
// Each browser here asks for English, so a page in Spanish shows ui_locales winning over the
// browser, and a page in Portuguese shows the page language winning over both. Every case pairs
// with its Automatic twin, which keeps today's answer. The expected text is each catalog's own.

// acceptLanguageTransport sends the Accept-Language a browser configured for one language sends.
type acceptLanguageTransport struct {
	base     http.RoundTripper
	language string
}

func (a acceptLanguageTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Accept-Language", a.language)
	return a.base.RoundTrip(r)
}

// browserAskingFor is a browser with a cookie jar, not following redirects, whose every request
// asks for language.
func browserAskingFor(t *testing.T, language string) *http.Client {
	t.Helper()
	browser := createHttpClient(t)
	browser.Transport = acceptLanguageTransport{base: browser.Transport, language: language}
	return browser
}

// newPageLanguageUser is an account with a password, a Language and region and a page language.
func newPageLanguageUser(t *testing.T, enabled bool, locale, pageLanguage string) (*record.User, string) {
	t.Helper()

	password := fake.Password(12)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)

	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      enabled,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
		Locale:       locale,
		PageLanguage: pageLanguage,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	return user, password
}

// setPageLanguage stores a new page language for a user, as a save in the console does.
func setPageLanguage(t *testing.T, userId int64, pageLanguage string) {
	t.Helper()
	user, err := database.GetUserById(context.Background(), nil, userId)
	require.NoError(t, err)
	require.NotNil(t, user)
	user.PageLanguage = pageLanguage
	require.NoError(t, database.UpdateUser(context.Background(), nil, user))
}

// withOTP gives a user an authenticator, and answers its secret.
func withOTP(t *testing.T, user *record.User) string {
	t.Helper()
	secret := newOTPSecretForTest(t, user.Email)
	stored, err := database.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	stored.OTPSecretEncrypted = encryptOTPSecretForTest(t, secret)
	stored.OTPEnabled = true
	require.NoError(t, database.UpdateUser(context.Background(), nil, stored))
	return secret
}

// newPageLanguageClient is a client at the level given, asking for consent when consent is true.
func newPageLanguageClient(t *testing.T, level record.AcrLevel, consent bool) (*record.Client, *record.RedirectURI) {
	t.Helper()
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-pagelang-" + fake.LetterN(8),
		ConsentRequired:  consent,
		DefaultAcrLevel:  level,
	})
	redirectUri := &record.RedirectURI{ClientId: client.Id, URI: fake.URL()}
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, redirectUri))
	return client, redirectUri
}

// authorizeURL is an authorization request for client, with extra parameters such as ui_locales and
// prompt added when not empty.
func authorizeURL(client *record.Client, redirectUri *record.RedirectURI, extra url.Values) string {
	params := url.Values{
		"client_id":             {client.ClientIdentifier},
		"redirect_uri":          {redirectUri.URI},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {fake.LetterN(43)},
		"scope":                 {"openid profile email"},
		"state":                 {fake.LetterN(8)},
		"nonce":                 {fake.LetterN(8)},
	}
	for key, values := range extra {
		params[key] = values
	}
	return appConfig.AuthServer.BaseURL + "/auth/authorize/?" + params.Encode()
}

// followToPage loads target and follows the auth server's redirects until a response that is not
// one of them: a page, or the redirect to the client. The caller closes it.
func followToPage(t *testing.T, browser *http.Client, target string) *http.Response {
	t.Helper()
	resp := loadPage(t, browser, target)
	for range 20 {
		if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
			return resp
		}
		location := resp.Header.Get("Location")
		if !strings.HasPrefix(location, appConfig.AuthServer.BaseURL) {
			return resp
		}
		_ = resp.Body.Close()
		resp = loadPage(t, browser, location)
	}
	t.Fatal("too many redirects")
	return nil
}

// submitPassword posts the password form the page shows, to the address it was loaded from, and
// follows the redirects after it.
func submitPassword(t *testing.T, browser *http.Client, pwdPage *http.Response, email, password string) *http.Response {
	t.Helper()
	require.Equal(t, http.StatusOK, pwdPage.StatusCode)
	resp := authenticateWithPassword(t, browser, pwdPage.Request.URL.String(), pwdPage, email, password)
	_ = pwdPage.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		return resp
	}
	location := resp.Header.Get("Location")
	_ = resp.Body.Close()
	return followToPage(t, browser, location)
}

// submitOtp posts the one-time code form the page shows, to the address it was loaded from, and
// follows the redirects after it.
func submitOtp(t *testing.T, browser *http.Client, otpPage *http.Response, code string) *http.Response {
	t.Helper()
	require.Equal(t, http.StatusOK, otpPage.StatusCode)
	resp := authenticateWithOtp(t, browser, otpPage.Request.URL.String(), otpPage, code)
	_ = otpPage.Body.Close()
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	location := resp.Header.Get("Location")
	_ = resp.Body.Close()
	return followToPage(t, browser, location)
}

// signedInBrowser is a browser asking for English, holding a level 1 session of user.
func signedInBrowser(t *testing.T, user *record.User, password string) *http.Client {
	t.Helper()
	client, redirectUri := newPageLanguageClient(t, record.AcrLevel1, false)
	browser := browserAskingFor(t, "en")

	pwdPage := followToPage(t, browser, authorizeURL(client, redirectUri, nil))
	resp := submitPassword(t, browser, pwdPage, user.Email, password)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.True(t, strings.HasPrefix(resp.Header.Get("Location"), redirectUri.URI),
		"the sign-in ends at the client: %s", resp.Header.Get("Location"))
	return browser
}

// pageIn is a page's title and the language its <html> is marked with.
type pageIn struct {
	title string
	lang  string
}

// assertPageIn asserts the page resp answered is want: its title, and the language it is marked with.
func assertPageIn(t *testing.T, want pageIn, resp *http.Response) {
	t.Helper()
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", resp.Request.URL)
	assertDocumentIn(t, want, parseHTMLResponse(t, resp))
}

func assertDocumentIn(t *testing.T, want pageIn, doc *goquery.Document) {
	t.Helper()
	assert.Equal(t, want.title, strings.TrimSpace(doc.Find("h1").First().Text()), "the page's title")
	assert.Equal(t, want.lang, doc.Find("html").AttrOr("lang", ""), "the language the page is marked with")
}

// The one-time code page comes before the sign-in binds a browser session, so only the sign-in's
// own user can choose its language; the consent page comes after.
func TestPageLanguage_TheSignInFollowsTheChoiceFromThePasswordOn(t *testing.T) {
	cases := []struct {
		name         string
		pageLanguage string
		otpPage      pageIn
		consentPage  pageIn
	}{
		{"chosen pt-BR", "pt-BR", pageIn{"Autenticação de dois fatores", "pt-BR"}, pageIn{"Permitir acesso", "pt-BR"}},
		{"Automatic", "", pageIn{"Autenticación de dos factores", "es"}, pageIn{"Permitir acceso", "es"}}, //nolint:misspell // the es catalog's text: "factores" is Spanish, not a misspelling of "factors"
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, password := newPageLanguageUser(t, true, "", tc.pageLanguage)
			otpSecret := withOTP(t, user)
			client, redirectUri := newPageLanguageClient(t, record.AcrLevel2Mandatory, true)
			browser := browserAskingFor(t, "en")

			// No user is known before the password, so the address typed there can disclose no
			// account's language: the page follows the client's ui_locales over the browser.
			pwdPage := followToPage(t, browser, authorizeURL(client, redirectUri, url.Values{"ui_locales": {"es"}}))
			assertPageIn(t, pageIn{"Iniciar sesión", "es"}, pwdPage)

			otpPage := submitPassword(t, browser, pwdPage, user.Email, password)
			assert.Equal(t, "/auth/otp", otpPage.Request.URL.Path)
			assertPageIn(t, tc.otpPage, otpPage)

			consentPage := submitOtp(t, browser, otpPage, otptest.Code(t, otpSecret, time.Now()))
			defer func() { _ = consentPage.Body.Close() }()
			assert.Equal(t, "/auth/consent", consentPage.Request.URL.Path)
			assertPageIn(t, tc.consentPage, consentPage)
		})
	}
}

// The refusal of a disabled account after its password no longer follows Language and region
// (decision 2), and follows the page language (decision 5).
func TestPageLanguage_TheAccountDisabledRefusalFollowsTheChoiceNotLanguageAndRegion(t *testing.T) {
	cases := []struct {
		name         string
		pageLanguage string
		refusal      string
		lang         string
	}{
		{"chosen pt-BR", "pt-BR", "Sua conta de usuário está desativada.", "pt-BR"},
		{"Automatic", "", "Your user account is disabled.", "en"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, password := newPageLanguageUser(t, false, "fr", tc.pageLanguage)
			client, redirectUri := newPageLanguageClient(t, record.AcrLevel1, false)
			browser := browserAskingFor(t, "en")

			pwdPage := followToPage(t, browser, authorizeURL(client, redirectUri, nil))
			resp := submitPassword(t, browser, pwdPage, user.Email, password)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			doc := parseHTMLResponse(t, resp)
			body := doc.Find("body").Text()
			assert.Contains(t, body, tc.refusal)
			assert.NotContains(t, body, "Votre compte utilisateur est désactivé.",
				"Language and region steers no page")
			assert.Equal(t, tc.lang, doc.Find("html").AttrOr("lang", ""))
		})
	}
}

// A signed-in browser asked to sign in again is shown the sign-in page in its session user's
// language, over the client's ui_locales.
func TestPageLanguage_TheSignInPageOfASignedInBrowserFollowsTheSessionsUser(t *testing.T) {
	cases := []struct {
		name         string
		pageLanguage string
		pwdPage      pageIn
	}{
		{"chosen pt-BR", "pt-BR", pageIn{"Entrar", "pt-BR"}},
		{"Automatic", "", pageIn{"Iniciar sesión", "es"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, password := newPageLanguageUser(t, true, "", tc.pageLanguage)
			browser := signedInBrowser(t, user, password)
			client, redirectUri := newPageLanguageClient(t, record.AcrLevel1, false)

			pwdPage := followToPage(t, browser, authorizeURL(client, redirectUri,
				url.Values{"ui_locales": {"es"}, "prompt": {"login"}}))
			defer func() { _ = pwdPage.Body.Close() }()
			assert.Equal(t, "/auth/pwd", pwdPage.Request.URL.Path)
			assertPageIn(t, tc.pwdPage, pwdPage)
		})
	}
}

// The sign-in's user wins over the browser session's when the two differ, being the person signing
// in now: in a browser signed in as a user who chose pt-BR, another user who chose German signs in,
// and is shown the one-time code page, which comes before the sign-in binds the browser session to
// them, in German.
func TestPageLanguage_TheSignInsUserWinsOverTheSessionsUser(t *testing.T) {
	sessionUser, sessionPassword := newPageLanguageUser(t, true, "", "pt-BR")
	browser := signedInBrowser(t, sessionUser, sessionPassword)
	signingIn, password := newPageLanguageUser(t, true, "", "de")
	withOTP(t, signingIn)
	client, redirectUri := newPageLanguageClient(t, record.AcrLevel2Mandatory, false)

	pwdPage := followToPage(t, browser, authorizeURL(client, redirectUri,
		url.Values{"ui_locales": {"es"}, "prompt": {"login"}}))
	assertPageIn(t, pageIn{"Entrar", "pt-BR"}, pwdPage)

	otpPage := submitPassword(t, browser, pwdPage, signingIn.Email, password)
	defer func() { _ = otpPage.Body.Close() }()
	assert.Equal(t, "/auth/otp", otpPage.Request.URL.Path)
	assertPageIn(t, pageIn{"Zwei-Faktor-Authentifizierung", "de"}, otpPage)
}

// The sign-out confirmation and the signed-out page follow the session user's page language over
// the ui_locales the sign-out carries. The choice is read from the user's row when the page is
// drawn, so one stored after the sign-in shows on the next page.
func TestPageLanguage_TheSignOutFollowsTheChoice(t *testing.T) {
	cases := []struct {
		name         string
		pageLanguage string
		confirmation pageIn
		signedOut    pageIn
	}{
		{"chosen pt-BR", "pt-BR", pageIn{"Sair", "pt-BR"}, pageIn{"Sessão encerrada", "pt-BR"}},
		{"Automatic", "", pageIn{"Cerrar sesión", "es"}, pageIn{"Sesión cerrada", "es"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, password := newPageLanguageUser(t, true, "", "")
			browser := signedInBrowser(t, user, password)
			setPageLanguage(t, user.Id, tc.pageLanguage)

			resp := loadPage(t, browser, appConfig.AuthServer.BaseURL+logoutPath+"?ui_locales=es")
			assertPageIn(t, tc.confirmation, resp)
			_ = resp.Body.Close()

			req, err := http.NewRequest(http.MethodPost, appConfig.AuthServer.BaseURL+logoutPath,
				strings.NewReader(url.Values{"ui_locales": {"es"}}.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", appConfig.AuthServer.BaseURL)
			resp, err = browser.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			assertPageIn(t, tc.signedOut, resp)
		})
	}
}

// The reset page follows the page language of the user the link names, in a browser no user is
// signed in to, from the form to the page saying the password is set.
func TestPageLanguage_TheResetPageFollowsTheLinksUser(t *testing.T) {
	cases := []struct {
		name         string
		pageLanguage string
		form         pageIn
		done         string
	}{
		{"chosen pt-BR", "pt-BR", pageIn{"Defina sua senha", "pt-BR"}, "Sua senha foi definida. Agora você pode entrar com:"},
		{"Automatic", "", pageIn{"Set your password", "en"}, "Your password is set. You can now sign in with:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useMailpitSMTP(t)

			email := plusAddress()
			user, _ := createResetTestUser(t, email)
			setPageLanguage(t, user.Id, tc.pageLanguage)

			browser := browserAskingFor(t, "en")
			requestPasswordReset(t, browser, email)
			cleanURL := followResetLink(t, browser, latestResetLink(t, email))

			formResp := loadPage(t, browser, cleanURL)
			formBody := bodyString(t, formResp)
			_ = formResp.Body.Close()
			formDoc, err := goquery.NewDocumentFromReader(strings.NewReader(formBody))
			require.NoError(t, err)
			assertDocumentIn(t, tc.form, formDoc)

			resp := postCleanReset(t, browser, cleanURL, fake.Password(20), continuationIdIn(t, formBody))
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Contains(t, bodyString(t, resp), tc.done)
		})
	}
}

// A verified user on Automatic, or whose stored tag's catalog has gone, replaces the browser
// session's user's choice with the language the request asks for: in a browser signed in as a user
// who chose pt-BR, another user on Automatic, whose account is disabled, enters their password, and
// the refusal follows the client's ui_locales=es, not the session user's Portuguese (decisions 2, 3
// and 5). A user who chose German is the control.
func TestPageLanguage_TheSignInsUserOnAutomaticReplacesTheSessionsUsersChoice(t *testing.T) {
	cases := []struct {
		name         string
		pageLanguage string
		refusal      string
		lang         string
	}{
		{"Automatic", "", "Tu cuenta de usuario está desactivada.", "es"},
		{"a catalog that has gone", "ja", "Tu cuenta de usuario está desactivada.", "es"},
		{"chosen de", "de", "Ihr Benutzerkonto ist deaktiviert.", "de"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessionUser, sessionPassword := newPageLanguageUser(t, true, "", "pt-BR")
			browser := signedInBrowser(t, sessionUser, sessionPassword)
			user, password := newPageLanguageUser(t, false, "fr", tc.pageLanguage)
			client, redirectUri := newPageLanguageClient(t, record.AcrLevel1, false)

			pwdPage := followToPage(t, browser, authorizeURL(client, redirectUri,
				url.Values{"ui_locales": {"es"}, "prompt": {"login"}}))
			assertPageIn(t, pageIn{"Entrar", "pt-BR"}, pwdPage)

			resp := submitPassword(t, browser, pwdPage, user.Email, password)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			doc := parseHTMLResponse(t, resp)
			body := doc.Find("body").Text()
			assert.Contains(t, body, tc.refusal)
			assert.NotContains(t, body, "Sua conta de usuário está desativada.", "the session user's choice loses")
			assert.Equal(t, tc.lang, doc.Find("html").AttrOr("lang", ""))
		})
	}
}

// The reset link's user on Automatic, or whose stored tag's catalog has gone, replaces the browser
// session's user's choice with the language the request asks for, on the form and on the page
// saying the password is set: a browser signed in as a user who chose pt-BR opens another user's
// reset link with ?ui_locales=es and is answered in Spanish (decisions 2, 3 and 5). A link whose
// user chose German is the control.
func TestPageLanguage_TheResetLinksUserOnAutomaticReplacesTheSessionsUsersChoice(t *testing.T) {
	cases := []struct {
		name         string
		pageLanguage string
		form         pageIn
		done         string
	}{
		{"Automatic", "", pageIn{"Establece tu contraseña", "es"}, "Tu contraseña está lista. Ya puedes iniciar sesión con:"},
		{"a catalog that has gone", "ja", pageIn{"Establece tu contraseña", "es"}, "Tu contraseña está lista. Ya puedes iniciar sesión con:"},
		{"chosen de", "de", pageIn{"Passwort festlegen", "de"}, "Ihr Passwort ist festgelegt. Sie können sich jetzt mit dieser E-Mail-Adresse anmelden:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useMailpitSMTP(t)

			sessionUser, sessionPassword := newPageLanguageUser(t, true, "", "pt-BR")
			browser := signedInBrowser(t, sessionUser, sessionPassword)
			email := plusAddress()
			user, _ := createResetTestUser(t, email)
			setPageLanguage(t, user.Id, tc.pageLanguage)

			requestPasswordReset(t, browser, email)
			cleanURL := followResetLink(t, browser, latestResetLink(t, email))

			formResp := loadPage(t, browser, cleanURL+"?ui_locales=es")
			formBody := bodyString(t, formResp)
			_ = formResp.Body.Close()
			formDoc, err := goquery.NewDocumentFromReader(strings.NewReader(formBody))
			require.NoError(t, err)
			assertDocumentIn(t, tc.form, formDoc)
			assert.NotContains(t, formBody, "Defina sua senha", "the session user's choice loses")

			resp := postCleanReset(t, browser, cleanURL+"?ui_locales=es", fake.Password(20), continuationIdIn(t, formBody))
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			doneBody := bodyString(t, resp)
			assert.Contains(t, doneBody, tc.done)
			assert.Contains(t, doneBody, `<html lang="`+tc.form.lang+`"`)
		})
	}
}
