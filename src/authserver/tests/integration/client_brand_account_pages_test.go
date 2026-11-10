package integration

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Registration, forgot password and activation, reached from a sign-in, keep its client's brand
// while their URL names that sign-in and the browser still holds it. A URL naming a sign-in the
// browser does not hold, a malformed id, or none draws the page in the default brand, and is never
// an error there (#812 decision 4). The forgot-password page links back to the sign-in it names
// (decision 8).
//
// Each test makes a dark Plum brand the default and gives the app a light Avocado brand, as the
// sign-in pages' tests do.

// forgotPasswordLink starts a sign-in at authorizeURL in browser and answers the address the password
// page's Forgot password? link leads to, read off the page, and the sign-in's id.
func forgotPasswordLink(t *testing.T, browser *http.Client, authorizeURL string) (string, string) {
	t.Helper()
	resp := loadPage(t, browser, authorizeURL)
	resp, _ = brandFollowTo(t, browser, resp, "/auth/level1")
	pwdPage, _ := brandFollowTo(t, browser, resp, "/auth/pwd")
	page := parseHTMLResponse(t, pwdPage)
	_ = pwdPage.Body.Close()
	href, ok := page.Find(`a[href^="/forgot-password"]`).Attr("href")
	require.True(t, ok, "the password page links Forgot password?")
	link, err := url.Parse(href)
	require.NoError(t, err)
	ceremonyId := link.Query().Get(ceremony.QueryParameter)
	require.True(t, ceremony.IsWellFormedId(ceremonyId), "the link names the sign-in: %s", href)
	return appConfig.AuthServer.BaseURL + href, ceremonyId
}

// backToSignInHref answers the href of the page's Back to sign in link, which it must have once.
func backToSignInHref(t *testing.T, resp *http.Response) string {
	t.Helper()
	page := parseHTMLResponse(t, resp)
	links := page.Find(`a.text-link`).FilterFunction(func(_ int, s *goquery.Selection) bool {
		return strings.TrimSpace(s.Text()) == "Back to sign in"
	})
	require.Equal(t, 1, links.Length(), "the page links Back to sign in once")
	href, _ := links.Attr("href")
	return href
}

// peekBody reads resp's body and puts it back, so the page can still be parsed after.
func peekBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return string(b)
}

// withCeremonyParameter is target with its ceremony parameter set to id.
func withCeremonyParameter(t *testing.T, target string, id string) string {
	t.Helper()
	parsed, err := url.Parse(target)
	require.NoError(t, err)
	params := parsed.Query()
	params.Set(ceremony.QueryParameter, id)
	parsed.RawQuery = params.Encode()
	return parsed.String()
}

func TestForgotPasswordPages_KeepTheClientsBrandWhileTheBrowserHoldsTheSignIn(t *testing.T) {
	useMailpitSMTP(t)
	defaultBrand := makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	client, clientBrand, redirectURI := brandedSignInClient(t, record.AcrLevel1)
	browser := createHttpClient(t)
	forgotURL, ceremonyId := forgotPasswordLink(t, browser, brandAuthorizeURL(client, redirectURI, ""))
	wantBack := "/auth/pwd?" + url.Values{ceremony.QueryParameter: {ceremonyId}}.Encode()

	t.Run("the form", func(t *testing.T) {
		page := loadPage(t, browser, forgotURL)
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, clientBrand, "light")
		assert.Equal(t, wantBack, backToSignInHref(t, page),
			"Back to sign in leads to the sign-in's password step")
	})

	t.Run("the form refusing a malformed address", func(t *testing.T) {
		resp := postRegisterAt(t, browser, forgotURL, url.Values{"email": {"not-an-address"}})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assertDrawnInBrand(t, resp, clientBrand, "light")
	})

	t.Run("the page saying the link was sent", func(t *testing.T) {
		resp := postRegisterAt(t, browser, forgotURL, url.Values{"email": {fake.Email()}})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body := peekBody(t, resp)
		require.Contains(t, body, "Check your email")
		assertDrawnInBrand(t, resp, clientBrand, "light")
		assert.Equal(t, wantBack, backToSignInHref(t, resp))
	})

	t.Run("the same link in another browser", func(t *testing.T) {
		page := loadPage(t, createHttpClient(t), forgotURL)
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, defaultBrand, "dark")
		assert.Equal(t, wantBack, backToSignInHref(t, page),
			"the link still names the sign-in, which it echoes without reading it")
	})

	t.Run("a sign-in the browser does not hold", func(t *testing.T) {
		page := loadPage(t, browser, withCeremonyParameter(t, forgotURL, ceremony.NewId()))
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, defaultBrand, "dark")
	})

	t.Run("a malformed id", func(t *testing.T) {
		page := loadPage(t, browser, withCeremonyParameter(t, forgotURL, ceremonyId+"x"))
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, defaultBrand, "dark")
		assert.Equal(t, "/auth/pwd", backToSignInHref(t, page),
			"an id of the wrong shape is not echoed")
	})

	t.Run("no sign-in named", func(t *testing.T) {
		page := loadPage(t, browser, appConfig.AuthServer.BaseURL+"/forgot-password")
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, defaultBrand, "dark")
		assert.Equal(t, "/auth/pwd", backToSignInHref(t, page),
			"a page naming no sign-in shows the link bare")
	})

	t.Run("the link sent page naming no sign-in", func(t *testing.T) {
		resp := postRegisterAt(t, browser, appConfig.AuthServer.BaseURL+"/forgot-password",
			url.Values{"email": {fake.Email()}})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assertDrawnInBrand(t, resp, defaultBrand, "dark")
		assert.Equal(t, "/auth/pwd", backToSignInHref(t, resp))
	})
}

func TestRegistrationPages_KeepTheClientsBrandWhileTheBrowserHoldsTheSignIn(t *testing.T) {
	setRegSettings(t, true, false, false)
	defaultBrand := makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	f, _ := newRegistrationApp(t)
	clientBrand := giveClientBrand(t, f.client, record.BrandAppearanceLight, "avocado")
	browser := createHttpClient(t)
	registerURL, ceremonyId := f.createAnAccountLink(t, browser)

	t.Run("the form", func(t *testing.T) {
		page := loadPage(t, browser, registerURL)
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, clientBrand, "light")
	})

	t.Run("the form refusing a submission", func(t *testing.T) {
		resp := postRegisterAt(t, browser, registerURL, url.Values{
			"email": {fake.Email()}, "password": {"Mismatched-1!"}, "passwordConfirmation": {"Mismatched-2!"},
		})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assertDrawnInBrand(t, resp, clientBrand, "light")
	})

	t.Run("the same link in another browser", func(t *testing.T) {
		page := loadPage(t, createHttpClient(t), registerURL)
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, defaultBrand, "dark")
	})

	t.Run("a sign-in the browser does not hold", func(t *testing.T) {
		page := loadPage(t, browser, withCeremonyParameter(t, registerURL, ceremony.NewId()))
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, defaultBrand, "dark")
	})

	t.Run("a malformed id", func(t *testing.T) {
		page := loadPage(t, browser, withCeremonyParameter(t, registerURL, ceremonyId[1:]))
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, defaultBrand, "dark")
	})

	t.Run("no sign-in named", func(t *testing.T) {
		page := loadPage(t, browser, appConfig.AuthServer.BaseURL+"/account/register")
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, defaultBrand, "dark")
	})
}

func TestActivationPages_KeepTheClientsBrandWhileTheBrowserHoldsTheSignIn(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, true, true)
	defaultBrand := makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	f, _ := newRegistrationApp(t)
	clientBrand := giveClientBrand(t, f.client, record.BrandAppearanceLight, "avocado")

	t.Run("the check your email page", func(t *testing.T) {
		browser := createHttpClient(t)
		registerURL, _ := f.createAnAccountLink(t, browser)
		resp := postRegisterAt(t, browser, registerURL, url.Values{"email": {registerAddress()}})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body := peekBody(t, resp)
		require.Contains(t, body, checkYourEmailTitle)
		assertDrawnInBrand(t, resp, clientBrand, "light")
	})

	t.Run("the activation form in the browser holding the sign-in", func(t *testing.T) {
		browser := createHttpClient(t)
		email := registerAddress()
		ceremonyId, link := f.registerFromTheApp(t, browser, email)
		cleanURL := followActivationLinkWithSignIn(t, browser, link, ceremonyId)
		page := loadPage(t, browser, cleanURL)
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		body := peekBody(t, page)
		require.Contains(t, body, activationFormTitle)
		assertDrawnInBrand(t, page, clientBrand, "light")
	})

	t.Run("the activation pages in another browser", func(t *testing.T) {
		email := registerAddress()
		ceremonyId, link := f.registerFromTheApp(t, createHttpClient(t), email)
		other := createHttpClient(t)
		cleanURL := followActivationLinkWithSignIn(t, other, link, ceremonyId)

		page := loadPage(t, other, cleanURL)
		body := peekBody(t, page)
		_ = page.Body.Close()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, defaultBrand, "dark")

		continuationId := continuationIdIn(t, body)
		const chosenPassword = "Chosen-At-Activation-1!"
		resp := postActivation(t, other, cleanURL, chosenPassword, chosenPassword, continuationId)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode, "the page answers in place")
		registeredUser(t, email)
		assertDrawnInBrand(t, resp, defaultBrand, "dark")
	})
}

// The reset page follows the same rule: its link names the sign-in its forgot-password page named,
// and the first hop keeps it, so the form, a refusal beside it and the first hop's own refusal are
// drawn in the client's brand in the browser holding the sign-in, and in the default anywhere else
// (#812 decisions 4 and 9).
func TestResetPasswordPages_KeepTheClientsBrandWhileTheBrowserHoldsTheSignIn(t *testing.T) {
	useMailpitSMTP(t)
	defaultBrand := makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	client, clientBrand, redirectURI := brandedSignInClient(t, record.AcrLevel1)
	user, _ := resetFromTheAppUser(t)
	browser := createHttpClient(t)
	ceremonyId, link := requestResetFromTheApp(t, browser, brandAuthorizeURL(client, redirectURI, ""), user.Email)

	t.Run("the form in the browser holding the sign-in", func(t *testing.T) {
		cleanURL := followResetLinkWithSignIn(t, browser, link, ceremonyId)
		page := loadPage(t, browser, cleanURL)
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		body := peekBody(t, page)
		require.Contains(t, body, `name="password"`)
		assertDrawnInBrand(t, page, clientBrand, "light")

		resp := postRegisterAt(t, browser, cleanURL, url.Values{
			"password": {"Mismatched-1!"}, "passwordConfirmation": {"Mismatched-2!"},
			"continuationId": {continuationIdIn(t, body)},
		})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode, "the form is drawn again beside the refusal")
		assertDrawnInBrand(t, resp, clientBrand, "light")
	})

	t.Run("a refused link in the browser holding the sign-in", func(t *testing.T) {
		page := loadPage(t, browser, withCeremonyParameter(t,
			appConfig.AuthServer.BaseURL+"/reset-password?code="+fake.LetterN(32), ceremonyId))
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		require.Contains(t, peekBody(t, page), resetCodeInvalidText)
		assertDrawnInBrand(t, page, clientBrand, "light")
	})

	t.Run("the pages in another browser", func(t *testing.T) {
		other := createHttpClient(t)
		cleanURL := followResetLinkWithSignIn(t, other, link, ceremonyId)
		page := loadPage(t, other, cleanURL)
		body := peekBody(t, page)
		_ = page.Body.Close()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, defaultBrand, "dark")

		resp := postCleanReset(t, other, cleanURL, fake.Password(20), continuationIdIn(t, body))
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode, "the page answers in place")
		assertDrawnInBrand(t, resp, defaultBrand, "dark")
	})
}
