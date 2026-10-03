package integration

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every step of a sign-in names the sign-in it belongs to, and a request that names another one, or
// none, is answered with the "no longer active" page. A browser holds ONE auth context, so a second
// /auth/authorize replaces the first; before this a page load acted on whatever context the browser
// held, and a tab of the replaced sign-in that reached its next step finished the other application's
// authorization (#246 decision 22). What is asserted here is what a user sees, over HTTP against the
// running server.

// assertCeremonyNoLongerActive asserts the page a request naming the wrong ceremony is answered with:
// 400, no redirect, and the ceremony mismatch text rather than the state mismatch one, which says a
// different thing and must not be confused with it.
func assertCeremonyNoLongerActive(t *testing.T, resp *http.Response, what string) {
	t.Helper()

	assertCeremonyMismatchPage(t, resp, what)

	body := parseHTMLResponse(t, resp).Text()
	assert.Contains(t, body, "This request is no longer active", what)
	assert.Contains(t, body, "so this one can no longer continue",
		"%s: the message reads for a page load as well as for a form", what)
	assert.NotContains(t, body, "so this form can no longer be submitted",
		"%s: the message no longer says only forms are refused", what)
}

// walkToPasswordPage starts one authorization request on the caller's browser and follows it to its
// login screen. It returns the screen's URL, which names the ceremony, and the screen itself.
func walkToPasswordPage(t *testing.T, httpClient *http.Client, client *record.Client,
	redirectUri *record.RedirectURI, state string) (string, *http.Response) {
	t.Helper()

	resp, err := httpClient.Get(authorizeUrlFor(client, redirectUri, "openid profile", state))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	level1Location := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, level1Location)
	defer func() { _ = resp.Body.Close() }()

	pwdLocation := assertRedirect(t, resp, "/auth/pwd")
	return pwdLocation, loadPage(t, httpClient, pwdLocation)
}

// TestAuthorize_APageOfAReplacedSignInIsRefusedAtItsNextStep is the defect end to end for a page
// load rather than a form. Tab A's sign-in is replaced by tab B's in the same browser, and tab A then
// loads a step. It gets the page, and B's sign-in, the one that is actually current, is untouched and
// finishes in its own tab.
func TestAuthorize_APageOfAReplacedSignInIsRefusedAtItsNextStep(t *testing.T) {
	clientA, redirectUriA := createConsentClient(t)
	clientB, redirectUriB := createLevel1Client(t, false)
	user, password := createCeremonyUser(t)

	httpClient := createHttpClient(t)

	pwdUrlA, pwdPageA := walkToPasswordPage(t, httpClient, clientA, redirectUriA, fake.LetterN(8))
	defer func() { _ = pwdPageA.Body.Close() }()
	assert.Equal(t, http.StatusOK, pwdPageA.StatusCode)

	stateB := fake.LetterN(8)
	pwdUrlB, pwdPageB := walkToPasswordPage(t, httpClient, clientB, redirectUriB, stateB)
	defer func() { _ = pwdPageB.Body.Close() }()
	assert.Equal(t, http.StatusOK, pwdPageB.StatusCode)

	// Tab A reloads its own login screen. It names A's ceremony, the browser now holds B's.
	reload := loadPage(t, httpClient, pwdUrlA)
	defer func() { _ = reload.Body.Close() }()
	assertCeremonyNoLongerActive(t, reload, "a page load of the replaced sign-in")

	// And it does not get to the step after either, which is the load a tab that followed a redirect
	// makes. Reached by the URL it would have been sent to, naming its own ceremony.
	next := loadPage(t, httpClient, stepURLOfTheSameCeremony(t, pwdUrlA, "/auth/level1completed"))
	defer func() { _ = next.Body.Close() }()
	assertCeremonyNoLongerActive(t, next, "the step after the login of the replaced sign-in")
	assertNothingWasCompleted(t, user.Id)

	// B's sign-in was not disturbed by any of it: its own screen signs in and receives its code.
	resp := authenticateWithPassword(t, httpClient, pwdUrlB, pwdPageB, user.Email, password)
	defer func() { _ = resp.Body.Close() }()

	location := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, location)
	defer func() { _ = resp.Body.Close() }()

	location = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, location)
	defer func() { _ = resp.Body.Close() }()

	location = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, location)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, stateB, stateVal, "the code belongs to the sign-in that is current, and to no other")
	assert.Equal(t, clientB.ClientIdentifier, loadCodeFromDatabase(t, codeVal).Client.ClientIdentifier)
}

// TestAuthorize_AStepThatNamesNoCeremonyOrAnotherIsRefused is every way a step's URL can fail to name
// the sign-in in progress, each varying one thing from the URL a redirect builds: the parameter
// absent, empty, an id that is not the stored one, the form field's name in its place, and a
// well-formed id from nowhere. The URL that works, last, shows the stored ceremony was never
// disturbed by any of them.
func TestAuthorize_AStepThatNamesNoCeremonyOrAnotherIsRefused(t *testing.T) {
	client, redirectUri := createLevel1Client(t, false)

	httpClient := createHttpClient(t)
	pwdUrl, pwdPage := walkToPasswordPage(t, httpClient, client, redirectUri, fake.LetterN(8))
	defer func() { _ = pwdPage.Body.Close() }()

	ceremonyId := getCeremonyIdFromPage(t, pwdPage)
	base := appConfig.AuthServer.BaseURL + "/auth/pwd"

	testCases := []struct {
		name string
		url  string
	}{
		{"no parameter at all, a hand-typed address", base},
		{"the parameter present and empty", base + "?" + ceremony.QueryParameter + "="},
		{"another ceremony's id", base + "?" + ceremony.QueryParameter + "=" + ceremony.NewId()},
		{"the stored id one character short", base + "?" + ceremony.QueryParameter + "=" + ceremonyId[:len(ceremonyId)-1]},
		{"the stored id and more", base + "?" + ceremony.QueryParameter + "=" + ceremonyId + "x"},
		{"the form field's name in place of the parameter", base + "?ceremonyId=" + url.QueryEscape(ceremonyId)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := loadPage(t, httpClient, tc.url)
			defer func() { _ = resp.Body.Close() }()

			assertCeremonyNoLongerActive(t, resp, tc.name)
		})
	}

	t.Run("the URL the redirect built still works", func(t *testing.T) {
		resp := loadPage(t, httpClient, pwdUrl)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, ceremonyId, getCeremonyIdFromPage(t, resp))
	})
}

// TestAuthorize_TheRegistrationLinksCarryTheSignInThroughAndBack is the one path into a step that is
// not a server redirect: the password page's "Register" link and the registration page's "Sign in"
// link. Register from a sign-in and go back, and the visitor lands on the same sign-in's password
// form, where a bare link would load a step naming no ceremony and get the "no longer active" page.
func TestAuthorize_TheRegistrationLinksCarryTheSignInThroughAndBack(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) {
		settings.SelfRegistrationEnabled = true
	})

	client, redirectUri := createLevel1Client(t, false)
	httpClient := createHttpClient(t)
	_, pwdPage := walkToPasswordPage(t, httpClient, client, redirectUri, fake.LetterN(8))
	defer func() { _ = pwdPage.Body.Close() }()
	require.Equal(t, http.StatusOK, pwdPage.StatusCode)

	ceremonyId := getCeremonyIdFromPage(t, pwdPage)

	// The password page's link names the sign-in it belongs to.
	registerLink, ok := parseHTMLResponse(t, pwdPage).Find(`a[href^="/account/register"]`).Attr("href")
	require.True(t, ok, "the password page links to registration")
	assert.Equal(t, "/account/register?"+url.Values{ceremony.QueryParameter: {ceremonyId}}.Encode(), registerLink)

	// Followed, the registration page's "Sign in" link names it too.
	registerPage := loadPage(t, httpClient, appConfig.AuthServer.BaseURL+registerLink)
	defer func() { _ = registerPage.Body.Close() }()
	require.Equal(t, http.StatusOK, registerPage.StatusCode)

	signInLink, ok := parseHTMLResponse(t, registerPage).Find(`a[href^="/auth/pwd"]`).Attr("href")
	require.True(t, ok, "the registration page links back to the sign-in")
	assert.Equal(t, "/auth/pwd?"+url.Values{ceremony.QueryParameter: {ceremonyId}}.Encode(), signInLink)

	// And followed, it is the same sign-in's password form.
	back := loadPage(t, httpClient, appConfig.AuthServer.BaseURL+signInLink)
	defer func() { _ = back.Body.Close() }()
	assert.Equal(t, http.StatusOK, back.StatusCode)
	assert.Equal(t, ceremonyId, getCeremonyIdFromPage(t, back), "the same sign-in, not a new one")

	t.Run("the registration page reached from anywhere else links back bare", func(t *testing.T) {
		bare := loadPage(t, httpClient, appConfig.AuthServer.BaseURL+"/account/register")
		defer func() { _ = bare.Body.Close() }()
		require.Equal(t, http.StatusOK, bare.StatusCode)

		link, ok := parseHTMLResponse(t, bare).Find(`a[href^="/auth/pwd"]`).Attr("href")
		require.True(t, ok)
		assert.Equal(t, "/auth/pwd", link)
	})

	for name, value := range map[string]string{
		"an id of the wrong length":      ceremonyId + "x",
		"an id with a foreign character": ceremonyId[:len(ceremonyId)-1] + "!",
		"markup":                         `"><script>alert(1)</script>`,
	} {
		t.Run("the registration page drops "+name, func(t *testing.T) {
			resp := loadPage(t, httpClient, appConfig.AuthServer.BaseURL+"/account/register?"+
				url.Values{ceremony.QueryParameter: {value}}.Encode())
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			doc := parseHTMLResponse(t, resp)
			link, ok := doc.Find(`a[href^="/auth/pwd"]`).Attr("href")
			require.True(t, ok)
			assert.Equal(t, "/auth/pwd", link, "a value that is not an id is not repeated into the page")
			assert.NotContains(t, doc.Text(), "<script>alert(1)</script>")
		})
	}
}
