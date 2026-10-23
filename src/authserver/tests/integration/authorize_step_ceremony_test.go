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

// Every step of a sign-in names the sign-in it belongs to, and a request that names one the browser
// does not hold, or none, is answered with the "no longer active" page. A browser holds up to five
// sign-ins side by side, and a sixth pushes out the one least recently moved; before the steps named
// their sign-in, a page load acted on whatever context the browser held, and a tab of a sign-in the
// browser no longer held that reached its next step finished another application's authorization
// (#246). What is asserted here is what a user sees, over HTTP against the running server.

// assertCeremonyNoLongerActive asserts the page a request naming the wrong ceremony is answered with:
// 400, no redirect, and the ceremony mismatch text rather than the state mismatch one, which says a
// different thing and must not be confused with it.
func assertCeremonyNoLongerActive(t *testing.T, resp *http.Response, what string) {
	t.Helper()

	assertCeremonyMismatchPage(t, resp, what)

	body := parseHTMLResponse(t, resp).Text()
	assert.Contains(t, body, "This request is no longer active", what)
	assert.Contains(t, body, "This page belongs to a sign-in that can no longer continue.", what)
	assert.Contains(t, body, "It may have finished already, or a later sign-in or sign-out in this browser ended it.",
		"%s: the message names what ends a sign-in, not only a newer one", what)
	assert.NotContains(t, body, "Another one was started in this browser",
		"%s: the message no longer blames a new sign-in", what)
}

// walkToPasswordPage starts one authorization request on the caller's browser and follows it to its
// login screen. It returns the screen's URL, which names the ceremony, and the screen itself.
func walkToPasswordPage(t *testing.T, httpClient *http.Client, client *record.Client,
	redirectUri *record.RedirectURI, state string) (string, *http.Response) {
	t.Helper()

	resp, err := httpClient.Get(authorizeUrlFor(client, redirectUri, "openid profile", state))
	require.NoError(t, err)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	level1Location := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, level1Location)
	defer func() { _ = resp.Body.Close() }()

	pwdLocation := assertRedirect(t, resp, "/auth/pwd")
	return pwdLocation, loadPage(t, httpClient, pwdLocation)
}

// TestAuthorize_APageOfASignInPushedOutByFiveNewerIsRefusedAtItsNextStep: tab A is at its login
// screen when five other sign-ins start in the same browser, which pushes A's out (#246 decision
// 2). Tab A then loads a step and gets the "no longer active" page, and the five newer sign-ins are
// untouched: the first of them, the one least recently moved now, still finishes.
func TestAuthorize_APageOfASignInPushedOutByFiveNewerIsRefusedAtItsNextStep(t *testing.T) {
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

	// With four more sign-ins, A's is the sixth from the latest.
	for i := 0; i < 4; i++ {
		_, page := walkToPasswordPage(t, httpClient, clientB, redirectUriB, fake.LetterN(8))
		_ = page.Body.Close()
	}

	// Tab A reloads its own login screen. It names A's ceremony, which the browser no longer holds.
	reload := loadPage(t, httpClient, pwdUrlA)
	defer func() { _ = reload.Body.Close() }()
	assertCeremonyNoLongerActive(t, reload, "a page load of the pushed-out sign-in")

	// And it does not get to the step after either, which is the load a tab that followed a redirect
	// makes. Reached by the URL it would have been sent to, naming its own ceremony.
	next := loadPage(t, httpClient, stepURLOfTheSameCeremony(t, pwdUrlA, "/auth/level1completed"))
	defer func() { _ = next.Body.Close() }()
	assertCeremonyNoLongerActive(t, next, "the step after the login of the pushed-out sign-in")

	// Nor does its form, submitted with the right password.
	submitted := authenticateWithPassword(t, httpClient, pwdUrlA, pwdPageA, user.Email, password)
	defer func() { _ = submitted.Body.Close() }()
	assertCeremonyNoLongerActive(t, submitted, "the login form of the pushed-out sign-in")
	assertNothingWasCompleted(t, user.Id)

	// B's sign-in, the oldest of the five newer ones, was not disturbed by any of it: its own screen
	// signs in and receives its code.
	resp := authenticateWithPassword(t, httpClient, pwdUrlB, pwdPageB, user.Email, password)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	location := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, location)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	location = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, location)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	assertCodeFor(t, httpClient, assertRedirect(t, resp, "/auth/issue"), clientB, redirectUriB, stateB)
}

// TestAuthorize_AStepOfASignInHeldBesideANewerOneFinishes: tab A's sign-in is at its login screen
// when tab B's starts in the same browser. Tab A reloads its screen, signs in and receives its own
// code: a newer sign-in no longer ends one in progress (#246).
func TestAuthorize_AStepOfASignInHeldBesideANewerOneFinishes(t *testing.T) {
	clientA, redirectUriA := createLevel1Client(t, false)
	clientB, redirectUriB := createLevel1Client(t, false)
	user, password := createCeremonyUser(t)

	httpClient := createHttpClient(t)

	stateA := fake.LetterN(8)
	pwdUrlA, pwdPageA := walkToPasswordPage(t, httpClient, clientA, redirectUriA, stateA)
	_ = pwdPageA.Body.Close()

	_, pwdPageB := walkToPasswordPage(t, httpClient, clientB, redirectUriB, fake.LetterN(8))
	_ = pwdPageB.Body.Close()

	reload := loadPage(t, httpClient, pwdUrlA)
	defer func() { _ = reload.Body.Close() }()
	require.Equal(t, http.StatusOK, reload.StatusCode, "tab A's own login screen still loads")

	resp := authenticateWithPassword(t, httpClient, pwdUrlA, reload, user.Email, password)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	location := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, location)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	location = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, location)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	assertCodeFor(t, httpClient, assertRedirect(t, resp, "/auth/issue"), clientA, redirectUriA, stateA)
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

// TestAuthorize_ThePasswordPageOffersRegisterOnlyWhileRegistrationIsAvailable: the Register link
// goes to /account/register, which answers the not-found page unless registration is available:
// self-registration on, and either verification off or email on (#526 decision 2). So the password
// page shows it only then. The re-render after a refused password is checked too, because it is a
// second render with its own data.
func TestAuthorize_ThePasswordPageOffersRegisterOnlyWhileRegistrationIsAvailable(t *testing.T) {
	for _, tc := range []struct {
		name                                  string
		selfRegistration, verification, email bool
		want                                  bool
	}{
		{"self-registration off", false, false, true, false},
		{"verification off and email off", true, false, false, true},
		{"verification on and email off", true, true, false, false},
		{"verification on and email on", true, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setRegSettings(t, tc.selfRegistration, tc.verification, tc.email)

			client, redirectUri := createLevel1Client(t, false)
			httpClient := createHttpClient(t)
			pwdUrl, pwdPage := walkToPasswordPage(t, httpClient, client, redirectUri, fake.LetterN(8))
			defer func() { _ = pwdPage.Body.Close() }()
			require.Equal(t, http.StatusOK, pwdPage.StatusCode)

			links := parseHTMLResponse(t, pwdPage).Find(`a[href^="/account/register"]`).Length()
			assert.Equal(t, map[bool]int{true: 1, false: 0}[tc.want], links, "Register links on the password page")

			refused := authenticateWithPassword(t, httpClient, pwdUrl, pwdPage, fake.Email(), fake.LetterN(16))
			defer func() { _ = refused.Body.Close() }()
			require.Equal(t, http.StatusOK, refused.StatusCode, "a refused password re-renders the form")

			links = parseHTMLResponse(t, refused).Find(`a[href^="/account/register"]`).Length()
			assert.Equal(t, map[bool]int{true: 1, false: 0}[tc.want], links, "Register links on the form's re-render")
		})
	}
}

// TestAuthorize_TheRegistrationLinksCarryTheSignInThroughAndBack is the one path into a step that is
// not a server redirect: the password page's "Register" link and the registration page's "Sign in"
// link. Register from a sign-in and go back, and the visitor lands on the same sign-in's password
// form, where a bare link would load a step naming no ceremony and get the "no longer active" page.
func TestAuthorize_TheRegistrationLinksCarryTheSignInThroughAndBack(t *testing.T) {
	setRegSettings(t, true, false, false)

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
