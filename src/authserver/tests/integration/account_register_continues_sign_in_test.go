package integration

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Registration carries on the sign-in that started it (#622 decision 9). A user who registers from
// an app's sign-in, through the password page's Create an account link, is signed straight in: the
// browser session's identifier is rotated, and the sign-in goes on through the acceptance step to
// the app. With email verification on, the emailed link carries the sign-in, and activating from it
// in the same browser does the same; opened anywhere else, it activates the account and the page
// tells the person to go back to the application.
//
// The app is a client of the test's own with a must-accept document for it alone, so the sign-in
// shows the acceptance step and no other test's sign-in owes it.

// returnToAppText is the activation page's text when the browser does not hold the sign-in.
const returnToAppText = "Your account is ready. Go back to the application you were signing in to, and sign in with " +
	"your new password and this email address:"

// newRegistrationApp is an app of the test's own whose sign-in asks for its terms, with no user yet:
// the user registers.
func newRegistrationApp(t *testing.T) (*legalAcceptanceFixture, int64) {
	t.Helper()
	adminToken, _ := createAdminClientWithToken(t)
	f := newLegalAcceptanceApp(t, nil, "", adminToken)
	termsId, _ := f.mustAcceptFor(t, "reg-terms", "Shop terms")
	return f, termsId
}

// createAnAccountLink starts a sign-in to the fixture's app in browser and answers the address the
// password page's Create an account link leads to, read off the page, and the sign-in's id.
func (f *legalAcceptanceFixture) createAnAccountLink(t *testing.T, browser *http.Client) (string, string) {
	t.Helper()
	resp, err := browser.Get(f.link(""))
	require.NoError(t, err)
	location := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	location = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()
	page := parseHTMLResponse(t, loadPage(t, browser, location))
	href, ok := page.Find(`a[href^="/account/register"]`).Attr("href")
	require.True(t, ok, "the password page links Create an account")
	link, err := url.Parse(href)
	require.NoError(t, err)
	ceremonyId := link.Query().Get(ceremony.QueryParameter)
	require.True(t, ceremony.IsWellFormedId(ceremonyId), "the link names the sign-in: %s", href)
	return appConfig.AuthServer.BaseURL + href, ceremonyId
}

// postRegisterAt submits the register form at the address it was loaded from, which is where its
// empty action sends it.
func postRegisterAt(t *testing.T, browser *http.Client, registerURL string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, registerURL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", registerURL)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)
	resp, err := browser.Do(req)
	require.NoError(t, err)
	return resp
}

// registeredUser answers the account registered for email, deleted when the test ends.
func registeredUser(t *testing.T, email string) *record.User {
	t.Helper()
	user, err := database.GetUserByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	require.NotNil(t, user, "the account for %s exists", email)
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	return user
}

// carriedOnToTheApp follows a sign-in carried on past the password, from the redirect that carried it
// on, through the acceptance step, which it accepts, to the code the app gets, and asserts that the
// acceptance is the new user's.
func (f *legalAcceptanceFixture) carriedOnToTheApp(t *testing.T, browser *http.Client, resp *http.Response,
	ceremonyId string, user *record.User, termsId int64) {
	t.Helper()
	location := assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	next, err := url.Parse(location)
	require.NoError(t, err)
	assert.Equal(t, ceremonyId, next.Query().Get(ceremony.QueryParameter), "the sign-in the link named")

	resp = loadPage(t, browser, location)
	location = assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	page, stepURL := toStep(t, browser, loadPage(t, browser, location))
	_, documents := readStep(t, page)
	require.Len(t, documents, 1, "the step asks for the app's terms")
	resp = postStep(t, browser, stepURL, page, versionsOf(documents), false)
	f.assertCodeIssued(t, browser, resp)

	assert.Equal(t, []int64{versionId(t, termsId, 1)}, acceptedVersionIds(t, user.Id),
		"the sign-in is the new user's")
}

func TestRegistrationContinuesSignIn_WithoutVerificationTheNewUserGoesOnIntoTheApp(t *testing.T) {
	setRegSettings(t, true, false, false)
	f, termsId := newRegistrationApp(t)
	browser := createHttpClient(t)
	registerURL, ceremonyId := f.createAnAccountLink(t, browser)
	before := decodeSessionIdentifier(t, requireSessionCookie(t, browser))

	email := fake.Email()
	password := fake.Password(20)
	resp := postRegisterAt(t, browser, registerURL, url.Values{
		"email": {email}, "password": {password}, "passwordConfirmation": {password},
	})
	user := registeredUser(t, email)
	assert.True(t, passwordhash.Verify(user.PasswordHash, password))

	assert.NotEqual(t, before, decodeSessionIdentifier(t, requireSessionCookie(t, browser)),
		"the browser session's identifier is rotated when the password is recorded")
	f.carriedOnToTheApp(t, browser, resp, ceremonyId, user, termsId)
}

// activationLinkFor answers the activation link mailed to email, which carries the sign-in's id and
// the code.
func activationLinkFor(t *testing.T, email, ceremonyId string) string {
	t.Helper()
	links := awaitActivationLinks(t, email, 1)
	require.Len(t, links, 1, "an activation link is mailed to %s", email)
	link, err := url.Parse(html.UnescapeString(links[0]))
	require.NoError(t, err)
	assert.Equal(t, []string{"ceremony", "code"}, queryKeys(link), "the link carries the sign-in and the code")
	assert.Equal(t, ceremonyId, link.Query().Get(ceremony.QueryParameter))
	return link.String()
}

// followActivationLinkWithSignIn performs the link's first hop and answers the clean URL it sends the
// browser to, which keeps the sign-in's id and drops the code.
func followActivationLinkWithSignIn(t *testing.T, browser *http.Client, link, ceremonyId string) string {
	t.Helper()
	resp := loadPage(t, browser, link)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/account/activate", location.Path)
	assert.Equal(t, url.Values{ceremony.QueryParameter: {ceremonyId}}, location.Query(),
		"the code leaves the URL, and the sign-in stays")
	return appConfig.AuthServer.BaseURL + location.String()
}

// registerFromTheApp registers email with verification from the fixture's sign-in in browser, and
// answers the sign-in's id and the link mailed.
func (f *legalAcceptanceFixture) registerFromTheApp(t *testing.T, browser *http.Client, email string) (string, string) {
	t.Helper()
	registerURL, ceremonyId := f.createAnAccountLink(t, browser)
	resp := postRegisterAt(t, browser, registerURL, url.Values{"email": {email}})
	body := bodyString(t, resp)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, body, checkYourEmailTitle)
	return ceremonyId, activationLinkFor(t, email, ceremonyId)
}

func TestRegistrationContinuesSignIn_ActivatingInTheSameBrowserGoesOnIntoTheApp(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, true, true)
	f, termsId := newRegistrationApp(t)
	browser := createHttpClient(t)
	email := registerAddress()
	ceremonyId, link := f.registerFromTheApp(t, browser, email)

	cleanURL := followActivationLinkWithSignIn(t, browser, link, ceremonyId)
	continuationId := loadActivationForm(t, browser, cleanURL, email)
	before := decodeSessionIdentifier(t, requireSessionCookie(t, browser))

	const chosenPassword = "Chosen-At-Activation-1!"
	resp := postActivation(t, browser, cleanURL, chosenPassword, chosenPassword, continuationId)
	user := registeredUser(t, email)
	assert.True(t, user.EmailVerified)
	assert.True(t, passwordhash.Verify(user.PasswordHash, chosenPassword))

	assert.NotEqual(t, before, decodeSessionIdentifier(t, requireSessionCookie(t, browser)),
		"the browser session's identifier is rotated when the password is recorded")
	f.carriedOnToTheApp(t, browser, resp, ceremonyId, user, termsId)
}

func TestRegistrationContinuesSignIn_ActivatingInAnotherBrowserActivatesAndSendsThePersonBackToTheApp(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, true, true)
	f, _ := newRegistrationApp(t)
	email := registerAddress()
	ceremonyId, link := f.registerFromTheApp(t, createHttpClient(t), email)

	other := createHttpClient(t)
	cleanURL := followActivationLinkWithSignIn(t, other, link, ceremonyId)
	continuationId := loadActivationForm(t, other, cleanURL, email)
	const chosenPassword = "Chosen-At-Activation-1!"
	resp := postActivation(t, other, cleanURL, chosenPassword, chosenPassword, continuationId)
	require.Equal(t, http.StatusOK, resp.StatusCode, "the page answers in place")
	page := parseHTMLResponse(t, resp)
	_ = resp.Body.Close()

	user := registeredUser(t, email)
	assert.True(t, user.EmailVerified, "the account is activated all the same")
	assert.Equal(t, "Account activated", strings.TrimSpace(page.Find("h1").Text()))
	assert.Contains(t, page.Find(".auth-status").Text(), returnToAppText)
	assert.Equal(t, email, page.Find("code.auth-address").Text())
	myAccount := page.Find(`.auth-status a[href="` + appConfig.AdminConsole.BaseURL + `/account/profile"]`)
	require.Equal(t, 1, myAccount.Length(), "My Account is linked")
	assert.Equal(t, "Sign in to your account", strings.TrimSpace(myAccount.Text()))
	assert.False(t, myAccount.HasClass("button-primary"), "as a secondary link")
}

// Registering from an app's sign-in answers every address alike, as registering from anywhere else
// does: the sign-in travels in the mailed link alone.
func TestRegistrationContinuesSignIn_WithVerificationEveryAddressGetsTheSamePage(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, true, true)
	f, _ := newRegistrationApp(t)
	browser := createHttpClient(t)
	registerURL, _ := f.createAnAccountLink(t, browser)

	taken := registerAddress()
	createResetTestUser(t, taken)
	pages := map[string]string{}
	for _, email := range []string{registerAddress(), taken} {
		resp := postRegisterAt(t, browser, registerURL, url.Values{"email": {email}})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		pages[email] = strings.ReplaceAll(bodyString(t, resp), email, "{email}")
		_ = resp.Body.Close()
	}
	require.Len(t, pages, 2)
	assert.Equal(t, pages[taken], func() string {
		for email, page := range pages {
			if email != taken {
				return page
			}
		}
		return ""
	}(), "an address with an account gets a new address's page")
}
