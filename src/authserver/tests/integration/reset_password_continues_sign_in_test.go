package integration

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A password reset started from an app's sign-in carries that sign-in on, as registration and
// activation do (#812 decisions 9 and 10). The forgot-password page's URL names the sign-in, the
// mailed link names it beside the code, and its first hop keeps it when it drops the code. Saved in
// the browser that still holds the sign-in at its password step, the new password is recorded as
// proven on it and the browser goes on into the app. Anywhere else the reset ends on its page, which
// tells a person whose link named a sign-in to go back to the application. The setup link an
// administrator mails a new user carries the code alone, as before.

// resetReturnToAppText is the reset page's text when the link named a sign-in the reset could not
// carry on.
const resetReturnToAppText = "Your password is set. Go back to the application you were signing in to, and sign in " +
	"with your new password and this email address:"

// resetFromTheAppUser is a verified, enabled account with a password, which recovery mails, deleted
// when the test ends.
func resetFromTheAppUser(t *testing.T) (*record.User, string) {
	t.Helper()
	user, password := createResetTestUser(t, plusAddress())
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	return user, password
}

// requestResetFromTheApp starts a sign-in at authorizeURL in browser, asks for a reset link for email
// from the password page's Forgot password? link, and answers the sign-in's id and the link mailed.
func requestResetFromTheApp(t *testing.T, browser *http.Client, authorizeURL, email string) (string, string) {
	t.Helper()
	forgotURL, ceremonyId := forgotPasswordLink(t, browser, authorizeURL)
	resp := postRegisterAt(t, browser, forgotURL, url.Values{"email": {email}})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return ceremonyId, resetLinkWithSignIn(t, email, ceremonyId)
}

// resetLinkWithSignIn answers the reset link mailed to email, which carries the sign-in's id and the
// code.
func resetLinkWithSignIn(t *testing.T, email, ceremonyId string) string {
	t.Helper()
	links := awaitResetLinks(t, email, 1)
	require.Len(t, links, 1, "a reset link is mailed to %s", email)
	link, err := url.Parse(html.UnescapeString(links[0]))
	require.NoError(t, err)
	assert.Equal(t, []string{"ceremony", "code"}, queryKeys(link), "the link carries the sign-in and the code")
	assert.Equal(t, ceremonyId, link.Query().Get(ceremony.QueryParameter))
	return link.String()
}

// followResetLinkWithSignIn performs the link's first hop and answers the clean URL it sends the
// browser to, which keeps the sign-in's id and drops the code.
func followResetLinkWithSignIn(t *testing.T, browser *http.Client, link, ceremonyId string) string {
	t.Helper()
	resp := loadPage(t, browser, link)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/reset-password", location.Path)
	assert.Equal(t, url.Values{ceremony.QueryParameter: {ceremonyId}}, location.Query(),
		"the code leaves the URL, and the sign-in stays")
	return appConfig.AuthServer.BaseURL + location.String()
}

// resetFromLink follows link in browser, loads the form and saves a new password with it, and
// answers the response and the password.
func resetFromLink(t *testing.T, browser *http.Client, link, ceremonyId string) (*http.Response, string) {
	t.Helper()
	cleanURL := followResetLinkWithSignIn(t, browser, link, ceremonyId)
	continuationId := loadResetForm(t, browser, cleanURL)
	password := fake.Password(20)
	return postCleanReset(t, browser, cleanURL, password, continuationId), password
}

// assertResetEndsOnItsPageSendingThePersonBack asserts the reset answered its page in place, telling
// the person to go back to the application, with My Account as a secondary link.
func assertResetEndsOnItsPageSendingThePersonBack(t *testing.T, resp *http.Response, email string) {
	t.Helper()
	require.Equal(t, http.StatusOK, resp.StatusCode, "the page answers in place")
	page := parseHTMLResponse(t, resp)
	_ = resp.Body.Close()
	assert.Equal(t, "Password set", strings.TrimSpace(page.Find("h1").Text()))
	assert.Contains(t, page.Find(".auth-status").Text(), resetReturnToAppText)
	assert.Equal(t, email, page.Find("code.auth-address").Text())
	myAccount := page.Find(`.auth-status a[href="` + appConfig.AdminConsole.BaseURL + `/account/profile"]`)
	require.Equal(t, 1, myAccount.Length(), "My Account is linked")
	assert.Equal(t, "Sign in to your account", strings.TrimSpace(myAccount.Text()))
	assert.False(t, myAccount.HasClass("button-primary"), "as a secondary link")
}

func TestResetPasswordContinuesSignIn_InTheSameBrowserTheUserGoesOnIntoTheApp(t *testing.T) {
	useMailpitSMTP(t)
	f, termsId := newRegistrationApp(t)
	user, oldPassword := resetFromTheAppUser(t)
	browser := createHttpClient(t)
	ceremonyId, link := requestResetFromTheApp(t, browser, f.link(""), user.Email)

	cleanURL := followResetLinkWithSignIn(t, browser, link, ceremonyId)
	continuationId := loadResetForm(t, browser, cleanURL)
	before := decodeSessionIdentifier(t, requireSessionCookie(t, browser))
	newPassword := fake.Password(20)
	resp := postCleanReset(t, browser, cleanURL, newPassword, continuationId)

	stored, err := database.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	assert.True(t, passwordhash.Verify(stored.PasswordHash, newPassword), "the reset set the new password")
	assert.False(t, passwordhash.Verify(stored.PasswordHash, oldPassword))
	assert.Equal(t, user.AuthStateGeneration+1, stored.AuthStateGeneration,
		"the reset still signs the user out everywhere")
	assert.Empty(t, stored.ForgotPasswordCodeHash, "the reset consumed the code")

	assert.NotEqual(t, before, decodeSessionIdentifier(t, requireSessionCookie(t, browser)),
		"the browser session's identifier is rotated when the password is recorded")
	f.carriedOnToTheApp(t, browser, resp, ceremonyId, user, termsId)

	require.Len(t, awaitMailWithSubject(t, user.Email, resetSubjectEn, 1), 1,
		"the account's address is told its password was reset")
}

func TestResetPasswordContinuesSignIn_InAnotherBrowserTheResetSendsThePersonBackToTheApp(t *testing.T) {
	useMailpitSMTP(t)
	f, _ := newRegistrationApp(t)
	user, _ := resetFromTheAppUser(t)
	ceremonyId, link := requestResetFromTheApp(t, createHttpClient(t), f.link(""), user.Email)

	resp, newPassword := resetFromLink(t, createHttpClient(t), link, ceremonyId)
	assertResetEndsOnItsPageSendingThePersonBack(t, resp, user.Email)
	assert.True(t, passwordhash.Verify(passwordHashOf(t, user.Id), newPassword), "the password is reset all the same")
}

func TestResetPasswordContinuesSignIn_ASignInPastItsPasswordStepIsNotCarriedOn(t *testing.T) {
	useMailpitSMTP(t)
	f, _ := newRegistrationApp(t)
	user, oldPassword := resetFromTheAppUser(t)
	browser := createHttpClient(t)
	ceremonyId, link := requestResetFromTheApp(t, browser, f.link(""), user.Email)

	// The person remembers the password after all, and signs in with it before using the link.
	pwdURL := appConfig.AuthServer.BaseURL + "/auth/pwd?" + url.Values{ceremony.QueryParameter: {ceremonyId}}.Encode()
	pwdPage := loadPage(t, browser, pwdURL)
	resp := authenticateWithPassword(t, browser, pwdURL, pwdPage, user.Email, oldPassword)
	_ = pwdPage.Body.Close()
	assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()

	resp, newPassword := resetFromLink(t, browser, link, ceremonyId)
	assertResetEndsOnItsPageSendingThePersonBack(t, resp, user.Email)
	assert.True(t, passwordhash.Verify(passwordHashOf(t, user.Id), newPassword))
}

func TestResetPasswordContinuesSignIn_AnAccountWithTwoFactorGoesOnToItsCode(t *testing.T) {
	useMailpitSMTP(t)
	f, _ := newRegistrationApp(t)
	// Level 2 optional: the app asks for the second factor of an account that has one.
	f.client.DefaultAcrLevel = record.AcrLevel2Optional
	require.NoError(t, database.UpdateClient(context.Background(), nil, f.client))
	hashed, err := passwordhash.Hash(fake.Password(20))
	require.NoError(t, err)
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: plusAddress(), EmailVerified: true,
		PasswordHash: hashed, OTPEnabled: true}
	user.OTPSecretEncrypted = encryptOTPSecretForTest(t, newOTPSecretForTest(t, user.Email))
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	browser := createHttpClient(t)
	ceremonyId, link := requestResetFromTheApp(t, browser, f.link(""), user.Email)

	resp, _ := resetFromLink(t, browser, link, ceremonyId)
	location := assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	location = assertRedirect(t, resp, "/auth/level2")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()
	assertRedirect(t, resp, "/auth/otp")
}

// The setup link an administrator mails a new user names no sign-in, so a browser holding one at its
// password step sets the password and ends on the page as it always has, the sign-in left where it
// was.
func TestResetPasswordContinuesSignIn_TheSetupLinkIsNeverCarriedOn(t *testing.T) {
	useMailpitSMTP(t)
	f, _ := newRegistrationApp(t)
	browser := createHttpClient(t)
	_, ceremonyId := forgotPasswordLink(t, browser, f.link(""))

	email := plusAddress()
	resp := makeAPIRequest(t, "POST", appConfig.AuthServer.BaseURL+"/api/v1/admin/users/create", f.adminToken,
		api.CreateUserAdminRequest{
			Email:           email,
			GivenName:       "Setup",
			FamilyName:      "Carry",
			SetPasswordType: api.SetPasswordTypeEmail,
		})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created api.CreateUserResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	_ = resp.Body.Close()
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, created.User.Id) })

	// latestResetLink asserts the link carries the code and nothing else.
	link := latestResetLink(t, email)
	cleanURL := followResetLink(t, browser, link)
	continuationId := loadResetForm(t, browser, cleanURL)
	resp = postCleanReset(t, browser, cleanURL, fake.Password(20), continuationId)
	body := bodyString(t, resp)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, resetSucceededText)
	assert.NotContains(t, body, "Go back to the application")

	pwdPage := loadPage(t, browser,
		appConfig.AuthServer.BaseURL+"/auth/pwd?"+url.Values{ceremony.QueryParameter: {ceremonyId}}.Encode())
	defer func() { _ = pwdPage.Body.Close() }()
	require.Equal(t, http.StatusOK, pwdPage.StatusCode, "the sign-in is still at its password step")
	assert.Contains(t, bodyString(t, pwdPage), `name="password"`)
}
