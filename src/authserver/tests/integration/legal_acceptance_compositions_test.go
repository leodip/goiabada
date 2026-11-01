package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The acceptance step in the sign-ins that compose it with the other steps (#622 decisions 7 and
// 9): the implicit flow, held before any token and answered in the fragment; a client that asks
// for consent, whose consent screen follows the step; and a registration carried on through a
// mandatory second factor, the step and consent into the app. Each app is a client of the test's
// own with a must-accept document for it alone.

// updateFixtureClient applies change to the fixture's client and stores it.
func (f *legalAcceptanceFixture) updateFixtureClient(t *testing.T, change func(client *record.Client)) {
	t.Helper()
	change(f.client)
	require.NoError(t, database.UpdateClient(context.Background(), nil, f.client))
}

// implicitLink is an implicit authorization request from the fixture's app for an ID token and an
// access token.
func (f *legalAcceptanceFixture) implicitLink() string {
	return appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + f.client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(f.redirectURI) +
		"&response_type=" + url.QueryEscape("id_token token") +
		"&scope=openid" +
		"&state=" + legalAcceptanceState +
		"&nonce=" + fake.LetterN(8)
}

// passwordToCompleted signs the fixture's user in at the password page link leads to, and answers
// /auth/completed's response. The caller closes it.
func (f *legalAcceptanceFixture) passwordToCompleted(t *testing.T, browser *http.Client, link string) *http.Response {
	t.Helper()
	resp, err := browser.Get(link)
	require.NoError(t, err)
	location := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	location = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()
	pwdPage := loadPage(t, browser, location)
	resp = authenticateWithPassword(t, browser, location, pwdPage, f.user.Email, f.password)
	_ = pwdPage.Body.Close()
	location = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	location = assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	return loadPage(t, browser, location)
}

// fragmentOf answers the fragment parameters of a redirect to the fixture's app, and asserts that
// nothing came back in the query.
func (f *legalAcceptanceFixture) fragmentOf(t *testing.T, resp *http.Response) url.Values {
	t.Helper()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, resp.StatusCode)
	redirect, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, f.redirectURI, redirect.Scheme+"://"+redirect.Host+redirect.Path, "back to the app: %s", redirect)
	assert.Empty(t, redirect.RawQuery, "the implicit flow answers in the fragment")
	values, err := url.ParseQuery(redirect.Fragment)
	require.NoError(t, err)
	return values
}

func TestLegalAcceptance_TheImplicitFlowIsHeldAtTheStepAndAnsweredInTheFragment(t *testing.T) {
	f := newLegalAcceptanceFixture(t)
	implicit := true
	f.updateFixtureClient(t, func(client *record.Client) { client.ImplicitGrantEnabled = &implicit })
	termsId, _ := f.mustAcceptFor(t, "implicit", "Implicit terms")

	t.Run("no token before the step, and the tokens on Accept", func(t *testing.T) {
		browser := createHttpClient(t)
		page, stepURL := toStep(t, browser, f.passwordToCompleted(t, browser, f.implicitLink()))

		// Issuance asked for while the step is owed issues nothing to the app.
		step, err := url.Parse(stepURL)
		require.NoError(t, err)
		early := loadPage(t, browser, appConfig.AuthServer.BaseURL+"/auth/issue?"+ceremony.QueryParameter+"="+
			url.QueryEscape(step.Query().Get(ceremony.QueryParameter)))
		assert.NotContains(t, early.Header.Get("Location"), "access_token", "no token before the step")
		assert.NotContains(t, early.Header.Get("Location"), "id_token")
		_ = early.Body.Close()
		assert.Empty(t, acceptedVersionIds(t, f.user.Id))

		_, documents := readStep(t, page)
		require.Len(t, documents, 1)
		resp := postStep(t, browser, stepURL, page, versionsOf(documents), false)
		_ = page.Body.Close()
		location := assertRedirect(t, resp, "/auth/issue")
		_ = resp.Body.Close()
		resp = loadPage(t, browser, location)
		tokens := f.fragmentOf(t, resp)
		_ = resp.Body.Close()
		assert.NotEmpty(t, tokens.Get("access_token"), "the app gets its access token")
		assert.NotEmpty(t, tokens.Get("id_token"), "and its ID token")
		assert.Equal(t, legalAcceptanceState, tokens.Get("state"))
		assert.Equal(t, []int64{versionId(t, termsId, 1)}, acceptedVersionIds(t, f.user.Id))
	})

	t.Run("Decline answers access_denied in the fragment", func(t *testing.T) {
		user, password := newLegalAcceptanceUser(t)
		other := &legalAcceptanceFixture{client: f.client, redirectURI: f.redirectURI, user: user, password: password}
		browser := createHttpClient(t)
		page, stepURL := toStep(t, browser, other.passwordToCompleted(t, browser, other.implicitLink()))
		resp := postStep(t, browser, stepURL, page, nil, true)
		_ = page.Body.Close()
		answer := other.fragmentOf(t, resp)
		_ = resp.Body.Close()
		assert.Equal(t, "access_denied", answer.Get("error"))
		assert.Equal(t, declinedDescription, answer.Get("error_description"))
		assert.Equal(t, legalAcceptanceState, answer.Get("state"))
		assert.Empty(t, answer.Get("access_token"))
		assert.Empty(t, answer.Get("id_token"))
		assert.Empty(t, acceptedVersionIds(t, user.Id))
	})
}

func TestLegalAcceptance_AnAppThatAsksForConsentShowsItsConsentScreenAfterTheStep(t *testing.T) {
	f := newLegalAcceptanceFixture(t)
	f.updateFixtureClient(t, func(client *record.Client) { client.ConsentRequired = true })
	termsId, _ := f.mustAcceptFor(t, "consented", "Consented terms")
	browser := createHttpClient(t)

	page, stepURL := toStep(t, browser, f.passwordToCompleted(t, browser, f.link("")))
	_, documents := readStep(t, page)
	resp := postStep(t, browser, stepURL, page, versionsOf(documents), false)
	_ = page.Body.Close()
	assert.Equal(t, []int64{versionId(t, termsId, 1)}, acceptedVersionIds(t, f.user.Id), "accepted before consent")

	consentURL := assertRedirect(t, resp, "/auth/consent")
	_ = resp.Body.Close()
	consentPage := loadPage(t, browser, consentURL)
	require.Equal(t, http.StatusOK, consentPage.StatusCode, "the consent screen comes next")
	ceremonyId := getCeremonyIdFromPage(t, consentPage)
	_ = consentPage.Body.Close()
	consents, err := database.GetConsentsByUserId(context.Background(), nil, f.user.Id)
	require.NoError(t, err)
	assert.Empty(t, consents, "no consent before the user gives it")

	resp, err = submitConsent(browser, appConfig.AuthServer.BaseURL+consentPathOf(t, consentURL), ceremonyId, []int{0})
	require.NoError(t, err)
	f.assertCodeIssued(t, browser, resp)
}

// consentPathOf answers the path and query of the consent screen's address, which may be relative.
func consentPathOf(t *testing.T, location string) string {
	t.Helper()
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	return parsed.RequestURI()
}

func TestRegistrationContinuesSignIn_ThroughAMandatorySecondFactorTheStepAndConsent(t *testing.T) {
	setRegSettings(t, true, false, false)
	f, termsId := newRegistrationApp(t)
	f.updateFixtureClient(t, func(client *record.Client) {
		client.DefaultAcrLevel = record.AcrLevel2Mandatory
		client.ConsentRequired = true
	})
	browser := createHttpClient(t)
	registerURL, ceremonyId := f.createAnAccountLink(t, browser)

	email := fake.Email()
	password := fake.Password(20)
	resp := postRegisterAt(t, browser, registerURL, url.Values{
		"email": {email}, "password": {password}, "passwordConfirmation": {password},
	})
	user := registeredUser(t, email)

	location := assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	next, err := url.Parse(location)
	require.NoError(t, err)
	assert.Equal(t, ceremonyId, next.Query().Get(ceremony.QueryParameter), "the sign-in the link named")
	resp = loadPage(t, browser, location)
	location = assertRedirect(t, resp, "/auth/level2")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	otpURL := assertRedirect(t, resp, "/auth/otp")
	_ = resp.Body.Close()

	// The new user has no authenticator yet: the app's mandatory second factor enrols one.
	otpPage := loadPage(t, browser, otpURL)
	secret := getOtpSecretFromEnrollmentPage(t, otpPage)
	require.NotEmpty(t, secret, "the second factor is enrolled before the step")
	assert.Empty(t, acceptedVersionIds(t, user.Id))
	resp = authenticateWithOtp(t, browser, otpURL, otpPage, otptest.Code(t, secret, time.Now()))
	_ = otpPage.Body.Close()
	location = assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	enrolled, err := database.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	assert.True(t, enrolled.OTPEnabled, "the authenticator is enrolled")

	page, stepURL := toStep(t, browser, loadPage(t, browser, location))
	_, documents := readStep(t, page)
	require.Len(t, documents, 1, "the step asks for the app's terms")
	resp = postStep(t, browser, stepURL, page, versionsOf(documents), false)
	_ = page.Body.Close()
	assert.Equal(t, []int64{versionId(t, termsId, 1)}, acceptedVersionIds(t, user.Id), "the sign-in is the new user's")

	consentURL := assertRedirect(t, resp, "/auth/consent")
	_ = resp.Body.Close()
	consentPage := loadPage(t, browser, consentURL)
	require.Equal(t, http.StatusOK, consentPage.StatusCode)
	consentCeremonyId := getCeremonyIdFromPage(t, consentPage)
	_ = consentPage.Body.Close()
	resp, err = submitConsent(browser, appConfig.AuthServer.BaseURL+consentPathOf(t, consentURL), consentCeremonyId, []int{0})
	require.NoError(t, err)
	location = assertRedirect(t, resp, "/auth/issue")
	_ = resp.Body.Close()
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()
	codeValue := f.appRedirect(t, resp).Get("code")
	require.NotEmpty(t, codeValue, "the app gets a code")
	code := loadCodeFromDatabase(t, codeValue)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, record.AcrLevel2Mandatory, code.AcrLevel, "issued at the level the app requires")
	assert.Contains(t, code.AuthMethods, "otp", "with the second factor")
}
