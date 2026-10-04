package integration

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setRegSettings sets the three registration switches until the test ends.
func setRegSettings(t *testing.T, selfRegEnabled, requiresVerify, smtpEnabled bool) {
	t.Helper()
	changeSettings(t, func(settings *record.Settings) {
		settings.SelfRegistrationEnabled = selfRegEnabled
		settings.SelfRegistrationRequiresEmailVerification = requiresVerify
		settings.SMTPEnabled = smtpEnabled
	})
}

// loadRegisterPage fetches the registration form and asserts it renders, which every test below
// did as a side effect of scraping the CSRF token out of it. The token left with gorilla/csrf
// (#155) and the page load stayed: a POST test whose form does not render is testing nothing, and
// this is the only assertion in this file that the GET binding works at all.
func loadRegisterPage(t *testing.T, client *http.Client) {
	destUrl := appConfig.AuthServer.BaseURL + "/account/register"
	resp := loadPage(t, client, destUrl)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /account/register, got %d", resp.StatusCode)
	}
}

func postRegister(t *testing.T, client *http.Client, email, password, confirm string) *http.Response {
	destUrl := appConfig.AuthServer.BaseURL + "/account/register"
	formData := url.Values{
		"email":                {email},
		"password":             {password},
		"passwordConfirmation": {confirm},
	}
	// require, not assert: returning a nil response here would surface as a
	// SIGSEGV in the caller instead of the real connectivity error.
	req, err := http.NewRequest("POST", destUrl, strings.NewReader(formData.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", destUrl)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// postRegisterAddress submits the form registration with verification shows, which has the
// address alone: the password is chosen from the emailed link (#207 decision 1).
func postRegisterAddress(t *testing.T, client *http.Client, email string) *http.Response {
	t.Helper()
	destUrl := appConfig.AuthServer.BaseURL + "/account/register"
	req, err := http.NewRequest("POST", destUrl, strings.NewReader(url.Values{"email": {email}}.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", destUrl)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func bodyString(t *testing.T, resp *http.Response) string {
	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	return string(b)
}

// Scenario 1: GET /account/register
// 1a. With self-registration disabled the page answers the not-found page (#425).
func TestSelfRegister_GetPage_Disabled(t *testing.T) {
	setRegSettings(t, false, false, true)

	httpClient := createHttpClient(t)
	resp := loadPage(t, httpClient, appConfig.AuthServer.BaseURL+"/account/register")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// 1b. With self-registration enabled the page renders.
//
// It used to also assert the form carried a CSRF token. There is no token any more: the POST below
// is protected by the origin check in httpmw.CSRF, which reads the browser's own Sec-Fetch-Site
// report and refuses anything it calls cross-site (#155). Nothing about that is visible in the
// rendered HTML, so the assertion has no successor here rather than a weaker one.
func TestSelfRegister_GetPage_Enabled(t *testing.T) {
	setRegSettings(t, true, false, false)

	httpClient := createHttpClient(t)
	resp := loadPage(t, httpClient, appConfig.AuthServer.BaseURL+"/account/register")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// 1c. With verification required the form asks for the address alone, and says the password is
// chosen from the emailed link; without it the form still asks for the password (#207 decisions
// 1 and 13).
func TestSelfRegister_GetPage_WithVerification_AsksForTheAddressAlone(t *testing.T) {
	useMailpitSMTP(t)

	setRegSettings(t, true, true, true)
	httpClient := createHttpClient(t)
	resp := loadPage(t, httpClient, appConfig.AuthServer.BaseURL+"/account/register")
	body := bodyString(t, resp)
	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, `name="email"`)
	assert.NotContains(t, body, `name="password"`)
	assert.NotContains(t, body, `name="passwordConfirmation"`)
	assert.Contains(t, body, "We&#39;ll email you a link to choose your password.")

	setRegSettings(t, true, false, true)
	resp = loadPage(t, httpClient, appConfig.AuthServer.BaseURL+"/account/register")
	body = bodyString(t, resp)
	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, `name="password"`)
	assert.Contains(t, body, `name="passwordConfirmation"`)
	assert.NotContains(t, body, "choose your password")
}

// Scenario 2: POST /account/register with SMTP off
// User is created (EmailVerified=false), the success template renders, and the
// admin-console profile link is present. Locks in the issue #69 fix at the HTTP
// layer (no /auth/pwd redirect).
func TestSelfRegister_Post_SMTPDisabled_RendersSuccessPage(t *testing.T) {
	setRegSettings(t, true, false, false)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	email := fake.Email()
	resp := postRegister(t, httpClient, email, "Password123!", "Password123!")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := bodyString(t, resp)
	assert.Contains(t, body, "Your account has been created.")
	assert.Contains(t, body, appConfig.AdminConsole.BaseURL+"/account/profile")
	// Regression guard: the old broken behavior was a 302 to /auth/pwd.
	assert.NotEqual(t, http.StatusFound, resp.StatusCode)
	assert.NotContains(t, body, "/auth/pwd")

	user, err := database.GetUserByEmail(context.Background(), nil, email)
	assert.NoError(t, err)
	if assert.NotNil(t, user) {
		assert.False(t, user.EmailVerified)
	}

	preReg, err := database.GetPreRegistrationByEmail(context.Background(), nil, email)
	assert.NoError(t, err)
	assert.Nil(t, preReg)
}

// Scenario 4 (renumbered relative to plan; covered before scenario 3 in this
// file because it shares the SMTP-on path): POST with SMTP on but verification
// off. Welcome email is sent, success template renders, user is created
// directly (no pre-registration row).
func TestSelfRegister_Post_SMTPEnabled_NoVerification_RendersSuccess(t *testing.T) {
	setRegSettings(t, true, false, true)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	email := fake.Email()
	resp := postRegister(t, httpClient, email, "Password123!", "Password123!")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := bodyString(t, resp)
	assert.Contains(t, body, "Your account has been created.")
	assert.Contains(t, body, appConfig.AdminConsole.BaseURL+"/account/profile")

	user, err := database.GetUserByEmail(context.Background(), nil, email)
	assert.NoError(t, err)
	if assert.NotNil(t, user) {
		assert.False(t, user.EmailVerified)
	}

	preReg, err := database.GetPreRegistrationByEmail(context.Background(), nil, email)
	assert.NoError(t, err)
	assert.Nil(t, preReg)
}

// registerPlusAddress returns a unique address containing a '+', which is the class #112
// reports as broken: the activation link used to carry the address, Go parses a query with
// form-urlencoded rules where '+' decodes to a space, so the pre-registration was never found
// and these users could not register at all.
func registerPlusAddress() string {
	return "register+tag." + strings.ToLower(fake.LetterN(10)) + "@example.com"
}

var activationLinkPattern = regexp.MustCompile(`https?://[^"'<>\s]+/account/activate[^"'<>\s]*`)

// latestActivationLink is the link a user would click, read back out of mailpit rather than
// rebuilt (decision 6). Rebuilding it is precisely why the old version of this test would have
// kept passing with every build site broken: it exercised a correct URL against a handler fed
// a correct URL.
func latestActivationLink(t *testing.T, to string) string {
	t.Helper()

	links := emailedLinksMatching(t, to, activationLinkPattern)
	require.NotEmpty(t, links, "expected an activation link emailed to %s", to)

	link := links[0]
	assert.NotContains(t, link, "@", "the activation link must carry no email address")
	assert.NotContains(t, link, "email=", "the activation link must carry no email parameter")

	parsed, err := url.Parse(link)
	require.NoError(t, err)
	assert.Equal(t, []string{"code"}, queryKeys(parsed), "the link must carry the code and nothing else")

	return link
}

// followActivationLink performs the first hop and asserts the credential leaves the URL there.
// It returns the clean URL the browser is sent to.
func followActivationLink(t *testing.T, client *http.Client, link string) string {
	t.Helper()

	resp := loadPage(t, client, link)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusSeeOther, resp.StatusCode,
		"following the emailed link must answer 303, not activate in place")

	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/account/activate", location.Path)
	assert.Empty(t, location.RawQuery,
		"the redirect target must carry no query, so the code cannot persist in history or a Referer")

	return appConfig.AuthServer.BaseURL + location.Path
}

const activationSucceededText = "Congratulations! Your account has been activated."
const activationExpiredText = "Unable to activate the account. The verification code appears to be expired."
const activationFormTitle = "Choose your password"

// loadActivationForm fetches the clean URL the first hop redirected to, which renders the
// "choose your password" form and creates nothing, and returns the continuation id the form
// carries, read out of the page the way a browser gets it.
func loadActivationForm(t *testing.T, client *http.Client, cleanURL string, email string) string {
	t.Helper()

	resp := loadPage(t, client, cleanURL)
	body := bodyString(t, resp)
	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, body, activationFormTitle)
	// Unescaped, because html/template writes the '+' of these addresses as &#43;.
	assert.Contains(t, html.UnescapeString(body), "Choose a password for "+email+" to finish creating your account.")
	assert.Contains(t, body, `name="password"`)
	assert.Contains(t, body, `name="passwordConfirmation"`)
	assert.Contains(t, body, "Create account")
	return continuationIdIn(t, body)
}

// postActivation submits the form to the clean URL, which is where the template's empty action
// sends it.
func postActivation(t *testing.T, client *http.Client, cleanURL, password, confirmation,
	continuationId string) *http.Response {
	t.Helper()

	form := url.Values{
		"password":             {password},
		"passwordConfirmation": {confirmation},
		"continuationId":       {continuationId},
	}
	req, err := http.NewRequest("POST", cleanURL, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", cleanURL)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)

	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// registerAndFollowLink registers an address with verification, follows the link read out of the
// mail actually sent, and returns the clean URL with the browser that followed it.
func registerAndFollowLink(t *testing.T, email string) (*http.Client, string) {
	t.Helper()

	browser := createHttpClient(t)
	loadRegisterPage(t, browser)

	resp := postRegisterAddress(t, browser, email)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	return browser, followActivationLink(t, browser, latestActivationLink(t, email))
}

// Scenario 3: POST with SMTP on and verification required.
//
// The form takes the address alone and the pending registration stores no password. The link the
// handler actually emailed leads to a form where the password is chosen, and only that form's POST
// creates the account, verified, with that password (#207 decision 1). The address contains a
// '+', so this is also the end-to-end guard for #112 itself.
func TestSelfRegister_Post_SMTPEnabled_RequiresVerification_FullFlow(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, true, true)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	email := registerPlusAddress()
	resp := postRegisterAddress(t, httpClient, email)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	user, err := database.GetUserByEmail(context.Background(), nil, email)
	assert.NoError(t, err)
	assert.Nil(t, user, "user should not exist before activation")

	preReg, err := database.GetPreRegistrationByEmail(context.Background(), nil, email)
	assert.NoError(t, err)
	if !assert.NotNil(t, preReg, "pre-registration should exist after POST") {
		return
	}
	assert.Empty(t, preReg.PasswordHash, "the pending registration stores no password")

	// The hash is what the link resolves to, and it must be the hash of the code that was
	// issued or the registration is unactivatable.
	verificationCode, err := dataCipher.Decrypt(preReg.VerificationCodeEncrypted)
	assert.NoError(t, err)
	assert.NotEmpty(t, verificationCode)
	expectedHash := hashutil.HashString(verificationCode)
	assert.Equal(t, expectedHash, preReg.VerificationCodeHash)

	cleanURL := followActivationLink(t, httpClient, latestActivationLink(t, email))
	continuationId := loadActivationForm(t, httpClient, cleanURL, email)

	user, err = database.GetUserByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	assert.Nil(t, user, "rendering the password form must create nothing")

	const chosenPassword = "Chosen-At-Activation-1!"
	activateResp := postActivation(t, httpClient, cleanURL, chosenPassword, chosenPassword, continuationId)
	defer func() { _ = activateResp.Body.Close() }()

	assert.Equal(t, http.StatusOK, activateResp.StatusCode)
	activationBody := bodyString(t, activateResp)
	assert.Contains(t, activationBody, activationSucceededText)
	assert.Contains(t, activationBody, appConfig.AdminConsole.BaseURL+"/account/profile")

	user, err = database.GetUserByEmail(context.Background(), nil, email)
	assert.NoError(t, err)
	if assert.NotNil(t, user, "the '+' address must complete registration end to end") {
		assert.True(t, user.EmailVerified)
		assert.True(t, passwordhash.Verify(user.PasswordHash, chosenPassword),
			"the account's password must be the one chosen at activation")
	}

	preReg, err = database.GetPreRegistrationByEmail(context.Background(), nil, email)
	assert.NoError(t, err)
	assert.Nil(t, preReg, "pre-registration should be deleted after activation")
}

// The activation mail carries decision 13's text: the link leads to choosing a password, and no
// account exists unless it is used.
func TestSelfRegister_TheActivationMailSaysThePasswordIsChosenFromTheLink(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, true, true)

	email := registerPlusAddress()
	browser := createHttpClient(t)
	loadRegisterPage(t, browser)
	resp := postRegisterAddress(t, browser, email)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	messages := awaitMailTo(t, email)
	require.Len(t, messages, 1)
	message := messages[0]

	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)

	assert.Equal(t, "Activate your account", message.Subject)
	assert.Contains(t, message.HTML, "To finish creating your "+settings.AppName+" account, click the link below and choose a password:")
	assert.Contains(t, message.HTML, "The link expires in 5 minutes. If you have trouble clicking it, copy and paste it into your web browser.")
	assert.Contains(t, message.HTML, "If you didn't ask to create an account, ignore this message: no account is created unless the link is used.")
}

// What decision 1 exists for, at the only level that sees a real redirect: fetching the link and
// following its redirect, as a mail scanner or a link previewer does, creates no account. The
// pending registration survives, so the recipient's own click still works.
func TestSelfRegister_FetchingTheLinkCreatesNoAccount(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, true, true)

	email := registerPlusAddress()
	scanner, cleanURL := registerAndFollowLink(t, email)
	_ = loadActivationForm(t, scanner, cleanURL, email)

	user, err := database.GetUserByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	assert.Nil(t, user, "fetching the link must not create the account")

	preReg, err := database.GetPreRegistrationByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	assert.NotNil(t, preReg, "the pending registration must survive a fetch")

	// The recipient, in a browser of their own, still completes it.
	recipient := createHttpClient(t)
	recipientCleanURL := followActivationLink(t, recipient, latestActivationLink(t, email))
	continuationId := loadActivationForm(t, recipient, recipientCleanURL, email)
	activateResp := postActivation(t, recipient, recipientCleanURL, "Recipient-Chose-1!", "Recipient-Chose-1!", continuationId)
	body := bodyString(t, activateResp)
	_ = activateResp.Body.Close()
	require.Contains(t, body, activationSucceededText)

	user, err = database.GetUserByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.True(t, passwordhash.Verify(user.PasswordHash, "Recipient-Chose-1!"))
}

// A refused password redraws the form with the reason and creates nothing; the continuation it
// carries back still completes the activation.
func TestSelfRegister_ActivationRedrawsTheFormForAMismatchedConfirmation(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, true, true)

	email := registerPlusAddress()
	browser, cleanURL := registerAndFollowLink(t, email)
	continuationId := loadActivationForm(t, browser, cleanURL, email)

	resp := postActivation(t, browser, cleanURL, "Chosen-At-Activation-1!", "Something-Else-1!", continuationId)
	body := bodyString(t, resp)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, activationFormTitle)
	assert.Contains(t, body, "password confirmation does not match")
	assert.Equal(t, continuationId, continuationIdIn(t, body), "the redraw must carry the continuation back")

	user, err := database.GetUserByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	assert.Nil(t, user, "a refused password must create nothing")

	resp = postActivation(t, browser, cleanURL, "Chosen-At-Activation-1!", "Chosen-At-Activation-1!", continuationId)
	body = bodyString(t, resp)
	_ = resp.Body.Close()
	assert.Contains(t, body, activationSucceededText)
}

// The replay case only a real cookie jar can see. A copy of the browser's cookies, taken while the
// marker is still live, replays the submission after the activation completed. What refuses it
// is the code hash the marker names no longer resolving, because activating deleted the
// pre-registration.
func TestSelfRegister_ReplayedMarkerAfterActivationIsRefused(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, true, true)

	email := registerPlusAddress()
	httpClient, cleanURL := registerAndFollowLink(t, email)
	continuationId := loadActivationForm(t, httpClient, cleanURL, email)

	// Taken while the marker is still live and usable.
	captured := capturedSessionCookies(t, httpClient)

	activateResp := postActivation(t, httpClient, cleanURL, "Password123!", "Password123!", continuationId)
	activationBody := bodyString(t, activateResp)
	_ = activateResp.Body.Close()
	require.Contains(t, activationBody, activationSucceededText)

	activated, err := database.GetUserByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	require.NotNil(t, activated)

	replayResp := postActivation(t, clientCarrying(t, captured), cleanURL, "Attacker123!", "Attacker123!", continuationId)
	replayBody := bodyString(t, replayResp)
	_ = replayResp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, replayResp.StatusCode)
	assert.Contains(t, replayBody, activationExpiredText,
		"a replayed submission must land on the register-again page")
	assert.NotContains(t, replayBody, activationSucceededText)

	after, err := database.GetUserByEmail(context.Background(), nil, email)
	require.NoError(t, err)
	require.NotNil(t, after)
	assert.Equal(t, activated.Id, after.Id,
		"a replayed submission must not create a second account")
	assert.Equal(t, activated.PasswordHash, after.PasswordHash,
		"a replayed submission must not change the password")
}

// The activation half of the same defect (#112 decision 13). Two pending registrations and
// one cookie jar: a second link followed while the first continuation is live must not take the
// session over, so the form already on its way activates the registration that produced it.
func TestSelfRegister_ASecondLinkDoesNotRetargetTheRedirectInFlight(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, true, true)

	browser := createHttpClient(t)
	loadRegisterPage(t, browser)

	firstEmail := registerPlusAddress()
	firstResp := postRegisterAddress(t, browser, firstEmail)
	_ = firstResp.Body.Close()
	require.Equal(t, http.StatusOK, firstResp.StatusCode)

	// A second registration, made from somewhere else entirely.
	elsewhere := createHttpClient(t)
	loadRegisterPage(t, elsewhere)

	secondEmail := registerPlusAddress()
	secondResp := postRegisterAddress(t, elsewhere, secondEmail)
	_ = secondResp.Body.Close()
	require.Equal(t, http.StatusOK, secondResp.StatusCode)

	// The first link's redirect is in flight: followed, but its clean hop not yet made.
	cleanURL := followActivationLink(t, browser, latestActivationLink(t, firstEmail))

	// The steered navigation: the second link, followed in the first browser's jar.
	steeredResp := loadPage(t, browser, latestActivationLink(t, secondEmail))
	steeredBody := bodyString(t, steeredResp)
	_ = steeredResp.Body.Close()

	assert.NotEqual(t, http.StatusSeeOther, steeredResp.StatusCode,
		"a second link followed while one is live must not take over the session")
	assert.Contains(t, steeredBody, activationExpiredText)

	// The redirect in flight renders the form for, and activates, the registration that produced it.
	continuationId := loadActivationForm(t, browser, cleanURL, firstEmail)
	activateResp := postActivation(t, browser, cleanURL, "Password123!", "Password123!", continuationId)
	activationBody := bodyString(t, activateResp)
	_ = activateResp.Body.Close()
	require.Contains(t, activationBody, activationSucceededText)

	first, err := database.GetUserByEmail(context.Background(), nil, firstEmail)
	require.NoError(t, err)
	assert.NotNil(t, first, "the registration whose link produced the redirect is the one activated")

	second, err := database.GetUserByEmail(context.Background(), nil, secondEmail)
	require.NoError(t, err)
	assert.Nil(t, second, "the second registration must not have been activated")

	stillPending, err := database.GetPreRegistrationByEmail(context.Background(), nil, secondEmail)
	require.NoError(t, err)
	assert.NotNil(t, stillPending, "the second registration must still be pending, so its own link still works")
}

// createAccountAt gives an address an account behind the pending registration's back, as an
// administrator creating the user would.
func createAccountAt(t *testing.T, email string) *record.User {
	t.Helper()
	existing := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        email,
		PasswordHash: "irrelevant",
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, existing))
	return existing
}

// An address that gained an account between registration and activation is refused with the
// flow's one page, at 200 on the clean GET and 400 on the POST, and its pending registration is
// deleted; no second account appears and the existing one is untouched. It used to answer the
// 500 page (#207 decision 10).
func TestSelfRegister_ActivationIsRefusedForAnAddressThatHasAnAccount(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, true, true)

	t.Run("at the clean GET", func(t *testing.T) {
		email := registerPlusAddress()
		browser, cleanURL := registerAndFollowLink(t, email)
		existing := createAccountAt(t, email)

		resp := loadPage(t, browser, cleanURL)
		body := bodyString(t, resp)
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, body, activationExpiredText)
		assert.NotContains(t, body, activationFormTitle)

		preReg, err := database.GetPreRegistrationByEmail(context.Background(), nil, email)
		require.NoError(t, err)
		assert.Nil(t, preReg, "a pending registration that can never complete is deleted")

		after, err := database.GetUserByEmail(context.Background(), nil, email)
		require.NoError(t, err)
		require.NotNil(t, after)
		assert.Equal(t, existing.Id, after.Id)
		assert.Equal(t, "irrelevant", after.PasswordHash, "the existing account is untouched")
	})

	t.Run("at the POST", func(t *testing.T) {
		email := registerPlusAddress()
		browser, cleanURL := registerAndFollowLink(t, email)
		continuationId := loadActivationForm(t, browser, cleanURL, email)
		existing := createAccountAt(t, email)

		resp := postActivation(t, browser, cleanURL, "Password123!", "Password123!", continuationId)
		body := bodyString(t, resp)
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, body, activationExpiredText)
		assert.NotContains(t, body, activationSucceededText)

		preReg, err := database.GetPreRegistrationByEmail(context.Background(), nil, email)
		require.NoError(t, err)
		assert.Nil(t, preReg, "a pending registration that can never complete is deleted")

		after, err := database.GetUserByEmail(context.Background(), nil, email)
		require.NoError(t, err)
		require.NotNil(t, after)
		assert.Equal(t, existing.Id, after.Id)
		assert.Equal(t, "irrelevant", after.PasswordHash, "the existing account is untouched")
	})
}

// Scenario 5a: POST while self-registration is disabled returns the not-found
// page (#425). We load the form while it is enabled, then disable.
func TestSelfRegister_Post_Disabled_ReturnsError(t *testing.T) {
	setRegSettings(t, true, false, false)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	setRegSettings(t, false, false, false)

	resp := postRegister(t, httpClient, fake.Email(), "Password123!", "Password123!")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// Scenario 5b: duplicate user email is rejected with a friendly message.
func TestSelfRegister_Post_DuplicateEmail(t *testing.T) {
	setRegSettings(t, true, false, false)

	existing := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: "irrelevant",
	}
	err := database.CreateUser(context.Background(), nil, existing)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	resp := postRegister(t, httpClient, existing.Email, "Password123!", "Password123!")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := bodyString(t, resp)
	assert.Contains(t, body, "this email address is already registered")
}

// Scenario 5c: duplicate pre-registration is rejected with the same message.
func TestSelfRegister_Post_DuplicatePreRegistration(t *testing.T) {
	setRegSettings(t, true, true, true)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	email := fake.Email()
	resp1 := postRegister(t, httpClient, email, "Password123!", "Password123!")
	_ = resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	preReg, err := database.GetPreRegistrationByEmail(context.Background(), nil, email)
	assert.NoError(t, err)
	assert.NotNil(t, preReg, "pre-registration should exist after first POST")

	loadRegisterPage(t, httpClient)
	resp2 := postRegister(t, httpClient, email, "Password123!", "Password123!")
	defer func() { _ = resp2.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	body := bodyString(t, resp2)
	assert.Contains(t, body, "this email address is already registered")
}

// Scenario 5d: password confirmation mismatch is reported and no user is
// created.
func TestSelfRegister_Post_PasswordMismatch(t *testing.T) {
	setRegSettings(t, true, false, false)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	email := fake.Email()
	resp := postRegister(t, httpClient, email, "Password123!", "Different456!")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := bodyString(t, resp)
	assert.Contains(t, body, "password confirmation does not match")

	user, err := database.GetUserByEmail(context.Background(), nil, email)
	assert.NoError(t, err)
	assert.Nil(t, user, "no user should be created on validation failure")
}
