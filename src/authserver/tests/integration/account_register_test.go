package integrationtests

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// saveAndRestoreRegSettings snapshots the registration-related settings and
// returns a restore function meant to be deferred. This keeps tests isolated
// from each other and from the rest of the suite.
func saveAndRestoreRegSettings(t *testing.T) func() {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	origSelfReg := settings.SelfRegistrationEnabled
	origRequiresVerify := settings.SelfRegistrationRequiresEmailVerification
	origSMTPEnabled := settings.SMTPEnabled

	return func() {
		s, err := database.GetSettingsById(nil, 1)
		if err != nil {
			t.Logf("could not restore settings: %v", err)
			return
		}
		s.SelfRegistrationEnabled = origSelfReg
		s.SelfRegistrationRequiresEmailVerification = origRequiresVerify
		s.SMTPEnabled = origSMTPEnabled
		_ = database.UpdateSettings(nil, s)
	}
}

func setRegSettings(t *testing.T, selfRegEnabled, requiresVerify, smtpEnabled bool) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	settings.SelfRegistrationEnabled = selfRegEnabled
	settings.SelfRegistrationRequiresEmailVerification = requiresVerify
	settings.SMTPEnabled = smtpEnabled
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
}

// loadRegisterPage fetches the registration form and asserts it renders, which every test below
// did as a side effect of scraping the CSRF token out of it. The token left with gorilla/csrf
// (#155) and the page load stayed: a POST test whose form does not render is testing nothing, and
// this is the only assertion in this file that the GET binding works at all.
func loadRegisterPage(t *testing.T, client *http.Client) {
	destUrl := config.GetAuthServer().BaseURL + "/account/register"
	resp := loadPage(t, client, destUrl)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /account/register, got %d", resp.StatusCode)
	}
}

func postRegister(t *testing.T, client *http.Client, email, password, confirm string) *http.Response {
	destUrl := config.GetAuthServer().BaseURL + "/account/register"
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
	req.Header.Set("Origin", config.GetAuthServer().BaseURL)
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
// 1a. With self-registration disabled the page should not render.
func TestSelfRegister_GetPage_Disabled(t *testing.T) {
	defer saveAndRestoreRegSettings(t)()
	setRegSettings(t, false, false, true)

	httpClient := createHttpClient(t)
	resp := loadPage(t, httpClient, config.GetAuthServer().BaseURL+"/account/register")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// 1b. With self-registration enabled the page renders.
//
// It used to also assert the form carried a CSRF token. There is no token any more: the POST below
// is protected by the origin check in MiddlewareCsrf, which reads the browser's own Sec-Fetch-Site
// report and refuses anything it calls cross-site (#155). Nothing about that is visible in the
// rendered HTML, so the assertion has no successor here rather than a weaker one.
func TestSelfRegister_GetPage_Enabled(t *testing.T) {
	defer saveAndRestoreRegSettings(t)()
	setRegSettings(t, true, false, false)

	httpClient := createHttpClient(t)
	resp := loadPage(t, httpClient, config.GetAuthServer().BaseURL+"/account/register")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// Scenario 2: POST /account/register with SMTP off
// User is created (EmailVerified=false), the success template renders, and the
// admin-console profile link is present. Locks in the issue #69 fix at the HTTP
// layer (no /auth/pwd redirect).
func TestSelfRegister_Post_SMTPDisabled_RendersSuccessPage(t *testing.T) {
	defer saveAndRestoreRegSettings(t)()
	setRegSettings(t, true, false, false)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	email := gofakeit.Email()
	resp := postRegister(t, httpClient, email, "Password123!", "Password123!")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := bodyString(t, resp)
	assert.Contains(t, body, "Your account has been created.")
	assert.Contains(t, body, config.GetAdminConsole().BaseURL+"/account/profile")
	// Regression guard: the old broken behavior was a 302 to /auth/pwd.
	assert.NotEqual(t, http.StatusFound, resp.StatusCode)
	assert.NotContains(t, body, "/auth/pwd")

	user, err := database.GetUserByEmail(nil, email)
	assert.NoError(t, err)
	if assert.NotNil(t, user) {
		assert.False(t, user.EmailVerified)
	}

	preReg, err := database.GetPreRegistrationByEmail(nil, email)
	assert.NoError(t, err)
	assert.Nil(t, preReg)
}

// Scenario 4 (renumbered relative to plan; covered before scenario 3 in this
// file because it shares the SMTP-on path): POST with SMTP on but verification
// off. Welcome email is sent, success template renders, user is created
// directly (no pre-registration row).
func TestSelfRegister_Post_SMTPEnabled_NoVerification_RendersSuccess(t *testing.T) {
	defer saveAndRestoreRegSettings(t)()
	setRegSettings(t, true, false, true)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	email := gofakeit.Email()
	resp := postRegister(t, httpClient, email, "Password123!", "Password123!")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := bodyString(t, resp)
	assert.Contains(t, body, "Your account has been created.")
	assert.Contains(t, body, config.GetAdminConsole().BaseURL+"/account/profile")

	user, err := database.GetUserByEmail(nil, email)
	assert.NoError(t, err)
	if assert.NotNil(t, user) {
		assert.False(t, user.EmailVerified)
	}

	preReg, err := database.GetPreRegistrationByEmail(nil, email)
	assert.NoError(t, err)
	assert.Nil(t, preReg)
}

// registerPlusAddress returns a unique address containing a '+', which is the class #112
// reports as broken: the activation link used to carry the address, Go parses a query with
// form-urlencoded rules where '+' decodes to a space, so the pre-registration was never found
// and these users could not register at all.
func registerPlusAddress() string {
	return "register+tag." + strings.ToLower(gofakeit.LetterN(10)) + "@example.com"
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

	return config.GetAuthServer().BaseURL + location.Path
}

const activationSucceededText = "Congratulations! Your account has been activated."
const activationExpiredText = "Unable to activate the account. The verification code appears to be expired."

// Scenario 3: POST with SMTP on and verification required.
//
// Pre-registration row is created (no user yet); follow the link the handler actually emailed
// and verify the user is materialized with EmailVerified=true. The address contains a '+', so
// this is also the end-to-end guard for #112 itself: before the change this registration could
// never be completed.
func TestSelfRegister_Post_SMTPEnabled_RequiresVerification_FullFlow(t *testing.T) {
	defer saveAndRestoreRegSettings(t)()
	defer useMailpitSMTP(t)()
	setRegSettings(t, true, true, true)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	email := registerPlusAddress()
	resp := postRegister(t, httpClient, email, "Password123!", "Password123!")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	user, err := database.GetUserByEmail(nil, email)
	assert.NoError(t, err)
	assert.Nil(t, user, "user should not exist before activation")

	preReg, err := database.GetPreRegistrationByEmail(nil, email)
	assert.NoError(t, err)
	if !assert.NotNil(t, preReg, "pre-registration should exist after POST") {
		return
	}

	// The hash is what the link resolves to, and it must be the hash of the code that was
	// issued or the registration is unactivatable.
	verificationCode, err := encryption.DecryptData(preReg.VerificationCodeEncrypted)
	assert.NoError(t, err)
	assert.NotEmpty(t, verificationCode)
	expectedHash, err := hashutil.HashString(verificationCode)
	assert.NoError(t, err)
	assert.Equal(t, expectedHash, preReg.VerificationCodeHash)

	cleanURL := followActivationLink(t, httpClient, latestActivationLink(t, email))

	// The account is created from the clean URL, on the marker alone.
	activateResp := loadPage(t, httpClient, cleanURL)
	defer func() { _ = activateResp.Body.Close() }()

	assert.Equal(t, http.StatusOK, activateResp.StatusCode)
	activationBody := bodyString(t, activateResp)
	assert.Contains(t, activationBody, activationSucceededText)
	assert.Contains(t, activationBody, config.GetAdminConsole().BaseURL+"/account/profile")

	user, err = database.GetUserByEmail(nil, email)
	assert.NoError(t, err)
	if assert.NotNil(t, user, "the '+' address must complete registration end to end") {
		assert.True(t, user.EmailVerified)
	}

	preReg, err = database.GetPreRegistrationByEmail(nil, email)
	assert.NoError(t, err)
	assert.Nil(t, preReg, "pre-registration should be deleted after activation")
}

// The replay case only a real cookie jar can see. The marker lives in a client-side encrypted
// cookie, so the server clearing it replaces the browser's copy and cannot invalidate one an
// attacker kept. What refuses the copy is the code hash it names no longer resolving, because
// activating deleted the pre-registration.
func TestSelfRegister_ReplayedMarkerAfterActivationIsRefused(t *testing.T) {
	defer saveAndRestoreRegSettings(t)()
	defer useMailpitSMTP(t)()
	setRegSettings(t, true, true, true)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	email := registerPlusAddress()
	resp := postRegister(t, httpClient, email, "Password123!", "Password123!")
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	cleanURL := followActivationLink(t, httpClient, latestActivationLink(t, email))

	// Taken while the marker is still live and usable.
	captured := capturedSessionCookies(t, httpClient)

	activateResp := loadPage(t, httpClient, cleanURL)
	activationBody := bodyString(t, activateResp)
	_ = activateResp.Body.Close()
	require.Contains(t, activationBody, activationSucceededText)

	activated, err := database.GetUserByEmail(nil, email)
	require.NoError(t, err)
	require.NotNil(t, activated)

	replayResp := loadPage(t, clientCarrying(t, captured), cleanURL)
	replayBody := bodyString(t, replayResp)
	_ = replayResp.Body.Close()

	assert.Equal(t, http.StatusOK, replayResp.StatusCode)
	assert.Contains(t, replayBody, activationExpiredText,
		"a replayed marker must land on the register-again page")
	assert.NotContains(t, replayBody, activationSucceededText)

	after, err := database.GetUserByEmail(nil, email)
	require.NoError(t, err)
	require.NotNil(t, after)
	assert.Equal(t, activated.Id, after.Id,
		"a replayed marker must not create a second account")
}

// The activation half of the same defect (#112 decision 13). Two pending registrations and
// one cookie jar: the clean hop reads the marker alone, so before the first-writer-wins rule
// the redirect already in flight activated whichever link had been followed last, creating an
// account nobody in that browser had asked for and leaving the intended one pending.
func TestSelfRegister_ASecondLinkDoesNotRetargetTheRedirectInFlight(t *testing.T) {
	defer saveAndRestoreRegSettings(t)()
	defer useMailpitSMTP(t)()
	setRegSettings(t, true, true, true)

	browser := createHttpClient(t)
	loadRegisterPage(t, browser)

	firstEmail := registerPlusAddress()
	firstResp := postRegister(t, browser, firstEmail, "Password123!", "Password123!")
	_ = firstResp.Body.Close()
	require.Equal(t, http.StatusOK, firstResp.StatusCode)

	// A second registration, made from somewhere else entirely.
	elsewhere := createHttpClient(t)
	loadRegisterPage(t, elsewhere)

	secondEmail := registerPlusAddress()
	secondResp := postRegister(t, elsewhere, secondEmail, "Password123!", "Password123!")
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

	// The redirect in flight completes, and activates the registration that produced it.
	activateResp := loadPage(t, browser, cleanURL)
	activationBody := bodyString(t, activateResp)
	_ = activateResp.Body.Close()
	require.Contains(t, activationBody, activationSucceededText)

	first, err := database.GetUserByEmail(nil, firstEmail)
	require.NoError(t, err)
	assert.NotNil(t, first, "the registration whose link produced the redirect is the one activated")

	second, err := database.GetUserByEmail(nil, secondEmail)
	require.NoError(t, err)
	assert.Nil(t, second, "the second registration must not have been activated")

	stillPending, err := database.GetPreRegistrationByEmail(nil, secondEmail)
	require.NoError(t, err)
	assert.NotNil(t, stillPending, "the second registration must still be pending, so its own link still works")
}

// Scenario 5a: POST while self-registration is disabled returns the error
// page. We load the form while it is enabled, then disable.
func TestSelfRegister_Post_Disabled_ReturnsError(t *testing.T) {
	defer saveAndRestoreRegSettings(t)()
	setRegSettings(t, true, false, false)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	setRegSettings(t, false, false, false)

	resp := postRegister(t, httpClient, gofakeit.Email(), "Password123!", "Password123!")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// Scenario 5b: duplicate user email is rejected with a friendly message.
func TestSelfRegister_Post_DuplicateEmail(t *testing.T) {
	defer saveAndRestoreRegSettings(t)()
	setRegSettings(t, true, false, false)

	existing := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: "irrelevant",
	}
	err := database.CreateUser(nil, existing)
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
	defer saveAndRestoreRegSettings(t)()
	setRegSettings(t, true, true, true)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	email := gofakeit.Email()
	resp1 := postRegister(t, httpClient, email, "Password123!", "Password123!")
	_ = resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	preReg, err := database.GetPreRegistrationByEmail(nil, email)
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
	defer saveAndRestoreRegSettings(t)()
	setRegSettings(t, true, false, false)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	email := gofakeit.Email()
	resp := postRegister(t, httpClient, email, "Password123!", "Different456!")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := bodyString(t, resp)
	assert.Contains(t, body, "password confirmation does not match")

	user, err := database.GetUserByEmail(nil, email)
	assert.NoError(t, err)
	assert.Nil(t, user, "no user should be created on validation failure")
}
