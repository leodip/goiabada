package integrationtests

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
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

// Scenario 3: POST with SMTP on and verification required.
// Pre-registration row is created (no user yet); follow the activation link
// and verify the user is materialized with EmailVerified=true.
func TestSelfRegister_Post_SMTPEnabled_RequiresVerification_FullFlow(t *testing.T) {
	defer saveAndRestoreRegSettings(t)()
	setRegSettings(t, true, true, true)

	httpClient := createHttpClient(t)
	loadRegisterPage(t, httpClient)

	email := gofakeit.Email()
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

	verificationCode, err := encryption.DecryptData(preReg.VerificationCodeEncrypted)
	assert.NoError(t, err)
	assert.NotEmpty(t, verificationCode)

	activateUrl := config.GetAuthServer().BaseURL + "/account/activate?email=" + url.QueryEscape(email) + "&code=" + url.QueryEscape(verificationCode)
	activateResp := loadPage(t, httpClient, activateUrl)
	defer func() { _ = activateResp.Body.Close() }()

	assert.Equal(t, http.StatusOK, activateResp.StatusCode)
	activationBody := bodyString(t, activateResp)
	assert.Contains(t, activationBody, "Congratulations! Your account has been activated.")
	assert.Contains(t, activationBody, config.GetAdminConsole().BaseURL+"/account/profile")

	user, err = database.GetUserByEmail(nil, email)
	assert.NoError(t, err)
	if assert.NotNil(t, user) {
		assert.True(t, user.EmailVerified)
	}

	preReg, err = database.GetPreRegistrationByEmail(nil, email)
	assert.NoError(t, err)
	assert.Nil(t, preReg, "pre-registration should be deleted after activation")
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
