package integrationtests

import (
	"database/sql"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Phase 2: prompt=consent Tests
// =============================================================================

func TestPromptConsent_ForcesConsentEvenWhenAlreadyConsented(t *testing.T) {
	// Create client that does NOT require consent normally
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false, // Consent NOT normally required
		DefaultAcrLevel:          enums.AcrLevel1,
	}
	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	// Create user
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	// Create consent for all scopes
	consent := &models.UserConsent{
		UserId:    user.Id,
		ClientId:  client.Id,
		Scope:     "openid profile",
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	err = database.CreateUserConsent(nil, consent)
	if err != nil {
		t.Fatal(err)
	}

	// Create session first
	httpClient := createHttpClient(t)
	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Go through auth flow
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Should skip consent (not required and already exists) and go to issue
	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	_, _ = getCodeAndStateFromUrl(t, resp)

	// Now request with prompt=consent - should force consent screen
	requestState2 := gofakeit.LetterN(8)
	requestNonce2 := gofakeit.LetterN(8)
	requestCodeChallenge2 := gofakeit.LetterN(43)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge2 +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState2 +
		"&nonce=" + requestNonce2 +
		"&prompt=consent"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	// Should use existing session (SSO flow goes through level1completed first)
	redirectLocation = assertRedirect(t, resp2, "/auth/level1completed")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/completed")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	// Should redirect to consent (forced by prompt=consent)
	assertRedirect(t, resp2, "/auth/consent")
}

func TestPromptConsent_NoSession_RequiresLoginFirst(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	httpClient := createHttpClient(t)

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=consent"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Without session, should redirect to login first
	assertRedirect(t, resp, "/auth/level1")
}

func TestPromptLoginConsent_Combined(t *testing.T) {
	// Create session
	httpClient, client, redirectUri, user, password := createSessionWithAcrLevel1AndPassword(t)

	// Create consent for all scopes
	consent := &models.UserConsent{
		UserId:    user.Id,
		ClientId:  client.Id,
		Scope:     "openid profile email",
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	err := database.CreateUserConsent(nil, consent)
	if err != nil {
		t.Fatal(err)
	}

	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)

	// Use both prompt=login and prompt=consent
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&prompt=login%20consent"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to level1 (login required by prompt=login)
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// After auth, should redirect to consent (forced by prompt=consent)
	assertRedirect(t, resp, "/auth/consent")
}

// =============================================================================
// Phase 2: Extended prompt=login Tests
// =============================================================================

func TestPromptLogin_NoSession(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	httpClient := createHttpClient(t)

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=login"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to login (normal flow, no session to skip)
	assertRedirect(t, resp, "/auth/level1")
}

func TestPromptLogin_MaxAgeIrrelevant(t *testing.T) {
	// Create very recent session
	httpClient, client, redirectUri, _, _ := createSessionWithAcrLevel1AndPassword(t)

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	// Even with max_age=600 (which would normally allow SSO), prompt=login forces re-auth
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=login" +
		"&max_age=600"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to login (forced by prompt=login despite max_age being satisfied)
	assertRedirect(t, resp, "/auth/level1")
}

func TestPromptLogin_PreservesAcrLevel(t *testing.T) {
	httpClient, client, redirectUri, user, password := createSessionWithAcrLevel1AndPassword(t)

	// Enable OTP for user
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: user.Email,
	})
	if err != nil {
		t.Fatal(err)
	}
	user.OTPEnabled = true
	user.OTPSecret = key.Secret()
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)

	// Request level2_optional with prompt=login
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&prompt=login" +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to level1 (re-auth)
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to level2 (because acr_values requested level2_optional and user has OTP)
	assertRedirect(t, resp, "/auth/level2")
}

func TestPromptLogin_PreservesNonce(t *testing.T) {
	httpClient, client, redirectUri, user, password := createSessionWithAcrLevel1AndPassword(t)

	requestState := gofakeit.LetterN(8)
	requestNonce := "test-nonce-" + gofakeit.LetterN(16)
	requestCodeChallenge := gofakeit.LetterN(43)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&prompt=login"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Complete the re-auth flow
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, _ := getCodeAndStateFromUrl(t, resp)

	// Verify the code has the nonce preserved
	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, requestNonce, code.Nonce)
}

// =============================================================================
// Phase 4: User Interaction Tests
// =============================================================================

func TestPromptConsent_UserDeclines(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel1,
	}
	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := createHttpClient(t)
	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&prompt=consent"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Go through auth flow to consent page
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Get CSRF from consent page
	csrf = getCsrfValue(t, resp)

	// Submit consent form with decline (btn=cancel)
	consentEndpoint := config.GetAuthServer().BaseURL + "/auth/consent"
	form := url.Values{
		"gorilla.csrf.Token": {csrf},
		"btn":                {"cancel"},
	}

	formDataString := form.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", consentEndpoint, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", consentEndpoint)
	request.Header.Set("Origin", config.GetAuthServer().BaseURL)

	resp, err = httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to client with access_denied error
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "access_denied", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPromptLogin_WrongPassword(t *testing.T) {
	httpClient, client, redirectUri, user, _ := createSessionWithAcrLevel1AndPassword(t)

	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&prompt=login"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to level1 (forced re-auth)
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	// Submit wrong password
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, "wrongpassword123", csrf)
	defer func() { _ = resp.Body.Close() }()

	// Should stay on password page with error (HTTP 200, not redirect)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body := readResponseBody(t, resp)
	assert.Contains(t, body, "Authentication failed", "should show authentication error")
}

// =============================================================================
// prompt=login: User Disabled and New Auth Time
// =============================================================================

// TestPromptLogin_UserDisabled verifies that when prompt=login forces re-authentication,
// a disabled user sees an error on the password form.
func TestPromptLogin_UserDisabled(t *testing.T) {
	httpClient, client, redirectUri, user, password := createSessionWithAcrLevel1AndPassword(t)

	// Disable the user
	user.Enabled = false
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + gofakeit.LetterN(8) +
		"&prompt=login"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to level1 (forcing re-auth)
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	// Submit correct password for disabled user
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	// Should stay on password page with disabled error (HTTP 200, not redirect)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body := readResponseBody(t, resp)
	assert.Contains(t, body, "disabled", "should show user disabled error")
}

// TestPromptLogin_NewAuthTime verifies that prompt=login re-authentication
// creates a new auth_time in the issued token (not preserving the old one).
func TestPromptLogin_NewAuthTime(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	client := &models.Client{
		ClientIdentifier:                        "test-client-" + gofakeit.LetterN(8),
		ClientSecretEncrypted:                   clientSecretEncrypted,
		Enabled:                                 true,
		AuthorizationCodeEnabled:                true,
		ConsentRequired:                         false,
		DefaultAcrLevel:                         enums.AcrLevel1,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}
	err = database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := createHttpClient(t)
	codeVerifier := "code-verifier"
	codeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)
	requestState := gofakeit.LetterN(8)

	// Login at T1 to establish session
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + gofakeit.LetterN(8)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal1, _ := getCodeAndStateFromUrl(t, resp)

	// Exchange first code for tokens to get T1 auth_time
	tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token"
	form1 := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeVal1},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {codeVerifier},
	}

	data1 := postToTokenEndpoint(t, httpClient, tokenEndpoint, form1)
	idToken1, ok := data1["id_token"].(string)
	assert.True(t, ok)
	claims1 := decodeJWTPayload(t, idToken1)
	authTime1 := claims1["auth_time"].(float64)

	// Wait to ensure different auth_time
	time.Sleep(1100 * time.Millisecond)

	// Re-authenticate with prompt=login at T2
	codeVerifier2 := "code-verifier-two"
	codeChallenge2 := oauth.GeneratePKCECodeChallenge(codeVerifier2)
	requestState2 := gofakeit.LetterN(8)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge2 +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState2 +
		"&nonce=" + gofakeit.LetterN(8) +
		"&prompt=login"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/level1")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/pwd")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	csrf = getCsrfValue(t, resp2)
	resp2 = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/level1completed")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/completed")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/issue")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	codeVal2, _ := getCodeAndStateFromUrl(t, resp2)

	// Exchange second code for tokens to get T2 auth_time
	form2 := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeVal2},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {codeVerifier2},
	}

	data2 := postToTokenEndpoint(t, httpClient, tokenEndpoint, form2)
	idToken2, ok := data2["id_token"].(string)
	assert.True(t, ok)
	claims2 := decodeJWTPayload(t, idToken2)
	authTime2 := claims2["auth_time"].(float64)

	// auth_time from prompt=login should be NEWER than original
	assert.Greater(t, authTime2, authTime1,
		"prompt=login should create new auth_time (T1=%v, T2=%v)", authTime1, authTime2)
}
