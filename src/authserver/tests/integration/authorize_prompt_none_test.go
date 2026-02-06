package integrationtests

import (
	"database/sql"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Basic prompt=none Error Tests
// =============================================================================

func TestPromptNone_MaxAge0_ReturnsLoginRequired(t *testing.T) {
	httpClient, client, redirectUri, _ := createSessionWithAcrLevel1(t)

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	// max_age=0 means authentication must have JUST happened, which it hasn't
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=none" +
		"&max_age=0"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "login_required", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPromptNone_AcrStepUpNeeded_ReturnsInteractionRequired(t *testing.T) {
	// Create session at level1
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	// Enable OTP for user so level2_optional would require interaction
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
	requestCodeChallenge := gofakeit.LetterN(43)
	// Request level2_optional with existing level1 session - requires step-up
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=none" +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "interaction_required", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPromptNone_OtpEnrollmentNeeded_ReturnsInteractionRequired(t *testing.T) {
	// Create session at level1, user has NO OTP
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	// Ensure user does NOT have OTP enabled
	user.OTPEnabled = false
	user.OTPSecret = ""
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	// Request level2_mandatory - requires OTP enrollment (interaction)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=none" +
		"&acr_values=" + enums.AcrLevel2Mandatory.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "interaction_required", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPromptNone_UserDisabled_ReturnsAccessDenied(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	// Disable the user after session was created
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
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "access_denied", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPromptNone_ConsentRequired_ReturnsConsentRequired(t *testing.T) {
	// Create client that requires consent
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true, // Consent required
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

	// Create user and session
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

	// Create session first (normal flow, will ask for consent)
	httpClient := createHttpClient(t)
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

	// Should redirect to consent
	_ = assertRedirect(t, resp, "/auth/consent")

	// Now try prompt=none - should fail because no consent exists
	requestState2 := gofakeit.LetterN(8)
	requestCodeChallenge2 := gofakeit.LetterN(43)
	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge2 +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState2 +
		"&prompt=none"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp2.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp2)

	assert.Equal(t, "consent_required", errorCode)
	assert.Equal(t, requestState2, state)
}

// =============================================================================
// Phase 2: Extended prompt=none Tests
// =============================================================================

func TestPromptNone_MaxAgeSatisfied_Success(t *testing.T) {
	// Create session - it will be very recent
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)

	// max_age=600 (10 minutes) should be satisfied by a session created just now
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&prompt=none" +
		"&max_age=600"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to /auth/issue
	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Should have code, no error
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectURL.Query().Get("code")
	errorVal := redirectURL.Query().Get("error")

	assert.NotEmpty(t, codeVal, "code should be present")
	assert.Empty(t, errorVal, "error should not be present")

	// Verify code belongs to the user
	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, user.Id, code.User.Id)
}

func TestPromptNone_OtpOptionalNoOtp_ReturnsInteractionRequired(t *testing.T) {
	// Create session at level1, user has NO OTP
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	// Ensure user does NOT have OTP enabled
	user.OTPEnabled = false
	user.OTPSecret = ""
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)

	// Request level2_optional with session at level1 - this is an ACR step-up
	// Even though user has no OTP, prompt=none cannot silently step up ACR levels
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=none" +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	// ACR step-up always requires interaction, even if user has no OTP
	assert.Equal(t, "interaction_required", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPromptNone_OtpConfigChanged_ReturnsInteractionRequired(t *testing.T) {
	// Create session at level1
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

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

	// Set Level2AuthConfigHasChanged flag on the session
	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(userSessions))

	userSessions[0].Level2AuthConfigHasChanged = true
	err = database.UpdateUserSession(nil, &userSessions[0])
	if err != nil {
		t.Fatal(err)
	}

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	// Request level2_optional - should require interaction because OTP config changed
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=none" +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "interaction_required", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPromptNone_OtpConfigChangedLevel1Target_Success(t *testing.T) {
	// Create session at level1
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	// Set Level2AuthConfigHasChanged flag on the session
	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(userSessions))

	userSessions[0].Level2AuthConfigHasChanged = true
	err = database.UpdateUserSession(nil, &userSessions[0])
	if err != nil {
		t.Fatal(err)
	}

	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)

	// Request level1 - the OTP config changed flag should be irrelevant
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&prompt=none" +
		"&acr_values=" + enums.AcrLevel1.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to /auth/issue (success)
	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectURL.Query().Get("code")
	errorVal := redirectURL.Query().Get("error")

	assert.NotEmpty(t, codeVal, "code should be present")
	assert.Empty(t, errorVal, "error should not be present")

	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, user.Id, code.User.Id)
}

func TestPromptNone_ConsentExists_Success(t *testing.T) {
	// Use a client that does NOT require consent (ConsentRequired=false)
	// This tests that prompt=none works with a valid session when no consent is needed
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)

	// prompt=none with valid session and client that doesn't require consent
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to /auth/issue
	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectURL.Query().Get("code")
	errorVal := redirectURL.Query().Get("error")

	assert.NotEmpty(t, codeVal, "code should be present")
	assert.Empty(t, errorVal, "error should not be present")

	// Verify code belongs to correct user
	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, user.Id, code.User.Id)
}

func TestPromptNone_SessionBumped_Success(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	// Get original LastAccessed
	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(userSessions))
	originalLastAccessed := userSessions[0].LastAccessed

	// Wait a bit to ensure different timestamp
	time.Sleep(100 * time.Millisecond)

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
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to /auth/issue
	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Verify success
	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectURL.Query().Get("code")
	assert.NotEmpty(t, codeVal, "code should be present")

	// Check that session was bumped
	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(userSessions))

	assert.True(t, userSessions[0].LastAccessed.After(originalLastAccessed),
		"LastAccessed should be updated (was: %v, now: %v)",
		originalLastAccessed, userSessions[0].LastAccessed)
}

// =============================================================================
// Phase 3: Consent Scope Coverage Tests
// =============================================================================

func TestPromptNone_FullConsentCoverage(t *testing.T) {
	// Create client that requires consent
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

	// Create consent that covers MORE than what we'll request
	consent := &models.UserConsent{
		UserId:    user.Id,
		ClientId:  client.Id,
		Scope:     "openid profile email", // Covers openid profile
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	err = database.CreateUserConsent(nil, consent)
	if err != nil {
		t.Fatal(err)
	}

	// Create session
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

	// Complete auth flow
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

	// Client has ConsentRequired=true, so flow goes through /auth/consent
	// But since all scopes are already consented, consent handler redirects to /auth/issue
	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	_, _ = getCodeAndStateFromUrl(t, resp)

	// Now prompt=none should work since consent covers requested scopes
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
		"&prompt=none"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	// Should succeed
	redirectLocation = assertRedirect(t, resp2, "/auth/issue")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	location := resp2.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectURL.Query().Get("code")
	errorVal := redirectURL.Query().Get("error")

	assert.NotEmpty(t, codeVal, "code should be present")
	assert.Empty(t, errorVal, "error should not be present")
}

func TestPromptNone_PartialConsentCoverage(t *testing.T) {
	// Create client that requires consent
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

	// Create consent for only openid (partial coverage)
	consent := &models.UserConsent{
		UserId:    user.Id,
		ClientId:  client.Id,
		Scope:     "openid", // Only openid, not profile
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	err = database.CreateUserConsent(nil, consent)
	if err != nil {
		t.Fatal(err)
	}

	// Create session
	httpClient := createHttpClient(t)
	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") + // Requesting profile which isn't consented
		"&state=" + requestState +
		"&nonce=" + requestNonce

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Complete auth flow up to consent
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

	// Should redirect to consent (partial coverage requires re-consent)
	assertRedirect(t, resp, "/auth/consent")

	// Now prompt=none should fail with consent_required
	requestState2 := gofakeit.LetterN(8)
	requestCodeChallenge2 := gofakeit.LetterN(43)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge2 +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState2 +
		"&prompt=none"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp2.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp2)

	assert.Equal(t, "consent_required", errorCode)
	assert.Equal(t, requestState2, state)
}

func TestPromptNone_OfflineAccessNotInConsent(t *testing.T) {
	// Create client that requires consent
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

	// Create consent WITHOUT offline_access
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

	// Create session first (without requesting offline_access)
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

	// Complete auth flow
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

	// Client has ConsentRequired=true, so flow goes through /auth/consent
	// Since all scopes (openid profile) are consented and no offline_access, consent handler redirects to /auth/issue
	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	_, _ = getCodeAndStateFromUrl(t, resp)

	// Now request with offline_access - should fail since not consented
	requestState2 := gofakeit.LetterN(8)
	requestCodeChallenge2 := gofakeit.LetterN(43)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge2 +
		"&scope=" + url.QueryEscape("openid offline_access") +
		"&state=" + requestState2 +
		"&prompt=none"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp2.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp2)

	assert.Equal(t, "consent_required", errorCode)
	assert.Equal(t, requestState2, state)
}

func TestPromptNone_OfflineAccessInConsent(t *testing.T) {
	// Create client that requires consent
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

	// Create consent WITH offline_access
	consent := &models.UserConsent{
		UserId:    user.Id,
		ClientId:  client.Id,
		Scope:     "openid profile offline_access",
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	err = database.CreateUserConsent(nil, consent)
	if err != nil {
		t.Fatal(err)
	}

	// Create session
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

	// Complete auth flow
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

	// Client has ConsentRequired=true, so flow goes through /auth/consent
	// Since all scopes (openid profile) are consented and no offline_access in request, consent handler redirects to /auth/issue
	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	_, _ = getCodeAndStateFromUrl(t, resp)

	// Now request with offline_access - should succeed since consented
	requestState2 := gofakeit.LetterN(8)
	requestNonce2 := gofakeit.LetterN(8)
	requestCodeChallenge2 := gofakeit.LetterN(43)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge2 +
		"&scope=" + url.QueryEscape("openid offline_access") +
		"&state=" + requestState2 +
		"&nonce=" + requestNonce2 +
		"&prompt=none"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	// Should succeed
	redirectLocation = assertRedirect(t, resp2, "/auth/issue")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	location := resp2.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectURL.Query().Get("code")
	errorVal := redirectURL.Query().Get("error")

	assert.NotEmpty(t, codeVal, "code should be present")
	assert.Empty(t, errorVal, "error should not be present")
}

func TestPromptNone_RequestSubsetOfConsent(t *testing.T) {
	// Create client that requires consent
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

	// Create consent for more scopes than we'll request
	consent := &models.UserConsent{
		UserId:    user.Id,
		ClientId:  client.Id,
		Scope:     "openid profile email address phone",
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	err = database.CreateUserConsent(nil, consent)
	if err != nil {
		t.Fatal(err)
	}

	// Create session
	httpClient := createHttpClient(t)
	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid") +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Complete auth flow
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

	// Client has ConsentRequired=true, so flow goes through /auth/consent
	// Since request is for "openid" (subset of consented "openid profile email address phone"),
	// consent handler sees all requested scopes are consented and redirects to /auth/issue
	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	_, _ = getCodeAndStateFromUrl(t, resp)

	// Now request only openid with prompt=none - should succeed
	requestState2 := gofakeit.LetterN(8)
	requestNonce2 := gofakeit.LetterN(8)
	requestCodeChallenge2 := gofakeit.LetterN(43)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge2 +
		"&scope=" + url.QueryEscape("openid email") + // Subset of consented scopes
		"&state=" + requestState2 +
		"&nonce=" + requestNonce2 +
		"&prompt=none"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	// Should succeed
	redirectLocation = assertRedirect(t, resp2, "/auth/issue")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	location := resp2.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectURL.Query().Get("code")
	errorVal := redirectURL.Query().Get("error")

	assert.NotEmpty(t, codeVal, "code should be present")
	assert.Empty(t, errorVal, "error should not be present")
}

// =============================================================================
// Skipped Tests: Effective Scopes and Invalid Scope
// =============================================================================

// TestPromptNone_EffectiveScopesEmpty_ReturnsAccessDenied verifies that when a user
// requests only custom scopes they don't have permission for, prompt=none returns access_denied.
func TestPromptNone_EffectiveScopesEmpty_ReturnsAccessDenied(t *testing.T) {
	// Create a resource and permission
	resource := createResource(t)
	permission := createPermission(t, resource.Id)

	client, redirectUri := createTestClientAndRedirectURI(t)

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
	// Note: user does NOT have the permission assigned

	httpClient := createHttpClient(t)
	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)

	// First, create a session by logging in with openid scope
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
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

	_, _ = getCodeAndStateFromUrl(t, resp)

	// Now use prompt=none requesting ONLY the custom scope (no openid)
	// The user does NOT have the permission, so effective scope will be empty
	customScope := resource.ResourceIdentifier + ":" + permission.PermissionIdentifier
	requestState2 := gofakeit.LetterN(8)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape(customScope) +
		"&state=" + requestState2 +
		"&prompt=none"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	errorCode, _, state := getErrorFromUrl(t, resp2)
	assert.Equal(t, "access_denied", errorCode)
	assert.Equal(t, requestState2, state)
}

// TestPromptNone_InvalidScope verifies that an invalid scope format returns invalid_scope
// error via redirect (scope validation happens before prompt=none logic).
func TestPromptNone_InvalidScope(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)

	httpClient := createHttpClient(t)
	requestState := gofakeit.LetterN(8)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape("openid invalid:scope:format") +
		"&state=" + requestState +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	errorCode, _, state := getErrorFromUrl(t, resp)
	assert.Equal(t, "invalid_scope", errorCode)
	assert.Equal(t, requestState, state)
}
