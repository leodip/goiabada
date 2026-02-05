package integrationtests

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Core OIDC Conformance Tests
// =============================================================================

func TestPromptNone_NoSession_ReturnsLoginRequired(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)

	// Create fresh HTTP client (no session)
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
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to client with error
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, errorDescription, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "login_required", errorCode)
	assert.Equal(t, requestState, state)
	assert.NotEmpty(t, errorDescription)
}

func TestPromptNone_ValidSession_SilentCodeIssuance(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	// Get the session to check auth_time later
	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(userSessions))
	originalSession := userSessions[0]
	originalAuthTime := originalSession.AuthTime

	// Wait a bit to ensure different timestamps if auth_time was recalculated
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

	// prompt=none redirects to /auth/issue, then to client with code
	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Now we should have the final redirect to the client with the code
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	// Should have code and state, no error
	codeVal := redirectURL.Query().Get("code")
	stateVal := redirectURL.Query().Get("state")
	errorVal := redirectURL.Query().Get("error")

	assert.NotEmpty(t, codeVal, "code should be present")
	assert.Equal(t, requestState, stateVal, "state should match")
	assert.Empty(t, errorVal, "error should not be present")

	// Load the code and verify auth_time is preserved from session
	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)

	// Auth time should match the original session's auth time (preserved, not new)
	assert.Equal(t, originalAuthTime.Unix(), code.AuthenticatedAt.Unix(), "auth_time should be preserved from session")
}

func TestPromptLogin_WithSession_ForcesReAuth(t *testing.T) {
	httpClient, client, redirectUri, user, password := createSessionWithAcrLevel1AndPassword(t)

	// Get original session
	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(userSessions))
	originalSessionAuthTime := userSessions[0].AuthTime

	// Wait to ensure new auth_time will be different
	time.Sleep(200 * time.Millisecond)

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

	// Should redirect to level1 (forcing re-auth, not using existing session)
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	// Re-authenticate
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

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	// Verify code has NEW auth_time (not the original session's)
	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, user.Id, code.User.Id)

	// Auth time should be NEWER than the original session (re-authenticated)
	assert.True(t, code.AuthenticatedAt.After(originalSessionAuthTime),
		"auth_time should be newer than original session (was: %v, got: %v)",
		originalSessionAuthTime, code.AuthenticatedAt)
}

// =============================================================================
// Validation Tests
// =============================================================================

func TestPrompt_InvalidValue(t *testing.T) {
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
		"&prompt=foo"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, errorDescription, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, requestState, state)
	assert.Contains(t, strings.ToLower(errorDescription), "invalid prompt value")
}

func TestPrompt_ConflictNoneLogin(t *testing.T) {
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
		"&prompt=none%20login" // URL encoded space

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	// Should be invalid_request (validation error), NOT login_required
	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPrompt_ConflictNoneConsent(t *testing.T) {
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
		"&prompt=none%20consent"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	// Should be invalid_request (validation error), NOT consent_required
	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPrompt_ConflictNoneLoginConsent(t *testing.T) {
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
		"&prompt=none%20login%20consent"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPrompt_CaseSensitivityUppercase(t *testing.T) {
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
		"&prompt=LOGIN"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPrompt_CaseSensitivityMixed(t *testing.T) {
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
		"&prompt=Login"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPrompt_SelectAccountNotImplemented(t *testing.T) {
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
		"&prompt=select_account"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPrompt_EmptyParameter(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	httpClient := createHttpClient(t)

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	// Empty prompt parameter should be treated as absent (normal flow)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt="

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to normal auth flow (level1), not return an error
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	assert.NotEmpty(t, redirectLocation)
}

func TestPrompt_WhitespaceOnlyParameter(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	httpClient := createHttpClient(t)

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	// Whitespace-only prompt parameter should be treated as absent
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=%20%20%20" // URL encoded spaces

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to normal auth flow (level1), not return an error
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	assert.NotEmpty(t, redirectLocation)
}

func TestPrompt_UrlEncodedSpaces(t *testing.T) {
	// With a valid session, "login consent" should work
	httpClient, client, redirectUri, _, _ := createSessionWithAcrLevel1AndPassword(t)

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	// URL encoded "login consent" - this is valid and should trigger re-auth flow
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=login%20consent"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to auth flow (login forces re-auth), not return an error
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	assert.NotEmpty(t, redirectLocation)
}
