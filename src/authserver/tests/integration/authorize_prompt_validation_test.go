package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Core OIDC Conformance Tests
// =============================================================================

func TestPromptNone_NoSession_ReturnsLoginRequired(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)

	// Create fresh HTTP client (no session)
	httpClient := createHttpClient(t)

	requestState := fake.LetterN(8)
	requestCodeChallenge := fake.LetterN(43)
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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
	userSessions, err := database.GetUserSessionsByUserId(context.Background(), nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, userSessions, 1)
	originalSession := userSessions[0]
	originalAuthTime := originalSession.AuthTime

	// Wait a bit to ensure different timestamps if auth_time was recalculated
	time.Sleep(100 * time.Millisecond)

	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestCodeChallenge := fake.LetterN(43)
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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
	userSessions, err := database.GetUserSessionsByUserId(context.Background(), nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, userSessions, 1)
	originalSessionAuthTime := userSessions[0].AuthTime

	// Wait to ensure new auth_time will be different
	time.Sleep(200 * time.Millisecond)

	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestCodeChallenge := fake.LetterN(43)
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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

	// Re-authenticate
	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
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
	httpClient := createAuthenticatedHttpClient(t)

	requestState := fake.LetterN(8)
	requestCodeChallenge := fake.LetterN(43)
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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

	requestState := fake.LetterN(8)
	requestCodeChallenge := fake.LetterN(43)
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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

	requestState := fake.LetterN(8)
	requestCodeChallenge := fake.LetterN(43)
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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

	requestState := fake.LetterN(8)
	requestCodeChallenge := fake.LetterN(43)
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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
	httpClient := createAuthenticatedHttpClient(t)

	requestState := fake.LetterN(8)
	requestCodeChallenge := fake.LetterN(43)
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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
	httpClient := createAuthenticatedHttpClient(t)

	requestState := fake.LetterN(8)
	requestCodeChallenge := fake.LetterN(43)
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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

// select_account is a value OIDC Core defines and this server cannot honour, so it is answered
// account_selection_required and not as an unknown value (#244, decision 20).
func TestPrompt_SelectAccountIsKnownButNotSupported(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	httpClient := createAuthenticatedHttpClient(t)

	requestState := fake.LetterN(8)
	requestCodeChallenge := fake.LetterN(43)
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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

	errorCode, description, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "account_selection_required", errorCode)
	assert.Equal(t, "prompt=select_account is not supported: the authorization server cannot ask the end user to select an account.", description)
	assert.Equal(t, requestState, state)
}

func TestPrompt_EmptyParameter(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	httpClient := createHttpClient(t)

	requestState := fake.LetterN(8)
	requestCodeChallenge := fake.LetterN(43)
	// Empty prompt parameter should be treated as absent (normal flow)
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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

// A prompt of spaces alone used to be trimmed and read as absent. Since #244 it is malformed (OIDC
// Core 1.0 3.1.2.1 makes prompt space delimited, and spaces alone are no values separated by single
// spaces), so it is refused invalid_request. A browser with a valid session is answered at once
// (#213), which puts the refusal on the redirect itself; an empty prompt is the control, and reaches
// the client as an issued code's route.
func TestPrompt_WhitespaceOnlyParameter(t *testing.T) {
	httpClient, client, redirectUri, _, _ := createSessionWithAcrLevel1AndPassword(t)

	request := func(prompt string) *http.Response {
		t.Helper()
		destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
			"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
			"&response_type=code" +
			"&code_challenge_method=S256" +
			"&code_challenge=" + fake.LetterN(43) +
			"&scope=" + url.QueryEscape("openid profile") +
			"&state=" + fake.LetterN(8) +
			"&prompt=" + prompt
		resp, err := httpClient.Get(destUrl)
		require.NoError(t, err)
		return resp
	}

	t.Run("spaces alone are malformed", func(t *testing.T) {
		resp := request("%20%20%20")
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusFound, resp.StatusCode)
		location, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, redirectUri.URI, location.Scheme+"://"+location.Host+location.Path)
		assert.Equal(t, "invalid_request", location.Query().Get("error"))
		assert.Equal(t, "The 'prompt' parameter is malformed. Separate its values with a single space, with no space before the first value or after the last.",
			location.Query().Get("error_description"))
	})

	t.Run("an empty prompt is absent", func(t *testing.T) {
		resp := request("")
		defer func() { _ = resp.Body.Close() }()

		assertRedirect(t, resp, "/auth/level1completed")
	})
}

func TestPrompt_UrlEncodedSpaces(t *testing.T) {
	// With a valid session, "login consent" should work
	httpClient, client, redirectUri, _, _ := createSessionWithAcrLevel1AndPassword(t)

	requestState := fake.LetterN(8)
	requestCodeChallenge := fake.LetterN(43)
	// URL encoded "login consent" - this is valid and should trigger re-auth flow
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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
