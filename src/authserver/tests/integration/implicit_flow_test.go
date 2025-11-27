package integrationtests

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// Helper function to extract tokens from fragment response
func getTokensFromFragment(t *testing.T, resp *http.Response) map[string]string {
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	// Parse fragment parameters
	fragment := redirectLocation.Fragment
	values, err := url.ParseQuery(fragment)
	if err != nil {
		t.Fatal(err)
	}

	result := make(map[string]string)
	for key, vals := range values {
		if len(vals) > 0 {
			result[key] = vals[0]
		}
	}
	return result
}

// Helper function to get error from fragment
func getErrorFromFragment(t *testing.T, resp *http.Response) (errorCode string, errorDescription string, state string) {
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	fragment := redirectLocation.Fragment
	values, err := url.ParseQuery(fragment)
	if err != nil {
		t.Fatal(err)
	}

	return values.Get("error"), values.Get("error_description"), values.Get("state")
}

// createImplicitFlowClient creates a client configured for implicit flow
func createImplicitFlowClient(t *testing.T, implicitEnabled *bool) (*models.Client, *models.RedirectURI) {
	client := &models.Client{
		ClientIdentifier:         "implicit-test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: false, // Disable auth code to test implicit-only
		ImplicitGrantEnabled:     implicitEnabled,
		ConsentRequired:          false,
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

	return client, redirectUri
}

// createTestUser creates a user for testing
func createTestUserForImplicit(t *testing.T) (*models.User, string) {
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

	return user, password
}

// TestImplicitFlow_TokenResponseType tests the basic implicit flow with response_type=token
func TestImplicitFlow_TokenResponseType(t *testing.T) {
	// Enable implicit flow globally for this test
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	client, redirectUri := createImplicitFlowClient(t, nil)
	user, password := createTestUserForImplicit(t)

	requestState := gofakeit.LetterN(16)
	requestScope := "openid"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=token" +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Follow redirects through auth flow
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

	// Verify redirect to client with tokens in fragment
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.True(t, strings.HasPrefix(location, redirectUri.URI+"#"), "Should redirect to client with fragment")

	tokens := getTokensFromFragment(t, resp)

	// Verify access token is present
	assert.NotEmpty(t, tokens["access_token"], "access_token should be present")
	assert.Equal(t, "Bearer", tokens["token_type"], "token_type should be Bearer")
	assert.NotEmpty(t, tokens["expires_in"], "expires_in should be present")
	assert.Equal(t, requestState, tokens["state"], "state should match")

	// Verify NO id_token (we only requested token)
	assert.Empty(t, tokens["id_token"], "id_token should NOT be present for response_type=token")

	// Verify NO refresh token (implicit flow never issues refresh tokens)
	assert.Empty(t, tokens["refresh_token"], "refresh_token should NOT be present in implicit flow")
}

// TestImplicitFlow_IdTokenResponseType tests implicit flow with response_type=id_token
func TestImplicitFlow_IdTokenResponseType(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	client, redirectUri := createImplicitFlowClient(t, nil)
	user, password := createTestUserForImplicit(t)

	requestState := gofakeit.LetterN(16)
	requestNonce := gofakeit.LetterN(16) // Required for id_token
	requestScope := "openid"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=id_token" +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Follow auth flow
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

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.True(t, strings.HasPrefix(location, redirectUri.URI+"#"), "Should redirect to client with fragment")

	tokens := getTokensFromFragment(t, resp)

	// Verify id_token is present
	assert.NotEmpty(t, tokens["id_token"], "id_token should be present")
	assert.Equal(t, requestState, tokens["state"], "state should match")

	// Verify NO access_token (we only requested id_token)
	assert.Empty(t, tokens["access_token"], "access_token should NOT be present for response_type=id_token")

	// Parse and validate id_token
	idToken := tokens["id_token"]
	parts := strings.Split(idToken, ".")
	assert.Equal(t, 3, len(parts), "id_token should be a valid JWT with 3 parts")

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	assert.NoError(t, err)
	assert.Contains(t, string(payload), requestNonce, "id_token should contain the nonce")
	assert.Contains(t, string(payload), user.Subject.String(), "id_token should contain user subject")
}

// TestImplicitFlow_IdTokenTokenResponseType tests implicit flow with response_type=id_token token
func TestImplicitFlow_IdTokenTokenResponseType(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	client, redirectUri := createImplicitFlowClient(t, nil)
	user, password := createTestUserForImplicit(t)

	requestState := gofakeit.LetterN(16)
	requestNonce := gofakeit.LetterN(16)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=" + url.QueryEscape("id_token token") +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Follow auth flow
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

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.True(t, strings.HasPrefix(location, redirectUri.URI+"#"), "Should redirect to client with fragment")

	tokens := getTokensFromFragment(t, resp)

	// Verify both tokens are present
	assert.NotEmpty(t, tokens["access_token"], "access_token should be present")
	assert.NotEmpty(t, tokens["id_token"], "id_token should be present")
	assert.Equal(t, "Bearer", tokens["token_type"], "token_type should be Bearer")
	assert.NotEmpty(t, tokens["expires_in"], "expires_in should be present")
	assert.Equal(t, requestState, tokens["state"], "state should match")

	// Verify id_token contains at_hash claim (OIDC Core 3.2.2.10)
	idToken := tokens["id_token"]
	parts := strings.Split(idToken, ".")
	assert.Equal(t, 3, len(parts), "id_token should be a valid JWT")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	assert.NoError(t, err)
	assert.Contains(t, string(payload), "at_hash", "id_token should contain at_hash when access_token is also issued")
	assert.Contains(t, string(payload), requestNonce, "id_token should contain the nonce")
}

// TestImplicitFlow_Disabled_GlobalSetting tests that implicit flow is rejected when disabled globally
func TestImplicitFlow_Disabled_GlobalSetting(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = false
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	client, redirectUri := createImplicitFlowClient(t, nil) // nil means inherit from global

	requestState := gofakeit.LetterN(16)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=token" +
		"&scope=openid" +
		"&state=" + requestState

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect with error in fragment (implicit flow uses fragment for errors)
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, errorDescription, state := getErrorFromFragment(t, resp)
	assert.Equal(t, "unauthorized_client", errorCode)
	assert.Contains(t, errorDescription, "implicit")
	assert.Equal(t, requestState, state)
}

// TestImplicitFlow_ClientOverride_Enabled tests client-level implicit flow enable
func TestImplicitFlow_ClientOverride_Enabled(t *testing.T) {
	// Disable globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = false
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	// Create client with explicit enable
	implicitEnabled := true
	client, redirectUri := createImplicitFlowClient(t, &implicitEnabled)
	user, password := createTestUserForImplicit(t)

	requestState := gofakeit.LetterN(16)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=token" +
		"&scope=openid" +
		"&state=" + requestState

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should proceed with auth flow (client override enabled)
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

	// Should succeed with tokens
	tokens := getTokensFromFragment(t, resp)
	assert.NotEmpty(t, tokens["access_token"], "Should issue access token when client override enables implicit flow")
}

// TestImplicitFlow_ClientOverride_Disabled tests client-level implicit flow disable
func TestImplicitFlow_ClientOverride_Disabled(t *testing.T) {
	// Enable globally
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	// Create client with explicit disable
	implicitDisabled := false
	client, redirectUri := createImplicitFlowClient(t, &implicitDisabled)

	requestState := gofakeit.LetterN(16)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=token" +
		"&scope=openid" +
		"&state=" + requestState

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect with error
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, _ := getErrorFromFragment(t, resp)
	assert.Equal(t, "unauthorized_client", errorCode)
}

// TestImplicitFlow_MissingNonce_IdToken tests that nonce is required for id_token
func TestImplicitFlow_MissingNonce_IdToken(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	client, redirectUri := createImplicitFlowClient(t, nil)

	requestState := gofakeit.LetterN(16)

	// No nonce parameter
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=id_token" +
		"&scope=openid" +
		"&state=" + requestState

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, errorDescription, _ := getErrorFromFragment(t, resp)
	assert.Equal(t, "invalid_request", errorCode)
	assert.Contains(t, strings.ToLower(errorDescription), "nonce")
}

// TestImplicitFlow_MissingOpenIdScope_IdToken tests that openid scope is required for id_token
func TestImplicitFlow_MissingOpenIdScope_IdToken(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	client, redirectUri := createImplicitFlowClient(t, nil)

	requestState := gofakeit.LetterN(16)
	requestNonce := gofakeit.LetterN(16)

	// No openid scope
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=id_token" +
		"&scope=profile" +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, errorDescription, _ := getErrorFromFragment(t, resp)
	assert.Equal(t, "invalid_request", errorCode)
	assert.Contains(t, strings.ToLower(errorDescription), "openid")
}

// TestImplicitFlow_UnsupportedResponseType_HybridFlow tests that hybrid flows are rejected
func TestImplicitFlow_UnsupportedResponseType_HybridFlow(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	// Create a client with both auth code and implicit enabled
	client := &models.Client{
		ClientIdentifier:         "hybrid-test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ImplicitGrantEnabled:     nil,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	requestState := gofakeit.LetterN(16)

	// Try hybrid flow: code token
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=" + url.QueryEscape("code token") +
		"&scope=openid" +
		"&state=" + requestState

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should get unsupported_response_type error
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")

	// Hybrid flow uses query for errors (since it contains code)
	parsedUrl, err := url.Parse(location)
	assert.NoError(t, err)
	errorCode := parsedUrl.Query().Get("error")
	assert.Equal(t, "unsupported_response_type", errorCode)
}

// TestImplicitFlow_ValidateAccessToken tests that the access token can be used
func TestImplicitFlow_ValidateAccessToken(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	client, redirectUri := createImplicitFlowClient(t, nil)
	user, password := createTestUserForImplicit(t)

	requestState := gofakeit.LetterN(16)
	requestScope := "openid profile"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=token" +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState

	httpClient := createHttpClient(t)

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

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	tokens := getTokensFromFragment(t, resp)
	accessToken := tokens["access_token"]
	assert.NotEmpty(t, accessToken)

	// Parse access token JWT
	token, _, err := new(jwt.Parser).ParseUnverified(accessToken, jwt.MapClaims{})
	assert.NoError(t, err)

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)

	// Verify claims
	assert.Equal(t, user.Subject.String(), claims["sub"])
	// Note: aud in access token is the resource server ("authserver"), not the client
	assert.NotEmpty(t, claims["aud"])
	assert.NotEmpty(t, claims["iat"])
	assert.NotEmpty(t, claims["exp"])

	// Use access token to call userinfo endpoint
	userinfoUrl := config.GetAuthServer().BaseURL + "/userinfo"
	req, err := http.NewRequest("GET", userinfoUrl, nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	userinfoResp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = userinfoResp.Body.Close() }()

	assert.Equal(t, http.StatusOK, userinfoResp.StatusCode)
}

// TestImplicitFlow_ErrorInFragment tests that errors use fragment for implicit flow
func TestImplicitFlow_ErrorInFragment(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	client, redirectUri := createImplicitFlowClient(t, nil)

	requestState := gofakeit.LetterN(16)

	// Missing openid scope for id_token - should return error in fragment
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=id_token" +
		"&scope=profile" +
		"&state=" + requestState +
		"&nonce=test-nonce"

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")

	// Verify error is in fragment (not query)
	parsedUrl, err := url.Parse(location)
	assert.NoError(t, err)

	// Query should be empty for implicit flow errors
	assert.Empty(t, parsedUrl.Query().Get("error"), "error should NOT be in query for implicit flow")

	// Fragment should contain error
	assert.NotEmpty(t, parsedUrl.Fragment, "error should be in fragment for implicit flow")
	errorCode, _, _ := getErrorFromFragment(t, resp)
	assert.NotEmpty(t, errorCode, "error code should be present in fragment")
}

// TestImplicitFlow_WithResourcePermissions tests implicit flow with resource permissions requiring consent
func TestImplicitFlow_WithResourcePermissions(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	// Create client with consent required
	client := &models.Client{
		ClientIdentifier:         "implicit-consent-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: false,
		ImplicitGrantEnabled:     nil,
		ConsentRequired:          true, // Consent required
		DefaultAcrLevel:          enums.AcrLevel1,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	user, password := createTestUserForImplicit(t)

	// Create resource and permission to trigger consent
	resource := createResource(t)
	permission := createPermission(t, resource.Id)
	assignPermissionToUser(t, user.Id, permission.Id)

	requestState := gofakeit.LetterN(16)
	// Include resource permission in scope
	requestScope := "openid profile " + resource.ResourceIdentifier + ":" + permission.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=token" +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Auth flow
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

	// Should redirect to consent page (because resource permissions require consent)
	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Get consent page and submit consent for all scopes (openid, profile, resource:permission)
	csrf = getCsrfValue(t, resp)
	resp = postConsent(t, httpClient, redirectLocation, []int{0, 1, 2}, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Should get tokens
	tokens := getTokensFromFragment(t, resp)
	assert.NotEmpty(t, tokens["access_token"], "Should get access token after consent")
	// Implicit flow should NOT issue refresh tokens
	assert.Empty(t, tokens["refresh_token"], "Implicit flow should NOT issue refresh tokens")
}

// TestImplicitFlow_AtHashValidation tests that at_hash is correctly calculated per OIDC Core 3.2.2.10
func TestImplicitFlow_AtHashValidation(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	client, redirectUri := createImplicitFlowClient(t, nil)
	user, password := createTestUserForImplicit(t)

	requestState := gofakeit.LetterN(16)
	requestNonce := gofakeit.LetterN(16)
	requestScope := "openid"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=" + url.QueryEscape("id_token token") +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

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

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	tokens := getTokensFromFragment(t, resp)
	accessToken := tokens["access_token"]
	idToken := tokens["id_token"]

	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, idToken)

	// Parse id_token to extract at_hash
	idTokenParts := strings.Split(idToken, ".")
	assert.Equal(t, 3, len(idTokenParts))

	payload, err := base64.RawURLEncoding.DecodeString(idTokenParts[1])
	assert.NoError(t, err)

	// Verify at_hash is present
	assert.Contains(t, string(payload), "at_hash")

	// Parse id_token claims
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	assert.NoError(t, err)
	claims := token.Claims.(jwt.MapClaims)

	atHashFromToken := claims["at_hash"].(string)
	assert.NotEmpty(t, atHashFromToken)

	// Manually calculate expected at_hash per OIDC Core 3.2.2.10
	// at_hash = base64url(left_half(SHA256(access_token)))
	hash := sha256.Sum256([]byte(accessToken))
	leftHalf := hash[:len(hash)/2]
	expectedAtHash := base64.RawURLEncoding.EncodeToString(leftHalf)

	assert.Equal(t, expectedAtHash, atHashFromToken, "at_hash should match OIDC spec calculation")
}

// TestImplicitFlow_NoRefreshTokenInResponse tests that refresh tokens are NEVER issued in implicit flow
// Per RFC 6749 Section 4.2.2: The authorization server MUST NOT issue a refresh token for implicit grant
func TestImplicitFlow_NoRefreshTokenInResponse(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	client, redirectUri := createImplicitFlowClient(t, nil)
	user, password := createTestUserForImplicit(t)

	requestState := gofakeit.LetterN(16)
	requestNonce := gofakeit.LetterN(16)
	// Request multiple scopes to verify no refresh token is issued
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=" + url.QueryEscape("id_token token") +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

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

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	tokens := getTokensFromFragment(t, resp)

	// Verify tokens are issued
	assert.NotEmpty(t, tokens["access_token"], "access_token should be present")
	assert.NotEmpty(t, tokens["id_token"], "id_token should be present")

	// Verify NO refresh token - this is the key assertion per RFC 6749 4.2.2
	assert.Empty(t, tokens["refresh_token"], "refresh_token should NEVER be present in implicit flow per RFC 6749 4.2.2")
}

// TestImplicitFlow_StatePreservation tests that state is correctly preserved through the flow
func TestImplicitFlow_StatePreservation(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	testCases := []struct {
		name  string
		state string
	}{
		{"Simple state", "abc123"},
		{"State with dashes and underscores", "state-test_value"},
		{"State with unicode", "state_日本語"},
		{"Long state", strings.Repeat("a", 256)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, redirectUri := createImplicitFlowClient(t, nil)
			user, password := createTestUserForImplicit(t)

			destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
				"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
				"&response_type=token" +
				"&scope=openid" +
				"&state=" + url.QueryEscape(tc.state)

			httpClient := createHttpClient(t)

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

			redirectLocation = assertRedirect(t, resp, "/auth/issue")
			resp = loadPage(t, httpClient, redirectLocation)
			defer func() { _ = resp.Body.Close() }()

			tokens := getTokensFromFragment(t, resp)
			assert.Equal(t, tc.state, tokens["state"], "state should be preserved exactly")
		})
	}
}

// TestImplicitFlow_EmptyState tests behavior when no state is provided
func TestImplicitFlow_EmptyState(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	client, redirectUri := createImplicitFlowClient(t, nil)
	user, password := createTestUserForImplicit(t)

	// No state parameter
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=token" +
		"&scope=openid"

	httpClient := createHttpClient(t)

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

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Should succeed without state
	tokens := getTokensFromFragment(t, resp)
	assert.NotEmpty(t, tokens["access_token"])
	// State should be empty or not present
	assert.Empty(t, tokens["state"])
}

// TestImplicitFlow_NonceInIdToken tests that nonce is correctly included in id_token
func TestImplicitFlow_NonceInIdToken(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	client, redirectUri := createImplicitFlowClient(t, nil)
	user, password := createTestUserForImplicit(t)

	requestNonce := "unique-nonce-" + gofakeit.LetterN(16)
	requestState := gofakeit.LetterN(16)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=id_token" +
		"&scope=openid" +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

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

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	tokens := getTokensFromFragment(t, resp)
	idToken := tokens["id_token"]
	assert.NotEmpty(t, idToken)

	// Parse id_token and verify nonce
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	assert.NoError(t, err)
	claims := token.Claims.(jwt.MapClaims)

	nonceFromToken := claims["nonce"].(string)
	assert.Equal(t, requestNonce, nonceFromToken, "nonce in id_token should match request nonce")
}

// TestImplicitFlow_AudienceInTokens tests that audience claims are correct in tokens
func TestImplicitFlow_AudienceInTokens(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	client, redirectUri := createImplicitFlowClient(t, nil)
	user, password := createTestUserForImplicit(t)

	requestNonce := gofakeit.LetterN(16)
	requestState := gofakeit.LetterN(16)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=" + url.QueryEscape("id_token token") +
		"&scope=openid" +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

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

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	tokens := getTokensFromFragment(t, resp)

	// Parse access_token
	accessToken, _, err := new(jwt.Parser).ParseUnverified(tokens["access_token"], jwt.MapClaims{})
	assert.NoError(t, err)
	accessTokenClaims := accessToken.Claims.(jwt.MapClaims)

	// Access token audience should be the resource server (authserver for OIDC scopes)
	accessTokenAud := accessTokenClaims["aud"]
	assert.NotNil(t, accessTokenAud, "access_token should have aud claim")

	// Parse id_token
	idToken, _, err := new(jwt.Parser).ParseUnverified(tokens["id_token"], jwt.MapClaims{})
	assert.NoError(t, err)
	idTokenClaims := idToken.Claims.(jwt.MapClaims)

	// ID token audience should be the client identifier
	idTokenAud := idTokenClaims["aud"].(string)
	assert.Equal(t, client.ClientIdentifier, idTokenAud, "id_token audience should be client identifier")
}

// TestImplicitFlow_AuthCodeFlowClient_CanAlsoUseImplicit tests that a client with auth code enabled can also use implicit if enabled
func TestImplicitFlow_AuthCodeFlowClient_CanAlsoUseImplicit(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}()

	// Create client with BOTH auth code AND implicit enabled
	client := &models.Client{
		ClientIdentifier:         "both-flows-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true, // Auth code enabled
		ImplicitGrantEnabled:     nil,  // Inherit from global (enabled)
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	user, password := createTestUserForImplicit(t)

	requestState := gofakeit.LetterN(16)

	// Use implicit flow with this client
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=token" +
		"&scope=openid" +
		"&state=" + requestState

	httpClient := createHttpClient(t)

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

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Should succeed with tokens
	tokens := getTokensFromFragment(t, resp)
	assert.NotEmpty(t, tokens["access_token"], "Client with both flows enabled should be able to use implicit flow")
}
