package integrationtests

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Phase 5: Implicit Flow + prompt=none Tests
// =============================================================================

// enableImplicitFlowGlobally enables implicit flow at the settings level and
// returns a cleanup function to restore the original setting.
func enableImplicitFlowGlobally(t *testing.T) func() {
	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	originalImplicitFlow := settings.ImplicitFlowEnabled
	settings.ImplicitFlowEnabled = true
	err = database.UpdateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	return func() {
		settings.ImplicitFlowEnabled = originalImplicitFlow
		_ = database.UpdateSettings(nil, settings)
	}
}

// createImplicitClientForPromptTests creates a client that supports both auth code
// (for establishing sessions) and implicit flow (for prompt=none implicit tests).
func createImplicitClientForPromptTests(t *testing.T) (*models.Client, *models.RedirectURI) {
	client := &models.Client{
		ClientIdentifier:         "implicit-prompt-test-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true, // Needed for establishing session
		ImplicitGrantEnabled:     nil,  // Inherit from global (enabled)
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

func TestPromptNone_ImplicitResponseTypeToken(t *testing.T) {
	cleanup := enableImplicitFlowGlobally(t)
	defer cleanup()

	// Establish session via auth code flow
	httpClient, _, _, _ := createSessionWithAcrLevel1(t)

	// Create a client that supports implicit flow
	client, redirectUri := createImplicitClientForPromptTests(t)

	requestState := gofakeit.LetterN(8)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=token" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should redirect to /auth/issue (SSO - session exists)
	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// Implicit flow returns tokens in fragment
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.True(t, strings.HasPrefix(location, redirectUri.URI+"#"), "Should redirect with fragment")

	tokens := getTokensFromFragment(t, resp)

	assert.NotEmpty(t, tokens["access_token"], "access_token should be present")
	assert.Equal(t, "Bearer", tokens["token_type"], "token_type should be Bearer")
	assert.NotEmpty(t, tokens["expires_in"], "expires_in should be present")
	assert.Equal(t, requestState, tokens["state"], "state should match")

	// response_type=token should NOT issue id_token
	assert.Empty(t, tokens["id_token"], "id_token should NOT be present for response_type=token")
	// Implicit flow NEVER issues refresh tokens
	assert.Empty(t, tokens["refresh_token"], "refresh_token should NOT be present in implicit flow")
}

func TestPromptNone_ImplicitResponseTypeIdToken(t *testing.T) {
	cleanup := enableImplicitFlowGlobally(t)
	defer cleanup()

	httpClient, _, _, _ := createSessionWithAcrLevel1(t)

	client, redirectUri := createImplicitClientForPromptTests(t)

	requestState := gofakeit.LetterN(8)
	requestNonce := "test-nonce-" + gofakeit.LetterN(16)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=id_token" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.True(t, strings.HasPrefix(location, redirectUri.URI+"#"), "Should redirect with fragment")

	tokens := getTokensFromFragment(t, resp)

	assert.NotEmpty(t, tokens["id_token"], "id_token should be present")
	assert.Equal(t, requestState, tokens["state"], "state should match")

	// response_type=id_token should NOT issue access_token
	assert.Empty(t, tokens["access_token"], "access_token should NOT be present for response_type=id_token")

	// Verify nonce is in the id_token
	idClaims := decodeJWTPayload(t, tokens["id_token"])
	assert.Equal(t, requestNonce, idClaims["nonce"], "nonce should be preserved in id_token")
}

func TestPromptNone_ImplicitResponseTypeIdTokenToken(t *testing.T) {
	cleanup := enableImplicitFlowGlobally(t)
	defer cleanup()

	httpClient, _, _, _ := createSessionWithAcrLevel1(t)

	client, redirectUri := createImplicitClientForPromptTests(t)

	requestState := gofakeit.LetterN(8)
	requestNonce := "test-nonce-" + gofakeit.LetterN(16)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=" + url.QueryEscape("id_token token") +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.True(t, strings.HasPrefix(location, redirectUri.URI+"#"), "Should redirect with fragment")

	tokens := getTokensFromFragment(t, resp)

	// Both tokens should be present
	assert.NotEmpty(t, tokens["access_token"], "access_token should be present")
	assert.NotEmpty(t, tokens["id_token"], "id_token should be present")
	assert.Equal(t, "Bearer", tokens["token_type"], "token_type should be Bearer")
	assert.NotEmpty(t, tokens["expires_in"], "expires_in should be present")
	assert.Equal(t, requestState, tokens["state"], "state should match")

	// Verify nonce and at_hash in id_token
	idClaims := decodeJWTPayload(t, tokens["id_token"])
	assert.Equal(t, requestNonce, idClaims["nonce"], "nonce should be preserved in id_token")
	assert.NotEmpty(t, idClaims["at_hash"], "at_hash should be present when access_token is also issued")
}

func TestPromptNone_ImplicitAuthTimeCorrect(t *testing.T) {
	cleanup := enableImplicitFlowGlobally(t)
	defer cleanup()

	// Establish session at T1
	httpClient, _, _, _ := createSessionWithAcrLevel1(t)

	client, redirectUri := createImplicitClientForPromptTests(t)

	// Wait to ensure different timestamps
	time.Sleep(1100 * time.Millisecond)

	// Use prompt=none at T2 with implicit flow
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=" + url.QueryEscape("id_token token") +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	tokens := getTokensFromFragment(t, resp)
	assert.NotEmpty(t, tokens["id_token"], "id_token should be present")

	// Verify auth_time in id_token
	idClaims := decodeJWTPayload(t, tokens["id_token"])
	authTime, ok := idClaims["auth_time"].(float64)
	assert.True(t, ok, "auth_time should be present in id_token")

	// auth_time should be from the ORIGINAL login (T1), not the prompt=none request (T2)
	// Since we waited 1.1 seconds, if auth_time were set to "now" it would be > T1
	// The auth_time should be <= now - 1 second (approximately T1)
	now := float64(time.Now().Unix())
	assert.True(t, authTime < now, "auth_time should be from original login, not current time")
	assert.True(t, authTime <= now-1, "auth_time should be at least 1 second in the past (from original login)")
}

func TestPromptNone_ImplicitMissingNonce(t *testing.T) {
	cleanup := enableImplicitFlowGlobally(t)
	defer cleanup()

	// Establish session (needed so prompt=none doesn't fail with login_required first)
	httpClient, _, _, _ := createSessionWithAcrLevel1(t)

	client, redirectUri := createImplicitClientForPromptTests(t)

	requestState := gofakeit.LetterN(8)
	// Missing nonce - required for response_type=id_token
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=id_token" +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	// Error should be in fragment (implicit flow uses fragment for errors)
	errorCode, errorDescription, _ := getErrorFromFragment(t, resp)
	assert.Equal(t, "invalid_request", errorCode)
	assert.Contains(t, strings.ToLower(errorDescription), "nonce", "error should mention nonce")
}
