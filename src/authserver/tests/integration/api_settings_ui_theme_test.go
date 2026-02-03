package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/uithemes"
	"github.com/stretchr/testify/assert"
	"strings"
)

// GET /api/v1/admin/settings/ui-theme
func TestAPISettingsUIThemeGet_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Fetch current settings directly from DB for expected values
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.NotNil(t, settings)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/ui-theme"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsUIThemeResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	assert.Equal(t, settings.UITheme, body.UITheme)
	// available themes should match core list
	assert.ElementsMatch(t, uithemes.Get(), body.AvailableThemes)
}

// PUT /api/v1/admin/settings/ui-theme - success set and clear
func TestAPISettingsUIThemePut_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/ui-theme"

	// Pick a valid theme from core list
	themes := uithemes.Get()
	valid := "dark"
	if len(themes) > 0 {
		valid = themes[0]
	}

	// Set to a valid theme (with surrounding spaces to ensure trimming)
	resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsUIThemeRequest{UITheme: "  " + valid + "  "})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.SettingsUIThemeResponse
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.Equal(t, valid, body.UITheme)
	assert.ElementsMatch(t, uithemes.Get(), body.AvailableThemes)

	// DB persisted
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.Equal(t, valid, settings.UITheme)

	// Clear to default (empty string allowed)
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsUIThemeRequest{UITheme: ""})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var body2 api.SettingsUIThemeResponse
	_ = json.NewDecoder(resp2.Body).Decode(&body2)
	assert.Equal(t, "", body2.UITheme)
	assert.ElementsMatch(t, uithemes.Get(), body2.AvailableThemes)

	// DB persisted default
	settings2, err2 := database.GetSettingsById(nil, 1)
	assert.NoError(t, err2)
	assert.Equal(t, "", settings2.UITheme)
}

// PUT /api/v1/admin/settings/ui-theme - validation errors
func TestAPISettingsUIThemePut_ValidationErrors(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/ui-theme"

	// Invalid theme
	resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsUIThemeRequest{UITheme: "not-a-theme"})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errBody api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errBody)
	assert.Equal(t, "Invalid theme.", errBody.Error.Message)
}

func TestAPISettingsUITheme_InvalidRequestBodyAndUnauthorized(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/ui-theme"

	// Invalid body (nil) - PUT
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != nil {
		msg := body["error"].(map[string]interface{})["message"].(string)
		assert.Equal(t, "Invalid request body", msg)
	}

	// Unauthorized - GET
	req2, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)
	resp2, err := httpClient.Do(req2)
	assert.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

func TestAPISettingsUITheme_UnauthorizedAndScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/ui-theme"

	// No token - GET
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	bodyBytes, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, "Access token required", strings.TrimSpace(string(bodyBytes)))

	// Invalid token - GET
	resp2 := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)

	// Insufficient scope
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp3 := makeAPIRequest(t, "GET", url, tok, nil)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
	bodyBytes3, _ := io.ReadAll(resp3.Body)
	assert.Equal(t, "Insufficient scope", strings.TrimSpace(string(bodyBytes3)))
}
