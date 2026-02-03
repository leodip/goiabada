package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
	"strings"
)

// GET /api/v1/admin/settings/sessions
func TestAPISettingsSessionsGet_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Read current settings from DB for comparison
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.NotNil(t, settings)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/sessions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsSessionsResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	assert.Equal(t, settings.UserSessionIdleTimeoutInSeconds, body.UserSessionIdleTimeoutInSeconds)
	assert.Equal(t, settings.UserSessionMaxLifetimeInSeconds, body.UserSessionMaxLifetimeInSeconds)
}

// PUT /api/v1/admin/settings/sessions - success
func TestAPISettingsSessionsPut_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	req := api.UpdateSettingsSessionsRequest{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 7200,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/sessions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsSessionsResponse
	err := json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	assert.Equal(t, req.UserSessionIdleTimeoutInSeconds, body.UserSessionIdleTimeoutInSeconds)
	assert.Equal(t, req.UserSessionMaxLifetimeInSeconds, body.UserSessionMaxLifetimeInSeconds)

	// Verify DB persisted
	settings, err2 := database.GetSettingsById(nil, 1)
	assert.NoError(t, err2)
	assert.Equal(t, req.UserSessionIdleTimeoutInSeconds, settings.UserSessionIdleTimeoutInSeconds)
	assert.Equal(t, req.UserSessionMaxLifetimeInSeconds, settings.UserSessionMaxLifetimeInSeconds)
}

// PUT /api/v1/admin/settings/sessions - validation errors
func TestAPISettingsSessionsPut_ValidationErrors(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/sessions"

	// idle <= 0
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsSessionsRequest{
		UserSessionIdleTimeoutInSeconds: 0,
		UserSessionMaxLifetimeInSeconds: 10,
	})
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
	var err1 api.ErrorResponse
	_ = json.NewDecoder(resp1.Body).Decode(&err1)
	assert.Equal(t, "User session - idle timeout in seconds must be greater than zero.", err1.Error.Message)

	// max <= 0
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsSessionsRequest{
		UserSessionIdleTimeoutInSeconds: 10,
		UserSessionMaxLifetimeInSeconds: 0,
	})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var err2 api.ErrorResponse
	_ = json.NewDecoder(resp2.Body).Decode(&err2)
	assert.Equal(t, "User session - max lifetime in seconds must be greater than zero.", err2.Error.Message)

	// idle > max
	resp3 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsSessionsRequest{
		UserSessionIdleTimeoutInSeconds: 11,
		UserSessionMaxLifetimeInSeconds: 10,
	})
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
	var err3 api.ErrorResponse
	_ = json.NewDecoder(resp3.Body).Decode(&err3)
	assert.Equal(t, "User session - the idle timeout cannot be greater than the max lifetime.", err3.Error.Message)

	// idle > max allowed
	resp4 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsSessionsRequest{
		UserSessionIdleTimeoutInSeconds: 160000001,
		UserSessionMaxLifetimeInSeconds: 160000001,
	})
	defer func() { _ = resp4.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp4.StatusCode)
	var err4 api.ErrorResponse
	_ = json.NewDecoder(resp4.Body).Decode(&err4)
	assert.Equal(t, "User session - idle timeout in seconds cannot be greater than 160000000.", err4.Error.Message)

	// max > max allowed
	resp5 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsSessionsRequest{
		UserSessionIdleTimeoutInSeconds: 10,
		UserSessionMaxLifetimeInSeconds: 160000001,
	})
	defer func() { _ = resp5.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp5.StatusCode)
	var err5 api.ErrorResponse
	_ = json.NewDecoder(resp5.Body).Decode(&err5)
	assert.Equal(t, "User session - max lifetime in seconds cannot be greater than 160000000.", err5.Error.Message)
}

func TestAPISettingsSessionsPut_InvalidRequestBodyAndUnauthorized(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/sessions"

	// Invalid body (nil/empty)
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

	// Unauthorized (no Authorization header) - PUT
	req2, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)
	resp2, err := httpClient.Do(req2)
	assert.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

func TestAPISettingsSessions_UnauthorizedAndScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/sessions"

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

//
