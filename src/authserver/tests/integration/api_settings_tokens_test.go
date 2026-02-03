package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
)

// GET /api/v1/admin/settings/tokens
func TestAPISettingsTokensGet_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Read current settings from DB for comparison
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.NotNil(t, settings)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/tokens"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsTokensResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	assert.Equal(t, settings.TokenExpirationInSeconds, body.TokenExpirationInSeconds)
	assert.Equal(t, settings.RefreshTokenOfflineIdleTimeoutInSeconds, body.RefreshTokenOfflineIdleTimeoutInSeconds)
	assert.Equal(t, settings.RefreshTokenOfflineMaxLifetimeInSeconds, body.RefreshTokenOfflineMaxLifetimeInSeconds)
	assert.Equal(t, settings.IncludeOpenIDConnectClaimsInAccessToken, body.IncludeOpenIDConnectClaimsInAccessToken)
	assert.Equal(t, settings.IncludeOpenIDConnectClaimsInIdToken, body.IncludeOpenIDConnectClaimsInIdToken)
}

// PUT /api/v1/admin/settings/tokens - success
func TestAPISettingsTokensPut_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	req := api.UpdateSettingsTokensRequest{
		TokenExpirationInSeconds:                600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 7200,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		IncludeOpenIDConnectClaimsInIdToken:     false,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/tokens"
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsTokensResponse
	err := json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	assert.Equal(t, req.TokenExpirationInSeconds, body.TokenExpirationInSeconds)
	assert.Equal(t, req.RefreshTokenOfflineIdleTimeoutInSeconds, body.RefreshTokenOfflineIdleTimeoutInSeconds)
	assert.Equal(t, req.RefreshTokenOfflineMaxLifetimeInSeconds, body.RefreshTokenOfflineMaxLifetimeInSeconds)
	assert.Equal(t, req.IncludeOpenIDConnectClaimsInAccessToken, body.IncludeOpenIDConnectClaimsInAccessToken)
	assert.Equal(t, req.IncludeOpenIDConnectClaimsInIdToken, body.IncludeOpenIDConnectClaimsInIdToken)

	// Verify DB persisted
	settings, err2 := database.GetSettingsById(nil, 1)
	assert.NoError(t, err2)
	assert.Equal(t, req.TokenExpirationInSeconds, settings.TokenExpirationInSeconds)
	assert.Equal(t, req.RefreshTokenOfflineIdleTimeoutInSeconds, settings.RefreshTokenOfflineIdleTimeoutInSeconds)
	assert.Equal(t, req.RefreshTokenOfflineMaxLifetimeInSeconds, settings.RefreshTokenOfflineMaxLifetimeInSeconds)
	assert.Equal(t, req.IncludeOpenIDConnectClaimsInAccessToken, settings.IncludeOpenIDConnectClaimsInAccessToken)
	assert.Equal(t, req.IncludeOpenIDConnectClaimsInIdToken, settings.IncludeOpenIDConnectClaimsInIdToken)
}

// PUT /api/v1/admin/settings/tokens - validation errors
func TestAPISettingsTokensPut_ValidationErrors(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/tokens"

	// token expiration <= 0
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsTokensRequest{
		TokenExpirationInSeconds:                0,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		IncludeOpenIDConnectClaimsInIdToken:     true,
	})
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
	var err1 api.ErrorResponse
	_ = json.NewDecoder(resp1.Body).Decode(&err1)
	assert.Equal(t, "Token expiration in seconds must be greater than zero.", err1.Error.Message)

	// token expiration > max allowed
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsTokensRequest{
		TokenExpirationInSeconds:                160000001,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		IncludeOpenIDConnectClaimsInIdToken:     true,
	})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var err2 api.ErrorResponse
	_ = json.NewDecoder(resp2.Body).Decode(&err2)
	assert.Equal(t, "Token expiration in seconds cannot be greater than 160000000.", err2.Error.Message)

	// idle <= 0
	resp3 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsTokensRequest{
		TokenExpirationInSeconds:                1,
		RefreshTokenOfflineIdleTimeoutInSeconds: 0,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		IncludeOpenIDConnectClaimsInIdToken:     true,
	})
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
	var err3 api.ErrorResponse
	_ = json.NewDecoder(resp3.Body).Decode(&err3)
	assert.Equal(t, "Refresh token offline - idle timeout in seconds must be greater than zero.", err3.Error.Message)

	// idle > max allowed
	resp4 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsTokensRequest{
		TokenExpirationInSeconds:                1,
		RefreshTokenOfflineIdleTimeoutInSeconds: 160000001,
		RefreshTokenOfflineMaxLifetimeInSeconds: 160000001,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		IncludeOpenIDConnectClaimsInIdToken:     true,
	})
	defer func() { _ = resp4.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp4.StatusCode)
	var err4 api.ErrorResponse
	_ = json.NewDecoder(resp4.Body).Decode(&err4)
	assert.Equal(t, "Refresh token offline - idle timeout in seconds cannot be greater than 160000000.", err4.Error.Message)

	// max lifetime <= 0
	resp5 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsTokensRequest{
		TokenExpirationInSeconds:                1,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1,
		RefreshTokenOfflineMaxLifetimeInSeconds: 0,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		IncludeOpenIDConnectClaimsInIdToken:     true,
	})
	defer func() { _ = resp5.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp5.StatusCode)
	var err5 api.ErrorResponse
	_ = json.NewDecoder(resp5.Body).Decode(&err5)
	assert.Equal(t, "Refresh token offline - max lifetime in seconds must be greater than zero.", err5.Error.Message)

	// max lifetime > max allowed
	resp6 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsTokensRequest{
		TokenExpirationInSeconds:                1,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1,
		RefreshTokenOfflineMaxLifetimeInSeconds: 160000001,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		IncludeOpenIDConnectClaimsInIdToken:     true,
	})
	defer func() { _ = resp6.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp6.StatusCode)
	var err6 api.ErrorResponse
	_ = json.NewDecoder(resp6.Body).Decode(&err6)
	assert.Equal(t, "Refresh token offline - max lifetime in seconds cannot be greater than 160000000.", err6.Error.Message)

	// idle > max lifetime
	resp7 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsTokensRequest{
		TokenExpirationInSeconds:                10,
		RefreshTokenOfflineIdleTimeoutInSeconds: 11,
		RefreshTokenOfflineMaxLifetimeInSeconds: 10,
		IncludeOpenIDConnectClaimsInAccessToken: false,
		IncludeOpenIDConnectClaimsInIdToken:     true,
	})
	defer func() { _ = resp7.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp7.StatusCode)
	var err7 api.ErrorResponse
	_ = json.NewDecoder(resp7.Body).Decode(&err7)
	assert.Equal(t, "Refresh token offline - idle timeout cannot be greater than max lifetime.", err7.Error.Message)
}

func TestAPISettingsTokens_InvalidRequestBodyAndUnauthorized(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/tokens"

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

func TestAPISettingsTokens_UnauthorizedAndScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/settings/tokens"

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
