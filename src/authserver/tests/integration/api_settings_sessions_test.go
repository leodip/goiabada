package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GET /api/v1/admin/settings/sessions
func TestAPISettingsSessionsGet_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Read current settings from DB for comparison
	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	assert.NotNil(t, settings)

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/sessions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsSessionsResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)

	assert.Equal(t, settings.UserSessionIdleTimeoutInSeconds, body.UserSessionIdleTimeoutInSeconds)
	assert.Equal(t, settings.UserSessionMaxLifetimeInSeconds, body.UserSessionMaxLifetimeInSeconds)
	assert.Equal(t, settings.MaxUserSessionsPerUser, body.MaxUserSessionsPerUser)
}

// PUT /api/v1/admin/settings/sessions - success
func TestAPISettingsSessionsPut_Success(t *testing.T) {
	restoreSettings(t)
	accessToken, _ := createAdminClientWithToken(t)

	req := api.UpdateSettingsSessionsRequest{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 7200,
		MaxUserSessionsPerUser:          sessionCapOf(7),
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/sessions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsSessionsResponse
	err := json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)

	assert.Equal(t, req.UserSessionIdleTimeoutInSeconds, body.UserSessionIdleTimeoutInSeconds)
	assert.Equal(t, req.UserSessionMaxLifetimeInSeconds, body.UserSessionMaxLifetimeInSeconds)
	assert.Equal(t, 7, body.MaxUserSessionsPerUser)

	// Verify DB persisted
	settings, err2 := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err2)
	assert.Equal(t, req.UserSessionIdleTimeoutInSeconds, settings.UserSessionIdleTimeoutInSeconds)
	assert.Equal(t, req.UserSessionMaxLifetimeInSeconds, settings.UserSessionMaxLifetimeInSeconds)
	assert.Equal(t, 7, settings.MaxUserSessionsPerUser)
}

// PUT /api/v1/admin/settings/sessions - validation errors
func TestAPISettingsSessionsPut_ValidationErrors(t *testing.T) {
	restoreSettings(t)
	accessToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/sessions"

	// idle <= 0
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsSessionsRequest{
		UserSessionIdleTimeoutInSeconds: 0,
		UserSessionMaxLifetimeInSeconds: 10,
		MaxUserSessionsPerUser:          sessionCapOf(20),
	})
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
	var err1 api.ErrorResponse
	_ = json.NewDecoder(resp1.Body).Decode(&err1)
	assert.Equal(t, "The idle timeout must be greater than zero.", err1.ErrorDescription)

	// max <= 0
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsSessionsRequest{
		UserSessionIdleTimeoutInSeconds: 10,
		UserSessionMaxLifetimeInSeconds: 0,
		MaxUserSessionsPerUser:          sessionCapOf(20),
	})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var err2 api.ErrorResponse
	_ = json.NewDecoder(resp2.Body).Decode(&err2)
	assert.Equal(t, "The maximum lifetime must be greater than zero.", err2.ErrorDescription)

	// idle > max
	resp3 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsSessionsRequest{
		UserSessionIdleTimeoutInSeconds: 11,
		UserSessionMaxLifetimeInSeconds: 10,
		MaxUserSessionsPerUser:          sessionCapOf(20),
	})
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
	var err3 api.ErrorResponse
	_ = json.NewDecoder(resp3.Body).Decode(&err3)
	assert.Equal(t, "The idle timeout cannot be longer than the maximum lifetime.", err3.ErrorDescription)

	// idle > max allowed
	resp4 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsSessionsRequest{
		UserSessionIdleTimeoutInSeconds: 160000001,
		UserSessionMaxLifetimeInSeconds: 160000001,
		MaxUserSessionsPerUser:          sessionCapOf(20),
	})
	defer func() { _ = resp4.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp4.StatusCode)
	var err4 api.ErrorResponse
	_ = json.NewDecoder(resp4.Body).Decode(&err4)
	assert.Equal(t, "The idle timeout cannot be more than 160000000 seconds.", err4.ErrorDescription)

	// max > max allowed
	resp5 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsSessionsRequest{
		UserSessionIdleTimeoutInSeconds: 10,
		UserSessionMaxLifetimeInSeconds: 160000001,
		MaxUserSessionsPerUser:          sessionCapOf(20),
	})
	defer func() { _ = resp5.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp5.StatusCode)
	var err5 api.ErrorResponse
	_ = json.NewDecoder(resp5.Body).Decode(&err5)
	assert.Equal(t, "The maximum lifetime cannot be more than 160000000 seconds.", err5.ErrorDescription)
}

func TestAPISettingsSessionsPut_InvalidRequestBodyAndUnauthorized(t *testing.T) {
	restoreSettings(t)
	accessToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/sessions"

	// Invalid body (nil/empty)
	req, err := http.NewRequest("PUT", url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error_description"] != nil {
		msg := body["error_description"].(string)
		assert.Equal(t, "Invalid request body", msg)
	}

	// Unauthorized (no Authorization header) - PUT
	req2, err := http.NewRequest("PUT", url, nil)
	require.NoError(t, err)
	resp2, err := httpClient.Do(req2)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

func TestAPISettingsSessions_UnauthorizedAndScope(t *testing.T) {
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/sessions"

	// No token - GET
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	bodyBytes, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Contains(t, string(bodyBytes), "Access token required.")

	// Invalid token - GET
	resp2 := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)

	// Insufficient scope
	tok := createClientCredentialsTokenWithoutRouteScope(t)
	resp3 := makeAPIRequest(t, "GET", url, tok, nil)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
	bodyBytes3, _ := io.ReadAll(resp3.Body)
	assert.Contains(t, string(bodyBytes3), "Insufficient scope.")
}

//

// sessionCapOf is a cap as the request type holds it: a pointer, so an absent one is told from 0.
func sessionCapOf(maxSessions int) *int {
	return &maxSessions
}

// PUT /api/v1/admin/settings/sessions requires maxUserSessionsPerUser, and refuses one outside 0 to
// 1000, saving nothing (#564 decision 6). The body is raw JSON here, so an absent field is absent.
func TestAPISettingsSessionsPut_TheCapIsRequiredAndBounded(t *testing.T) {
	before := restoreSettings(t)
	accessToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/sessions"

	for _, tc := range []struct {
		name    string
		body    string
		message string
	}{
		{"absent", `{"userSessionIdleTimeoutInSeconds":3600,"userSessionMaxLifetimeInSeconds":7200}`,
			"Enter the maximum sessions per user."},
		{"null", `{"userSessionIdleTimeoutInSeconds":3600,"userSessionMaxLifetimeInSeconds":7200,"maxUserSessionsPerUser":null}`,
			"Enter the maximum sessions per user."},
		{"below 0", `{"userSessionIdleTimeoutInSeconds":3600,"userSessionMaxLifetimeInSeconds":7200,"maxUserSessionsPerUser":-1}`,
			"The maximum sessions per user must be between 0 and 1000."},
		{"above 1000", `{"userSessionIdleTimeoutInSeconds":3600,"userSessionMaxLifetimeInSeconds":7200,"maxUserSessionsPerUser":1001}`,
			"The maximum sessions per user must be between 0 and 1000."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(tc.body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+accessToken)
			req.Header.Set("Content-Type", "application/json")
			resp, err := createHttpClient(t).Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var refusal api.ErrorResponse
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&refusal))
			assert.Equal(t, "VALIDATION_ERROR", refusal.ErrorCode)
			assert.Equal(t, tc.message, refusal.ErrorDescription)

			after, err := database.GetSettingsById(context.Background(), nil, 1)
			require.NoError(t, err)
			assert.Equal(t, before.UserSessionIdleTimeoutInSeconds, after.UserSessionIdleTimeoutInSeconds, "nothing is saved")
			assert.Equal(t, before.MaxUserSessionsPerUser, after.MaxUserSessionsPerUser, "nothing is saved")
		})
	}

	t.Run("0, no limit, is saved as 0", func(t *testing.T) {
		resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsSessionsRequest{
			UserSessionIdleTimeoutInSeconds: 3600,
			UserSessionMaxLifetimeInSeconds: 7200,
			MaxUserSessionsPerUser:          sessionCapOf(0),
		})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		after, err := database.GetSettingsById(context.Background(), nil, 1)
		require.NoError(t, err)
		assert.Equal(t, 0, after.MaxUserSessionsPerUser)
	})
}

// updated_sessions_settings records who saved and the three values before and after the save, under
// old and new (#564 decision 10).
func TestAPISettingsSessionsPut_TheEventRecordsEachValueBeforeAndAfter(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) {
		settings.AuditLogsInDatabaseEnabled = true
		settings.UserSessionIdleTimeoutInSeconds = 7200
		settings.UserSessionMaxLifetimeInSeconds = 86400
		settings.MaxUserSessionsPerUser = 20
	})
	accessToken, adminClient := createAdminClientWithToken(t)

	resp, requestId := sendAdmin(t, accessToken, http.MethodPut, "/api/v1/admin/settings/sessions", api.UpdateSettingsSessionsRequest{
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 43200,
		MaxUserSessionsPerUser:          sessionCapOf(5),
	})
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	assert.Equal(t, []map[string]any{{
		"logged_in_user": adminClient.ClientIdentifier,
		"old": map[string]any{
			"user_session_idle_timeout_in_seconds": float64(7200),
			"user_session_max_lifetime_in_seconds": float64(86400),
			"max_user_sessions_per_user":           float64(20),
		},
		"new": map[string]any{
			"user_session_idle_timeout_in_seconds": float64(3600),
			"user_session_max_lifetime_in_seconds": float64(43200),
			"max_user_sessions_per_user":           float64(5),
		},
	}}, auditRows(t, accessToken, "updated_sessions_settings", requestId))
}
