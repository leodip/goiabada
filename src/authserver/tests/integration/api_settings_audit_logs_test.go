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
)

// GET / PUT /api/v1/admin/settings/audit-logs

const settingsAuditLogsURL = "/api/v1/admin/settings/audit-logs"

// restoreAuditLogSettings snapshots the audit log settings and puts them back
// when the test ends. Unlike most settings, these govern whether audit logging
// happens at all, so leaving them modified would quietly change the behavior
// every later test runs against.
func restoreAuditLogSettings(t *testing.T) {
	t.Helper()

	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.NotNil(t, settings)

	console := settings.AuditLogsInConsoleEnabled
	db := settings.AuditLogsInDatabaseEnabled
	retention := settings.AuditLogRetentionDays

	t.Cleanup(func() {
		current, err := database.GetSettingsById(nil, 1)
		if err != nil || current == nil {
			return
		}
		current.AuditLogsInConsoleEnabled = console
		current.AuditLogsInDatabaseEnabled = db
		current.AuditLogRetentionDays = retention
		_ = database.UpdateSettings(nil, current)
	})
}

func TestAPISettingsAuditLogsGet_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.NotNil(t, settings)

	url := config.GetAuthServer().BaseURL + settingsAuditLogsURL
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsAuditLogsResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	assert.Equal(t, settings.AuditLogsInConsoleEnabled, body.AuditLogsInConsoleEnabled)
	assert.Equal(t, settings.AuditLogsInDatabaseEnabled, body.AuditLogsInDatabaseEnabled)
	assert.Equal(t, settings.AuditLogRetentionDays, body.AuditLogRetentionDays)
}

func TestAPISettingsAuditLogsPut_Success(t *testing.T) {
	restoreAuditLogSettings(t)
	accessToken, _ := createAdminClientWithToken(t)

	req := api.UpdateSettingsAuditLogsRequest{
		AuditLogsInConsoleEnabled:  true,
		AuditLogsInDatabaseEnabled: true,
		AuditLogRetentionDays:      45,
	}

	url := config.GetAuthServer().BaseURL + settingsAuditLogsURL
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.SettingsAuditLogsResponse
	err := json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)

	assert.Equal(t, req.AuditLogsInConsoleEnabled, body.AuditLogsInConsoleEnabled)
	assert.Equal(t, req.AuditLogsInDatabaseEnabled, body.AuditLogsInDatabaseEnabled)
	assert.Equal(t, req.AuditLogRetentionDays, body.AuditLogRetentionDays)

	// Persisted, not just echoed back.
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.Equal(t, req.AuditLogsInConsoleEnabled, settings.AuditLogsInConsoleEnabled)
	assert.Equal(t, req.AuditLogsInDatabaseEnabled, settings.AuditLogsInDatabaseEnabled)
	assert.Equal(t, req.AuditLogRetentionDays, settings.AuditLogRetentionDays)
}

// Disabling both sinks must persist too. This is the case where the change is
// most consequential, since it turns audit logging off.
func TestAPISettingsAuditLogsPut_CanDisableBothSinks(t *testing.T) {
	restoreAuditLogSettings(t)
	accessToken, _ := createAdminClientWithToken(t)

	req := api.UpdateSettingsAuditLogsRequest{
		AuditLogsInConsoleEnabled:  false,
		AuditLogsInDatabaseEnabled: false,
		AuditLogRetentionDays:      10,
	}

	url := config.GetAuthServer().BaseURL + settingsAuditLogsURL
	resp := makeAPIRequest(t, "PUT", url, accessToken, req)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	assert.False(t, settings.AuditLogsInConsoleEnabled)
	assert.False(t, settings.AuditLogsInDatabaseEnabled)
}

// Retention is bounded at 0 (meaning infinite) and 3650 days.
func TestAPISettingsAuditLogsPut_RetentionBoundaries(t *testing.T) {
	restoreAuditLogSettings(t)
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + settingsAuditLogsURL

	accepted := []struct {
		name string
		days int
	}{
		{"zero means infinite retention", 0},
		{"one day", 1},
		{"the maximum of 3650 days", 3650},
	}

	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsAuditLogsRequest{
				AuditLogsInConsoleEnabled:  true,
				AuditLogsInDatabaseEnabled: true,
				AuditLogRetentionDays:      tc.days,
			})
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var body api.SettingsAuditLogsResponse
			err := json.NewDecoder(resp.Body).Decode(&body)
			assert.NoError(t, err)
			assert.Equal(t, tc.days, body.AuditLogRetentionDays)
		})
	}
}

func TestAPISettingsAuditLogsPut_ValidationErrors(t *testing.T) {
	restoreAuditLogSettings(t)
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + settingsAuditLogsURL

	testCases := []struct {
		name    string
		days    int
		wantMsg string
	}{
		{
			name:    "negative retention",
			days:    -1,
			wantMsg: "Audit log retention days cannot be negative. Use 0 for infinite retention.",
		},
		{
			name:    "retention just above the maximum",
			days:    3651,
			wantMsg: "Audit log retention days cannot exceed 3650 days (10 years).",
		},
		{
			name:    "retention far above the maximum",
			days:    100000,
			wantMsg: "Audit log retention days cannot exceed 3650 days (10 years).",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Capture the stored value so we can prove a rejected request changed nothing.
			before, err := database.GetSettingsById(nil, 1)
			assert.NoError(t, err)

			resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsAuditLogsRequest{
				AuditLogsInConsoleEnabled:  true,
				AuditLogsInDatabaseEnabled: true,
				AuditLogRetentionDays:      tc.days,
			})
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

			var errResp api.ErrorResponse
			_ = json.NewDecoder(resp.Body).Decode(&errResp)
			assert.Equal(t, tc.wantMsg, errResp.ErrorDescription)

			after, err := database.GetSettingsById(nil, 1)
			assert.NoError(t, err)
			assert.Equal(t, before.AuditLogRetentionDays, after.AuditLogRetentionDays,
				"a rejected request must not change the stored retention")
		})
	}
}

func TestAPISettingsAuditLogsPut_InvalidBody(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + settingsAuditLogsURL

	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Invalid request body", errResp.ErrorDescription)
}

// Changing these settings is itself an audited action, and the handler logs it
// before saving precisely so that turning logging off is still recorded.
func TestAPISettingsAuditLogsPut_IsItselfAudited(t *testing.T) {
	restoreAuditLogSettings(t)
	accessToken, _ := createAdminClientWithToken(t)

	// Database logging must be on for the event to be queryable.
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	settings.AuditLogsInDatabaseEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)

	before, _, err := database.GetAuditLogsPaginated(nil, 1, 1, constants.AuditUpdatedAuditLogsSettings)
	assert.NoError(t, err)
	var lastIdBefore int64
	if len(before) > 0 {
		lastIdBefore = before[0].Id
	}

	url := config.GetAuthServer().BaseURL + settingsAuditLogsURL
	resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsAuditLogsRequest{
		AuditLogsInConsoleEnabled:  true,
		AuditLogsInDatabaseEnabled: true,
		AuditLogRetentionDays:      33,
	})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	after, total, err := database.GetAuditLogsPaginated(nil, 1, 1, constants.AuditUpdatedAuditLogsSettings)
	assert.NoError(t, err)
	assert.Greater(t, total, 0, "the settings change must be recorded")
	assert.NotEmpty(t, after)
	if len(after) > 0 {
		assert.NotEqual(t, lastIdBefore, after[0].Id, "a new audit entry must have been written")
		assert.Contains(t, after[0].Details, "auditLogRetentionDays")
	}
}

func TestAPISettingsAuditLogs_UnauthorizedAndScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + settingsAuditLogsURL
	httpClient := createHttpClient(t)

	for _, method := range []string{"GET", "PUT"} {
		t.Run(method+" without a token", func(t *testing.T) {
			req, err := http.NewRequest(method, url, nil)
			assert.NoError(t, err)
			resp, err := httpClient.Do(req)
			assert.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			bodyBytes, _ := io.ReadAll(resp.Body)
			assert.Contains(t, string(bodyBytes), "Access token required.")
		})

		t.Run(method+" with an invalid token", func(t *testing.T) {
			resp := makeAPIRequest(t, method, url, "invalid-token", nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		})

		t.Run(method+" with insufficient scope", func(t *testing.T) {
			tok := createClientCredentialsTokenWithScope(t,
				constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
			resp := makeAPIRequest(t, method, url, tok, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			bodyBytes, _ := io.ReadAll(resp.Body)
			assert.Contains(t, string(bodyBytes), "Insufficient scope.")
		})
	}
}

// Reading the settings requires only a read scope, while changing them requires a
// write scope. A read-only credential must therefore be able to GET but not PUT.
func TestAPISettingsAuditLogs_ReadScopeCannotWrite(t *testing.T) {
	url := config.GetAuthServer().BaseURL + settingsAuditLogsURL

	readOnlyToken := createClientCredentialsTokenWithScope(t,
		constants.AuthServerResourceIdentifier, constants.AdminReadPermissionIdentifier)

	getResp := makeAPIRequest(t, "GET", url, readOnlyToken, nil)
	defer func() { _ = getResp.Body.Close() }()
	assert.Equal(t, http.StatusOK, getResp.StatusCode, "a read scope must be able to read the settings")

	putResp := makeAPIRequest(t, "PUT", url, readOnlyToken, api.UpdateSettingsAuditLogsRequest{
		AuditLogsInConsoleEnabled:  false,
		AuditLogsInDatabaseEnabled: false,
		AuditLogRetentionDays:      1,
	})
	defer func() { _ = putResp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, putResp.StatusCode, "a read scope must not be able to change the settings")
}
