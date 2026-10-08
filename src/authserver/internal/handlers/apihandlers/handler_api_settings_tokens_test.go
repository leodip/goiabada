package apihandlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// updated_tokens_settings records who saved the token settings, each value before the save under
// old and each value after it under new, so a save changing all five records all five both ways
// (#522 decision 7).
func TestSettingsTokensPut_TheEventRecordsTheCallerAndEachValueBeforeAndAfter(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	var saved record.Settings
	database.On("UpdateSettings", mock.Anything, (*sql.Tx)(nil), mock.AnythingOfType("*record.Settings")).
		Run(func(args mock.Arguments) { saved = *args.Get(2).(*record.Settings) }).
		Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedTokensSettings, map[string]interface{}{
		"logged_in_user": grantCaller,
		"old": map[string]interface{}{
			"token_expiration_in_seconds":                    300,
			"refresh_token_offline_idle_timeout_in_seconds":  1800,
			"refresh_token_offline_max_lifetime_in_seconds":  7200,
			"include_open_id_connect_claims_in_access_token": true,
			"include_open_id_connect_claims_in_id_token":     false,
		},
		"new": map[string]interface{}{
			"token_expiration_in_seconds":                    600,
			"refresh_token_offline_idle_timeout_in_seconds":  3600,
			"refresh_token_offline_max_lifetime_in_seconds":  86400,
			"include_open_id_connect_claims_in_access_token": false,
			"include_open_id_connect_claims_in_id_token":     true,
		},
	}).Return().Once()

	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/tokens", strings.NewReader(`{
		"tokenExpirationInSeconds": 600,
		"refreshTokenOfflineIdleTimeoutInSeconds": 3600,
		"refreshTokenOfflineMaxLifetimeInSeconds": 86400,
		"includeOpenIDConnectClaimsInAccessToken": false,
		"includeOpenIDConnectClaimsInIdToken": true
	}`))
	r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 7200,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		IncludeOpenIDConnectClaimsInIdToken:     false,
	}))
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage", "sub": grantCaller})
	rr := httptest.NewRecorder()

	HandleSettingsTokensPut(database, auditLogger).ServeHTTP(rr, r)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, 600, saved.TokenExpirationInSeconds)
	assert.Equal(t, 3600, saved.RefreshTokenOfflineIdleTimeoutInSeconds)
	assert.Equal(t, 86400, saved.RefreshTokenOfflineMaxLifetimeInSeconds)
	assert.False(t, saved.IncludeOpenIDConnectClaimsInAccessToken)
	assert.True(t, saved.IncludeOpenIDConnectClaimsInIdToken)
	auditLogger.AssertNumberOfCalls(t, "Log", 1)
}
