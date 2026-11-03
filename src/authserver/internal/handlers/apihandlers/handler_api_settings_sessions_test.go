package apihandlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// storedSessionsSettings is the settings row each case starts from: distinct values, so a response
// or an event naming the wrong field shows.
func storedSessionsSettings() *record.Settings {
	return &record.Settings{
		UserSessionIdleTimeoutInSeconds: 7200,
		UserSessionMaxLifetimeInSeconds: 86400,
		MaxUserSessionsPerUser:          20,
		KeepSignedIn:                    record.KeepSignedInNever,
	}
}

func serveSessionsPut(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/sessions", strings.NewReader(body))
	r = r.WithContext(reqctx.WithSettings(r.Context(), storedSessionsSettings()))
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage", "sub": grantCaller})
	rr := httptest.NewRecorder()
	HandleSettingsSessionsPut(database, auditLogger).ServeHTTP(rr, r)
	return rr
}

// The GET answers the per-user session cap beside the two lifetimes (#564 decision 6), and whether
// users stay signed in after the browser closes (#743 decision 4).
func TestSettingsSessionsGet_AnswersTheCapAndKeepSignedInBesideTheLifetimes(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/sessions", nil)
	r = r.WithContext(reqctx.WithSettings(r.Context(), storedSessionsSettings()))
	rr := httptest.NewRecorder()

	HandleSettingsSessionsGet().ServeHTTP(rr, r)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.JSONEq(t, `{
		"userSessionIdleTimeoutInSeconds": 7200,
		"userSessionMaxLifetimeInSeconds": 86400,
		"maxUserSessionsPerUser": 20,
		"keepSignedIn": "never"
	}`, rr.Body.String())
}

// The PUT requires the cap. Absent and null are both refused, where reading either as 0 would turn
// the cap off for a caller that does not know the field, and so is a value outside 0 to 1000.
// Nothing is saved and nothing is audited (#564 decision 6). The strict mocks are the assertion.
func TestSettingsSessionsPut_RefusesAMissingOrOutOfRangeCap(t *testing.T) {
	testCases := []struct {
		name    string
		body    string
		code    string
		message string
	}{
		{
			name:    "absent",
			body:    `{"userSessionIdleTimeoutInSeconds":3600,"userSessionMaxLifetimeInSeconds":7200,"keepSignedIn":"ask"}`,
			code:    "handler.settings_sessions.max_sessions_per_user_required",
			message: "Enter the maximum sessions per user.",
		},
		{
			name:    "null",
			body:    `{"userSessionIdleTimeoutInSeconds":3600,"userSessionMaxLifetimeInSeconds":7200,"maxUserSessionsPerUser":null,"keepSignedIn":"ask"}`,
			code:    "handler.settings_sessions.max_sessions_per_user_required",
			message: "Enter the maximum sessions per user.",
		},
		{
			name:    "below 0",
			body:    `{"userSessionIdleTimeoutInSeconds":3600,"userSessionMaxLifetimeInSeconds":7200,"maxUserSessionsPerUser":-1,"keepSignedIn":"ask"}`,
			code:    "handler.settings_sessions.max_sessions_per_user_out_of_range",
			message: "The maximum sessions per user must be between 0 and 1000.",
		},
		{
			name:    "above 1000",
			body:    `{"userSessionIdleTimeoutInSeconds":3600,"userSessionMaxLifetimeInSeconds":7200,"maxUserSessionsPerUser":1001,"keepSignedIn":"ask"}`,
			code:    "handler.settings_sessions.max_sessions_per_user_out_of_range",
			message: "The maximum sessions per user must be between 0 and 1000.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			rr := serveSessionsPut(database, auditLogger, tc.body)

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			var refusal api.ErrorResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &refusal))
			assert.Equal(t, tc.code, refusal.ErrorCode)
			assert.Equal(t, tc.message, refusal.ErrorDescription)
		})
	}
}

// Both ends of the range are accepted, 0, no limit, and 1000, and so is 1, one session per user. Each is saved and answered as given.
func TestSettingsSessionsPut_SavesACapAtEitherEndOfTheRange(t *testing.T) {
	for _, value := range []int{0, 1, 1000} {
		t.Run(strconv.Itoa(value), func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			var saved record.Settings
			expectSettingsSave(database)
			database.On("UpdateSettings", mock.Anything, settingsSaveTx, mock.AnythingOfType("*record.Settings")).
				Run(func(args mock.Arguments) { saved = *args.Get(2).(*record.Settings) }).
				Return(nil).Once()
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedSessionsSettings, mock.Anything).Return().Once()

			body, err := json.Marshal(map[string]any{
				"userSessionIdleTimeoutInSeconds": 3600,
				"userSessionMaxLifetimeInSeconds": 7200,
				"maxUserSessionsPerUser":          value,
				"keepSignedIn":                    "ask",
			})
			require.NoError(t, err)
			rr := serveSessionsPut(database, auditLogger, string(body))

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.Equal(t, value, saved.MaxUserSessionsPerUser)
			var answered api.SettingsSessionsResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &answered))
			assert.Equal(t, value, answered.MaxUserSessionsPerUser)
		})
	}
}

// updated_sessions_settings records who saved, each of the four values before the save under old
// and each after it under new, in the shape updated_tokens_settings uses (#564 decision 10, #743).
func TestSettingsSessionsPut_TheEventRecordsTheCallerAndEachValueBeforeAndAfter(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	var saved record.Settings
	expectSettingsSave(database)
	database.On("UpdateSettings", mock.Anything, settingsSaveTx, mock.AnythingOfType("*record.Settings")).
		Run(func(args mock.Arguments) { saved = *args.Get(2).(*record.Settings) }).
		Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedSessionsSettings, map[string]interface{}{
		"logged_in_user": grantCaller,
		"old": map[string]interface{}{
			"user_session_idle_timeout_in_seconds": 7200,
			"user_session_max_lifetime_in_seconds": 86400,
			"max_user_sessions_per_user":           20,
			"keep_signed_in":                       "never",
		},
		"new": map[string]interface{}{
			"user_session_idle_timeout_in_seconds": 3600,
			"user_session_max_lifetime_in_seconds": 43200,
			"max_user_sessions_per_user":           5,
			"keep_signed_in":                       "always",
		},
	}).Return().Once()

	rr := serveSessionsPut(database, auditLogger, `{
		"userSessionIdleTimeoutInSeconds": 3600,
		"userSessionMaxLifetimeInSeconds": 43200,
		"maxUserSessionsPerUser": 5,
		"keepSignedIn": "always"
	}`)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, 3600, saved.UserSessionIdleTimeoutInSeconds)
	assert.Equal(t, 43200, saved.UserSessionMaxLifetimeInSeconds)
	assert.Equal(t, 5, saved.MaxUserSessionsPerUser)
	assert.Equal(t, record.KeepSignedInAlways, saved.KeepSignedIn)
	assert.JSONEq(t, `{
		"userSessionIdleTimeoutInSeconds": 3600,
		"userSessionMaxLifetimeInSeconds": 43200,
		"maxUserSessionsPerUser": 5,
		"keepSignedIn": "always"
	}`, rr.Body.String())
	auditLogger.AssertNumberOfCalls(t, "Log", 1)
}

// The PUT requires keepSignedIn, one of always, ask and never. Absent, null, empty and any other
// value are refused, nothing saved and nothing audited: a caller that does not know the field must
// not choose for the deployment by omission (#743 decision 4). The strict mocks are the assertion.
func TestSettingsSessionsPut_RefusesAMissingOrUnknownKeepSignedIn(t *testing.T) {
	const lifetimesAndCap = `"userSessionIdleTimeoutInSeconds":3600,"userSessionMaxLifetimeInSeconds":7200,"maxUserSessionsPerUser":20`
	required := struct{ code, message string }{
		"handler.settings_sessions.keep_signed_in_required",
		"Choose whether users stay signed in after the browser closes.",
	}
	invalid := struct{ code, message string }{
		"handler.settings_sessions.keep_signed_in_invalid",
		"Keep users signed in after the browser closes must be always, ask or never.",
	}
	testCases := []struct {
		name          string
		body          string
		code, message string
	}{
		{"absent", `{` + lifetimesAndCap + `}`, required.code, required.message},
		{"null", `{` + lifetimesAndCap + `,"keepSignedIn":null}`, required.code, required.message},
		{"empty", `{` + lifetimesAndCap + `,"keepSignedIn":""}`, required.code, required.message},
		{"another value", `{` + lifetimesAndCap + `,"keepSignedIn":"sometimes"}`, invalid.code, invalid.message},
		{"a mode in another case", `{` + lifetimesAndCap + `,"keepSignedIn":"Always"}`, invalid.code, invalid.message},
		{"a mode's console label", `{` + lifetimesAndCap + `,"keepSignedIn":"Let each user choose"}`, invalid.code, invalid.message},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			rr := serveSessionsPut(database, auditLogger, tc.body)

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			var refusal api.ErrorResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &refusal))
			assert.Equal(t, tc.code, refusal.ErrorCode)
			assert.Equal(t, tc.message, refusal.ErrorDescription)
		})
	}
}

// Each of the three modes is saved and answered as given.
func TestSettingsSessionsPut_SavesEachKeepSignedInMode(t *testing.T) {
	for _, mode := range []record.KeepSignedIn{"always", "ask", "never"} {
		t.Run(string(mode), func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			var saved record.Settings
			expectSettingsSave(database)
			database.On("UpdateSettings", mock.Anything, settingsSaveTx, mock.AnythingOfType("*record.Settings")).
				Run(func(args mock.Arguments) { saved = *args.Get(2).(*record.Settings) }).
				Return(nil).Once()
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedSessionsSettings, mock.Anything).Return().Once()

			rr := serveSessionsPut(database, auditLogger, `{"userSessionIdleTimeoutInSeconds":3600,`+
				`"userSessionMaxLifetimeInSeconds":7200,"maxUserSessionsPerUser":20,"keepSignedIn":"`+string(mode)+`"}`)

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.Equal(t, mode, saved.KeepSignedIn)
			var answered api.SettingsSessionsResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &answered))
			assert.Equal(t, string(mode), answered.KeepSignedIn)
		})
	}
}
