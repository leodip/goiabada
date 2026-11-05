package apihandlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Every admin and account API route runs under middleware.Settings, so a handler reached without
// settings is a wiring defect. It answers the one JSON 500 envelope this surface uses, with
// reqctx.ErrNoSettings in the record, and this row stands for every settings read in the package:
// they share this writer (#433 decision 6).
func TestHandleSettingsGeneralGet_WithoutSettingsAnswersTheJSON500Envelope(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	rr := httptest.NewRecorder()

	HandleSettingsGeneralGet().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/general", nil))

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	code, description := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", code)
	assert.Contains(t, description, "Request Id:")

	attrs := oneErrorRecord(t, capture)
	logged, isError := attrs["error"].(error)
	require.True(t, isError, "the error attribute must carry the error value itself")
	assert.ErrorIs(t, logged, reqctx.ErrNoSettings)
}

// The email verification choice is stored as sent, whether or not self-registration is on. It was
// cleared whenever self-registration was off, so turning self-registration off and on again
// brought it back without email verification, which makes which addresses have an account
// discoverable, and nothing on the page said so. Found checking the self-registration page on the
// demo before 1.7.0.
func TestHandleSettingsGeneralPut_KeepsEmailVerificationWhileSelfRegistrationIsOff(t *testing.T) {
	for _, requiresVerification := range []bool{true, false} {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		var saved *record.Settings
		expectSettingsSave(database)
		database.On("UpdateSettings", mock.Anything, settingsSaveTx, mock.Anything).
			Run(func(args mock.Arguments) { saved = args.Get(2).(*record.Settings) }).Return(nil).Once()
		auditLogger.On("Log", mock.Anything, audit.EventUpdatedGeneralSettings, mock.Anything).Return().Once()

		body, err := json.Marshal(api.UpdateSettingsGeneralRequest{
			AppName:                 "Goiabada",
			Issuer:                  "https://auth.example.com",
			SelfRegistrationEnabled: false,
			SelfRegistrationRequiresEmailVerification: requiresVerification,
			PasswordPolicy:         "low",
			AccountDeletionEnabled: accountDeletionOf(true),
		})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/general", bytes.NewReader(body))
		req = req.WithContext(reqctx.WithSettings(req.Context(),
			&record.Settings{Id: 1, SelfRegistrationEnabled: true, SelfRegistrationRequiresEmailVerification: !requiresVerification}))
		rr := httptest.NewRecorder()

		HandleSettingsGeneralPut(database, auditLogger, "http://localhost:9090").ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.NotNil(t, saved)
		assert.False(t, saved.SelfRegistrationEnabled)
		assert.Equal(t, requiresVerification, saved.SelfRegistrationRequiresEmailVerification,
			"the verification choice is kept while self-registration is off")
	}
}

// nist is the fifth policy, stored as 4 after high, so the stored 0 to 3 keep their meaning: the
// API reads a stored 4 back as nist, and saves nist as 4 and answers it (#550 decision 3).
func TestHandleSettingsGeneral_NistIsStoredAsFour(t *testing.T) {
	t.Run("a stored 4 reads as nist", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/general", nil)
		req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{Id: 1, PasswordPolicy: record.PasswordPolicy(4)}))
		rr := httptest.NewRecorder()

		HandleSettingsGeneralGet().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var resp api.SettingsGeneralResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Equal(t, "nist", resp.PasswordPolicy)
	})

	t.Run("nist is saved as 4 and answered", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		var saved *record.Settings
		expectSettingsSave(database)
		database.On("UpdateSettings", mock.Anything, settingsSaveTx, mock.Anything).
			Run(func(args mock.Arguments) { saved = args.Get(2).(*record.Settings) }).Return(nil).Once()
		auditLogger.On("Log", mock.Anything, audit.EventUpdatedGeneralSettings, mock.Anything).Return().Once()

		body, err := json.Marshal(api.UpdateSettingsGeneralRequest{
			AppName: "Goiabada", Issuer: "https://auth.example.com", PasswordPolicy: " nist ",
			AccountDeletionEnabled: accountDeletionOf(true),
		})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/general", bytes.NewReader(body))
		req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{Id: 1, PasswordPolicy: record.PasswordPolicyLow}))
		rr := httptest.NewRecorder()

		HandleSettingsGeneralPut(database, auditLogger, "http://localhost:9090").ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.NotNil(t, saved)
		assert.Equal(t, record.PasswordPolicy(4), saved.PasswordPolicy)
		var resp api.SettingsGeneralResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Equal(t, "nist", resp.PasswordPolicy)
	})
}

// putSettingsGeneral serves one general settings save of appName over database, and answers the
// response.
func putSettingsGeneral(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, appName string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(api.UpdateSettingsGeneralRequest{
		AppName: appName, Issuer: "https://auth.example.com", PasswordPolicy: "low",
		AccountDeletionEnabled: accountDeletionOf(true),
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/general", bytes.NewReader(body))
	req = req.WithContext(reqctx.WithSettings(req.Context(),
		&record.Settings{Id: 1, AppName: "Before", Issuer: "https://auth.example.com", PasswordPolicy: record.PasswordPolicyLow}))
	rr := httptest.NewRecorder()
	HandleSettingsGeneralPut(database, auditLogger, "http://localhost:9090").ServeHTTP(rr, req)
	return rr
}

// An App name that is empty once trimmed is refused at the field with its own code, and nothing is
// written: stored, it left page titles reading "Sign in – " and every authenticator enrolment
// failing with a 500 (#646 decision 7). The database mock expects no call, so a write fails it.
func TestHandleSettingsGeneralPut_RefusesABlankAppName(t *testing.T) {
	for name, appName := range map[string]string{"empty": "", "spaces alone": "   \t "} {
		t.Run(name, func(t *testing.T) {
			rr := putSettingsGeneral(t, datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t), appName)

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, "handler.settings_general.app_name_required", code)
			assert.Equal(t, "App name is required.", description)
		})
	}
}

// The App name is measured once trimmed, as the first start measures GOIABADA_APPNAME: 30
// characters with spaces around them are accepted and stored trimmed, where the spaces used to count
// against the 30; 31 once trimmed and an angle bracket keep their codes (#646 decision 3).
func TestHandleSettingsGeneralPut_MeasuresTheAppNameTrimmed(t *testing.T) {
	t.Run("30 characters inside surrounding space are stored trimmed", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		var saved *record.Settings
		expectSettingsSave(database)
		database.On("UpdateSettings", mock.Anything, settingsSaveTx, mock.Anything).
			Run(func(args mock.Arguments) { saved = args.Get(2).(*record.Settings) }).Return(nil).Once()
		auditLogger.On("Log", mock.Anything, audit.EventUpdatedGeneralSettings, mock.Anything).Return().Once()

		rr := putSettingsGeneral(t, database, auditLogger, "  "+strings.Repeat("é", 30)+"\t")

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.NotNil(t, saved)
		assert.Equal(t, strings.Repeat("é", 30), saved.AppName)
	})

	for name, refusal := range map[string]struct{ appName, code string }{
		"31 characters inside surrounding space": {"  " + strings.Repeat("a", 31) + " ", "handler.settings_general.app_name_too_long"},
		"an angle bracket":                       {"Acme <Corp>", "validator.settings.app_name_angle_brackets"},
	} {
		t.Run(name, func(t *testing.T) {
			rr := putSettingsGeneral(t, datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t), refusal.appName)

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			code, _ := decodeErrorEnvelope(t, rr)
			assert.Equal(t, refusal.code, code)
		})
	}
}

// accountDeletionOf is a general settings save's accountDeletionEnabled, which the PUT requires.
func accountDeletionOf(enabled bool) *bool {
	return &enabled
}

// GET answers whether users may delete their own account, as stored (#783 decision 5).
func TestHandleSettingsGeneralGet_AnswersAccountDeletionEnabled(t *testing.T) {
	for _, stored := range []bool{true, false} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/general", nil)
		req = req.WithContext(reqctx.WithSettings(req.Context(),
			&record.Settings{Id: 1, PasswordPolicy: record.PasswordPolicyLow, AccountDeletionEnabled: stored}))
		rr := httptest.NewRecorder()

		HandleSettingsGeneralGet().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var body map[string]any
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		assert.Equal(t, stored, body["accountDeletionEnabled"], "stored %v", stored)
	}
}

// The PUT requires accountDeletionEnabled: absent and null are refused with the refusal naming the
// setting, nothing saved and nothing audited, because a PUT replaces the whole section and a
// caller that does not know the field must not choose for the deployment by leaving it out (#783
// decision 5). The strict mocks are the assertion that nothing is written.
func TestHandleSettingsGeneralPut_RequiresAccountDeletionEnabled(t *testing.T) {
	const rest = `"appName":"Goiabada","issuer":"https://auth.example.com","passwordPolicy":"low"`
	for name, body := range map[string]string{
		"absent": `{` + rest + `}`,
		"null":   `{` + rest + `,"accountDeletionEnabled":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/general", strings.NewReader(body))
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{Id: 1,
				Issuer: "https://auth.example.com", PasswordPolicy: record.PasswordPolicyLow, AccountDeletionEnabled: true}))
			rr := httptest.NewRecorder()

			HandleSettingsGeneralPut(datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t), "http://localhost:9090").ServeHTTP(rr, req)

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, "handler.settings_general.account_deletion_enabled_required", code)
			assert.Equal(t, "Choose whether to let users delete their own account.", description)
		})
	}
}

// The PUT stores accountDeletionEnabled as sent, either way, and answers it.
func TestHandleSettingsGeneralPut_StoresAccountDeletionEnabledAsSent(t *testing.T) {
	for _, sent := range []bool{false, true} {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		var saved *record.Settings
		expectSettingsSave(database)
		database.On("UpdateSettings", mock.Anything, settingsSaveTx, mock.Anything).
			Run(func(args mock.Arguments) { saved = args.Get(2).(*record.Settings) }).Return(nil).Once()
		auditLogger.On("Log", mock.Anything, audit.EventUpdatedGeneralSettings, mock.Anything).Return().Once()

		body := `{"appName":"Goiabada","issuer":"https://auth.example.com","passwordPolicy":"low",` +
			`"accountDeletionEnabled":` + map[bool]string{false: "false", true: "true"}[sent] + `}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/general", strings.NewReader(body))
		req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{Id: 1,
			Issuer: "https://auth.example.com", PasswordPolicy: record.PasswordPolicyLow, AccountDeletionEnabled: !sent}))
		rr := httptest.NewRecorder()

		HandleSettingsGeneralPut(database, auditLogger, "http://localhost:9090").ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.NotNil(t, saved)
		assert.Equal(t, sent, saved.AccountDeletionEnabled, "sent %v", sent)
		var answered map[string]any
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &answered))
		assert.Equal(t, sent, answered["accountDeletionEnabled"], "sent %v", sent)
	}
}
