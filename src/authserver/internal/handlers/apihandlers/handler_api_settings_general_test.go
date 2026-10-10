package apihandlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		database.On("UpdateSettings", mock.Anything, mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { saved = args.Get(2).(*record.Settings) }).Return(nil).Once()
		auditLogger.On("Log", mock.Anything, audit.EventUpdatedGeneralSettings, mock.Anything).Return().Once()

		body, err := json.Marshal(api.UpdateSettingsGeneralRequest{
			AppName:                 "Goiabada",
			Issuer:                  "https://auth.example.com",
			SelfRegistrationEnabled: false,
			SelfRegistrationRequiresEmailVerification: requiresVerification,
			PasswordPolicy: "low",
		})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/general", bytes.NewReader(body))
		req = req.WithContext(reqctx.WithSettings(req.Context(),
			&record.Settings{Id: 1, SelfRegistrationEnabled: true, SelfRegistrationRequiresEmailVerification: !requiresVerification}))
		rr := httptest.NewRecorder()

		HandleSettingsGeneralPut(database, auditLogger).ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.NotNil(t, saved)
		assert.False(t, saved.SelfRegistrationEnabled)
		assert.Equal(t, requiresVerification, saved.SelfRegistrationRequiresEmailVerification,
			"the verification choice is kept while self-registration is off")
	}
}
