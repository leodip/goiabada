package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/cache"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// settingsServer stands in for the auth server's /api/public/settings, which is
// the only place the admin console may learn any of these values from.
func settingsServer(t *testing.T, payload string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(server.Close)

	return server
}

// runSettingsChain drives MiddlewareSettingsCache against authServerBaseURL and
// reports what the next handler saw, or nil if it was never reached.
func runSettingsChain(t *testing.T, authServerBaseURL string) (*httptest.ResponseRecorder, *models.Settings) {
	t.Helper()

	var seen *models.Settings
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		settings, ok := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		require.True(t, ok, "the middleware must put *models.Settings on the context")
		seen = settings
		w.WriteHeader(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	MiddlewareSettingsCache(cache.NewSettingsCache(authServerBaseURL))(next).
		ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/admin/clients", nil))

	return recorder, seen
}

// The defect this pins: the issuer used to come from GOIABADA_ADMINCONSOLE_ISSUER
// while every other field on the same models.Settings came from the auth server.
// Changing the issuer in Settings > General then left the console comparing a new
// iss claim against a stale configured value, and every sign-in attempt landed
// back at / (#285).
func TestMiddlewareSettingsCache_IssuerComesFromThePayload(t *testing.T) {
	server := settingsServer(t, `{"appName":"A","uiTheme":"light","smtpEnabled":true,"issuer":"https://from-authserver.example"}`)

	recorder, settings := runSettingsChain(t, server.URL)

	assert.Equal(t, http.StatusOK, recorder.Code)
	require.NotNil(t, settings)
	assert.Equal(t, "https://from-authserver.example", settings.Issuer)
}

// Without this, the case above is satisfied by a middleware that hardcodes a
// models.Settings and ignores the payload entirely.
func TestMiddlewareSettingsCache_TheOtherFieldsStillComeFromThePayload(t *testing.T) {
	server := settingsServer(t, `{"appName":"A","uiTheme":"light","smtpEnabled":true,"issuer":"https://from-authserver.example"}`)

	recorder, settings := runSettingsChain(t, server.URL)

	assert.Equal(t, http.StatusOK, recorder.Code)
	require.NotNil(t, settings)
	assert.Equal(t, "A", settings.AppName)
	assert.Equal(t, "light", settings.UITheme)
	assert.True(t, settings.SMTPEnabled)
}

// An auth server too old to serve the field. Absent and explicitly empty decode
// to the same Go value today, so they are separate cases on purpose: a later
// change making the field a *string would split them.
func TestMiddlewareSettingsCache_AbsentIssuerIsRefused(t *testing.T) {
	server := settingsServer(t, `{"appName":"A","uiTheme":"light","smtpEnabled":false}`)

	recorder, settings := runSettingsChain(t, server.URL)

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "authserver")
	assert.Nil(t, settings, "the next handler must not run with no issuer to validate against")
}

func TestMiddlewareSettingsCache_EmptyIssuerIsRefused(t *testing.T) {
	server := settingsServer(t, `{"appName":"A","uiTheme":"light","smtpEnabled":false,"issuer":""}`)

	recorder, settings := runSettingsChain(t, server.URL)

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "authserver")
	assert.Nil(t, settings, "the next handler must not run with no issuer to validate against")
}

// Pre-existing behaviour, in this file because the fixture is shared and nothing
// else in the repository asserts that a failed fetch stops the chain rather than
// serving a zero-valued Settings.
func TestMiddlewareSettingsCache_AnUnreachableAuthServerIsRefused(t *testing.T) {
	server := settingsServer(t, `{"appName":"A","uiTheme":"light","smtpEnabled":false,"issuer":"https://from-authserver.example"}`)
	baseURL := server.URL
	server.Close()

	recorder, settings := runSettingsChain(t, baseURL)

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "authserver")
	assert.Nil(t, settings, "the next handler must not run without settings")
}
