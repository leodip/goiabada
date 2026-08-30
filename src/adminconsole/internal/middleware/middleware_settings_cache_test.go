package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/cache"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/i18n"
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

	return runSettingsChainForRequest(t, authServerBaseURL,
		httptest.NewRequest(http.MethodGet, "/admin/clients", nil))
}

// runSettingsChainForRequest is the same with the caller's request, and with the
// locale middleware in front of the settings cache exactly as Server.initMiddleware
// mounts it.
//
// That order is the point rather than a detail of the fixture. Both refusals below
// render through i18n.T, which reads the localizer off the context, and until #285
// this middleware ran first: there was no localizer to read and an administrator
// whose browser asked for pt-BR was told in English that their auth server needed
// upgrading. TestInitMiddleware_RefusalsAreLocalized in internal/server pins the
// real chain; this fixture pins that the middleware honours a localizer when one is
// there.
func runSettingsChainForRequest(t *testing.T, authServerBaseURL string, req *http.Request) (*httptest.ResponseRecorder, *models.Settings) {
	t.Helper()

	var seen *models.Settings
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		settings, ok := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		require.True(t, ok, "the middleware must put *models.Settings on the context")
		seen = settings
		w.WriteHeader(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	i18n.MiddlewareLocale(nil)(
		MiddlewareSettingsCache(cache.NewSettingsCache(authServerBaseURL))(next),
	).ServeHTTP(recorder, req)

	return recorder, seen
}

// wantBody reads the message from the catalog rather than repeating it here, so
// rewording an entry does not fail the suite while a middleware that stopped
// rendering that entry still does.
func wantBody(t *testing.T, locale, key string) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/?ui_locales="+locale, nil)
	return i18n.T(i18n.ResolveRequestLocale(req.Context(), req), key)
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
	assert.Equal(t, wantBody(t, "en", "adminconsole.error.issuer_missing"), strings.TrimSpace(recorder.Body.String()))
	assert.Nil(t, settings, "the next handler must not run with no issuer to validate against")
}

func TestMiddlewareSettingsCache_EmptyIssuerIsRefused(t *testing.T) {
	server := settingsServer(t, `{"appName":"A","uiTheme":"light","smtpEnabled":false,"issuer":""}`)

	recorder, settings := runSettingsChain(t, server.URL)

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Equal(t, wantBody(t, "en", "adminconsole.error.issuer_missing"), strings.TrimSpace(recorder.Body.String()))
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
	assert.Equal(t, wantBody(t, "en", "adminconsole.error.settings_unavailable"), strings.TrimSpace(recorder.Body.String()))
	assert.Nil(t, settings, "the next handler must not run without settings")
}

// Both refusals in the caller's language. Each row asserts the Portuguese entry
// and, separately, that it differs from the English one: without that second
// assertion a middleware that ignored the localizer entirely would still pass here
// on any key whose two translations happened to match.
func TestMiddlewareSettingsCache_RefusalsAreLocalized(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		// closed is the unreachable-auth-server case, which has no payload to serve.
		closed bool
		key    string
	}{
		{
			name:    "an auth server too old to report an issuer",
			payload: `{"appName":"A","uiTheme":"light","smtpEnabled":false}`,
			key:     "adminconsole.error.issuer_missing",
		},
		{
			name:   "an auth server that cannot be reached",
			closed: true,
			key:    "adminconsole.error.settings_unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := settingsServer(t, tt.payload)
			baseURL := server.URL
			if tt.closed {
				server.Close()
			}

			req := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
			req.Header.Set("Accept-Language", "pt-BR")

			recorder, settings := runSettingsChainForRequest(t, baseURL, req)

			ptBR := wantBody(t, "pt-BR", tt.key)
			require.NotEqual(t, wantBody(t, "en", tt.key), ptBR,
				"the two catalogs answer this key identically, so this case cannot tell a "+
					"localized refusal from an unlocalized one; pick another key or reword one entry")

			assert.Equal(t, http.StatusInternalServerError, recorder.Code)
			assert.Equal(t, ptBR, strings.TrimSpace(recorder.Body.String()))
			assert.Nil(t, settings)
		})
	}
}

// The transport error used to be interpolated into the response and logged
// nowhere. It names the auth server's address and whatever the dial failed with,
// which is the operator's to read in the log and not the administrator's to read on
// a page they cannot act on.
func TestMiddlewareSettingsCache_TheFetchErrorStaysOutOfTheResponse(t *testing.T) {
	server := settingsServer(t, `{"appName":"A","uiTheme":"light","smtpEnabled":false,"issuer":"https://from-authserver.example"}`)
	baseURL := server.URL
	server.Close()

	recorder, _ := runSettingsChain(t, baseURL)

	body := recorder.Body.String()
	assert.NotContains(t, body, baseURL, "the response must not name the auth server's address")
	assert.NotContains(t, body, "connection refused")
	assert.NotContains(t, body, "dial tcp")
}
