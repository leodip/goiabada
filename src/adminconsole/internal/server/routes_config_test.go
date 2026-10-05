package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/publicsettings"
	"github.com/leodip/goiabada/core/metrics"
)

// The route table hands each handler the values it uses from the configuration the server was
// built with, which the handlers' own tests cannot see: each is given its value directly. The home
// page is the one that tells the auth server's two base URLs apart, linking to the public one,
// which a browser can reach, while the console calls the auth server at the internal one. Both are
// set and differ here, so a route table handing the page the internal URL, or a page still reading
// a default, fails (#441).
func TestInitRoutes_TheHomePageLinksToTheConfiguredPublicAuthServerURL(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"appName":"Goiabada Test","issuer":"https://auth.example.test","uiTheme":"light","smtpEnabled":false}`))
	}))
	t.Cleanup(authServer.Close)

	cfg := &config.Config{
		AdminConsole: config.AdminConsoleConfig{BaseURL: "https://console.example.test"},
		AuthServer: config.AuthServerConfig{
			BaseURL:         "https://auth.example.test",
			InternalBaseURL: authServer.URL,
		},
	}
	s := NewServer(chi.NewRouter(), newTestSessionStore(),
		publicsettings.NewCache(publicsettings.NewClient(authServer.URL, nil), publicsettings.DefaultTTL, metrics.NewRegistry()), nil, cfg, nil, nil, metrics.NewRegistry(), nil)
	s.initRoutes(s.initMiddleware())

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	body, err := io.ReadAll(recorder.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), `href="https://auth.example.test/.well-known/openid-configuration"`)
	assert.NotContains(t, string(body), authServer.URL, "the page links to an address only the console can reach")
}
