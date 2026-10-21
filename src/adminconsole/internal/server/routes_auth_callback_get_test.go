package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/metrics"
)

// A browser that reaches the console's OAuth callback by GET -- a bookmark, the history, a pasted
// address -- is a person at a dead end: the callback takes the auth server's form_post, and the
// route answered every other method with a bare 405, an empty body with nothing to do next. The GET
// now draws the sign-in error page every other dead end here draws, at the same honest 405 with
// the same Allow header, so the person is told the sign-in cannot be finished this way and offered
// the start-again button (#632 item 3).
func TestRoutes_TheCallbackReachedByGetAnswersTheSignInErrorPage(t *testing.T) {
	logtest.CaptureSlog(t)

	cfg := &config.Config{
		AdminConsole: config.AdminConsoleConfig{BaseURL: "https://console.example.test", OAuthClientSecret: "the-secret"},
		AuthServer:   config.AuthServerConfig{BaseURL: "https://auth.example.test"},
	}
	tokenClient := oauthclient.NewTokenClient(
		oauthclient.TokenEndpointURL(cfg.AuthServer.GetEffectiveBaseURL()),
		builtin.AdminConsoleClientIdentifier, cfg.AdminConsole.OAuthClientSecret, http.DefaultClient, nil)

	s := NewServer(chi.NewRouter(), newTestSessionStore(), nil, nil, cfg, http.DefaultClient, nil, tokenClient, metrics.NewRegistry(), nil)
	s.initRoutes(s.router)

	get := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	get = get.WithContext(reqctx.WithSettings(get.Context(),
		&api.PublicSettingsResponse{AppName: "Goiabada Test", UITheme: "light", Issuer: "https://auth.example.test"}))
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, get)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code, "the method is still wrong, so the status stays honest")
	assert.Equal(t, http.MethodPost, w.Header().Get("Allow"),
		"the 405 keeps naming the one method the route takes")
	body := w.Body.String()
	assert.Contains(t, body, "This sign-in can&#39;t be finished",
		"the GET draws the sign-in error page's title rather than a blank body")
	assert.Contains(t, body, "This address receives the auth server&#39;s answer to a sign-in",
		"the page names why it cannot be opened on its own")
	assert.Contains(t, body, "Start again",
		"the page offers the way on every other dead end here draws")
}
