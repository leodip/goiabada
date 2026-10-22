package server

import (
	"fmt"
	"log/slog"
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
// the start-again button (#632 item 3). Every other method but POST gets the same answer, and the
// same Allow: POST: chi's own 405 would name every method registered on the path, so once GET had
// a route of its own it advertised GET, which RFC 9110 section 15.5.6 forbids when GET is refused.
func TestRoutes_TheCallbackByAnyMethodButPostAnswersTheSignInErrorPage(t *testing.T) {
	cfg := &config.Config{
		AdminConsole: config.AdminConsoleConfig{BaseURL: "https://console.example.test", OAuthClientSecret: "the-secret"},
		AuthServer:   config.AuthServerConfig{BaseURL: "https://auth.example.test"},
	}
	tokenClient := oauthclient.NewTokenClient(
		oauthclient.TokenEndpointURL(cfg.AuthServer.GetEffectiveBaseURL()),
		builtin.AdminConsoleClientIdentifier, cfg.AdminConsole.OAuthClientSecret, http.DefaultClient, nil)

	s := NewServer(chi.NewRouter(), newTestSessionStore(), nil, nil, cfg, http.DefaultClient, nil, tokenClient, metrics.NewRegistry(), nil)
	s.initRoutes(s.router)

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete,
		http.MethodPatch, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)
			req := httptest.NewRequest(method, "/auth/callback", nil)
			req = req.WithContext(reqctx.WithSettings(req.Context(),
				&api.PublicSettingsResponse{AppName: "Goiabada Test", UITheme: "light", Issuer: "https://auth.example.test"}))
			w := httptest.NewRecorder()
			s.router.ServeHTTP(w, req)

			require.Equal(t, http.StatusMethodNotAllowed, w.Code, "the method is still wrong, so the status stays honest")
			assert.Equal(t, []string{http.MethodPost}, w.Header().Values("Allow"),
				"the 405 names the one method the route takes, and only it")
			records := capture.Records()
			require.Len(t, records, 1, "the refusal is logged once")
			assert.Equal(t, slog.LevelWarn, records[0].Level, "a person at a bookmark pages nobody")
			assert.Equal(t, "sign-in refused", records[0].Message)
			assert.Contains(t, fmt.Sprint(records[0].Attrs["error"]), "the callback was reached by "+method,
				"the log names the method that reached the callback")
			if method != http.MethodGet {
				return
			}
			body := w.Body.String()
			assert.Contains(t, body, "This sign-in can&#39;t be finished",
				"the GET draws the sign-in error page's title rather than a blank body")
			assert.Contains(t, body, "This address receives the auth server&#39;s answer to a sign-in",
				"the page names why it cannot be opened on its own")
			assert.Contains(t, body, "Start again",
				"the page offers the way on every other dead end here draws")
		})
	}
}
