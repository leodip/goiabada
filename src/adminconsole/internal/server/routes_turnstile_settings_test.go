package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Turnstile settings page tells the administrator which host the widget's hostnames must
// include: the auth server's, whose forms draw the widget, never the console's own. The route table
// hands the page both base URLs side by side, and the handler's own tests pass in a URL of their
// own, so only a request through the routes shows which one the page gets. Swapped, the page names
// the console's host, the widget fails on the auth server's forms, and with the challenge on every
// sign-in is refused (#750).
func TestInitRoutes_TheTurnstilePageNamesTheAuthServersHost(t *testing.T) {
	s, cookies := newSignedInConsole(t, "openid authserver:manage", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/settings/turnstile" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"turnstileEnabled":false,"turnstileSiteKey":"","hasTurnstileSecretKey":false}`))
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/settings/turnstile", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	s.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	page := rec.Body.String()
	assert.Contains(t, page, "must include 127.0.0.1,", "the auth server's host, its httptest server's")
	assert.NotContains(t, page, "must include console.example.test", "never the console's own host")
}
