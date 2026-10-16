package server

import (
	"encoding/gob"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient/oauthclienttest"
	"github.com/leodip/goiabada/adminconsole/internal/publicsettings"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/oauth"
)

// The four admin list pages have shared one handler name since #443, so in initRoutes only the
// package qualifier tells their registrations apart. Two of them swapped would render the wrong
// page and no unit test would notice: each handler's tests call the function directly, and no test
// in this package reaches a list page as a signed-in administrator (#483). Each page is requested
// here through the real route table, past the whole adminAuth chain, against an auth server that
// records which admin API path it is asked for. Swapping any two registrations fails: a page that
// reaches another area's endpoint, or none, does not pass.
func TestInitRoutes_EachAdminListPageReachesItsOwnAreasEndpoint(t *testing.T) {
	signing, _ := oauthclienttest.Keys(t)

	var peerMu sync.Mutex
	var peerPaths []string
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/public/settings":
			_, _ = w.Write([]byte(`{"appName":"Goiabada Test","issuer":"` + oauthclienttest.Issuer + `"}`))
		case "/certs":
			assert.NoError(t, json.NewEncoder(w).Encode(oauth.Jwks{
				Keys: []oauth.Jwk{oauthclienttest.JwkFromPublicKey("key-1", &signing.PublicKey)}}))
		default:
			peerMu.Lock()
			peerPaths = append(peerPaths, r.URL.Path)
			peerMu.Unlock()
			_, _ = w.Write([]byte("{}"))
		}
	}))
	t.Cleanup(authServer.Close)

	cfg := &config.Config{
		AdminConsole: config.AdminConsoleConfig{BaseURL: "https://console.example.test"},
		AuthServer:   config.AuthServerConfig{BaseURL: authServer.URL},
	}
	registry := metrics.NewRegistry()
	upstream := upstreammetrics.Register(registry)
	cache := publicsettings.NewCache(publicsettings.NewClient(authServer.URL, upstream), publicsettings.DefaultTTL, registry)
	store := newTestSessionStore()
	s := NewServer(chi.NewRouter(), store, cache, nil, cfg, oauthclient.NewAuthServerHTTPClient(), nil, registry, upstream)
	s.templateFS = web.TemplateFS()
	s.registerRoutes()

	claims := oauthclienttest.ValidClaims()
	claims["aud"] = builtin.AdminConsoleClientIdentifier
	gob.Register(oauth.TokenResponse{})
	seed := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, err := store.Get(seed, builtin.AdminConsoleSessionName)
	require.NoError(t, err)
	sess.Values[sessionkeys.JWT] = oauth.TokenResponse{
		AccessToken: "an-access-token",
		IdToken:     oauthclienttest.SignRS256(t, signing, "key-1", claims),
		TokenType:   "Bearer",
		Scope:       "openid authserver:manage",
	}
	sess.Values[sessionkeys.JWTExpiresAt] = time.Now().Add(time.Hour).Unix()
	saved := httptest.NewRecorder()
	require.NoError(t, store.Save(seed, saved, sess))

	adminPages := []struct {
		path     string
		endpoint string
	}{
		{"/admin/clients", "/api/v1/admin/clients"},
		{"/admin/resources", "/api/v1/admin/resources"},
		{"/admin/groups", "/api/v1/admin/groups"},
		{"/admin/users", "/api/v1/admin/users/search"},
	}

	for _, page := range adminPages {
		peerMu.Lock()
		peerPaths = nil
		peerMu.Unlock()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, page.path, nil)
		for _, cookie := range saved.Result().Cookies() {
			req.AddCookie(cookie)
		}
		s.router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, "GET %s as a signed-in administrator", page.path)

		peerMu.Lock()
		asked := append([]string(nil), peerPaths...)
		peerMu.Unlock()
		require.Contains(t, asked, page.endpoint, "GET %s asks the admin API for", page.path)
		for _, other := range adminPages {
			if other.endpoint == page.endpoint {
				continue
			}
			assert.NotContains(t, asked, other.endpoint, "GET %s asks the admin API for", page.path)
		}
	}
}
