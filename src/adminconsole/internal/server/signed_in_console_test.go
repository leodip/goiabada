package server

import (
	"encoding/gob"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/oauth"
)

// newSignedInConsole is the real route table over a registry composed as main composes it, and the
// cookies of a session it accepts: a signed ID token for the console's client and a token response
// granting scope, past the whole adminAuth chain. The auth server behind it answers the public
// settings and the JWKS itself and hands every other request, the admin API's, to adminAPI. The
// tests that reach a page as a signed-in user build that user here, so a change to what the console
// accepts as a session is made once.
func newSignedInConsole(t *testing.T, scope string, adminAPI http.HandlerFunc) (*Server, []*http.Cookie) {
	t.Helper()
	signing, _ := oauthclienttest.Keys(t)
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/public/settings":
			_, _ = w.Write([]byte(`{"appName":"Goiabada Test","issuer":"` + oauthclienttest.Issuer + `"}`))
		case "/certs":
			assert.NoError(t, json.NewEncoder(w).Encode(oauth.Jwks{
				Keys: []oauth.Jwk{oauthclienttest.JwkFromPublicKey("key-1", &signing.PublicKey)}}))
		default:
			adminAPI(w, r)
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
		Scope:       scope,
	}
	sess.Values[sessionkeys.JWTExpiresAt] = time.Now().Add(time.Hour).Unix()
	saved := httptest.NewRecorder()
	require.NoError(t, store.Save(seed, saved, sess))
	return s, saved.Result().Cookies()
}
