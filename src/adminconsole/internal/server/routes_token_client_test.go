package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

// recordingTransport records every request the HTTP client it sits in sends, then sends it.
type recordingTransport struct {
	mu   sync.Mutex
	seen []string
}

func (t *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.seen = append(t.seen, r.Method+" "+r.URL.Path)
	t.mu.Unlock()
	return http.DefaultTransport.RoundTrip(r)
}

func (t *recordingTransport) requests() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.seen...)
}

// The sign-in's code exchange and its JWKS fetch go through the token client and the HTTP client
// the server was handed, the pair main also hands the session token source, rather than through a
// pair the route table builds for itself. The internal base URL ends in a slash, which a route
// table appending "/auth/token" to it turned into "//auth/token" while the session token source
// reached "/auth/token": two constructions of one client, drifting (#441).
func TestInitRoutes_TheSignInUsesTheTokenClientTheServerWasHanded(t *testing.T) {
	logtest.CaptureSlog(t)

	var mu sync.Mutex
	var peerPaths []string
	// An RS256 header naming a key the JWKS does not hold, so the parser fetches /certs before it
	// refuses the token: the sign-in fails, and what is measured is where it sent its requests.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"absent","typ":"JWT"}`))
	idToken := header + "." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + ".c2ln"
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		peerPaths = append(peerPaths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /auth/token":
			_, _ = w.Write([]byte(`{"access_token":"at","id_token":"` + idToken + `","expires_in":3600}`))
		case "GET /certs":
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(peer.Close)

	cfg := &config.Config{
		AdminConsole: config.AdminConsoleConfig{BaseURL: "https://console.example.test", OAuthClientSecret: "the-secret"},
		AuthServer:   config.AuthServerConfig{BaseURL: "https://auth.example.test", InternalBaseURL: peer.URL + "/"},
	}
	transport := &recordingTransport{}
	httpClient := &http.Client{Transport: transport, Timeout: oauthclient.TokenExchangeTimeout}
	tokenClient := oauthclient.NewTokenClient(oauthclient.TokenEndpointURL(cfg.AuthServer.GetEffectiveBaseURL()), builtin.AdminConsoleClientIdentifier, cfg.AdminConsole.OAuthClientSecret, httpClient, nil)

	s := NewServer(chi.NewRouter(), newTestSessionStore(), nil, nil, cfg, httpClient, tokenClient, metrics.NewRegistry(), nil)
	s.initRoutes(s.router)

	start := httptest.NewRecorder()
	s.router.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/admin/clients", nil))
	require.Equal(t, http.StatusFound, start.Code)
	destination, err := url.Parse(start.Header().Get("Location"))
	require.NoError(t, err)
	state := destination.Query().Get("state")
	require.NotEmpty(t, state, "the authorize redirect carries a state")

	form := url.Values{"state": {state}, "code": {"the-code"}}
	callback := httptest.NewRequest(http.MethodPost, "/auth/callback", strings.NewReader(form.Encode()))
	callback.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range start.Result().Cookies() {
		callback.AddCookie(c)
	}
	callback = callback.WithContext(reqctx.WithSettings(callback.Context(),
		&api.PublicSettingsResponse{AppName: "Goiabada Test", UITheme: "light", Issuer: "https://auth.example.test"}))
	s.router.ServeHTTP(httptest.NewRecorder(), callback)

	assert.Equal(t, []string{"POST /auth/token", "GET /certs"}, transport.requests(),
		"the exchange and the JWKS fetch go through the HTTP client the server was handed")
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"POST /auth/token", "GET /certs"}, peerPaths,
		"the exchange reaches the token endpoint at its canonical path")
}
