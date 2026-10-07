package server

import (
	"encoding/gob"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/oauth"
)

// The metrics listener and the HTTP metrics on the main router (#400 decisions 3 and 6), the auth
// server's cases for this binary. The listener is reached over a real socket, built by the
// constructor every listener is built by, so what is tested is the handler Start serves on it; the
// HTTP metrics are read the way a scraper reads them, from that handler's exposition after
// requests through the real chain.

// metricsContentType is the text exposition format 0.0.4's media type, which Prometheus 3 needs to
// accept a scrape (#400 decision 2).
const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"

// newMetricsTestServer is the server main builds, over a registry composed as main composes it:
// the upstream recorder and the settings cache register on it before NewServer does. The auth
// server is a local stub answering the public settings, so the application branch serves.
func newMetricsTestServer(t *testing.T) *Server {
	t.Helper()

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"appName":"Goiabada Test","issuer":"https://auth.example.test","uiTheme":"light","smtpEnabled":false}`))
	}))
	t.Cleanup(authServer.Close)

	cfg := &config.Config{
		AdminConsole: config.AdminConsoleConfig{BaseURL: "https://console.example.test"},
		AuthServer:   config.AuthServerConfig{BaseURL: authServer.URL},
	}
	registry := metrics.NewRegistry()
	upstream := upstreammetrics.Register(registry)
	cache := publicsettings.NewCache(publicsettings.NewClient(authServer.URL, upstream), publicsettings.DefaultTTL, registry)

	s := NewServer(chi.NewRouter(), newTestSessionStore(), cache, nil, cfg, nil, nil, registry, upstream)
	s.registerRoutes()
	return s
}

// get sends one request to url and answers its status, Content-Type and body.
func get(t *testing.T, method, url string) (int, string, string) {
	t.Helper()

	req, err := http.NewRequest(method, url, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header.Get("Content-Type"), string(body)
}

// scrape reads the server's exposition through the metrics listener's handler.
func scrape(t *testing.T, s *Server) string {
	t.Helper()

	rec := httptest.NewRecorder()
	metricsHandler(s.metrics).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	return rec.Body.String()
}

// The listener answers GET /metrics with the exposition and 404 for every other path, the two
// paths Go's default mux carries in this binary included (#462). Before the 404s are asserted, the
// default mux is shown to answer them: chi's middleware package links net/http/pprof and expvar,
// which register there, so a listener serving the default mux would answer both with 200.
func TestMetricsListener_ServesTheExpositionAndNothingElse(t *testing.T) {
	for _, path := range []string{"/debug/pprof/", "/debug/vars"} {
		rec := httptest.NewRecorder()
		http.DefaultServeMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, http.StatusOK, rec.Code, "the default mux answers %s in this binary, which is what the 404 below is about", path)
	}

	s := newMetricsTestServer(t)
	served := servedOnLoopback(t, metricsHandler(s.metrics))
	go func() { _ = served.serve() }()
	base := "http://" + served.server.Addr

	status, contentType, body := get(t, http.MethodGet, base+"/metrics")
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, metricsContentType, contentType)
	assert.Contains(t, body, "# TYPE goiabada_build_info gauge\n")
	assert.Contains(t, body, "# TYPE goiabada_upstream_requests_total counter\n")

	for _, path := range []string{"/debug/pprof/", "/debug/pprof/cmdline", "/debug/vars", "/", "/metrics/", "/health", "/admin"} {
		pathStatus, _, pathBody := get(t, http.MethodGet, base+path)
		assert.Equal(t, http.StatusNotFound, pathStatus, "%s on the metrics listener", path)
		assert.NotContains(t, pathBody, "goiabada_", "%s on the metrics listener", path)
	}

	status, _, body = get(t, http.MethodPost, base+"/metrics")
	assert.Equal(t, http.StatusMethodNotAllowed, status, "the listener answers GET /metrics, not a POST")
	assert.NotContains(t, body, "goiabada_")
}

// The main listener has no /metrics: the endpoint is on its own listener so no gateway route
// publishes it (#400 decision 3).
func TestRegisterRoutes_TheMainRouterServesNoMetrics(t *testing.T) {
	s := newMetricsTestServer(t)

	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.NotContains(t, rec.Body.String(), "goiabada_http_requests_total")
}

// Every request the main router answers is counted by its route, method and status, and timed by
// route and method, a request no route answered under unmatched; a panic is counted as the 500 its
// client received, which holds only while the middleware sits above the panic recovery. A scrape,
// served by the metrics listener's own handler, is not a request the main router answered.
func TestRegisterRoutes_CountsTheRequestsTheMainRouterAnswers(t *testing.T) {
	s := newMetricsTestServer(t)
	s.router.Get("/probe/panic", func(http.ResponseWriter, *http.Request) { panic("a handler panicked") })

	for _, req := range []struct {
		target string
		status int
	}{
		{"/health", http.StatusOK},
		{"/health", http.StatusOK},
		{"/no/such/route", http.StatusNotFound},
		{"/probe/panic", http.StatusInternalServerError},
	} {
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, req.target, nil))
		require.Equal(t, req.status, rec.Code, "GET %s", req.target)
	}

	scrape(t, s)
	exposition := scrape(t, s)

	for _, line := range []string{
		`goiabada_http_requests_total{route="/health",method="GET",status="200"} 2`,
		`goiabada_http_requests_total{route="unmatched",method="GET",status="404"} 1`,
		`goiabada_http_requests_total{route="/probe/panic",method="GET",status="500"} 1`,
		`goiabada_http_request_duration_seconds_count{route="/health",method="GET"} 2`,
		`goiabada_http_request_duration_seconds_bucket{route="/health",method="GET",le="60"} 2`,
		`goiabada_build_info{version="development",commit="development"} 1`,
	} {
		assert.Contains(t, exposition, line+"\n")
	}
	assert.Contains(t, exposition, "# TYPE go_goroutines gauge\n")
	assert.Contains(t, exposition, "# TYPE go_memstats_heap_inuse_bytes gauge\n")
	assert.NotContains(t, exposition, `route="/metrics"`, "a scrape is not a request the main router answered")
	assert.Equal(t, 3, strings.Count(exposition, "goiabada_http_requests_total{"),
		"three series and no more: the two scrapes added none")
}

// The route table hands the JWKS fetch and the admin API client the recorder the server was built
// with. A signed-in administrator's request to a page that calls the admin API makes both calls:
// the JWT middleware verifies the stored ID token against the JWKS it fetches, and the page asks
// the admin API for the account's sessions, which this auth server refuses 503.
func TestInitRoutes_TheJWKSFetchAndTheAdminAPIRecordOnTheServersRegistry(t *testing.T) {
	signing, _ := oauthclienttest.Keys(t)
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/public/settings":
			_, _ = w.Write([]byte(`{"appName":"Goiabada Test","issuer":"` + oauthclienttest.Issuer + `"}`))
		case "/certs":
			require.NoError(t, json.NewEncoder(w).Encode(oauth.Jwks{
				Keys: []oauth.Jwk{oauthclienttest.JwkFromPublicKey("key-1", &signing.PublicKey)}}))
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
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
		Scope:       "openid authserver:manage-account",
	}
	sess.Values[sessionkeys.JWTExpiresAt] = time.Now().Add(time.Hour).Unix()
	saved := httptest.NewRecorder()
	require.NoError(t, store.Save(seed, saved, sess))

	req := httptest.NewRequest(http.MethodGet, "/account/sessions", nil)
	for _, cookie := range saved.Result().Cookies() {
		req.AddCookie(cookie)
	}
	s.router.ServeHTTP(httptest.NewRecorder(), req)

	exposition := scrape(t, s)
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="jwks",status="200"} 1`+"\n")
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="admin_api",status="503"} 1`+"\n")
	assert.Contains(t, exposition, `goiabada_upstream_requests_total{target="settings",status="200"} 1`+"\n")
}

// The console's registry, composed as main composes it, is held to the metrics catalog on the
// docs' Monitoring page, in both directions (#400 decision 4).
func TestMetricsCatalog_TheAdminConsoleRegistryIsTheDocumentedOne(t *testing.T) {
	s := newMetricsTestServer(t)

	guard.AssertMetricsCatalog(t, "site/src/content/docs/deploy/monitoring.mdx",
		"admin console", s.metrics.Families())
}
