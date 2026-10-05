package server

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/guard"
)

// The metrics listener and the HTTP metrics on the main router (#400 decisions 3 and 5). The
// listener is reached over a real socket, built by the constructor every listener is built by, so
// what is tested is the handler Start serves on it; the HTTP metrics are read the way a scraper
// reads them, from that handler's exposition after requests through the real chain.

// metricsContentType is the text exposition format 0.0.4's media type, which Prometheus 3 needs to
// accept a scrape (#400 decision 2).
const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"

// newMetricsTestServer is the server main builds, through NewServer, with its routes registered as
// Start registers them. The database answers the settings read the application branch makes, and
// nothing else.
func newMetricsTestServer(t *testing.T) *Server {
	t.Helper()

	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).
		Return(&record.Settings{Id: 1, AppName: "Goiabada"}, nil).Maybe()

	cfg := &config.Config{}
	cfg.AuthServer.ProfilePictureMaxSizeBytes = testProfilePictureMaxSizeBytes

	s := NewServer(chi.NewRouter(), database, newTestSessionStore(), nil, nil, cfg)
	s.registerRoutes()
	return s
}

// get sends one request to addr and answers its status, Content-Type and body.
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
	assert.Contains(t, body, "# TYPE goiabada_http_requests_total counter\n")

	for _, path := range []string{"/debug/pprof/", "/debug/pprof/cmdline", "/debug/vars", "/", "/metrics/", "/health", "/auth/token"} {
		status, _, body := get(t, http.MethodGet, base+path)
		assert.Equal(t, http.StatusNotFound, status, "%s on the metrics listener", path)
		assert.NotContains(t, body, "goiabada_", "%s on the metrics listener", path)
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

// The auth server's registry is held to the metrics catalog on the docs' Monitoring page, in both
// directions (#400 decision 4).
func TestMetricsCatalog_TheAuthServerRegistryIsTheDocumentedOne(t *testing.T) {
	s := newMetricsTestServer(t)

	guard.AssertMetricsCatalog(t, "site/src/content/docs/production-deployment/monitoring.mdx",
		"auth server", s.metrics.Families())
}
