package metrics_test

// Seam: a chi router with the request middleware mounted the way both servers mount it, above
// chi's Recoverer, driven with real requests and read back through a scrape. The router has a
// parameterized route, a subrouter from Route, a mounted subrouter, a route that panics and one
// that returns without writing, which are the shapes whose route label is not simply the path.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/metrics"
)

func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

// newInstrumentedRouter builds the fixture router. The middleware is mounted before any route,
// which chi requires, and reads the route table once the routes exist.
func newInstrumentedRouter(reg *metrics.Registry) *chi.Mux {
	r := chi.NewRouter()
	r.Use(metrics.HTTPRequests(reg, r))
	r.Use(chimiddleware.Recoverer)

	r.Get("/health", ok)
	r.Get("/users/{id}", ok)
	r.Get("/panic", func(http.ResponseWriter, *http.Request) { panic("boom") })
	r.Get("/silent", func(http.ResponseWriter, *http.Request) {})
	r.Route("/auth", func(sr chi.Router) {
		sr.Get("/", ok)
		sr.Post("/token", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) })
	})
	api := chi.NewRouter()
	api.Get("/clients/{id}", ok)
	r.Mount("/api", api)
	return r
}

func serve(t *testing.T, h http.Handler, method, target string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec.Code
}

func TestHTTPRequests_RecordsByRouteMethodAndStatus(t *testing.T) {
	reg := metrics.NewRegistry()
	router := newInstrumentedRouter(reg)

	// The status each request is answered with is asserted too, so the expectations below are
	// about the requests this test thinks it sent.
	for _, req := range []struct {
		method, target string
		status         int
	}{
		{http.MethodGet, "/users/42", 200},
		{http.MethodGet, "/users/43", 200},
		{http.MethodGet, "/health", 200},
		{http.MethodGet, "/auth", 200},
		{http.MethodPost, "/auth/token", 400},
		{http.MethodGet, "/api/clients/7", 200},
		{http.MethodGet, "/silent", 200},
		{http.MethodGet, "/panic", 500},
		{http.MethodGet, "/nope/abc", 404},
		{http.MethodGet, "/api/nope", 404},
		{http.MethodPost, "/health", 405},
		{"FOO", "/health", 405},
		{"get", "/health", 405},
	} {
		require.Equal(t, req.status, serve(t, router, req.method, req.target), "%s %s", req.method, req.target)
	}

	assert.Equal(t, []string{
		`goiabada_http_requests_total{route="/api/clients/{id}",method="GET",status="200"} 1`,
		`goiabada_http_requests_total{route="/auth",method="GET",status="200"} 1`,
		`goiabada_http_requests_total{route="/auth/token",method="POST",status="400"} 1`,
		`goiabada_http_requests_total{route="/health",method="GET",status="200"} 1`,
		// A panicking request counts as the 500 the client received, because Recoverer writes it
		// through the writer this middleware wrapped.
		`goiabada_http_requests_total{route="/panic",method="GET",status="500"} 1`,
		// A handler that writes nothing is answered 200 by net/http, and that is what it counts as.
		`goiabada_http_requests_total{route="/silent",method="GET",status="200"} 1`,
		`goiabada_http_requests_total{route="/users/{id}",method="GET",status="200"} 2`,
		// No route matched: an unknown path, an unknown path under a mounted subrouter, a known
		// path under a method it does not answer, and a method chi does not know. The method is a
		// standard verb or other, since any token reaches the router and HTTP methods are case
		// sensitive.
		`goiabada_http_requests_total{route="unmatched",method="GET",status="404"} 2`,
		`goiabada_http_requests_total{route="unmatched",method="POST",status="405"} 1`,
		`goiabada_http_requests_total{route="unmatched",method="other",status="405"} 2`,
	}, lines(scrape(t, reg), "goiabada_http_requests_total{"))
}

func TestHTTPRequests_RecordsDurationByRouteAndMethod(t *testing.T) {
	reg := metrics.NewRegistry()
	router := newInstrumentedRouter(reg)

	serve(t, router, http.MethodGet, "/users/1")
	serve(t, router, http.MethodGet, "/users/2")
	serve(t, router, http.MethodGet, "/nope")

	body := scrape(t, reg)
	assert.Equal(t, []string{
		`goiabada_http_request_duration_seconds_count{route="/users/{id}",method="GET"} 2`,
		`goiabada_http_request_duration_seconds_count{route="unmatched",method="GET"} 1`,
	}, lines(body, "goiabada_http_request_duration_seconds_count{"))

	// The buckets are Prometheus's defaults plus 30 and 60 seconds, because the slowest handlers
	// send mail synchronously for up to 40 seconds under a 60-second write timeout. Only the
	// boundaries are read here: which bucket a fast request lands in is the scheduler's, and the
	// test below times a request it controls.
	var les []string
	for _, line := range lines(body, `goiabada_http_request_duration_seconds_bucket{route="/users/{id}",method="GET",le=`) {
		le, _, _ := strings.Cut(strings.TrimPrefix(line, `goiabada_http_request_duration_seconds_bucket{route="/users/{id}",method="GET",le=`), "}")
		les = append(les, le)
	}
	assert.Equal(t, []string{
		`"0.005"`, `"0.01"`, `"0.025"`, `"0.05"`, `"0.1"`, `"0.25"`, `"0.5"`, `"1"`, `"2.5"`, `"5"`, `"10"`, `"30"`, `"60"`, `"+Inf"`,
	}, les)
	assert.Contains(t, body, `goiabada_http_request_duration_seconds_bucket{route="/users/{id}",method="GET",le="+Inf"} 2`+"\n")

	assert.Equal(t, []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}, metrics.DurationBuckets())
}

// slowHandlerDelay is how long the slow route below takes. Long enough that no fast-path bucket can
// hold it, short enough that a loaded test machine still finishes it inside the one-second bucket.
const slowHandlerDelay = 100 * time.Millisecond

// A request's duration is the time its handler took, in seconds: a handler sleeping 100 ms is
// observed above the 0.05 bucket and inside the one-second one, and the sum is at least the sleep.
// An observation of zero, or one in milliseconds, fails both.
func TestHTTPRequests_RecordsTheElapsedTimeInSeconds(t *testing.T) {
	reg := metrics.NewRegistry()
	r := chi.NewRouter()
	r.Use(metrics.HTTPRequests(reg, r))
	r.Get("/slow", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(slowHandlerDelay)
		w.WriteHeader(http.StatusOK)
	})

	require.Equal(t, http.StatusOK, serve(t, r, http.MethodGet, "/slow"))

	body := scrape(t, reg)
	const series = `goiabada_http_request_duration_seconds`
	const labels = `{route="/slow",method="GET"`
	sum := sampleValue(t, body, series+"_sum"+labels+"}")
	assert.GreaterOrEqual(t, sum, slowHandlerDelay.Seconds())
	assert.Less(t, sum, 1.0, "a 100 ms handler observed in seconds, with a generous margin for the scheduler")
	assert.Contains(t, body, series+"_bucket"+labels+`,le="0.05"} 0`+"\n")
	assert.Contains(t, body, series+"_bucket"+labels+`,le="1"} 1`+"\n")
	assert.Contains(t, body, series+"_count"+labels+"} 1\n")
}

// DurationBuckets hands out a copy, so a caller appending to or editing its slice cannot change
// another family's buckets.
func TestDurationBuckets_IsAFreshCopy(t *testing.T) {
	first := metrics.DurationBuckets()
	first[0] = 99

	assert.InDelta(t, 0.005, metrics.DurationBuckets()[0], 0)
}

// The value sets the two families declare: the router's own route table and unmatched, the
// standard methods, and the status codes. This is what the catalog check holds to the docs.
func TestHTTPRequests_DeclaresTheRouteTable(t *testing.T) {
	reg := metrics.NewRegistry()
	newInstrumentedRouter(reg)

	families := reg.Families()

	require.Len(t, families, 2)
	duration, requests := families[0], families[1]
	assert.Equal(t, "goiabada_http_request_duration_seconds", duration.Name)
	assert.Equal(t, "histogram", duration.Type)
	assert.Equal(t, "goiabada_http_requests_total", requests.Name)
	assert.Equal(t, "counter", requests.Type)

	require.Len(t, requests.Labels, 3)
	route, method, status := requests.Labels[0], requests.Labels[1], requests.Labels[2]

	assert.Equal(t, "route", route.Name())
	assert.Equal(t, "the route table, `unmatched`", route.Description())
	assert.Equal(t, []string{
		"/api/clients/{id}", "/auth", "/auth/token", "/health", "/panic", "/silent", "/users/{id}", "unmatched",
	}, route.Values())

	assert.Equal(t, "method", method.Name())
	assert.Empty(t, method.Description())
	assert.Equal(t, []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "OPTIONS", "TRACE"}, method.Values())

	assert.Equal(t, "status", status.Name())
	assert.Equal(t, "the response's status code", status.Description())
	assert.Len(t, status.Values(), 500)
	assert.Equal(t, "100", status.Values()[0])
	assert.Equal(t, "599", status.Values()[499])

	require.Len(t, duration.Labels, 2)
	assert.Equal(t, route.Values(), duration.Labels[0].Values())
	assert.Equal(t, "method", duration.Labels[1].Name())
}
