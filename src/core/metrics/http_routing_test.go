package metrics_test

// Seam: the request middleware mounted on core/routing's router the way both servers will mount it,
// above httpmw.Recoverer, driven with real requests and read back through a scrape. The same shapes
// as the chi fixture beside it, plus a group whose guard answers before any route, until #462's
// slice 8 removes the chi form.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/httpmw"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/routing"
)

func newInstrumentedRoutingRouter(reg *metrics.Registry) *routing.Router {
	r := routing.New()
	r.Use(metrics.HTTPRequestsOn(reg, r))
	r.Use(httpmw.Recoverer)

	r.Get("/health", ok)
	r.Get("/users/{id}", ok)
	r.Get("/panic", func(http.ResponseWriter, *http.Request) { panic("boom") })
	r.Get("/silent", func(http.ResponseWriter, *http.Request) {})
	r.Route("/auth", func(sr *routing.Router) {
		sr.Get("/", ok)
		sr.Post("/token", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) })
	})
	r.Route("/api", func(api *routing.Router) {
		api.Get("/clients/{id}", ok)
	})
	r.Route("/admin", func(admin *routing.Router) {
		admin.Use(func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
		})
		admin.Get("/clients", ok)
	})
	r.Get("/static/*", ok)
	return r
}

func TestHTTPRequestsOn_RecordsByRouteMethodAndStatus(t *testing.T) {
	reg := metrics.NewRegistry()
	router := newInstrumentedRoutingRouter(reg)

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
		{http.MethodGet, "/static/css/main.css", 200},
		{http.MethodGet, "/silent", 200},
		{http.MethodGet, "/panic", 500},
		{http.MethodGet, "/nope/abc", 404},
		{http.MethodGet, "/api/nope", 404},
		{http.MethodPost, "/health", 405},
		{"FOO", "/health", 405},
		{"get", "/health", 405},
		{http.MethodGet, "/admin/clients", 401},
	} {
		require.Equal(t, req.status, serve(t, router, req.method, req.target), "%s %s", req.method, req.target)
	}

	assert.Equal(t, []string{
		`goiabada_http_requests_total{route="/api/clients/{id}",method="GET",status="200"} 1`,
		`goiabada_http_requests_total{route="/auth",method="GET",status="200"} 1`,
		`goiabada_http_requests_total{route="/auth/token",method="POST",status="400"} 1`,
		`goiabada_http_requests_total{route="/health",method="GET",status="200"} 1`,
		`goiabada_http_requests_total{route="/panic",method="GET",status="500"} 1`,
		`goiabada_http_requests_total{route="/silent",method="GET",status="200"} 1`,
		`goiabada_http_requests_total{route="/static/*",method="GET",status="200"} 1`,
		`goiabada_http_requests_total{route="/users/{id}",method="GET",status="200"} 2`,
		// A group's guard answered before any route, as chi's subrouter middleware did.
		`goiabada_http_requests_total{route="unmatched",method="GET",status="401"} 1`,
		`goiabada_http_requests_total{route="unmatched",method="GET",status="404"} 2`,
		`goiabada_http_requests_total{route="unmatched",method="POST",status="405"} 1`,
		`goiabada_http_requests_total{route="unmatched",method="other",status="405"} 2`,
	}, lines(scrape(t, reg), "goiabada_http_requests_total{"))
}

func TestHTTPRequestsOn_DeclaresTheRouteTable(t *testing.T) {
	reg := metrics.NewRegistry()
	newInstrumentedRoutingRouter(reg)

	families := reg.Families()
	require.Len(t, families, 2)
	requests := families[1]
	require.Equal(t, "goiabada_http_requests_total", requests.Name)
	route := requests.Labels[0]

	assert.Equal(t, "route", route.Name())
	assert.Equal(t, "the route table, `unmatched`", route.Description())
	assert.Equal(t, []string{
		"/admin/clients", "/api/clients/{id}", "/auth", "/auth/token", "/health", "/panic", "/silent",
		"/static/*", "/users/{id}", "unmatched",
	}, route.Values())
}
