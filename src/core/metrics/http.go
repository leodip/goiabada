package metrics

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// unmatched is the route a request no route answered is recorded under.
const unmatched = "unmatched"

// standardMethods are the HTTP methods the method label takes; any other token, which reaches the
// router as readily as these do, is recorded as other.
var standardMethods = []string{
	http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
	http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace,
}

// DurationBuckets are the upper bounds, in seconds, of every request duration histogram: the
// requests a server answers and the calls the admin console makes to the auth server. They are
// Prometheus's defaults plus 30 and 60, because the slowest handlers send mail synchronously for up
// to 40 seconds under a 60-second write timeout (#400 decision 5). A fresh copy on every call.
func DurationBuckets() []float64 {
	return []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}
}

// HTTPRequests registers goiabada_http_requests_total and goiabada_http_request_duration_seconds
// on reg and returns the middleware that records every request router answers in them, by route,
// method and status, and its duration by route and method.
//
// The route label's set is router's own route table, read once at the first request or scrape,
// since chi takes its middleware before its routes; a request no route answered is "unmatched".
// The middleware must be mounted on router itself, with Use: chi's routing context, which names
// the route, is not on the request above it. Mount it above the panic recovery, as the request
// logger is, so a panicking request is counted as the 500 its client received.
func HTTPRequests(reg *Registry, router chi.Routes) func(http.Handler) http.Handler {
	routes := sync.OnceValue(func() map[string]bool { return routeTable(router) })
	route := Label{
		name:        "route",
		description: "the route table, `unmatched`",
		described:   true,
		deferred:    true,
		values: func() []string {
			table := make([]string, 0, len(routes()))
			for pattern := range routes() {
				table = append(table, pattern)
			}
			sort.Strings(table)
			return append(table, unmatched)
		},
	}
	method := Enum("method", standardMethods...)
	status := Described("status", "the response's status code", statusCodes()...)

	requests := reg.Counter("goiabada_http_requests_total",
		"HTTP requests answered, by route, method and status code.", route, method, status)
	duration := reg.Histogram("goiabada_http_request_duration_seconds",
		"How long HTTP requests took to answer, by route and method.", DurationBuckets(), route, method)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			started := time.Now()
			returned := false

			// Deferred, so a request whose handler panics past this middleware is still counted.
			defer func() {
				pattern := routePattern(r)
				if !routes()[pattern] {
					pattern = unmatched
				}
				code := wrapped.Status()
				// A handler that returns without writing is answered 200 by net/http, and 200 is
				// what its client received. One that panicked past here received no status, and 0
				// is outside the set, so it counts as other.
				if code == 0 && returned {
					code = http.StatusOK
				}
				requests.Inc(pattern, r.Method, strconv.Itoa(code))
				duration.Observe(time.Since(started).Seconds(), pattern, r.Method)
			}()

			next.ServeHTTP(wrapped, r)
			returned = true
		})
	}
}

// routePattern is the one place the route a request was answered by is read, as chi spells it,
// read after the handler ran. A request no route matched reads "".
func routePattern(r *http.Request) string {
	rctx := chi.RouteContext(r.Context())
	if rctx == nil {
		return ""
	}
	return rctx.RoutePattern()
}

// routeTable is every pattern router answers, spelled as routePattern reads it. chi.Walk joins a
// subrouter's mount pattern to its routes and collapses the wildcard between them once; the route
// context also trims a trailing slash, so "/auth" with a "/" route reads "/auth" there and
// "/auth/" here. normalizeRoute applies the route context's rules to what Walk returns.
func routeTable(router chi.Routes) map[string]bool {
	table := map[string]bool{}
	// The walk function returns no error, so Walk returns none.
	_ = chi.Walk(router, func(_ string, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		table[normalizeRoute(pattern)] = true
		return nil
	})
	return table
}

// normalizeRoute mirrors chi's Context.RoutePattern on a joined pattern.
func normalizeRoute(pattern string) string {
	for strings.Contains(pattern, "/*/") {
		pattern = strings.ReplaceAll(pattern, "/*/", "/")
	}
	if pattern != "/" {
		pattern = strings.TrimSuffix(pattern, "//")
		pattern = strings.TrimSuffix(pattern, "/")
	}
	return pattern
}

// statusCodes is every three-digit code from 100 to 599: the status label's set. The status a
// response carries is the server's choice, so the set bounds the label without listing the codes
// either server happens to send today.
func statusCodes() []string {
	codes := make([]string, 0, 500)
	for code := 100; code <= 599; code++ {
		codes = append(codes, strconv.Itoa(code))
	}
	return codes
}
