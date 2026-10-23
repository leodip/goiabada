package metrics

import (
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/leodip/goiabada/core/httpmw/statuswriter"
	"github.com/leodip/goiabada/core/routing"
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
// since the router takes its middleware before its routes; the router names each route in chi's
// spelling, so the label values are the ones chi gave (#462 decision 5). A request no route
// answered, a 404, a 405 or one a group's middleware answered before any route, is "unmatched".
// Mount it with Use on router itself, above the panic recovery, as the request logger is, so a
// panicking request is counted as the 500 its client received.
func HTTPRequests(reg *Registry, router *routing.Router) func(http.Handler) http.Handler {
	return httpRequests(reg, func() map[string]bool {
		table := map[string]bool{}
		// The walk function returns no error, so Walk returns none.
		_ = router.Walk(func(_ string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			table[route] = true
			return nil
		})
		return table
	}, routing.RouteName)
}

// httpRequests registers the two families and returns the middleware recording into them, with
// the route label's set read from table once and each request's route read by routeOf after its
// handler ran.
func httpRequests(reg *Registry, table func() map[string]bool, routeOf func(*http.Request) string) func(http.Handler) http.Handler {
	routes := sync.OnceValue(table)
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
			wrapped := statuswriter.Wrap(w)
			started := time.Now()
			returned := false

			// Deferred, so a request whose handler panics past this middleware is still counted.
			defer func() {
				pattern := routeOf(r)
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
