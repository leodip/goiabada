package server

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

// TestInitRoutes_EveryApiRouteRefusesToBeStored is goal 5 of #247, and it is the reason this seam
// exists rather than a pair of spot checks: the route set comes from the router, so a route or a
// whole group added under /api/v1/ later is covered without this file being edited.
//
// The claim is that MiddlewareNoStore is mounted on every API group, in a position early enough to
// cover refusals as well as successes. Neither the middleware's own table in src/core/middleware
// nor any handler test can make it. The table composes the middleware around a handler by hand,
// which is exactly the arrangement that keeps passing when the r.Use line disappears from
// routes.go; routes_ratelimiter_test.go's own header records the same lesson for the limiters,
// where removing any one of twelve wrappers left the whole module suite green.
//
// Every route is called WITHOUT credentials, which is deliberate on two counts. It is the case the
// mount position exists for, since RFC 6749 section 5.1's "other sensitive information" covers a
// refusal body and emitAuthError commits its own status; and it means no handler is ever reached,
// so the database mock needs no expectations and this test does not break when a handler changes.
//
// WHAT THIS DOES NOT OWN, and must not be described as owning (decision 16). It builds initRoutes
// alone, so it cannot observe any response the four middleware mounted in initMiddleware produce
// without calling next: a CORS preflight, which MiddlewareCors answers 200 itself; a settings
// lookup failure's 500; MiddlewareCookieReset's redirect on a cookie it cannot decode; and
// MiddlewareSessionIdentifier's return on a session-store error. Those four ship with neither
// header field. None of them carries a credential, so RFC 6749 section 5.1 does not reach them.
// This test is exhaustive over the routes the router registers, and it is not exhaustive over the
// API's whole response surface.
func TestInitRoutes_EveryApiRouteRefusesToBeStored(t *testing.T) {
	s := newRoutesTestServer(t)

	type apiRoute struct {
		method  string
		pattern string
		target  string
		// first is the runtime name of the first middleware in this route's chain, which is
		// what says the mount is ahead of every guard rather than merely present.
		first string
	}
	var routes []apiRoute

	err := chi.Walk(s.router, func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		if !strings.HasPrefix(route, "/api/v1/") {
			return nil
		}
		var first string
		if len(middlewares) > 0 {
			first = runtime.FuncForPC(reflect.ValueOf(middlewares[0]).Pointer()).Name()
		}
		routes = append(routes, apiRoute{method: method, pattern: route, target: routeTestTarget(route), first: first})
		return nil
	})
	assert.NoError(t, err)

	// A chi.Walk that silently enumerated nothing would make every assertion below vacuous, and
	// so would a walk that reached one group and not the other. Both prefixes are named because
	// the mount is two separate r.Use lines and losing either one is the failure this catches.
	assert.NotEmpty(t, routes, "chi.Walk found no /api/v1/ routes, so this test asserts nothing")
	var sawAdmin, sawAccount bool
	for _, rt := range routes {
		switch {
		case strings.HasPrefix(rt.pattern, "/api/v1/admin/"):
			sawAdmin = true
		case strings.HasPrefix(rt.pattern, "/api/v1/account/"):
			sawAccount = true
		}
	}
	assert.True(t, sawAdmin, "no /api/v1/admin route was enumerated")
	assert.True(t, sawAccount, "no /api/v1/account route was enumerated")

	for _, rt := range routes {
		t.Run(rt.method+" "+rt.pattern, func(t *testing.T) {
			recorder := serve(s, withRoutesTestSettings(httptest.NewRequest(rt.method, rt.target, nil)))
			result := recorder.Result()
			defer func() { _ = result.Body.Close() }()

			// The status says the request reached the group's guards rather than falling
			// out of the router: a 404 from a botched parameter substitution would still
			// carry the header, because the group's middleware runs ahead of the
			// subrouter's NotFound handler, and the header assertion alone would not
			// notice. 401 is the unauthenticated refusal; 403 is what an insufficient
			// scope produces on the routes that check scope before token presence.
			assert.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, result.StatusCode,
				"an unauthenticated request must be refused by a guard, not answered or lost")

			// Result().Header, never recorder.Header(): the refusals commit their status
			// with WriteHeader, which is exactly the case where the live map and the
			// snapshot a client receives disagree.
			assert.Equal(t, "no-store", result.Header.Get("Cache-Control"),
				"every route under /api/v1 must tell caches not to store its response")
			assert.Equal(t, "no-cache", result.Header.Get("Pragma"),
				"RFC 6749 section 5.1 requires the Pragma field alongside Cache-Control")

			// FIRST, not merely present, and this is the only assertion that says so.
			//
			// The sweep above sends no credentials, so it only ever reaches a refusal
			// written by a per-route scope guard. Two group middleware sit ahead of that
			// and can write a response of their own: RequireValidSession rejects a token
			// that parses but names no subject or whose session was terminated. Moving
			// the mount behind those left the whole sweep green, because no
			// unauthenticated request reaches them. This assertion is what catches it,
			// and it is why the mount comment in routes.go calls the position a
			// requirement rather than a preference.
			//
			// Matched on the runtime function name rather than the function pointer:
			// every call to MiddlewareNoStore returns a fresh closure with its own
			// wrapper address, so reflect.Pointer comparison against a locally built one
			// does not hold, while the compiler-assigned name does. A rename of
			// MiddlewareNoStore fails this test loudly, which is the right outcome.
			assert.True(t, strings.HasPrefix(rt.first, noStoreMiddlewareName+"."),
				"MiddlewareNoStore must be the FIRST middleware on this route so that a "+
					"refusal written by a guard still carries the pair; the chain starts with %q", rt.first)
		})
	}
}

// noStoreMiddlewareName is the compiler-assigned name of the closure MiddlewareNoStore returns,
// minus the trailing instance suffix (".1", ".func1") which differs between a mounted instance
// and a freshly constructed one.
const noStoreMiddlewareName = "github.com/leodip/goiabada/core/middleware.MiddlewareNoStore"

// routeTestPathParam matches a chi path parameter, including the {id:[0-9]+} form.
var routeTestPathParam = regexp.MustCompile(`\{[^}]+\}`)

// routeTestTarget turns a chi pattern into a request target by substituting each path parameter.
// The value is a plain "1": it has to satisfy any regexp constraint in the pattern, and every
// parameter this API declares is either a numeric id or a free identifier. A substitution that
// fails to match produces a 404, which the status assertion above turns into a failure rather than
// letting it pass on the header alone.
func routeTestTarget(pattern string) string {
	target := routeTestPathParam.ReplaceAllString(pattern, "1")
	return strings.TrimSuffix(target, "/*")
}
