package server

import (
	"errors"
	"net/http"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestRegisterRoutes_EveryAPIRouteRefusesToBeStored is goal 5 of #247, and it is the reason this seam
// exists rather than a pair of spot checks: the route set comes from the router, so a route or a
// whole group added under /api/v1/ later is covered without this file being edited.
//
// The claim is that middleware.NoStore heads the API branch, ahead of the settings read and of every
// group's guards, so it covers refusals as well as successes. Neither the middleware's own table in
// src/authserver/internal/middleware nor any handler test can make it. The table composes the
// middleware around a handler by hand, which is exactly the arrangement that keeps passing when the
// mount disappears from initMiddleware; routes_ratelimiter_test.go's own header records the same
// lesson for the limiters, where removing any one of twelve wrappers left the whole module suite
// green. So this builds the server main builds, the root's middleware, the branches' and the
// groups' all real.
//
// Every route is called WITHOUT credentials, which is deliberate on two counts. It is the case the
// mount position exists for, since RFC 6749 section 5.1's "other sensitive information" covers a
// refusal body and the guards' refusal writer commits its own status; and it means no handler is ever reached,
// so the database mock needs no expectations beyond the settings and this test does not break when a
// handler changes.
//
// WHAT THIS DOES NOT OWN, and must not be described as owning (decision 16). A CORS preflight is
// answered 200 by middleware.CORS at the root, ahead of every branch, and ships with neither header
// field; it carries no credential, so RFC 6749 section 5.1 does not reach it. The JSON 500 a fault in
// front of the groups answers is TestRegisterRoutes_AnAPIFaultInFrontOfTheGroupsIsNoStore's.
// This test is exhaustive over the routes the router registers, and it is not exhaustive over the
// API's whole response surface.
func TestRegisterRoutes_EveryAPIRouteRefusesToBeStored(t *testing.T) {
	s := newRoutingTestServer(t, newRoutingDatabase(t))

	type apiRoute struct {
		method  string
		pattern string
		target  string
		// chain is the runtime names of this route's middleware, the root's first, which is what
		// says the mount is ahead of the branch's chain and every guard rather than merely present.
		chain []string
	}
	var routes []apiRoute
	var rootChain []string

	err := s.router.Walk(func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		var chain []string
		for _, mounted := range middlewares {
			chain = append(chain, runtime.FuncForPC(reflect.ValueOf(mounted).Pointer()).Name())
		}
		// The static files run the root's middleware alone (TestInitMiddleware_TheWholeChainInOrder).
		if route == "/static/*" {
			rootChain = chain
		}
		if strings.HasPrefix(route, "/api/v1/") {
			routes = append(routes, apiRoute{method: method, pattern: route, target: routeTestTarget(route), chain: chain})
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, rootChain, "the static route must have been walked, for the root's chain")

	// A router walk that silently enumerated nothing would make every assertion below vacuous, and
	// so would a walk that reached one group and not another.
	require.NotEmpty(t, routes, "the router walk found no /api/v1/ routes, so this test asserts nothing")
	for _, group := range []string{"/api/v1/admin/", "/api/v1/account/", "/api/v1/sessions/"} {
		assert.True(t, slices.ContainsFunc(routes, func(rt apiRoute) bool { return strings.HasPrefix(rt.pattern, group) }),
			"no %s route was enumerated", group)
	}

	for _, rt := range routes {
		t.Run(rt.method+" "+rt.pattern, func(t *testing.T) {
			recorder := serveRouting(s, rt.method, rt.target, nil)
			result := recorder.Result()
			defer func() { _ = result.Body.Close() }()

			// The status says a guard refused the request rather than a handler answering it:
			// 401, which the scope guard answers a request with no bearer token before it looks at
			// a scope; the guards ahead of it let such a request through. On the admin group,
			// whose guards let a caller with no token through to its routes, it also catches a
			// botched parameter substitution: the group's 404 would still carry the header,
			// because the branch's middleware runs ahead of the subrouter's NotFound handler. The
			// account and session groups refuse any path under them 401, a made-up one included
			// (TestRegisterRoutes_AnUnmatchedPathUnderAnAPIGroupMeetsItsGuardsFirst).
			assert.Equal(t, http.StatusUnauthorized, result.StatusCode,
				"an unauthenticated request must be refused by a guard, not answered or lost")

			// Result().Header, never recorder.Header(): the refusals commit their status
			// with WriteHeader, which is exactly the case where the live map and the
			// snapshot a client receives disagree.
			assert.Equal(t, "no-store", result.Header.Get("Cache-Control"),
				"every route under /api/v1 must tell caches not to store its response")
			assert.Equal(t, "no-cache", result.Header.Get("Pragma"),
				"RFC 6749 section 5.1 requires the Pragma field alongside Cache-Control")

			// FIRST beneath the root's, not merely present, and this is the only assertion that
			// says so.
			//
			// The two sweeps observe only the answers they drive: this one, over a settings read
			// that succeeds, a guard's refusal of a caller with no token, and the fault sweep below
			// the 500 of a settings read that fails or panics. A middleware added ahead of NoStore
			// that answers on a condition those requests do not meet would send neither header
			// field, and neither sweep would see it. This assertion catches the placement itself,
			// whichever requests trigger the answer.
			//
			// Matched on the runtime function name rather than the function pointer:
			// every call to middleware.NoStore returns a fresh closure with its own
			// wrapper address, so reflect.Pointer comparison against a locally built one
			// does not hold, while the compiler-assigned name does. A rename of
			// middleware.NoStore fails this test loudly, which is the right outcome.
			require.Greater(t, len(rt.chain), len(rootChain), "the route must run more than the root's middleware")
			assert.Equal(t, rootChain, rt.chain[:len(rootChain)], "the route's chain must start with the root's")
			assert.True(t, strings.HasPrefix(rt.chain[len(rootChain)], noStoreMiddlewareName+"."),
				"middleware.NoStore must be the FIRST middleware beneath the root's on this route, so that a "+
					"refusal written by a guard and a fault in front of the groups still carry the pair; it is %q",
				rt.chain[len(rootChain)])
		})
	}
}

// TestRegisterRoutes_AnAPIFaultInFrontOfTheGroupsIsNoStore: a settings read that fails, and a panic
// in it, stop every request on the API branch before its group's middleware, and the JSON 500 either
// answers is no-store, as every other answer of the API is (#825). The routes come from the router,
// as in the sweep above, the public settings among them.
func TestRegisterRoutes_AnAPIFaultInFrontOfTheGroupsIsNoStore(t *testing.T) {
	failing := datamocks.NewDatabase(t)
	failing.On("GetSettingsByID", mock.Anything, mock.Anything, int64(1)).
		Return(nil, errors.New("the settings row could not be read"))

	for _, fault := range []struct {
		name   string
		server *Server
	}{
		{"a settings read that fails", newRoutingTestServer(t, failing)},
		{"a panic in the settings read", newPanickingServer(t, "the settings read panicked")},
	} {
		t.Run(fault.name, func(t *testing.T) {
			var routes []string
			for _, route := range registeredRoutes(t, fault.server) {
				if _, pattern, _ := strings.Cut(route, " "); strings.HasPrefix(pattern, "/api/") {
					routes = append(routes, route)
				}
			}
			for _, prefix := range []string{"/api/v1/admin/", "/api/v1/account/", "/api/v1/sessions/", "/api/public/"} {
				require.True(t, slices.ContainsFunc(routes, func(route string) bool { return strings.Contains(route, " "+prefix) }),
					"no %s route was enumerated", prefix)
			}

			for _, route := range routes {
				t.Run(route, func(t *testing.T) {
					method, pattern, _ := strings.Cut(route, " ")
					rr := serveRouting(fault.server, method, routeTestTarget(pattern), nil)

					assertFaultFormat(t, "api", "", rr)
					assertNoStore(t, rr)
				})
			}
		})
	}
}

// noStoreMiddlewareName is the compiler-assigned name of the closure middleware.NoStore returns,
// minus the trailing instance suffix (".1", ".func1") which differs between a mounted instance
// and a freshly constructed one.
const noStoreMiddlewareName = "github.com/leodip/goiabada/authserver/internal/middleware.NoStore"

// routeTestPathParam matches a path parameter, {name}.
var routeTestPathParam = regexp.MustCompile(`\{[^}]+\}`)

// routeTestTarget turns a route into a request target by substituting each path parameter. The
// value is a plain "1": every parameter this API declares is either a numeric id or a free
// identifier. On the admin group, a substitution that fails to match falls to the group's 404,
// which the sweep's status assertion turns into a failure rather than letting it pass on the header
// alone.
func routeTestTarget(pattern string) string {
	target := routeTestPathParam.ReplaceAllString(pattern, "1")
	return strings.TrimSuffix(target, "/*")
}
