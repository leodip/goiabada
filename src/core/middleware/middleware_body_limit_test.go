package middleware

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixture policy the lookup tests drive, deliberately neither application's: core owns the
// lookup and no route, so the binaries' own tables are tested beside them (#426).
//
// Every limit differs, so the limit a request met names the entry that supplied it.
func bodyLimitFixturePolicy() BodyLimitPolicy {
	return BodyLimitPolicy{
		Default: 16,
		Prefixes: map[string]int64{
			"/api/":      32,
			"/api/deep/": 48,
		},
		Routes: map[string]int64{
			"POST /api/items/{id}": 64,
		},
	}
}

// bodyLimitReader reads the whole body and answers what it saw: the byte count on success, the
// limit that refused it otherwise, and the {id} parameter chi routed with, so a lookup that wrote
// into the request's route context would show here.
func bodyLimitReader(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		_, _ = fmt.Fprintf(w, "refused at %d", tooLarge.Limit)
	case err != nil:
		_, _ = fmt.Fprintf(w, "error %v", err)
	default:
		_, _ = fmt.Fprintf(w, "read %d id=%s", len(body), chi.URLParam(r, "id"))
	}
}

// newBodyLimitRouter mounts the middleware the way both servers do, after StripSlashes, on a router
// with a subrouter, so the lookup has a full pattern to resolve across the two.
func newBodyLimitRouter(policy BodyLimitPolicy, handler http.HandlerFunc) *chi.Mux {
	router := chi.NewRouter()
	router.Use(chimiddleware.StripSlashes)
	router.Use(MiddlewareBodyLimit(router, policy))
	registerBodyLimitRoutes(router, handler)
	return router
}

func registerBodyLimitRoutes(router *chi.Mux, handler http.HandlerFunc) {
	router.NotFound(handler)
	router.Post("/plain", handler)
	router.Route("/api", func(api chi.Router) {
		api.Post("/items", handler)
		api.Post("/items/{id}", handler)
		api.Put("/items/{id}", handler)
		api.Post("/deep/thing", handler)
	})
}

func serveBody(router http.Handler, method string, target string, size int) string {
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(method, target, strings.NewReader(strings.Repeat("x", size))))
	return recorder.Body.String()
}

// TestMiddlewareBodyLimit_TheLimitEachRequestMeets drives each rule of the lookup with a body far
// past every limit in the table, so the answer is the limit that refused it.
func TestMiddlewareBodyLimit_TheLimitEachRequestMeets(t *testing.T) {
	router := newBodyLimitRouter(bodyLimitFixturePolicy(), bodyLimitReader)

	tests := []struct {
		name   string
		method string
		target string
		want   string
	}{
		{"a path no route matches gets the default", http.MethodPost, "/nowhere", "refused at 16"},
		{"a route no entry names gets the default", http.MethodPost, "/plain", "refused at 16"},
		{"a route under a prefix gets the prefix", http.MethodPost, "/api/items", "refused at 32"},
		{"the longest prefix wins", http.MethodPost, "/api/deep/thing", "refused at 48"},
		{"an exact route wins over its prefix", http.MethodPost, "/api/items/7", "refused at 64"},
		{"the same pattern under another method falls to the prefix", http.MethodPut, "/api/items/7", "refused at 32"},
		{"a trailing slash resolves as StripSlashes routes it", http.MethodPost, "/api/items/7/", "refused at 64"},
		{"an escaped path resolves by its raw form, as chi routes it", http.MethodPost, "/api/items/a%2Fb", "refused at 64"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, serveBody(router, test.method, test.target, 1000))
		})
	}
}

// TestMiddlewareBodyLimit_TheBoundary shows the limit is on bytes read, not one short or one over.
func TestMiddlewareBodyLimit_TheBoundary(t *testing.T) {
	router := newBodyLimitRouter(bodyLimitFixturePolicy(), bodyLimitReader)

	assert.Equal(t, "read 32 id=", serveBody(router, http.MethodPost, "/api/items", 32), "a body of exactly the limit reads whole")
	assert.Equal(t, "refused at 32", serveBody(router, http.MethodPost, "/api/items", 33), "one byte more is refused")
}

// TestMiddlewareBodyLimit_LeavesTheRouteContextAlone: the lookup resolves a pattern with a
// parameter in it, and must do so without touching the request's own route context. Given that
// context, Find would rewrite its RoutePath to the subrouter's remainder, which the root then
// routes by, and would leave its parameters behind. So the handler reports the pattern chi
// actually routed to and every parameter it holds, not only the one it looks for, which a leaked
// copy would also supply, and the report must equal the same router's without the middleware.
func TestMiddlewareBodyLimit_LeavesTheRouteContextAlone(t *testing.T) {
	report := func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		_, _ = fmt.Fprintf(w, "%s %v %v", rctx.RoutePattern(), rctx.URLParams.Keys, rctx.URLParams.Values)
	}
	without := chi.NewRouter()
	without.Use(chimiddleware.StripSlashes)
	registerBodyLimitRoutes(without, report)
	want := serveBody(without, http.MethodPost, "/api/items/7", 3)
	require.Contains(t, want, "/api/items/{id} ", "the baseline must have reached the route under test")

	assert.Equal(t, want, serveBody(newBodyLimitRouter(bodyLimitFixturePolicy(), report), http.MethodPost, "/api/items/7", 3))
}

// TestMiddlewareBodyLimit_ARequestWithNoBodyIsUntouched covers both shapes of "no body": the
// http.NoBody net/http gives a request without one, and a nil a handler-level caller may pass.
func TestMiddlewareBodyLimit_ARequestWithNoBodyIsUntouched(t *testing.T) {
	var seen io.ReadCloser
	router := newBodyLimitRouter(bodyLimitFixturePolicy(), func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Body
	})

	noBody := httptest.NewRequest(http.MethodPost, "/api/items", http.NoBody)
	router.ServeHTTP(httptest.NewRecorder(), noBody)
	assert.Equal(t, http.NoBody, seen, "http.NoBody must reach the handler as itself")

	nilBody := httptest.NewRequest(http.MethodPost, "/api/items", nil)
	nilBody.Body = nil
	seen = http.NoBody
	router.ServeHTTP(httptest.NewRecorder(), nilBody)
	assert.Nil(t, seen, "a nil body must stay nil")
}

// TestMiddlewareBodyLimit_AHandlersTighterBoundStillTrips: the table sits above the handlers that
// bound their own bodies, and must not be what answers for them.
func TestMiddlewareBodyLimit_AHandlersTighterBoundStillTrips(t *testing.T) {
	router := newBodyLimitRouter(bodyLimitFixturePolicy(), func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 10)
		bodyLimitReader(w, r)
	})

	assert.Equal(t, "refused at 10", serveBody(router, http.MethodPost, "/api/items/7", 20), "past the handler's bound, inside the table's")
	assert.Equal(t, "refused at 10", serveBody(router, http.MethodPost, "/api/items/7", 1000), "past both")
}

// TestMiddlewareBodyLimit_RefusesASilentlyWrongPolicy: each shape below would boot a server whose
// table does not say what it looks like it says.
func TestMiddlewareBodyLimit_RefusesASilentlyWrongPolicy(t *testing.T) {
	valid := bodyLimitFixturePolicy

	tests := []struct {
		name   string
		policy func() BodyLimitPolicy
	}{
		{"a zero default", func() BodyLimitPolicy { p := valid(); p.Default = 0; return p }},
		{"a negative default", func() BodyLimitPolicy { p := valid(); p.Default = -1; return p }},
		{"an empty prefix", func() BodyLimitPolicy { p := valid(); p.Prefixes[""] = 32; return p }},
		{"a prefix that is not a path", func() BodyLimitPolicy { p := valid(); p.Prefixes["api/"] = 32; return p }},
		{"a prefix with a zero limit", func() BodyLimitPolicy { p := valid(); p.Prefixes["/other/"] = 0; return p }},
		{"a route with no method", func() BodyLimitPolicy { p := valid(); p.Routes["/api/items"] = 64; return p }},
		{"a route with a lowercase method", func() BodyLimitPolicy { p := valid(); p.Routes["post /api/items"] = 64; return p }},
		{"a route whose pattern is not a path", func() BodyLimitPolicy { p := valid(); p.Routes["POST api/items"] = 64; return p }},
		{"a route with a zero limit", func() BodyLimitPolicy { p := valid(); p.Routes["POST /api/items"] = 0; return p }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := test.policy()
			assert.Panics(t, func() { MiddlewareBodyLimit(chi.NewRouter(), policy) })
		})
	}

	t.Run("the fixture itself is accepted", func(t *testing.T) {
		require.NotPanics(t, func() { MiddlewareBodyLimit(chi.NewRouter(), valid()) })
	})
}
