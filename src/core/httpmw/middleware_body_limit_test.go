package httpmw

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/routing"
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
// limit that refused it otherwise, and the {id} parameter the route was reached with.
func bodyLimitReader(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		_, _ = fmt.Fprintf(w, "refused at %d", tooLarge.Limit)
	case err != nil:
		_, _ = fmt.Fprintf(w, "error %v", err)
	default:
		_, _ = fmt.Fprintf(w, "read %d id=%s", len(body), r.PathValue("id"))
	}
}

// newBodyLimitRouter mounts the middleware the way both servers do, after StripTrailingSlash, on a router
// with a group, so the lookup has a full pattern to resolve across the two.
func newBodyLimitRouter(policy BodyLimitPolicy, handler http.HandlerFunc) *routing.Router {
	router := routing.New()
	router.Use(StripTrailingSlash)
	router.Use(BodyLimit(router, policy))
	registerBodyLimitRoutes(router, handler)
	return router
}

func registerBodyLimitRoutes(router *routing.Router, handler http.HandlerFunc) {
	router.NotFound(handler)
	router.Post("/plain", handler)
	router.Route("/api", func(api *routing.Router) {
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

// TestBodyLimit_TheLimitEachRequestMeets drives each rule of the lookup with a body far
// past every limit in the table, so the answer is the limit that refused it.
func TestBodyLimit_TheLimitEachRequestMeets(t *testing.T) {
	router := newBodyLimitRouter(bodyLimitFixturePolicy(), bodyLimitReader)

	tests := []struct {
		name   string
		method string
		target string
		want   string
	}{
		{"a path no route matches gets the default", http.MethodPost, "/nowhere", "refused at 16"},
		{"a path under a prefix no route matches gets the default", http.MethodPost, "/api/nowhere", "refused at 16"},
		{"a route no entry names gets the default", http.MethodPost, "/plain", "refused at 16"},
		{"a route under a prefix gets the prefix", http.MethodPost, "/api/items", "refused at 32"},
		{"the longest prefix wins", http.MethodPost, "/api/deep/thing", "refused at 48"},
		{"an exact route wins over its prefix", http.MethodPost, "/api/items/7", "refused at 64"},
		{"the same pattern under another method falls to the prefix", http.MethodPut, "/api/items/7", "refused at 32"},
		{"a trailing slash resolves as the strip routes it", http.MethodPost, "/api/items/7/", "refused at 64"},
		{"an escaped parameter resolves to its route", http.MethodPost, "/api/items/a%2Fb", "refused at 64"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, serveBody(router, test.method, test.target, 1000))
		})
	}
}

// TestBodyLimit_TheBoundary shows the limit is on bytes read, not one short or one over.
func TestBodyLimit_TheBoundary(t *testing.T) {
	router := newBodyLimitRouter(bodyLimitFixturePolicy(), bodyLimitReader)

	assert.Equal(t, "read 32 id=", serveBody(router, http.MethodPost, "/api/items", 32), "a body of exactly the limit reads whole")
	assert.Equal(t, "refused at 32", serveBody(router, http.MethodPost, "/api/items", 33), "one byte more is refused")
	assert.Equal(t, "read 64 id=7", serveBody(router, http.MethodPost, "/api/items/7", 64), "a route's own limit, exactly")
	assert.Equal(t, "refused at 64", serveBody(router, http.MethodPost, "/api/items/7", 65), "and one byte more")
}

// TestBodyLimit_LeavesTheRequestAlone: the lookup resolves a route with a parameter in it before
// routing, and must leave the request the router routes as it found it, so the handler reports the
// route it was reached by and its parameter, and the report must equal the same router's without
// the middleware.
func TestBodyLimit_LeavesTheRequestAlone(t *testing.T) {
	report := func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%s id=%s", routing.RouteName(r), r.PathValue("id"))
	}
	without := routing.New()
	without.Use(StripTrailingSlash)
	registerBodyLimitRoutes(without, report)
	want := serveBody(without, http.MethodPost, "/api/items/7", 3)
	require.Equal(t, "/api/items/{id} id=7", want, "the baseline must have reached the route under test")

	assert.Equal(t, want, serveBody(newBodyLimitRouter(bodyLimitFixturePolicy(), report), http.MethodPost, "/api/items/7", 3))
}

// TestBodyLimit_ARequestWithNoBodyIsUntouched covers both shapes of "no body": the
// http.NoBody net/http gives a request without one, and a nil a handler-level caller may pass.
func TestBodyLimit_ARequestWithNoBodyIsUntouched(t *testing.T) {
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

// TestBodyLimit_AHandlersTighterBoundStillTrips: the table sits above the handlers that
// bound their own bodies, and must not be what answers for them.
func TestBodyLimit_AHandlersTighterBoundStillTrips(t *testing.T) {
	router := newBodyLimitRouter(bodyLimitFixturePolicy(), func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 10)
		bodyLimitReader(w, r)
	})

	assert.Equal(t, "refused at 10", serveBody(router, http.MethodPost, "/api/items/7", 20), "past the handler's bound, inside the table's")
	assert.Equal(t, "refused at 10", serveBody(router, http.MethodPost, "/api/items/7", 1000), "past both")
}

// TestBodyLimit_RefusesASilentlyWrongPolicy: each shape below would boot a server whose
// table does not say what it looks like it says.
func TestBodyLimit_RefusesASilentlyWrongPolicy(t *testing.T) {
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
			assert.Panics(t, func() { BodyLimit(routing.New(), policy) })
		})
	}

	t.Run("the fixture itself is accepted", func(t *testing.T) {
		require.NotPanics(t, func() { BodyLimit(routing.New(), valid()) })
	})
}
