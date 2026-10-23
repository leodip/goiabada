package routing_test

// Seam: the router's exported API, driven with real requests through ServeHTTP and read back as
// status, headers and body, the route a request was named by, and the walk. The rules here are the
// ones #462 decisions 2 to 5 settle once for both servers: which middleware meets a request no
// route matches, the 404 and 405 answers, HEAD, non-canonical paths and how a route is spelled.
// Several tests are ServeMux's traps, each named where it is set.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/routing"
)

// answer writes the handler's name and the route the request was named by, so a body says which
// handler answered and under what name.
func answer(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%s route=%s", name, routing.RouteName(r))
	}
}

// visits records, in a response header, every middleware a request passed through, in order.
func visits(name string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Visited", name)
			next.ServeHTTP(w, r)
		})
	}
}

// guard answers every request it meets 401, the way the bearer guards and the console's sign-in
// redirect answer before any route.
func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
}

type response struct {
	status  int
	body    string
	header  http.Header
	visited []string
}

func serve(t *testing.T, h http.Handler, method, target string) response {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return response{status: rec.Code, body: rec.Body.String(), header: rec.Header(), visited: rec.Header().Values("Visited")}
}

// newSite is the fixture: a root chain, a page branch carrying the not-found page and a page group,
// an API branch with a guarded group and no not-found handler of its own, and the static files.
func newSite() *routing.Router {
	root := routing.New()
	root.Use(visits("root"))

	pages := root.With(visits("pages"))
	pages.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, "<h1>Page not found</h1>")
	})
	pages.Get("/", answer("index"))
	pages.Get("/health", answer("health"))
	pages.Get("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "user %s route=%s", r.PathValue("id"), routing.RouteName(r))
	})
	pages.Route("/auth", func(r *routing.Router) {
		r.Use(visits("auth"))
		r.Get("/", answer("auth index"))
		r.Get("/authorize", answer("authorize get"))
		r.Post("/authorize", answer("authorize post"))
		r.Get("/logout", answer("logout"))
		r.Head("/logout", answer("logout head"))
		r.With(visits("limited")).Post("/pwd", answer("pwd"))
	})

	api := root.With(visits("api"))
	api.Route("/api/v1/admin", func(r *routing.Router) {
		r.Use(guard)
		r.Get("/users/{id}", answer("admin user"))
	})
	api.Route("/api/v1/open", func(r *routing.Router) {
		r.Get("/things", answer("things"))
		r.Put("/things/{id}", answer("put thing"))
		r.Delete("/things/{id}", answer("delete thing"))
	})
	// Outside the /auth group, on a branch of its own, as the auth server's token endpoint is.
	api.Post("/auth/token", answer("token"))

	root.Get("/static/*", answer("static"))
	root.Handle("/callback", answer("callback"))
	return root
}

func TestRouter_EachVerbAnswersItsOwnMethod(t *testing.T) {
	r := routing.New()
	r.Get("/x", answer("get"))
	r.Head("/x", answer("head"))
	r.Post("/x", answer("post"))
	r.Put("/x", answer("put"))
	r.Patch("/x", answer("patch"))
	r.Delete("/x", answer("delete"))
	r.Options("/x", answer("options"))
	r.Method("PROPFIND", "/x", answer("propfind"))

	for method, want := range map[string]string{
		http.MethodGet: "get", http.MethodPost: "post", http.MethodPut: "put", http.MethodPatch: "patch",
		http.MethodDelete: "delete", http.MethodOptions: "options", "PROPFIND": "propfind",
	} {
		got := serve(t, r, method, "/x")
		assert.Equal(t, http.StatusOK, got.status, method)
		assert.Equal(t, want+" route=/x", got.body, method)
	}
	// httptest's recorder keeps a HEAD's body, which only the real server drops.
	assert.Equal(t, "head route=/x", serve(t, r, http.MethodHead, "/x").body)
}

func TestRouter_ARouteReadsItsPathParameters(t *testing.T) {
	got := serve(t, newSite(), http.MethodGet, "/users/42")

	require.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, "user 42 route=/users/{id}", got.body)

	// ServeMux decodes a parameter; chi handed the raw form (#462, assumed).
	assert.Equal(t, "user a/b route=/users/{id}", serve(t, newSite(), http.MethodGet, "/users/a%2Fb").body)
}

// Decision 5: a route is named as chi spelled it, the path alone, the group's prefix joined on,
// parameters as {name}, a group's own "/" as the prefix, and the static files as /static/*.
func TestRouter_EachRouteIsNamedInChisSpelling(t *testing.T) {
	site := newSite()
	for target, want := range map[string]string{
		"/":                    "index route=/",
		"/health":              "health route=/health",
		"/auth":                "auth index route=/auth",
		"/auth/authorize":      "authorize get route=/auth/authorize",
		"/static/css/main.css": "static route=/static/*",
		"/static/":             "static route=/static/*",
		"/callback":            "callback route=/callback",
	} {
		got := serve(t, site, http.MethodGet, target)
		assert.Equal(t, http.StatusOK, got.status, target)
		assert.Equal(t, want, got.body, target)
	}
}

// ServeMux puts the pattern and the path values on the request it hands its handler, which a
// middleware above holds only when no WithContext copy came between, and every middleware in both
// servers' chains makes one. The name is read through the router instead, after the handler ran.
func TestRouter_TheRouteNameReachesAMiddlewareAboveACopiedRequest(t *testing.T) {
	var seenAfter, patternAfter string
	r := routing.New()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req)
			seenAfter, patternAfter = routing.RouteName(req), req.Pattern
		})
	})
	copying := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			type key struct{}
			next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), key{}, "copy")))
		})
	}
	r.Use(copying)
	r.Route("/g", func(g *routing.Router) {
		g.Use(copying)
		g.With(copying).Get("/items/{id}", func(w http.ResponseWriter, req *http.Request) {
			_, _ = fmt.Fprint(w, req.PathValue("id"))
		})
	})

	got := serve(t, r, http.MethodGet, "/g/items/7")

	require.Equal(t, "7", got.body, "the handler reads its parameter through every copy")
	assert.Equal(t, "/g/items/{id}", seenAfter)
	assert.Empty(t, patternAfter, "the trap: ServeMux's own pattern never reaches the request above the copies")
}

func TestRouter_ARequestNoRouteAnsweredHasNoRouteName(t *testing.T) {
	var name string
	seen := false
	r := routing.New()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req)
			name, seen = routing.RouteName(req), true
		})
	})
	r.Get("/x", answer("x"))
	r.Route("/g", func(g *routing.Router) {
		g.Use(guard)
		g.Get("/y", answer("y"))
	})

	for _, request := range []struct{ method, target string }{
		{http.MethodGet, "/nope"}, {http.MethodPost, "/x"}, {http.MethodGet, "/g/y"},
	} {
		seen, name = false, "set"
		serve(t, r, request.method, request.target)
		require.True(t, seen)
		assert.Empty(t, name, "%s %s: a 404, a 405 and a group's guard answering first name no route", request.method, request.target)
	}
	assert.Empty(t, routing.RouteName(httptest.NewRequest(http.MethodGet, "/x", nil)), "a request the router never saw")
}

// The root's middleware runs before routing, for every request, and a path it rewrites is the path
// routed, which is how the one-trailing-slash strip reaches the router.
func TestRouter_TheRootChainRunsFirstAndRoutesThePathItLeaves(t *testing.T) {
	r := routing.New()
	r.Use(visits("first"))
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if len(req.URL.Path) > 1 && strings.HasSuffix(req.URL.Path, "/") {
				req.URL.Path = strings.TrimSuffix(req.URL.Path, "/")
			}
			next.ServeHTTP(w, req)
		})
	})
	r.Get("/health", answer("health"))

	got := serve(t, r, http.MethodGet, "/health/")
	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, "health route=/health", got.body)

	got = serve(t, r, http.MethodGet, "/nope")
	assert.Equal(t, http.StatusNotFound, got.status)
	assert.Equal(t, []string{"first"}, got.visited)
}

// A route's chain is the root's, then each group's from the outside in, then the With chain it
// was registered through, and only the routes registered through a With carry it.
func TestRouter_EachRouteRunsItsChainInOrder(t *testing.T) {
	site := newSite()

	got := serve(t, site, http.MethodPost, "/auth/pwd")
	require.Equal(t, "pwd route=/auth/pwd", got.body)
	assert.Equal(t, []string{"root", "pages", "auth", "limited"}, got.visited)

	got = serve(t, site, http.MethodPost, "/auth/authorize")
	require.Equal(t, "authorize post route=/auth/authorize", got.body)
	assert.Equal(t, []string{"root", "pages", "auth"}, got.visited)

	got = serve(t, site, http.MethodPost, "/auth/token")
	require.Equal(t, "token route=/auth/token", got.body, "a route outside the group whose prefix its path shares")
	assert.Equal(t, []string{"root", "api"}, got.visited)

	got = serve(t, site, http.MethodGet, "/static/main.css")
	require.Equal(t, "static route=/static/*", got.body)
	assert.Equal(t, []string{"root"}, got.visited)
}

// Decision 2: a request no route matches meets its group's middleware first, so a guard answers
// it as it answers a real route under the group.
func TestRouter_AGroupsMiddlewareMeetsEveryPathUnderIt(t *testing.T) {
	site := newSite()

	for _, request := range []struct{ method, target string }{
		{http.MethodGet, "/api/v1/admin/users/42"},
		{http.MethodGet, "/api/v1/admin/made-up"},
		{http.MethodGet, "/api/v1/admin"},
		{http.MethodDelete, "/api/v1/admin/users/42"},
		{http.MethodGet, "/api/v1/admin//users/42"},
		{http.MethodGet, "/api/v1/admin%2Fusers"},
	} {
		got := serve(t, site, request.method, request.target)
		assert.Equal(t, http.StatusUnauthorized, got.status, "%s %s", request.method, request.target)
		assert.Equal(t, []string{"root", "api"}, got.visited, "%s %s", request.method, request.target)
	}

	got := serve(t, site, http.MethodGet, "/auth/made-up")
	assert.Equal(t, []string{"root", "pages", "auth"}, got.visited, "an unmatched path under a page group")

	got = serve(t, site, http.MethodGet, "/authority")
	assert.Equal(t, http.StatusNotFound, got.status)
	assert.Equal(t, []string{"root", "pages"}, got.visited, "a path sharing the prefix's letters is not under the group")
}

// ServeMux decodes each segment before it compares it, so /%61dmin/... is /admin/...: the route it
// matches must still run behind its group's guard.
func TestRouter_AnEscapedSegmentStillMeetsItsGroupsGuard(t *testing.T) {
	r := routing.New()
	r.Route("/admin", func(g *routing.Router) {
		g.Use(guard)
		g.Get("/clients", answer("clients"))
	})

	for _, target := range []string{"/admin/clients", "/%61dmin/clients", "/admin/%63lients"} {
		got := serve(t, r, http.MethodGet, target)
		assert.Equal(t, http.StatusUnauthorized, got.status, target)
		assert.Empty(t, got.body, target)
	}
}

// Decision 2: a group answers an unmatched path with the not-found handler of the router it was
// created from, inherited through With and Route, behind its own middleware; a group created where
// no not-found handler was set answers net/http's plain text.
func TestRouter_TheNotFoundAnswer(t *testing.T) {
	site := newSite()

	for target, visited := range map[string][]string{
		"/no/such/page":   {"root", "pages"},
		"/auth/made-up":   {"root", "pages", "auth"},
		"/auth/pwd/extra": {"root", "pages", "auth"},
	} {
		got := serve(t, site, http.MethodGet, target)
		assert.Equal(t, http.StatusNotFound, got.status, target)
		assert.Equal(t, "<h1>Page not found</h1>", got.body, target)
		assert.Equal(t, visited, got.visited, target)
	}

	got := serve(t, site, http.MethodGet, "/api/v1/open/made-up")
	assert.Equal(t, http.StatusNotFound, got.status)
	assert.Equal(t, "404 page not found\n", got.body)
	assert.Equal(t, "text/plain; charset=utf-8", got.header.Get("Content-Type"))
	assert.Equal(t, []string{"root", "api"}, got.visited)

	bare := routing.New()
	bare.Get("/x", answer("x"))
	assert.Equal(t, "404 page not found\n", serve(t, bare, http.MethodGet, "/y").body, "a router with no not-found handler")
}

func TestRouter_AGroupsOwnNotFoundWins(t *testing.T) {
	r := routing.New()
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, "root's")
	})
	r.Route("/g", func(g *routing.Router) {
		g.NotFound(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, "group's")
		})
		g.Route("/inner", func(inner *routing.Router) {
			inner.Get("/x", answer("x"))
		})
	})
	r.Route("/h", func(h *routing.Router) {
		h.Get("/x", answer("x"))
	})

	assert.Equal(t, "root's", serve(t, r, http.MethodGet, "/nope").body)
	assert.Equal(t, "group's", serve(t, r, http.MethodGet, "/g/nope").body)
	assert.Equal(t, "group's", serve(t, r, http.MethodGet, "/g/inner/nope").body, "inherited from the router it was created from")
	assert.Equal(t, "root's", serve(t, r, http.MethodGet, "/h/nope").body)
}

// Decision 3: a path that exists for other methods answers 405 with an empty body, no Content-Type,
// and an Allow naming every method registered for it, sorted; HEAD only where HEAD is registered.
func TestRouter_TheMethodNotAllowedAnswer(t *testing.T) {
	site := newSite()

	for _, request := range []struct {
		method, target, allow string
		visited               []string
	}{
		{http.MethodPut, "/auth/authorize", "GET, POST", []string{"root", "pages", "auth"}},
		{http.MethodHead, "/auth/authorize", "GET, POST", []string{"root", "pages", "auth"}},
		{"FOO", "/auth/authorize", "GET, POST", []string{"root", "pages", "auth"}},
		{"get", "/auth/authorize", "GET, POST", []string{"root", "pages", "auth"}},
		{http.MethodPost, "/auth/logout", "GET, HEAD", []string{"root", "pages", "auth"}},
		{http.MethodPost, "/health", "GET", []string{"root"}},
		{http.MethodHead, "/health", "GET", []string{"root"}},
		{http.MethodPost, "/static/main.css", "GET", []string{"root"}},
		{http.MethodGet, "/api/v1/open/things/7", "DELETE, PUT", []string{"root", "api"}},
		// The route sits outside the /auth group, so the group meets the request first, as chi's
		// catch-all did.
		{http.MethodGet, "/auth/token", "POST", []string{"root", "pages", "auth"}},
	} {
		got := serve(t, site, request.method, request.target)
		assert.Equal(t, http.StatusMethodNotAllowed, got.status, "%s %s", request.method, request.target)
		assert.Equal(t, request.allow, got.header.Get("Allow"), "%s %s", request.method, request.target)
		assert.Empty(t, got.body, "%s %s", request.method, request.target)
		assert.Empty(t, got.header.Get("Content-Type"), "%s %s", request.method, request.target)
		assert.Equal(t, request.visited, got.visited, "%s %s", request.method, request.target)
	}

	got := serve(t, site, http.MethodDelete, "/api/v1/admin/users/42")
	assert.Equal(t, http.StatusUnauthorized, got.status, "a guarded group's middleware answers before the 405")
	assert.Empty(t, got.header.Get("Allow"))
}

// A route registered for every method is never a 405.
func TestRouter_ARouteForEveryMethodTakesAnyMethod(t *testing.T) {
	site := newSite()
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, "FOO"} {
		got := serve(t, site, method, "/callback")
		assert.Equal(t, http.StatusOK, got.status, method)
		assert.Equal(t, "callback route=/callback", got.body, method)
	}

	r := routing.New()
	r.Post("/x", answer("post"))
	r.HandleFunc("/x", answer("any"))
	assert.Equal(t, "post route=/x", serve(t, r, http.MethodPost, "/x").body, "a method's own route wins")
	assert.Equal(t, "any route=/x", serve(t, r, http.MethodGet, "/x").body)
}

// HEAD is answered only where it is registered. The trap: ServeMux matches a GET pattern for HEAD.
func TestRouter_HeadOnlyWhereRegistered(t *testing.T) {
	r := routing.New()
	r.Get("/get-only", answer("get"))
	r.Get("/both", answer("get"))
	r.Head("/both", answer("head"))

	got := serve(t, r, http.MethodHead, "/get-only")
	assert.Equal(t, http.StatusMethodNotAllowed, got.status)
	assert.Equal(t, "GET", got.header.Get("Allow"))

	got = serve(t, r, http.MethodHead, "/both")
	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, "head route=/both", got.body)

	// Through a real server, which drops a HEAD's body.
	server := httptest.NewServer(r)
	defer server.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodHead, server.URL+"/get-only", nil)
	require.NoError(t, err)
	resp, err := server.Client().Do(request)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	assert.Equal(t, "GET", resp.Header.Get("Allow"))
}

// Decision 4: a path with an empty, . or .. segment matches no route and is answered 404 behind
// its group's middleware. The trap: ServeMux cleans such a path and redirects to the clean form.
func TestRouter_ANonCanonicalPathIsNotFound(t *testing.T) {
	site := newSite()

	for target, visited := range map[string][]string{
		"//health":             {"root", "pages"},
		"/./health?x=1":        {"root", "pages"},
		"/health/.":            {"root", "pages"},
		"/users/../health":     {"root", "pages"},
		"/auth//authorize":     {"root", "pages", "auth"},
		"/auth/./authorize":    {"root", "pages", "auth"},
		"/static//main.css":    {"root", "pages"},
		"/static/css/../x.css": {"root", "pages"},
	} {
		got := serve(t, site, http.MethodGet, target)
		assert.Equal(t, http.StatusNotFound, got.status, target)
		assert.Empty(t, got.header.Get("Location"), target)
		assert.Equal(t, "<h1>Page not found</h1>", got.body, target)
		assert.Equal(t, visited, got.visited, target)
	}

	// ServeMux leaves a CONNECT's path as it came, so a parameter would take the dot segment
	// whole, where every other method is redirected; the router refuses it for every method.
	r := routing.New()
	r.Handle("/files/{name}/meta", answer("meta"))
	require.Equal(t, http.StatusOK, serve(t, r, http.MethodConnect, "/files/a/meta").status)
	for _, target := range []string{"/files/./meta", "/files/../meta", "/files//meta"} {
		assert.Equal(t, http.StatusNotFound, serve(t, r, http.MethodConnect, target).status, target)
	}
}

// The trap: ServeMux redirects /tree to /tree/ when only the subtree is registered. /static is not
// a route, so it is a 404 and not a redirect into the file tree (#462 decision 7).
func TestRouter_ASubtreeDoesNotRedirectItsBarePrefix(t *testing.T) {
	got := serve(t, newSite(), http.MethodGet, "/static")

	assert.Equal(t, http.StatusNotFound, got.status)
	assert.Empty(t, got.header.Get("Location"))
}

// The trap: a ServeMux pattern ending in a slash matches the whole subtree. A route is its own path
// and nothing below it.
func TestRouter_ARouteDoesNotMatchItsSubtree(t *testing.T) {
	site := newSite()

	for _, target := range []string{"/anything", "/health/more", "/users/42/more", "/auth/authorize/x"} {
		assert.Equal(t, http.StatusNotFound, serve(t, site, http.MethodGet, target).status, target)
	}
	// A group's own "/" answers the group's prefix, with or without the slash.
	assert.Equal(t, "auth index route=/auth", serve(t, site, http.MethodGet, "/auth/").body)
}

// The routes the router answers are what a body-limit lookup and the metrics read before and after
// routing: the route a request will be answered by, or "" where it will be a 404 or a 405.
func TestRouter_RouteForNamesTheRouteThatWillAnswer(t *testing.T) {
	site := newSite()

	for _, request := range []struct{ method, target, want string }{
		{http.MethodGet, "/users/42", "/users/{id}"},
		{http.MethodGet, "/auth", "/auth"},
		{http.MethodPost, "/auth/token", "/auth/token"},
		{http.MethodGet, "/api/v1/admin/users/42", "/api/v1/admin/users/{id}"},
		{http.MethodGet, "/static/a/b.css", "/static/*"},
		{http.MethodPut, "/callback", "/callback"},
		{http.MethodGet, "/nope", ""},
		{http.MethodPut, "/health", ""},
		{http.MethodHead, "/health", ""},
		{http.MethodGet, "//health", ""},
		{http.MethodGet, "/static", ""},
	} {
		assert.Equal(t, request.want, site.RouteFor(httptest.NewRequest(request.method, request.target, nil)), "%s %s", request.method, request.target)
	}
}

func mwRoot(next http.Handler) http.Handler  { return next }
func mwGroup(next http.Handler) http.Handler { return next }
func mwWith(next http.Handler) http.Handler  { return next }
func mwInner(next http.Handler) http.Handler { return next }

func funcName(f any) string {
	name := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
	return name[strings.LastIndex(name, ".")+1:]
}

// The walk reports each route once per method, in chi's spelling, with the handler as registered
// and every middleware it runs behind, the root's first.
func TestRouter_TheWalk(t *testing.T) {
	health := func(http.ResponseWriter, *http.Request) {}
	r := routing.New()
	r.Use(mwRoot)
	r.Get("/health", health)
	r.Head("/health", health)
	r.With(mwWith).Route("/g", func(g *routing.Router) {
		g.Use(mwGroup)
		g.Get("/", health)
		g.With(mwInner).Post("/items/{id}", health)
	})
	r.Get("/static/*", health)
	r.HandleFunc("/callback", health)

	var got []string
	err := r.Walk(func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		chain := make([]string, 0, len(middlewares))
		for _, mw := range middlewares {
			chain = append(chain, funcName(mw))
		}
		got = append(got, fmt.Sprintf("%s %s %s %v", method, route, funcName(handler), chain))
		return nil
	})
	require.NoError(t, err)

	handler := funcName(http.HandlerFunc(health))
	assert.Equal(t, []string{
		"GET /health " + handler + " [mwRoot]",
		"HEAD /health " + handler + " [mwRoot]",
		"GET /g " + handler + " [mwRoot mwWith mwGroup]",
		"POST /g/items/{id} " + handler + " [mwRoot mwWith mwGroup mwInner]",
		"GET /static/* " + handler + " [mwRoot]",
		"* /callback " + handler + " [mwRoot]",
	}, got)

	stop := errors.New("stop")
	calls := 0
	err = r.Walk(func(string, string, http.Handler, ...func(http.Handler) http.Handler) error {
		calls++
		return stop
	})
	require.ErrorIs(t, err, stop)
	assert.Equal(t, 1, calls, "the walk stops at the first error")
}

// Two methods on one path may name its parameters differently, as chi let them and as the auth
// server's admin API does: GET /api/v1/admin/user-sessions/{sessionIdentifier} reads a session
// identifier where DELETE /api/v1/admin/user-sessions/{id} reads a numeric id. Each method's route
// keeps its own name, which the metrics and the audit log read, and reads its own parameter; the
// path is one, so its 405 names both methods.
func TestRouter_EachMethodNamesItsOwnParameters(t *testing.T) {
	param := func(method, name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintf(w, "%s %s=%s route=%s", method, name, r.PathValue(name), routing.RouteName(r))
		}
	}
	r := routing.New()
	r.Route("/sessions", func(g *routing.Router) {
		g.Get("/{sessionIdentifier}", param("get", "sessionIdentifier"))
		g.Delete("/{id}", param("delete", "id"))
	})

	assert.Equal(t, "get sessionIdentifier=abc route=/sessions/{sessionIdentifier}", serve(t, r, http.MethodGet, "/sessions/abc").body)
	assert.Equal(t, "delete id=7 route=/sessions/{id}", serve(t, r, http.MethodDelete, "/sessions/7").body)

	refused := serve(t, r, http.MethodPut, "/sessions/7")
	assert.Equal(t, http.StatusMethodNotAllowed, refused.status)
	assert.Equal(t, []string{"DELETE, GET"}, refused.header.Values("Allow"))

	assert.Equal(t, "/sessions/{sessionIdentifier}", r.RouteFor(httptest.NewRequest(http.MethodGet, "/sessions/abc", nil)))
	assert.Equal(t, "/sessions/{id}", r.RouteFor(httptest.NewRequest(http.MethodDelete, "/sessions/7", nil)))

	var walked []string
	require.NoError(t, r.Walk(func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		walked = append(walked, method+" "+route)
		return nil
	}))
	assert.Equal(t, []string{"GET /sessions/{sessionIdentifier}", "DELETE /sessions/{id}"}, walked)

	// Two methods may name the same parameters in a different order: each reads the values its own
	// pattern puts under each name, none overwritten by a name the other pattern gives another place.
	pair := func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "first=%s second=%s", r.PathValue("first"), r.PathValue("second"))
	}
	r.Get("/pairs/{first}/{second}", pair)
	r.Delete("/pairs/{second}/{first}", pair)
	assert.Equal(t, "first=left second=right", serve(t, r, http.MethodGet, "/pairs/left/right").body)
	assert.Equal(t, "first=right second=left", serve(t, r, http.MethodDelete, "/pairs/left/right").body)
}

// What would be silently wrong panics at registration: ServeMux's own conflicts, a route registered
// twice, a pattern in a syntax the router does not take, and middleware added after the routes it
// would have to wrap.
func TestRouter_RefusesAtRegistration(t *testing.T) {
	for name, register := range map[string]func(r *routing.Router){
		"one method on one path under two parameter names": func(r *routing.Router) {
			r.Get("/a/{id}", answer("a"))
			r.Get("/a/{name}", answer("b"))
		},
		"the same method and pattern twice":    func(r *routing.Router) { r.Get("/a", answer("a")); r.Get("/a", answer("b")) },
		"every method twice":                   func(r *routing.Router) { r.HandleFunc("/a", answer("a")); r.HandleFunc("/a", answer("b")) },
		"no leading slash":                     func(r *routing.Router) { r.Get("a", answer("a")) },
		"a trailing slash":                     func(r *routing.Router) { r.Get("/a/", answer("a")) },
		"an empty segment":                     func(r *routing.Router) { r.Get("/a//b", answer("a")) },
		"a dot segment":                        func(r *routing.Router) { r.Get("/a/../b", answer("a")) },
		"a regular-expression parameter":       func(r *routing.Router) { r.Get("/a/{id:[0-9]+}", answer("a")) },
		"a parameter inside a segment":         func(r *routing.Router) { r.Get("/a/{id}.json", answer("a")) },
		"a wildcard before the end":            func(r *routing.Router) { r.Get("/a/*/b", answer("a")) },
		"ServeMux's own end anchor":            func(r *routing.Router) { r.Get("/a/{$}", answer("a")) },
		"ServeMux's own remainder wildcard":    func(r *routing.Router) { r.Get("/a/{rest...}", answer("a")) },
		"a method in the pattern":              func(r *routing.Router) { r.Get("GET /a", answer("a")) },
		"an empty method":                      func(r *routing.Router) { r.Method("", "/a", answer("a")) },
		"a nil handler":                        func(r *routing.Router) { r.Get("/a", nil) },
		"a group prefix with a trailing slash": func(r *routing.Router) { r.Route("/g/", func(*routing.Router) {}) },
		"a group prefix with a parameter":      func(r *routing.Router) { r.Route("/g/{id}", func(*routing.Router) {}) },
		"a group prefix twice": func(r *routing.Router) {
			r.Route("/g", func(*routing.Router) {})
			r.With(mwWith).Route("/g", func(*routing.Router) {})
		},
		"Use on the root after a route": func(r *routing.Router) { r.Get("/a", answer("a")); r.Use(mwRoot) },
		"Use on the root after a group": func(r *routing.Router) { r.Route("/g", func(*routing.Router) {}); r.Use(mwRoot) },
		"Use in a group after its routes": func(r *routing.Router) {
			r.Route("/g", func(g *routing.Router) { g.Get("/a", answer("a")); g.Use(mwGroup) })
		},
		"Use on a With router": func(r *routing.Router) { r.With(mwWith).Use(mwRoot) },
	} {
		t.Run(name, func(t *testing.T) {
			assert.Panics(t, func() { register(routing.New()) })
		})
	}
}
