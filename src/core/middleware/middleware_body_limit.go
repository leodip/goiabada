package middleware

import (
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
)

// BodyLimitPolicy is one application's table of how many request-body bytes each of its routes may
// read. Each server declares its own at its composition root and passes it to MiddlewareBodyLimit;
// core owns the lookup and owns none of the numbers, as with CsrfPolicy, because the routes and what
// they legitimately carry are the application's (#426).
//
// A limit is found by the pattern chi routes the request to, not by the path, so a route with a
// parameter in it is one entry rather than one per value:
//
//   - Routes is matched exactly, on the method and the pattern together: "POST
//     /api/v1/admin/users/{id}/profile-picture". The same pattern under another method is a
//     different entry and falls through to the tables below.
//   - Prefixes inherit, and the longest prefix the pattern starts with wins, so a narrower subtree
//     can sit inside a wider one. Write the trailing slash: "/api/v1/admin/" and not "/api/v1/adm".
//   - Default is everything else, including a request no route matches.
//
// That last rule is what makes the table fail closed. A route added later that nobody remembers to
// list gets Default, the smallest limit the table has, so an omission shows up as a request refused
// rather than as a body read without bound.
type BodyLimitPolicy struct {
	// Default is the limit for every request no entry below names.
	Default int64

	// Prefixes maps a route-pattern prefix to its limit.
	Prefixes map[string]int64

	// Routes maps "METHOD /pattern" to its limit, and wins over any prefix.
	Routes map[string]int64
}

// bodyLimiter is a policy compiled for lookup: the prefixes longest first, so the first that
// matches is the longest.
type bodyLimiter struct {
	fallback int64
	prefixes []bodyLimitPrefix
	routes   map[string]int64
}

type bodyLimitPrefix struct {
	prefix string
	limit  int64
}

// newBodyLimiter compiles a policy and refuses the shapes that are silently wrong.
//
// It panics rather than returning an error for the reason newCsrfSkipper does: a policy is a literal
// at a composition root, evaluated once at startup, and every refusal here is a programming error no
// request can produce. A limit of zero refuses every body on its routes, and a key that is not
// "METHOD /pattern" or a prefix that is not a path can never match anything, so the entry it was
// written for would quietly get Default instead.
func newBodyLimiter(policy BodyLimitPolicy) bodyLimiter {
	if policy.Default <= 0 {
		panic("body limit policy: the default limit must be positive, or every request body is refused")
	}

	prefixes := make([]bodyLimitPrefix, 0, len(policy.Prefixes))
	for prefix, limit := range policy.Prefixes {
		if !strings.HasPrefix(prefix, "/") {
			panic("body limit policy: the prefix " + prefix + " is not a route pattern, so it matches nothing")
		}
		if limit <= 0 {
			panic("body limit policy: the prefix " + prefix + " has a limit that is not positive")
		}
		prefixes = append(prefixes, bodyLimitPrefix{prefix: prefix, limit: limit})
	}
	sort.Slice(prefixes, func(i, j int) bool { return len(prefixes[i].prefix) > len(prefixes[j].prefix) })

	for key, limit := range policy.Routes {
		method, pattern, ok := strings.Cut(key, " ")
		if !ok || method == "" || method != strings.ToUpper(method) || !strings.HasPrefix(pattern, "/") {
			panic("body limit policy: the route " + key + " is not \"METHOD /pattern\", so it matches nothing")
		}
		if limit <= 0 {
			panic("body limit policy: the route " + key + " has a limit that is not positive")
		}
	}

	return bodyLimiter{fallback: policy.Default, prefixes: prefixes, routes: policy.Routes}
}

// limitFor returns the limit for a request chi routes to pattern, which is empty when no route
// matches.
func (l bodyLimiter) limitFor(method string, pattern string) int64 {
	if pattern == "" {
		return l.fallback
	}
	if limit, ok := l.routes[method+" "+pattern]; ok {
		return limit
	}
	for _, p := range l.prefixes {
		if strings.HasPrefix(pattern, p.prefix) {
			return p.limit
		}
	}
	return l.fallback
}

// MiddlewareBodyLimit bounds every request body at the limit policy gives the route the request is
// about to reach, before anything downstream can read it. routes is the router the middleware is
// mounted on, consulted per request; the routes need not exist yet when this is called.
//
// It makes a read past the limit fail, with *http.MaxBytesError, and does nothing else. It writes no
// status and reads nothing ahead, so a request over the limit gets whatever answer its handler
// already gives a body it cannot read, and a handler that stops reading early, such as a JSON
// decoder after its one value, never meets the limit at all. That is deliberate: the bound is on
// what the server reads, and a byte nobody reads costs nothing (#426).
//
// A handler that bounds its body more tightly keeps its own bound. MaxBytesReader nests, and the
// inner, smaller one trips first.
//
// Mount it after chi's StripSlashes, whose normalized path is what the lookup reads, and before
// anything that reads a body at the root.
func MiddlewareBodyLimit(routes chi.Routes, policy BodyLimitPolicy) func(next http.Handler) http.Handler {
	limiter := newBodyLimiter(policy)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// net/http gives a request with no body http.NoBody, so every GET skips the lookup.
			if r.Body != nil && r.Body != http.NoBody {
				// A fresh route context, because Find writes the URL parameters it collects into
				// the one it is given, and the request's own must reach the router untouched.
				pattern := routes.Find(chi.NewRouteContext(), r.Method, routingPath(r))
				r.Body = http.MaxBytesReader(w, r.Body, limiter.limitFor(r.Method, pattern))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// routingPath is the path chi will route r by, resolved the way chi's own routeHTTP resolves it:
// the route context's RoutePath when set, which is where StripSlashes writes the path it
// normalized, else the raw path, else the decoded one.
func routingPath(r *http.Request) string {
	if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePath != "" {
		return rctx.RoutePath
	}
	if r.URL.RawPath != "" {
		return r.URL.RawPath
	}
	if r.URL.Path == "" {
		return "/"
	}
	return r.URL.Path
}
