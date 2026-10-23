// Package routing is the router both servers register their routes on: the part of chi's surface
// their two route tables use (Use, With, Route, the method verbs, NotFound and a walk), built on
// net/http.ServeMux, which does the matching (#462 decision 1). What every route must follow is
// decided here once rather than in each route table:
//
//   - A request no route answers meets the middleware of the group its path falls under first, so
//     a group's guards answer a made-up path as they answer a real one (decision 2).
//   - Behind them it is a 404, answered by the not-found handler of the router the group was
//     created from, or net/http's plain text where none was set (decision 2).
//   - A path registered for other methods is a 405 with an empty body and an Allow naming every
//     method registered for it, sorted, HEAD only where HEAD is registered (decision 3).
//   - A path with an empty, "." or ".." segment matches no route and is a 404; ServeMux's cleaning
//     redirect is never reached, nor its redirect from a subtree's bare prefix (decision 4).
//   - A route is named as chi spelled it: the path alone, the group's prefix joined on, parameters
//     as {name}, a group's own "/" as the prefix, and a trailing wildcard as "/*" (decision 5).
//     Two methods on one path may name its parameters differently, as chi let them, and each
//     method's route keeps its own name and reads its own parameters.
//
// Patterns take chi's syntax, restricted to what ServeMux can express: literal segments, {name}
// parameters as whole segments, and "*" as the last segment, matching everything below it.
// Anything else panics at registration, where a pattern that matched nothing would otherwise fail
// silently.
package routing

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
)

// anyMethod is the key, and the walk's method, of a route registered for every method.
const anyMethod = "*"

// Router registers routes and serves them. New returns the root; With and Route return routers
// sharing its table, each adding to the middleware the routes registered through it run behind.
// Every router serves the whole table.
//
// Registration is for startup: a Router is not safe to register on while it serves.
type Router struct {
	table *table
	// scope is the group this router registers into: the root's, or the one Route created.
	scope *group
	// parent is the router With or Route was called on, nil at the root. A group created from this
	// router inherits the first not-found handler on the way up.
	parent *Router
	// chain is the middleware With added since scope, which every route registered through this
	// router runs behind, beneath its group's.
	chain []func(http.Handler) http.Handler
	// notFound is the handler NotFound was given on this router, bare.
	notFound http.Handler
}

// table is what every router of one root shares.
type table struct {
	mux *http.ServeMux
	// use is the root's own middleware, which wraps routing itself; handler is it composed.
	use     []func(http.Handler) http.Handler
	handler http.Handler
	root    *group
	// groups is every group but the root's, the longest prefix first.
	groups    []*group
	endpoints []*endpoint
	// byShape is every endpoint by its path with each parameter's name left out, so two methods
	// naming one path's parameters differently share it, as ServeMux requires.
	byShape map[string]*endpoint
}

// group is a prefix with the middleware every request under it meets, matched or not.
type group struct {
	prefix string
	// router is the router Route handed the group's function, so a NotFound set within the
	// group is found from it.
	router *Router
	// chain is the group's whole middleware below the root's own: its parent group's, the chain of
	// the router it was created from, and its own Use; handler is it composed over answer.
	chain   []func(http.Handler) http.Handler
	handler http.Handler
	// notFound is a not-found handler set within the group, already behind the With chain of the
	// router it was set on.
	notFound http.Handler
	// sealed is set once a route or a group is registered in the group, after which Use would
	// leave them behind.
	sealed bool
}

// endpoint is one path, with a route per method.
type endpoint struct {
	table *table
	// params are the parameter names ServeMux matches the path with: those of its first route.
	params  []string
	methods map[string]*route
	// order is the methods in the order they were registered, for the walk.
	order []string
}

// route is one method of an endpoint, with its name, the names it gives the path's parameters, and
// the group and the With chain it was registered through.
type route struct {
	name    string
	params  []string
	scope   *group
	handler http.Handler
	chain   []func(http.Handler) http.Handler
	served  http.Handler
}

// match is what routing decided for one request, shared through the request's context by every
// copy of it made below the router: the endpoint its path matched, the route that will answer it,
// and the route's name once the route is reached.
type match struct {
	endpoint *endpoint
	route    *route
	name     string
}

type matchKey struct{}

// New returns a root router with no routes.
func New() *Router {
	t := &table{mux: http.NewServeMux(), byShape: map[string]*endpoint{}}
	root := &Router{table: t}
	t.root = &group{router: root}
	root.scope = t.root
	t.root.handler = http.HandlerFunc(t.root.answer)
	t.handler = http.HandlerFunc(t.dispatch)
	return root
}

// Use adds middleware to the root or to a group: on the root it runs for every request before
// routing, so a path it rewrites is the path routed; on a group it runs for every request under the
// group's prefix, whether or not a route matches. Middleware goes before the routes and groups it
// would wrap; Use after one, or on a router from With, panics.
func (rt *Router) Use(middlewares ...func(http.Handler) http.Handler) {
	if rt.scope.router != rt {
		panic("routing: Use on a router from With; pass the middleware to With")
	}
	if rt.scope.sealed {
		panic("routing: Use after a route or group was registered here, which it would not wrap")
	}
	if rt.scope == rt.table.root {
		rt.table.use = append(rt.table.use, middlewares...)
		rt.table.handler = compose(rt.table.use, http.HandlerFunc(rt.table.dispatch))
		return
	}
	rt.scope.chain = append(rt.scope.chain, middlewares...)
	rt.scope.handler = compose(rt.scope.chain, http.HandlerFunc(rt.scope.answer))
}

// With returns a router whose routes run behind middlewares too, after this router's own.
func (rt *Router) With(middlewares ...func(http.Handler) http.Handler) *Router {
	return &Router{
		table:  rt.table,
		scope:  rt.scope,
		parent: rt,
		chain:  append(slices.Clip(rt.chain), middlewares...),
	}
}

// Route creates a group at prefix under this router's, calls fn with its router, and returns it.
// The group runs behind this router's middleware and its own Use, for every path under it.
func (rt *Router) Route(prefix string, fn func(r *Router)) *Router {
	validatePrefix(prefix)
	full := rt.scope.prefix + prefix
	for _, existing := range rt.table.groups {
		if existing.prefix == full {
			panic("routing: the group " + full + " is registered twice")
		}
	}
	rt.scope.sealed = true

	g := &group{prefix: full, chain: append(slices.Clip(rt.scope.chain), rt.chain...)}
	sub := &Router{table: rt.table, scope: g, parent: rt}
	g.router = sub
	g.handler = compose(g.chain, http.HandlerFunc(g.answer))
	rt.table.groups = append(rt.table.groups, g)
	sort.SliceStable(rt.table.groups, func(i, j int) bool {
		return len(rt.table.groups[i].prefix) > len(rt.table.groups[j].prefix)
	})

	fn(sub)
	return sub
}

// Method registers handler for method on pattern.
func (rt *Router) Method(method string, pattern string, handler http.Handler) {
	if method == "" || strings.ContainsAny(method, " /") {
		panic(fmt.Sprintf("routing: %q is not a method", method))
	}
	rt.register(method, pattern, handler)
}

// Handle registers handler on pattern for every method, so the path is never a 405. A method
// registered on the same pattern with Method or a verb wins over it.
func (rt *Router) Handle(pattern string, handler http.Handler) {
	rt.register(anyMethod, pattern, handler)
}

// HandleFunc is Handle for a function.
func (rt *Router) HandleFunc(pattern string, handler http.HandlerFunc) {
	rt.Handle(pattern, nilOrHandler(handler))
}

// Get registers handler for GET on pattern. HEAD is not registered with it: a GET-only route
// answers HEAD 405, unless Head registers a handler for it too.
func (rt *Router) Get(pattern string, handler http.HandlerFunc) {
	rt.Method(http.MethodGet, pattern, nilOrHandler(handler))
}

// Head registers handler for HEAD on pattern.
func (rt *Router) Head(pattern string, handler http.HandlerFunc) {
	rt.Method(http.MethodHead, pattern, nilOrHandler(handler))
}

// Post registers handler for POST on pattern.
func (rt *Router) Post(pattern string, handler http.HandlerFunc) {
	rt.Method(http.MethodPost, pattern, nilOrHandler(handler))
}

// Put registers handler for PUT on pattern.
func (rt *Router) Put(pattern string, handler http.HandlerFunc) {
	rt.Method(http.MethodPut, pattern, nilOrHandler(handler))
}

// Patch registers handler for PATCH on pattern.
func (rt *Router) Patch(pattern string, handler http.HandlerFunc) {
	rt.Method(http.MethodPatch, pattern, nilOrHandler(handler))
}

// Delete registers handler for DELETE on pattern.
func (rt *Router) Delete(pattern string, handler http.HandlerFunc) {
	rt.Method(http.MethodDelete, pattern, nilOrHandler(handler))
}

// Options registers handler for OPTIONS on pattern.
func (rt *Router) Options(pattern string, handler http.HandlerFunc) {
	rt.Method(http.MethodOptions, pattern, nilOrHandler(handler))
}

// NotFound sets the handler that answers a path no route matches in this router's group, behind
// this router's With middleware, and in every group created from this router, or from a router
// With or Route derives from it, that sets none of its own. A group created where no not-found
// handler was set answers net/http's plain-text 404.
func (rt *Router) NotFound(handler http.HandlerFunc) {
	h := nilOrHandler(handler)
	rt.notFound = h
	rt.scope.notFound = compose(rt.chain, h)
}

// ServeHTTP routes the request through the root's middleware, then its group's, to its route, or
// to the 404 or 405 answer.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(context.WithValue(r.Context(), matchKey{}, &match{}))
	rt.table.handler.ServeHTTP(w, r)
}

// RouteFor names the route the router would answer r with, in chi's spelling, or "" when r would
// be a 404 or a 405. A middleware on the root reads it before routing, as the body limit does.
func (rt *Router) RouteFor(r *http.Request) string {
	if _, rte := rt.table.match(r); rte != nil {
		return rte.name
	}
	return ""
}

// RouteName names the route that answered r, in chi's spelling, once the request has reached it:
// read by the route's handler, or by a middleware of the router after its next handler returned.
// It is "" for a request no route answered, a 404 or a 405, or one a group's middleware answered
// before the route, and for a request the router never saw.
func RouteName(r *http.Request) string {
	if m, ok := r.Context().Value(matchKey{}).(*match); ok {
		return m.name
	}
	return ""
}

// WalkFunc is called by Walk for each method of each route: the method ("*" for a route registered
// for every method), the route's name, the handler as registered, and every middleware the route
// runs behind, the root's first.
type WalkFunc func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error

// Walk calls fn for each method of each route, in the order they were registered, and stops at the
// first error fn returns.
func (rt *Router) Walk(fn WalkFunc) error {
	for _, ep := range rt.table.endpoints {
		for _, method := range ep.order {
			rte := ep.methods[method]
			middlewares := slices.Concat(rt.table.use, rte.scope.chain, rte.chain)
			if err := fn(method, rte.name, rte.handler, middlewares...); err != nil {
				return err
			}
		}
	}
	return nil
}

// register adds one method of one route. A route's path is its group's prefix and pattern; its
// name is that path in chi's spelling, and ServeMux matches it by path alone, method-free, so
// ServeMux's own method rules, a GET pattern matching HEAD and its 405, never apply. A path is one
// endpoint whatever its parameters are named, so a method naming them differently from the one
// registered first joins it rather than conflicting with it in ServeMux.
func (rt *Router) register(method string, pattern string, handler http.Handler) {
	if handler == nil {
		panic("routing: a nil handler for " + pattern)
	}
	validatePattern(pattern)
	t := rt.table

	name, muxPatterns := spell(rt.scope.prefix, pattern)
	shape, params := parameters(name)
	ep := t.byShape[shape]
	if ep == nil {
		ep = &endpoint{table: t, params: params, methods: map[string]*route{}}
		for _, p := range muxPatterns {
			// ServeMux panics on a pattern that conflicts with one already registered.
			t.mux.Handle(p, ep)
		}
		t.byShape[shape] = ep
		t.endpoints = append(t.endpoints, ep)
	}
	if _, taken := ep.methods[method]; taken {
		panic(fmt.Sprintf("routing: %s %s is registered twice", method, name))
	}
	rt.scope.sealed = true
	t.root.sealed = true

	ep.methods[method] = &route{
		name:    name,
		params:  params,
		scope:   rt.scope,
		handler: handler,
		chain:   rt.chain,
		served:  compose(rt.chain, handler),
	}
	ep.order = append(ep.order, method)
}

// spell answers a route's name in chi's spelling and the ServeMux patterns that match its path. A
// group's own "/" is the prefix, with or without a trailing slash, the root's is "/" alone, and a
// trailing "*" is everything below its prefix: ServeMux's trailing slash, which matches a subtree.
func spell(prefix string, pattern string) (string, []string) {
	switch {
	case pattern == "/" && prefix == "":
		return "/", []string{"/{$}"}
	case pattern == "/":
		return prefix, []string{prefix, prefix + "/{$}"}
	case strings.HasSuffix(pattern, "/*"):
		return prefix + pattern, []string{prefix + strings.TrimSuffix(pattern, "*")}
	default:
		return prefix + pattern, []string{prefix + pattern}
	}
}

// parameters answers name with each parameter's name left out, which is the path's shape, and the
// parameters' names in order.
func parameters(name string) (string, []string) {
	segments := strings.Split(name, "/")
	var params []string
	for i, segment := range segments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			params = append(params, segment[1:len(segment)-1])
			segments[i] = "{}"
		}
	}
	return strings.Join(segments, "/"), params
}

// validatePattern refuses a pattern the router would not match as written: one not rooted, with a
// trailing slash, an empty or dot segment, a parameter that is not a whole segment or takes a
// regular expression, a wildcard before the end, or ServeMux's own {$} or {name...}.
func validatePattern(pattern string) {
	if pattern == "/" {
		return
	}
	if !strings.HasPrefix(pattern, "/") {
		panic("routing: the pattern " + pattern + " does not start with /")
	}
	segments := strings.Split(pattern[1:], "/")
	for i, segment := range segments {
		last := i == len(segments)-1
		switch {
		case segment == "" || segment == "." || segment == "..":
			panic("routing: the pattern " + pattern + " has an empty, . or .. segment, or a trailing slash")
		case segment == "*":
			if !last {
				panic("routing: the pattern " + pattern + " has a wildcard before its end")
			}
		case strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}"):
			if !isIdentifier(segment[1 : len(segment)-1]) {
				panic("routing: the parameter " + segment + " in " + pattern + " is not a plain {name}")
			}
		case strings.ContainsAny(segment, "{}* "):
			panic("routing: the segment " + segment + " in " + pattern + " is neither literal nor a whole {name}")
		}
	}
}

// validatePrefix refuses a group prefix that is not a rooted path of literal segments.
func validatePrefix(prefix string) {
	if !strings.HasPrefix(prefix, "/") || strings.HasSuffix(prefix, "/") {
		panic("routing: the group prefix " + prefix + " must start with / and not end with one")
	}
	for _, segment := range strings.Split(prefix[1:], "/") {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "{}* ") {
			panic("routing: the group prefix " + prefix + " must be literal segments")
		}
	}
}

func isIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		letter := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !letter && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// match decides what answers r: the endpoint its path matches, if any, and the route for its
// method, if the endpoint takes it. A route is matched only through ServeMux's answer being one of
// this table's endpoints, so its redirects, the cleaning one and the one from a subtree's bare
// prefix, are no match; a non-canonical path is refused before ServeMux sees it.
func (t *table) match(r *http.Request) (*endpoint, *route) {
	if !canonical(r.URL.EscapedPath()) {
		return nil, nil
	}
	h, _ := t.mux.Handler(r)
	ep, ok := h.(*endpoint)
	if !ok {
		return nil, nil
	}
	if rte := ep.methods[r.Method]; rte != nil {
		return ep, rte
	}
	return ep, ep.methods[anyMethod]
}

// canonical reports whether path is one ServeMux would route without cleaning it: rooted, with no
// empty, "." or ".." segment. One trailing slash is not an empty segment.
func canonical(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	segments := strings.Split(path[1:], "/")
	for i, segment := range segments {
		if segment == "." || segment == ".." || (segment == "" && i != len(segments)-1) {
			return false
		}
	}
	return true
}

// dispatch runs beneath the root's middleware, on the path it left. A request a route takes goes
// through the group that route was registered in; any other goes through the group its path falls
// under, to its 404 or 405.
func (t *table) dispatch(w http.ResponseWriter, r *http.Request) {
	m, ok := r.Context().Value(matchKey{}).(*match)
	if !ok {
		// Only ServeHTTP reaches dispatch, and it puts the match on first.
		m = &match{}
		r = r.WithContext(context.WithValue(r.Context(), matchKey{}, m))
	}
	m.endpoint, m.route = t.match(r)
	if m.route != nil {
		m.route.scope.handler.ServeHTTP(w, r)
		return
	}
	t.groupFor(r.URL.Path).handler.ServeHTTP(w, r)
}

// groupFor is the innermost group whose prefix path is, or is under; the root's when none.
func (t *table) groupFor(path string) *group {
	for _, g := range t.groups {
		if path == g.prefix || strings.HasPrefix(path, g.prefix+"/") {
			return g
		}
	}
	return t.root
}

// answer runs beneath the group's middleware: the route dispatch chose, through ServeMux so the
// request carries its path values, or the 405 or the 404.
func (g *group) answer(w http.ResponseWriter, r *http.Request) {
	m, _ := r.Context().Value(matchKey{}).(*match)
	switch {
	case m != nil && m.route != nil:
		m.endpoint.table.mux.ServeHTTP(w, r)
	case m != nil && m.endpoint != nil:
		w.Header().Set("Allow", m.endpoint.allow())
		w.WriteHeader(http.StatusMethodNotAllowed)
	default:
		g.notFoundHandler().ServeHTTP(w, r)
	}
}

// notFoundHandler is the group's own not-found handler, else the first one set on the way up from
// the router that created it, else net/http's.
func (g *group) notFoundHandler() http.Handler {
	if g.notFound != nil {
		return g.notFound
	}
	for rt := g.router.parent; rt != nil; rt = rt.parent {
		if rt.notFound != nil {
			return rt.notFound
		}
	}
	return http.NotFoundHandler()
}

// ServeHTTP is ServeMux's handler for the endpoint's path, reached only from the group answer the
// dispatch chose. A request whose match names another endpoint was routed somewhere else after the
// dispatch decided, by a middleware rewriting it, and its group's middleware may not be the one it
// met, so it is not served.
func (ep *endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m, _ := r.Context().Value(matchKey{}).(*match)
	if m == nil || m.endpoint != ep || m.route == nil {
		http.NotFound(w, r)
		return
	}
	m.name = m.route.name
	// ServeMux set the path values under the endpoint's names; a route naming them otherwise reads
	// them under its own. ServeMux hands its handler the request it was given, so they are set on
	// the one the route's chain is served. Every value is read before any is set, since the two may
	// give one name different places.
	if !slices.Equal(m.route.params, ep.params) {
		values := make([]string, len(ep.params))
		for i, param := range ep.params {
			values[i] = r.PathValue(param)
		}
		for i, param := range m.route.params {
			r.SetPathValue(param, values[i])
		}
	}
	m.route.served.ServeHTTP(w, r)
}

// allow is the Allow header of a 405 on the endpoint: every method registered for it, sorted.
func (ep *endpoint) allow() string {
	methods := slices.Clone(ep.order)
	slices.Sort(methods)
	return strings.Join(methods, ", ")
}

// compose wraps handler in middlewares, the first outermost.
func compose(middlewares []func(http.Handler) http.Handler, handler http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

// nilOrHandler keeps a nil function nil, so register refuses it rather than storing a handler that
// panics on its first request.
func nilOrHandler(handler http.HandlerFunc) http.Handler {
	if handler == nil {
		return nil
	}
	return handler
}
