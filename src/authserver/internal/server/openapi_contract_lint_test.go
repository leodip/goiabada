//go:build !race

package server

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/guard"
	"gopkg.in/yaml.v3"
)

// The tests in this file hold web/openapi.yaml to what routes.go and the handlers actually
// do. That file is embedded by web/embed_fs.go and served at GET /openapi.yaml, so
// it is not a README: it is the contract a caller generates a client from, and a status a
// handler can return but the spec does not declare reaches that client as an unmodelled
// error rather than as the failure it is.
//
// Nothing enforced the two agreeing before this, and they had drifted a long way: the
// duplicate-email 409 on createUser was undeclared, so were the two ownership 403s, so was
// every 500, and deleteSettingsKey declared a 404 its handler cannot produce. Every one of
// those is a branch a generated client either lacks or carries for nothing.
//
// The instrument is lexical, which is what it can be without executing the server, and the
// honest consequence is stated here rather than discovered later. It reads the statuses a
// handler *mentions*, not the ones it can be driven to return, so an unreachable branch is
// still documented (the conservative direction: a caller told about a failure that cannot
// happen loses nothing) and a status produced by a value computed at run time would be
// missed. No handler in this module does the latter today: writeJSONError and
// writeLocalizedError are always called with an http.Status constant, which
// TestAPIHandlers_WriteStatusesAsConstants below is what keeps true. A handler's statuses
// include those of every function of its own package it reaches, read from that function's
// body, so a status a helper writes needs no entry here. Only the shared writers of other
// packages that write a status they are not handed are read by name, in ownStatuses. A
// helper's branch one caller cannot reach is still read as that caller's, the same
// conservative direction as an unreachable branch.
//
// A route's statuses are its handler's and those of the middleware routes.go mounts in front of
// it, through the Use calls of its root router and its groups, the r.With of the router each group
// hangs off, and its own r.With, read in source order (collectRoutes says how), each read from its
// source as a handler is (routeChains says how a method value, a call to another method and a
// refusal written through an interface field are followed). Both directions hold for every status alike: a failure the
// chain can write must be declared, and a declared failure must be one the handler or the chain
// can write. No status has a rule of its own and no list names the middleware, so a new guard,
// limiter or refusal is checked from the day it is mounted, where a hand-written rule had to be
// remembered: the bearer middleware's 400 INVALID_REQUEST went undeclared on 27 operations under
// such rules (#261). Middleware mounted outside routes.go, around every route, is not read.
//
// What it does not check: response bodies, schemas, parameters, or whether an operation's
// description is true. Those stay hand-maintained.

// httpStatusConstants is the net/http spelling of every status this module may name. An
// unknown one fails the scan rather than being skipped, because silently ignoring a status
// nobody taught this file about is exactly the drift it exists to stop.
var httpStatusConstants = map[string]int{
	"StatusOK":                    200,
	"StatusCreated":               201,
	"StatusAccepted":              202,
	"StatusNoContent":             204,
	"StatusMovedPermanently":      301,
	"StatusFound":                 302,
	"StatusSeeOther":              303,
	"StatusNotModified":           304,
	"StatusTemporaryRedirect":     307,
	"StatusPermanentRedirect":     308,
	"StatusBadRequest":            400,
	"StatusUnauthorized":          401,
	"StatusForbidden":             403,
	"StatusNotFound":              404,
	"StatusMethodNotAllowed":      405,
	"StatusConflict":              409,
	"StatusGone":                  410,
	"StatusRequestEntityTooLarge": 413,
	"StatusUnsupportedMediaType":  415,
	"StatusUnprocessableEntity":   422,
	"StatusTooManyRequests":       429,
	"StatusInternalServerError":   500,
	"StatusNotImplemented":        501,
	"StatusBadGateway":            502,
	"StatusServiceUnavailable":    503,
}

// routeRegistration is one line of routes.go: what a caller reaches, where it lands, and the
// middleware routes.go mounts in front of it.
type routeRegistration struct {
	method  string // lower case, as the spec spells it
	path    string // as written, with routes.go's own parameter names
	key     string // method + path with parameter names erased, the join key with the spec
	handler string // package-qualified, apihandlers.HandleUserGet
	// mounted is the middleware routes.go mounts in front of the route, in the order it runs, as
	// collectRoutes reads it from the router the route is registered through: the Use calls of the
	// root router, then for each group the route sits in, outer group first, the With arguments of
	// the router the group hangs off and the group's own Use calls, and last the With arguments of
	// the router the route itself hangs off. That is how the Account group mounts its guards once
	// for all its routes and the Admin group its scope guards on each route.
	mounted []ast.Expr
	// unresolved says why collectRoutes cannot tell which middleware the route runs behind, such as
	// a router variable assigned inside a branch; empty when mounted is the whole chain.
	unresolved string
	// chain is what readRouteChains fills: each status the route's middleware can write, with the
	// middleware that writes it.
	chain map[int][]string
	line  int
}

// pathParam erases the name of a path parameter, so a route joins the spec by the URL a caller
// actually sends. The names themselves are held to agree by
// TestOpenAPI_NamesPathParametersAsTheRoutesDo, which reports a joined pair spelling them two
// ways rather than leaving it to fail as an undocumented route and an unrouted operation.
var pathParam = regexp.MustCompile(`\{[^}]*\}`)

func routeKey(method, path string) string {
	return method + " " + pathParam.ReplaceAllString(path, "{}")
}

// TestOpenAPI_DeclaresEveryStatusTheHandlersEmit is the forward direction: a status a route
// can write must appear in the spec. This is the one that matters to a caller, because the
// statuses it catches are the ones a generated client has no branch for.
//
// A route writes what its handler writes and what the middleware routes.go mounts in front of
// it writes. Scanning handler bodies alone once missed 103 statuses: every Admin and Account
// operation sits behind a scope guard that answers 403 before the handler runs, and the
// document declared that 403 on two of them (#245). The bearer middleware's 400
// INVALID_REQUEST went undeclared on 27 operations the same way, when a hand-written rule
// stood in for reading the middleware (#261). Middleware statuses are not less part of the
// contract for being written earlier, and a generated client has no branch for one either way.
func TestOpenAPI_DeclaresEveryStatusTheHandlersEmit(t *testing.T) {
	assertDeclaresEveryStatus(t, parseRouteChains(t), parseHandlerStatuses(t), parseSpec(t))
}

// TestOpenAPI_DeclaresNoStatusTheHandlersCannotEmit is the reverse: a documented failure
// must be one the handler or its middleware can actually produce, so the spec does not send a
// caller off writing a branch that never runs. Two operations declared a 404 for exactly that
// reason. deleteSettingsKey answers 400 for an id that matches no key, and
// getResourcePermissions never looks its resource up at all, so an unknown id comes back as
// an empty list.
//
// Only failures are checked, because a success status can be implicit: a handler that calls
// httpHelper.EncodeJSON and never touches WriteHeader answers 200 without naming it, so
// absence from the source would not be absence from the wire.
//
// No status has a rule of its own. A 401 is accepted where the bearer middleware or the handler
// writes one, so a handler's 401 INVALID_SESSION stays valid on a route with no bearer
// middleware, and a 401 declared where neither writes one fails as a 404 would.
func TestOpenAPI_DeclaresNoStatusTheHandlersCannotEmit(t *testing.T) {
	assertDeclaresNoUndeliverableStatus(t, parseRouteChains(t), parseHandlerStatuses(t), parseSpec(t))
}

// assertDeclaresEveryStatus is the forward test's reporting half: one failure per finding of
// undeclaredStatusFindings, and a stop for a join that matched no route to the spec, since a
// comparison of nothing proves nothing.
func assertDeclaresEveryStatus(r guard.Reporter, routes []routeRegistration,
	handlers map[string]map[int]bool, spec map[string]specOperation) {

	r.Helper()
	findings, joined := undeclaredStatusFindings(routes, handlers, spec)
	reportStatusFindings(r, findings, joined, len(routes), len(spec))
}

// assertDeclaresNoUndeliverableStatus is the reverse test's reporting half, as
// assertDeclaresEveryStatus is the forward one's.
func assertDeclaresNoUndeliverableStatus(r guard.Reporter, routes []routeRegistration,
	handlers map[string]map[int]bool, spec map[string]specOperation) {

	r.Helper()
	findings, joined := undeliverableStatusFindings(routes, handlers, spec)
	reportStatusFindings(r, findings, joined, len(routes), len(spec))
}

func reportStatusFindings(r guard.Reporter, findings []string, joined, routes, operations int) {
	r.Helper()
	if joined == 0 {
		r.Fatalf("joined none of %d routes to the %d operations of openapi.yaml; the status "+
			"comparison is no longer reaching the spec", routes, operations)
		return
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
}

// undeclaredStatusFindings returns one finding per status a documented route can write that its
// operation does not declare: each status its handler writes, and each status its chain writes,
// naming the middleware. It also reports a route whose handler no source declares, and returns
// how many routes it joined to the spec.
func undeclaredStatusFindings(routes []routeRegistration, handlers map[string]map[int]bool,
	spec map[string]specOperation) ([]string, int) {

	var findings []string
	joined := 0
	for _, r := range routes {
		op, documented := spec[r.key]
		if !documented {
			continue // TestOpenAPI_DescribesEveryAPIRoute owns this case
		}
		joined++
		emitted, known := handlers[r.handler]
		if !known {
			findings = append(findings, fmt.Sprintf("routes.go:%d: %s %s lands in %s, which no "+
				"non-test source under internal/handlers declares", r.line, strings.ToUpper(r.method), r.path, r.handler))
		}
		for _, code := range sortedCodes(emitted) {
			if !op.responses[code] {
				findings = append(findings, fmt.Sprintf("%s (%s %s) can answer %d, which openapi.yaml "+
					"does not declare: a generated client has no branch for it. Handler: %s",
					op.operationId, strings.ToUpper(r.method), r.path, code, r.handler))
			}
		}
		for _, code := range sortedKeysInt(r.chain) {
			if op.responses[code] || emitted[code] {
				continue // declared, or reported above as the handler's
			}
			findings = append(findings, fmt.Sprintf("%s (%s %s) can answer %d from %s, which "+
				"routes.go:%d mounts in front of %s, and openapi.yaml does not declare it: a "+
				"generated client has no branch for it", op.operationId, strings.ToUpper(r.method),
				r.path, code, strings.Join(r.chain[code], " and "), r.line, r.handler))
		}
	}
	return findings, joined
}

// undeliverableStatusFindings returns one finding per failure a documented route's operation
// declares that neither its handler nor its chain writes, and how many routes it joined to the
// spec.
func undeliverableStatusFindings(routes []routeRegistration, handlers map[string]map[int]bool,
	spec map[string]specOperation) ([]string, int) {

	var findings []string
	joined := 0
	for _, r := range routes {
		op, documented := spec[r.key]
		if !documented {
			continue
		}
		joined++
		emitted := handlers[r.handler]
		for _, code := range sortedCodes(op.responses) {
			if code < 400 || emitted[code] || len(r.chain[code]) > 0 {
				continue
			}
			findings = append(findings, fmt.Sprintf("%s (%s %s) declares %d, which neither %s nor the "+
				"middleware routes.go:%d mounts in front of it writes: the spec is promising a failure "+
				"that cannot arrive", op.operationId, strings.ToUpper(r.method), r.path, code, r.handler, r.line))
		}
	}
	return findings, joined
}

func sortedKeysInt[V any](m map[int]V) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// TestOpenAPI_DescribesEveryAPIRoute keeps the two surfaces the same size, in both
// directions: every route under /api/v1 is in the spec, and the spec describes no operation
// that no longer exists.
//
// There is no allowance list any more. There used to be one, knownUndocumentedRoutes, holding
// eleven routes with a reason each, and its note claimed several of them needed schemas that
// did not exist. That was stale: the profile picture operations answer JSON rather than image
// bytes, and the audit log and group search shapes were already declared in src/core/api. All
// eleven were written out (#245), so a new API route now has one way to satisfy this test,
// which is to be documented.
//
// The public routes outside /api/v1 that the document describes for callers are held the same
// way, in documentedPublicRoutes, so a GET dropped from the spec fails here as an API route would.
func TestOpenAPI_DescribesEveryAPIRoute(t *testing.T) {
	routes := parseRoutes(t)
	spec := parseSpec(t)

	routed := map[string]bool{}
	for _, r := range routes {
		routed[r.key] = true
		public := r.method == "get" && slices.Contains(documentedPublicRoutes, r.path)
		if !strings.HasPrefix(r.path, "/api/v1/") && !public {
			continue
		}
		if _, documented := spec[r.key]; !documented {
			t.Errorf("routes.go:%d: %s %s is not in openapi.yaml. Document it: the file is the "+
				"contract a caller generates a client from, and a route missing from it is a route "+
				"that caller cannot reach", r.line, strings.ToUpper(r.method), r.path)
		}
	}

	for key, op := range spec {
		if !routed[key] {
			t.Errorf("openapi.yaml describes %s (%s), which routes.go does not register",
				op.operationId, key)
		}
	}

	// A listed path routes.go no longer registers would hold nothing; the list goes with it.
	for _, path := range documentedPublicRoutes {
		if !routed[routeKey("get", path)] {
			t.Errorf("documentedPublicRoutes lists GET %s, which routes.go does not register", path)
		}
	}
}

// documentedPublicRoutes are the routes outside /api/v1 that openapi.yaml describes for callers,
// each by its GET: the public client logo and settings, and a brand's two stylesheets and its
// assets, whose URLs the admin API and the public settings hand out.
var documentedPublicRoutes = []string{
	"/client/logo/{clientIdentifier}",
	"/api/public/settings",
	brandthemes.StylesheetRoute,
	brandthemes.ColorsStylesheetRoute,
	brandasset.Route,
}

// routeConstants is each package constant routes.go registers a route by, mapped to the
// constant's own value, so the table cannot drift from what the constants say. A route
// registered by a constant this table does not hold is one collectRoutes cannot read, which
// TestOpenAPI_ReadsEveryRoutePath fails on rather than letting every test here skip it.
var routeConstants = map[string]string{
	"brandthemes.StylesheetRoute":           brandthemes.StylesheetRoute,
	"brandthemes.ColorsStylesheetRoute":     brandthemes.ColorsStylesheetRoute,
	"brandthemes.SafeStylesheetRoute":       brandthemes.SafeStylesheetRoute,
	"brandthemes.SafeColorsStylesheetRoute": brandthemes.SafeColorsStylesheetRoute,
	"brandasset.Route":                      brandasset.Route,
	"emaillinks.ForgotPasswordPath":         emaillinks.ForgotPasswordPath,
	"emaillinks.ResetPasswordPath":          emaillinks.ResetPasswordPath,
	"emaillinks.AccountActivatePath":        emaillinks.AccountActivatePath,
}

// routePath reads a registration's path: a string literal, or a package constant routeConstants
// holds, either in parentheses or not.
func routePath(e ast.Expr) (string, bool) {
	for {
		paren, ok := e.(*ast.ParenExpr)
		if !ok {
			break
		}
		e = paren.X
	}
	if path, ok := stringLiteral(e); ok {
		return path, true
	}
	if name, ok := selectorName(e); ok {
		path, known := routeConstants[name]
		return path, known
	}
	return "", false
}

// selectorName is pkg.Name for a selector on a package identifier.
func selectorName(e ast.Expr) (string, bool) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return pkg.Name + "." + sel.Sel.Name, true
}

// TestOpenAPI_ReadsEveryRoutePath holds collectRoutes to routes.go: a route whose path the parser
// cannot read is skipped by every test in this file, documented or not, and by the administrative
// route classification, which shares collectRoutes.
func TestOpenAPI_ReadsEveryRoutePath(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "routes.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing routes.go: %v", err)
	}

	assertRoutePathsReadable(t, fset, file)
}

// assertRoutePathsReadable reports each route registration in file whose path routePath cannot
// read, which is anything but a string literal or a constant routeConstants holds: a constant of
// the file's own, one of a package the table does not hold, a variable. It also reports a table
// entry no registration uses, and stops on a file with no registration at all, a walk that no
// longer matches how routes are registered.
func assertRoutePathsReadable(r guard.Reporter, fset *token.FileSet, file *ast.File) {
	r.Helper()
	registrations := 0
	used := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		path, ok := registrationPath(call)
		if !ok {
			return true
		}
		registrations++
		if _, readable := routePath(path); !readable {
			r.Errorf("routes.go:%d registers a route at %s, which the OpenAPI contract tests cannot "+
				"read: use a string literal, or a package constant added to routeConstants",
				fset.Position(call.Pos()).Line, types.ExprString(path))
			return true
		}
		if name, ok := selectorName(ast.Unparen(path)); ok {
			used[name] = true
		}
		return true
	})
	if registrations == 0 {
		r.Fatalf("read no route registration in routes.go; the walk no longer matches the way routes are registered")
		return
	}
	names := make([]string, 0, len(routeConstants))
	for name := range routeConstants {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !used[name] {
			r.Errorf("routeConstants holds %s, which no registration in routes.go uses: remove it", name)
		}
	}
}

// registrationPath is the path of a call that registers a route as collectRoutes reads one:
// getAndHead(r, path, pkg.HandleX(...)), r.Verb(path, pkg.HandleX(...)) or r.Route(path, func...).
func registrationPath(call *ast.CallExpr) (ast.Expr, bool) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		if fn.Name == "getAndHead" && len(call.Args) == 3 {
			if _, ok := handlerConstructor(call.Args[2]); ok {
				return call.Args[1], true
			}
		}
	case *ast.SelectorExpr:
		if fn.Sel.Name == "Route" && len(call.Args) == 2 {
			if _, ok := call.Args[1].(*ast.FuncLit); ok {
				return call.Args[0], true
			}
		}
		if _, isVerb := httpVerbs[fn.Sel.Name]; isVerb && len(call.Args) == 2 {
			if _, ok := handlerConstructor(call.Args[1]); ok {
				return call.Args[0], true
			}
		}
	}
	return nil, false
}

// routePathsFixture is a routes.go source registering each routeConstants entry once, by
// getAndHead, then the lines extra adds.
func routePathsFixture(extra string) string {
	names := make([]string, 0, len(routeConstants))
	for name := range routeConstants {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("package server\n\nfunc routes() {\n")
	for _, name := range names {
		fmt.Fprintf(&b, "\tgetAndHead(public, %s, handlers.HandleThing(h))\n", name)
	}
	b.WriteString(extra)
	b.WriteString("}\n")
	return b.String()
}

func runRoutePathsGuard(t *testing.T, src string) guard.Report {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "routes.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing the fixture: %v", err)
	}
	return guard.Run(func(r guard.Reporter) {
		assertRoutePathsReadable(r, fset, file)
	})
}

func TestRoutePaths_AnUnreadablePathFails(t *testing.T) {
	src := routePathsFixture("" +
		"\tr.Post(listPath, apihandlers.HandleThingsPost(db))\n" +
		"\tr.Get(routes.NotListed, handlers.HandleThing(h))\n" +
		"\tr.Get((routes.NotListed), handlers.HandleThing(h))\n" +
		"\tr.Route(prefix, func(r *routing.Router) {})\n")

	report := runRoutePathsGuard(t, src)

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	first := 4 + len(routeConstants)
	want := []string{}
	for i, path := range []string{"listPath", "routes.NotListed", "(routes.NotListed)", "prefix"} {
		want = append(want, fmt.Sprintf("routes.go:%d registers a route at %s, which the OpenAPI contract "+
			"tests cannot read: use a string literal, or a package constant added to routeConstants", first+i, path))
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestRoutePaths_StaleTableEntryFails(t *testing.T) {
	src := strings.Replace(routePathsFixture(""), "\tgetAndHead(public, brandasset.Route, handlers.HandleThing(h))\n", "", 1)

	report := runRoutePathsGuard(t, src)

	want := []string{"routeConstants holds brandasset.Route, which no registration in routes.go uses: remove it"}
	if report.Stopped || !slices.Equal(report.Errors, want) {
		t.Errorf("stopped %v, failures\n%q\nwant\n%q", report.Stopped, report.Errors, want)
	}
}

func TestRoutePaths_ReadablePathsPass(t *testing.T) {
	src := routePathsFixture("" +
		"\tr.Get(\"/api/v1/admin/things\", apihandlers.HandleThingsGet(db))\n" +
		"\tr.Get((brandasset.Route), handlers.HandleThing(h))\n" +
		"\tr.Route(\"/api/v1/account\", func(r *routing.Router) {})\n" +
		"\tvalues.Get(\"key\", fallback)\n")

	report := runRoutePathsGuard(t, src)

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("stopped %v (%s), failures %q", report.Stopped, report.Fatal, report.Errors)
	}
}

func TestRoutePaths_AWalkThatReachedNoRegistrationStops(t *testing.T) {
	report := runRoutePathsGuard(t, "package server\n\nfunc routes() {}\n")

	if !report.Stopped {
		t.Errorf("the check did not stop on a file with no route registration; failures %q", report.Errors)
	}
}

// TestOpenAPI_NamesPathParametersAsTheRoutesDo holds the names the join above erases. A path
// parameter's name is local to the document (OpenAPI 3.0.3 section 4.7.8), so nothing on the
// wire depends on it, but it is the argument name of the operation in a generated client and
// on the reference pages, and a spec naming it otherwise than routes.go is one parameter named
// two ways between the code and the contract (#651). routes.go's spelling is the one kept,
// because it is also the route's metrics label and the route detail of an audit event.
func TestOpenAPI_NamesPathParametersAsTheRoutesDo(t *testing.T) {
	assertPathParameterNames(t, parseRoutes(t), parseSpec(t))
}

// assertPathParameterNames is the reporting half: one failure per finding of
// pathParameterNameFindings, and a stop for a join that matched no route to the spec, since a
// comparison of nothing proves nothing.
func assertPathParameterNames(r guard.Reporter, routes []routeRegistration, spec map[string]specOperation) {
	r.Helper()
	findings, joined := pathParameterNameFindings(routes, spec)
	if joined == 0 {
		r.Fatalf("joined none of %d routes to the %d operations of openapi.yaml; the comparison "+
			"is no longer reaching the spec", len(routes), len(spec))
		return
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
}

// pathParameterNameFindings returns one finding per route whose path openapi.yaml describes
// under other parameter names, naming both spellings, and how many routes it joined to the
// spec. The join key erases the names, so a joined pair differs in nothing else.
func pathParameterNameFindings(routes []routeRegistration, spec map[string]specOperation) ([]string, int) {
	var findings []string
	joined := 0
	for _, r := range routes {
		op, documented := spec[r.key]
		if !documented {
			continue
		}
		joined++
		if op.path != r.path {
			findings = append(findings, fmt.Sprintf("routes.go:%d: %s %s is %s in openapi.yaml (%s): "+
				"name the spec's path parameters as routes.go does", r.line,
				strings.ToUpper(r.method), r.path, op.path, op.operationId))
		}
	}
	return findings, joined
}

// pathParameterNamesFixture is a route table and a spec agreeing on every name, plus a route
// the spec does not describe, which the comparison leaves to TestOpenAPI_DescribesEveryAPIRoute.
func pathParameterNamesFixture() ([]routeRegistration, map[string]specOperation) {
	route := func(method, path string, line int) routeRegistration {
		return routeRegistration{method: method, path: path, key: routeKey(method, path), line: line}
	}
	operation := func(method, path, operationId string) (string, specOperation) {
		return routeKey(method, path), specOperation{operationId: operationId, path: path}
	}
	routes := []routeRegistration{
		route("get", "/api/v1/admin/user-sessions/{id}", 10),
		route("delete", "/api/v1/admin/user-sessions/{id}", 11),
		route("get", "/api/v1/admin/groups/{groupId}/members/{userId}", 12),
		route("get", "/api/v1/admin/undocumented/{id}", 13),
	}
	spec := map[string]specOperation{}
	for _, op := range []struct{ method, path, operationId string }{
		{"get", "/api/v1/admin/user-sessions/{id}", "getUserSession"},
		{"delete", "/api/v1/admin/user-sessions/{id}", "deleteUserSession"},
		{"get", "/api/v1/admin/groups/{groupId}/members/{userId}", "getGroupMember"},
	} {
		key, value := operation(op.method, op.path, op.operationId)
		spec[key] = value
	}
	return routes, spec
}

func TestPathParameterNames_ASpecNamingAParameterOtherwiseFails(t *testing.T) {
	routes, spec := pathParameterNamesFixture()
	rename := func(method, path, operationId string) {
		spec[routeKey(method, path)] = specOperation{operationId: operationId, path: path}
	}
	rename("delete", "/api/v1/admin/user-sessions/{sessionIdentifier}", "deleteUserSession")
	rename("get", "/api/v1/admin/groups/{userId}/members/{groupId}", "getGroupMember")

	report := guard.Run(func(r guard.Reporter) {
		assertPathParameterNames(r, routes, spec)
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"routes.go:11: DELETE /api/v1/admin/user-sessions/{id} is /api/v1/admin/user-sessions/{sessionIdentifier} in openapi.yaml (deleteUserSession): name the spec's path parameters as routes.go does",
		"routes.go:12: GET /api/v1/admin/groups/{groupId}/members/{userId} is /api/v1/admin/groups/{userId}/members/{groupId} in openapi.yaml (getGroupMember): name the spec's path parameters as routes.go does",
	}
	got := append([]string(nil), report.Errors...)
	sort.Strings(got)
	if !slices.Equal(got, want) {
		t.Errorf("failures\n%q\nwant\n%q", got, want)
	}
}

func TestPathParameterNames_ASpecNamingEveryParameterAsTheRoutesPasses(t *testing.T) {
	routes, spec := pathParameterNamesFixture()

	report := guard.Run(func(r guard.Reporter) {
		assertPathParameterNames(r, routes, spec)
	})

	if report.Failed() {
		t.Errorf("a spec naming every path parameter as the routes do failed: %+v", report)
	}
}

func TestPathParameterNames_AJoinThatMatchedNoRouteStops(t *testing.T) {
	routes, _ := pathParameterNamesFixture()

	report := guard.Run(func(r guard.Reporter) {
		assertPathParameterNames(r, routes, map[string]specOperation{})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "joined none of 4 routes") {
		t.Errorf("a join that matched no route did not stop the check: %+v", report)
	}
}

// TestOpenAPI_GivesEachOperationItsOwnId holds each operationId to one operation, as OpenAPI 3.0.3
// section 4.7.10 requires ("The id MUST be unique among all operations described in the API"). The
// API reference gives each operation a page under its id, and a client generator names a method
// after it, so two operations sharing one leave one of them without a page and collide in a
// generated client.
func TestOpenAPI_GivesEachOperationItsOwnId(t *testing.T) {
	assertOperationIdsUnique(t, parseSpec(t))
}

// assertOperationIdsUnique is the reporting half: one failure per finding of operationIdFindings,
// and a stop for a spec holding no operation, since a check of nothing proves nothing.
func assertOperationIdsUnique(r guard.Reporter, spec map[string]specOperation) {
	r.Helper()
	if len(spec) == 0 {
		r.Fatalf("read no operation out of openapi.yaml; the check is no longer reaching the spec")
		return
	}
	for _, finding := range operationIdFindings(spec) {
		r.Errorf("%s", finding)
	}
}

// operationIdFindings returns one finding per operationId that more than one operation carries,
// naming each of those operations, and one per operation that has none.
func operationIdFindings(spec map[string]specOperation) []string {
	carriers := map[string][]string{}
	var findings []string
	for key, op := range spec {
		verb, _, _ := strings.Cut(key, " ")
		operation := strings.ToUpper(verb) + " " + op.path
		if op.operationId == "" {
			findings = append(findings, fmt.Sprintf("openapi.yaml: %s has no operationId", operation))
			continue
		}
		carriers[op.operationId] = append(carriers[op.operationId], operation)
	}
	for id, operations := range carriers {
		if len(operations) > 1 {
			sort.Strings(operations)
			findings = append(findings, fmt.Sprintf("openapi.yaml: operationId %s names %d operations, %s: "+
				"give each its own", id, len(operations), strings.Join(operations, " and ")))
		}
	}
	sort.Strings(findings)
	return findings
}

// operationIdsFixture is a spec whose three operations each carry an id of their own.
func operationIdsFixture() map[string]specOperation {
	spec := map[string]specOperation{}
	for _, op := range []struct{ method, path, operationId string }{
		{"get", "/api/v1/admin/brand-assets/{id}", "getBrandAsset"},
		{"get", "/brand-assets/{id}", "getBrandAssetFile"},
		{"get", "/client/logo/{clientIdentifier}", "getClientLogoImage"},
	} {
		spec[routeKey(op.method, op.path)] = specOperation{operationId: op.operationId, path: op.path}
	}
	return spec
}

func TestOperationIds_AnIdTwoOperationsCarryFails(t *testing.T) {
	spec := operationIdsFixture()
	spec[routeKey("get", "/brand-assets/{id}")] = specOperation{operationId: "getBrandAsset", path: "/brand-assets/{id}"}
	spec[routeKey("get", "/client/logo/{clientIdentifier}")] = specOperation{path: "/client/logo/{clientIdentifier}"}

	report := guard.Run(func(r guard.Reporter) {
		assertOperationIdsUnique(r, spec)
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"openapi.yaml: GET /client/logo/{clientIdentifier} has no operationId",
		"openapi.yaml: operationId getBrandAsset names 2 operations, GET /api/v1/admin/brand-assets/{id} and GET /brand-assets/{id}: give each its own",
	}
	if got := report.Errors; !slices.Equal(got, want) {
		t.Errorf("failures\n%q\nwant\n%q", got, want)
	}
}

func TestOperationIds_EachOperationWithItsOwnIdPasses(t *testing.T) {
	report := guard.Run(func(r guard.Reporter) {
		assertOperationIdsUnique(r, operationIdsFixture())
	})

	if report.Failed() {
		t.Errorf("a spec giving each operation its own id failed: %+v", report)
	}
}

func TestOperationIds_ASpecWithNoOperationStops(t *testing.T) {
	report := guard.Run(func(r guard.Reporter) {
		assertOperationIdsUnique(r, map[string]specOperation{})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "read no operation") {
		t.Errorf("a spec with no operation did not stop the check: %+v", report)
	}
}

// TestAPIHandlers_WriteStatusesAsConstants is what lets the three tests above be lexical.
// Every writeJSONError and writeLocalizedError call passes an http.Status constant, so reading
// the constants out of a handler reads its whole failure surface. A status computed at run
// time would be invisible to the scan and the spec could drift under it unnoticed, which is a
// hole worth closing at the call sites that could open it.
func TestAPIHandlers_WriteStatusesAsConstants(t *testing.T) {
	// go test runs with the package directory as the working directory, so this is
	// src/authserver/internal/handlers.
	assertStatusesAsConstants(t, filepath.Join("..", "handlers"), statusWriterCallFloor)
}

// statusWriters are the writers that take a status, by name, with their argument count and the
// status's index. writeLocalizedError is writeJSONError with the description translated (#559
// decision 2).
var statusWriters = map[string]struct{ args, status int }{
	"writeJSONError":      {args: 4, status: 3},
	"writeLocalizedError": {args: 5, status: 4},
}

// statusWriterCallFloor is how many writer calls the handlers hold at rest, as a floor so ordinary
// growth does not move it: a scan that inspected nothing passes while guarding nothing.
const statusWriterCallFloor = 100

// assertStatusesAsConstants is the reporting half: one failure per finding of
// statusConstantFindings, and a stop for a walk that could not be read or reached fewer writer
// calls than floor, since a scan that inspected nothing proves nothing.
func assertStatusesAsConstants(r guard.Reporter, root string, floor int) {
	r.Helper()
	findings, calls, err := statusConstantFindings(root)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	if calls < floor {
		r.Fatalf("found only %d error writer calls under %s; the walk is no longer reaching the "+
			"API handlers", calls, root)
		return
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
}

// statusConstantFindings walks the non-test Go sources under root and returns one finding per
// statusWriters call whose status is not an http.Status constant, located relative to root's
// parent, and how many writer calls it read. api_common.go is skipped: the helpers' own
// signatures take the int, and their callers are the subject.
func statusConstantFindings(root string) ([]string, int, error) {
	var findings []string
	calls := 0
	base := filepath.Dir(root)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
			d.Name() == "api_common.go" {
			return nil
		}
		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if pErr != nil {
			return fmt.Errorf("parsing %s: %w", path, pErr)
		}
		rel, relErr := filepath.Rel(base, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			writer, ok := statusWriters[name.Name]
			if !ok || len(call.Args) != writer.args {
				return true
			}
			calls++
			status := call.Args[writer.status]
			line := fset.Position(status.Pos()).Line
			sel, ok := status.(*ast.SelectorExpr)
			if !ok {
				findings = append(findings, fmt.Sprintf("%s:%d: %s is called with a computed status; "+
					"the openapi.yaml lint reads statuses lexically and cannot see it", rel, line, name.Name))
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "http" || httpStatusConstants[sel.Sel.Name] == 0 {
				findings = append(findings, fmt.Sprintf("%s:%d: %s is called with %s rather than an "+
					"http.Status constant", rel, line, name.Name, sel.Sel.Name))
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("walking %s: %w", root, err)
	}
	return findings, calls, nil
}

// statusConstantsFixture is a handler package whose writes of both writers each name a constant,
// plus the two files the walk skips, which would fail it if read.
func statusConstantsFixture(t *testing.T, root string) {
	t.Helper()
	writeDocFixture(t, root, "handlers/apihandlers/handler_ok.go", "package apihandlers\n\n"+
		"func HandleOK(w http.ResponseWriter, r *http.Request) {\n"+
		"\twriteJSONError(w, \"Invalid request body\", \"INVALID_REQUEST_BODY\", http.StatusBadRequest)\n"+
		"\twriteLocalizedError(w, r, i18n.NewLocalizedError(\"k\", nil), \"CONCURRENT_UPDATE\", http.StatusConflict)\n"+
		"}\n")
	writeDocFixture(t, root, "handlers/apihandlers/api_common.go", "package apihandlers\n\n"+
		"func writeLocalizedError(w http.ResponseWriter, r *http.Request, e error, code string, status int) {\n"+
		"\twriteJSONError(w, e.Error(), code, status)\n"+
		"}\n")
	writeDocFixture(t, root, "handlers/apihandlers/handler_ok_test.go", "package apihandlers\n\n"+
		"func helper(status int) { writeJSONError(nil, \"m\", \"C\", status) }\n")
}

func TestStatusesAsConstants_AComputedStatusFails(t *testing.T) {
	root := t.TempDir()
	statusConstantsFixture(t, root)
	writeDocFixture(t, root, "handlers/apihandlers/handler_bad.go", "package apihandlers\n\n"+
		"func HandleBad(w http.ResponseWriter, r *http.Request, status int) {\n"+
		"\twriteJSONError(w, \"m\", \"C\", status)\n"+
		"\twriteLocalizedError(w, r, nil, \"C\", status)\n"+
		"\twriteLocalizedError(w, r, nil, \"C\", statuses.Conflict)\n"+
		"\twriteJSONError(w, \"m\", \"C\", http.StatusTeapotish)\n"+
		"}\n")

	report := guard.Run(func(r guard.Reporter) {
		assertStatusesAsConstants(r, filepath.Join(root, "handlers"), 1)
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"handlers/apihandlers/handler_bad.go:4: writeJSONError is called with a computed status; the openapi.yaml lint reads statuses lexically and cannot see it",
		"handlers/apihandlers/handler_bad.go:5: writeLocalizedError is called with a computed status; the openapi.yaml lint reads statuses lexically and cannot see it",
		"handlers/apihandlers/handler_bad.go:6: writeLocalizedError is called with Conflict rather than an http.Status constant",
		"handlers/apihandlers/handler_bad.go:7: writeJSONError is called with StatusTeapotish rather than an http.Status constant",
	}
	got := append([]string(nil), report.Errors...)
	sort.Strings(got)
	if !slices.Equal(got, want) {
		t.Errorf("failures\n%q\nwant\n%q", got, want)
	}
}

func TestStatusesAsConstants_ConstantStatusesPass(t *testing.T) {
	root := t.TempDir()
	statusConstantsFixture(t, root)

	report := guard.Run(func(r guard.Reporter) {
		assertStatusesAsConstants(r, filepath.Join(root, "handlers"), 2)
	})

	if report.Failed() {
		t.Errorf("writes naming http.Status constants failed: %+v", report)
	}
}

func TestStatusesAsConstants_AWalkThatReachedNoWriterStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "handlers/apihandlers/handler_none.go", "package apihandlers\n\n"+
		"func HandleNone() {}\n")

	report := guard.Run(func(r guard.Reporter) {
		assertStatusesAsConstants(r, filepath.Join(root, "handlers"), 1)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "found only 0 error writer calls") {
		t.Errorf("a walk that reached no writer did not stop the check: %+v", report)
	}
}

// handlerStatusesFixture is three handler packages whose handlers write most of their statuses
// through helpers of their own package: called directly, through a chain of two, passed as a
// value, and in a pair that refer to each other. The accounthandlers package declares a helper of
// the same name as apihandlers', writing another status, and calls the parent package's
// ResourceNotFound through its package name and a method that shares the name of one of its
// plain functions, neither of which is followed.
func handlerStatusesFixture(t *testing.T, root string) {
	t.Helper()
	writeDocFixture(t, root, "handlers/apihandlers/handler_widget.go", `package apihandlers

import "net/http"

func HandleWidgetGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		widget, ok := loadWidget(w, r)
		if !ok {
			return
		}
		writeJSON(w, r, http.StatusOK, widget)
	}
}

func HandleWidgetDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		onMissing := writeWidgetNotFound
		if r.URL == nil {
			onMissing(w)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func HandleWidgetRetry() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		retryWidget(w)
	}
}
`)
	writeDocFixture(t, root, "handlers/apihandlers/widget_common.go", `package apihandlers

import "net/http"

func loadWidget(w http.ResponseWriter, r *http.Request) (any, bool) {
	if r.URL == nil {
		writeWidgetNotFound(w)
		return nil, false
	}
	return struct{}{}, true
}

func writeWidgetNotFound(w http.ResponseWriter) {
	writeJSONError(w, "Widget not found", "WIDGET_NOT_FOUND", http.StatusNotFound)
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	apiresponse.WriteJSON(w, r, status, v)
}

func retryWidget(w http.ResponseWriter) {
	retryWidgetAgain(w)
}

func retryWidgetAgain(w http.ResponseWriter) {
	retryWidget(w)
	writeJSONError(w, "Widget changed", "CONCURRENT_UPDATE", http.StatusConflict)
}
`)
	writeDocFixture(t, root, "handlers/accounthandlers/handler_gadget.go", `package accounthandlers

import "net/http"

func HandleGadgetGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL == nil {
			writeWidgetNotFound(w)
			return
		}
		if r.Body == nil {
			handlers.ResourceNotFound(w, r)
			return
		}
		if r.Form == nil {
			gadgets.refuseGadget(w)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func writeWidgetNotFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusGone)
}

func refuseGadget(w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
}
`)
	writeDocFixture(t, root, "handlers/not_found.go", `package handlers

import "net/http"

func HandleResource() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ResourceNotFound(w, r)
	}
}

func ResourceNotFound(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}
`)
}

func TestHandlerStatuses_AStatusReachedThroughASamePackageCallIsSeen(t *testing.T) {
	root := t.TempDir()
	handlerStatusesFixture(t, root)

	var statuses map[string]map[int]bool
	report := guard.Run(func(r guard.Reporter) {
		statuses = readHandlerStatuses(r, filepath.Join(root, "handlers"), 1, 0)
	})

	if report.Failed() {
		t.Fatalf("reading the fixture handlers failed: %+v", report)
	}
	want := map[string][]int{
		"apihandlers.HandleWidgetGet":     {200, 404, 500},
		"apihandlers.HandleWidgetDelete":  {204, 404},
		"apihandlers.HandleWidgetRetry":   {409},
		"accounthandlers.HandleGadgetGet": {200, 410},
		"handlers.HandleResource":         {404},
	}
	got := map[string][]int{}
	for name, codes := range statuses {
		got[name] = sortedCodes(codes)
	}
	if !maps.EqualFunc(got, want, slices.Equal[[]int]) {
		t.Errorf("statuses\n%v\nwant\n%v", got, want)
	}
}

func TestHandlerStatuses_AResolverThatFollowedNoCallStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "handlers/apihandlers/handler_direct.go", "package apihandlers\n\n"+
		"func HandleDirect(w http.ResponseWriter, r *http.Request) {\n"+
		"\twriteJSONError(w, \"m\", \"C\", http.StatusBadRequest)\n"+
		"}\n")

	report := guard.Run(func(r guard.Reporter) {
		readHandlerStatuses(r, filepath.Join(root, "handlers"), 1, 1)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "followed only 0 references to a same-package function") {
		t.Errorf("a resolver that followed no call did not stop the check: %+v", report)
	}
}

// routeChainsFixture is a routes.go and the packages it names, whose middleware write their
// statuses through the call shapes the real ones use: a scope guard writing every refusal through
// an interface field its constructor fills, built once for the API and once for the pages with
// another implementation in the field; a rate limiter mounted as a method value, reaching its
// writer through two more methods and a plain function, beside a limiter method nothing mounts;
// a recorder that names 200 as the status of a handler that never writes one; and a middleware
// that redirects with 307. The API group mounts the recorder and the guard with r.Use, the create
// route adds the limiter with r.With, and the page route hangs off a router variable assigned from
// a With call. Two more groups take their middleware from the router they hang off: the bolts
// group the API guard through api.With(...).Route, and the cogs group the redirect through a
// router variable assigned from a With call.
func routeChainsFixture(t *testing.T, root string, extraRoutes string) {
	t.Helper()
	writeDocFixture(t, root, "internal/server/routes.go", `package server

import (
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/routing"
)

func (s *Server) initRoutes(api, pages *routing.Router) {
	apiGuards := middleware.NewGuardsForAPI()
	pageGuards := middleware.NewGuardsForPages()
	limiter := middleware.NewLimiter()

	api.Route("/api/v1/widgets", func(r *routing.Router) {
		r.Use(middleware.Debug())
		r.Use(apiGuards.RequireToken())
		r.Get("/{id}", apihandlers.HandleWidgetGet())
		r.With(limiter.LimitWidgets).Post("/create", apihandlers.HandleWidgetCreatePost())
	})
	api.Get("/api/public/gadgets", apihandlers.HandleGadgetsGet())
	api.Get("/api/public/sprockets", apihandlers.HandleSprocketsGet())
	guarded := pages.With(pageGuards.RequireToken())
	guarded.Get("/widgets/{id}", apihandlers.HandleWidgetPageGet())
	api.With(apiGuards.RequireToken()).Route("/api/v1/bolts", func(r *routing.Router) {
		r.Get("/{id}", apihandlers.HandleBoltGet())
	})
	relocated := api.With(middleware.Relocate())
	relocated.Route("/api/v1/cogs", func(r *routing.Router) {
		r.Get("/{id}", apihandlers.HandleCogGet())
	})
`+extraRoutes+`}
`)
	writeDocFixture(t, root, "internal/middleware/guards.go", `package middleware

import "net/http"

type refusals interface {
	missing(w http.ResponseWriter)
	malformed(w http.ResponseWriter)
}

type Guards struct {
	refusals refusals
}

func NewGuardsForAPI() *Guards {
	return &Guards{refusals: apiRefusals{}}
}

func NewGuardsForPages() *Guards {
	return &Guards{refusals: pageRefusals{}}
}

func (g *Guards) RequireToken() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				g.refusals.missing(w)
				return
			}
			if len(r.Header.Values("Authorization")) > 1 {
				g.refusals.malformed(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type apiRefusals struct{}

func (apiRefusals) missing(w http.ResponseWriter) {
	apiresponse.WriteError(w, "Access token required.", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
}

func (apiRefusals) malformed(w http.ResponseWriter) {
	apiresponse.WriteError(w, "Send the header once.", "INVALID_REQUEST", http.StatusBadRequest)
}

type pageRefusals struct{}

func (pageRefusals) missing(w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
}

func (pageRefusals) malformed(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnprocessableEntity)
}
`)
	writeDocFixture(t, root, "internal/middleware/limiter.go", `package middleware

import "net/http"

type Limiter struct {
	enabled bool
}

func NewLimiter() *Limiter {
	return &Limiter{enabled: true}
}

func (l *Limiter) LimitWidgets(next http.Handler) http.Handler {
	return l.limit(next)
}

func (l *Limiter) LimitGadgets(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
}

func (l *Limiter) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if l.enabled {
			l.refuse(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) refuse(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	writeTooManyRequests(w)
}

func writeTooManyRequests(w http.ResponseWriter) {
	apiresponse.WriteError(w, "Too many requests.", "TOO_MANY_REQUESTS", http.StatusTooManyRequests)
}
`)
	writeDocFixture(t, root, "internal/middleware/debug.go", `package middleware

import "net/http"

type recorder struct {
	http.ResponseWriter
	status int
}

func Debug() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &recorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
		})
	}
}
`)
	writeDocFixture(t, root, "internal/middleware/relocate.go", `package middleware

import "net/http"

func Relocate() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere"+r.URL.Path, http.StatusTemporaryRedirect)
		})
	}
}
`)
	writeDocFixture(t, root, "internal/handlers/apihandlers/handler_widget.go", `package apihandlers

import "net/http"

func HandleWidgetGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL == nil {
			writeJSONError(w, "Widget not found", "WIDGET_NOT_FOUND", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func HandleWidgetCreatePost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}
}

func HandleGadgetsGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL == nil {
			writeJSONError(w, "Invalid session", "INVALID_SESSION", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func HandleSprocketsGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

func HandleWidgetPageGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

func HandleBoltGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

func HandleCogGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}
`)
}

// fixtureRouteChains reads the fixture's routes, the chain of each, and its handlers' statuses.
func fixtureRouteChains(t *testing.T, root string, middleware, calls int) ([]routeRegistration, map[string]map[int]bool, guard.Report) {
	t.Helper()
	routesPath := filepath.Join(root, "internal", "server", "routes.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, routesPath, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing the fixture routes.go: %v", err)
	}
	routes := collectRoutes(fset, file)
	var handlers map[string]map[int]bool
	report := guard.Run(func(r guard.Reporter) {
		handlers = readHandlerStatuses(r, filepath.Join(root, "internal", "handlers"), 1, 0)
		routes = readRouteChains(r, routesPath, filepath.Join(root, "internal"), routes, middleware, calls)
	})
	return routes, handlers, report
}

// routeChainsFixtureSpec declares every status each fixture route can write, and no other: the
// handler's, and its chain's, with no 200 on the create route, whose handler answers 201 behind
// the recorder that names 200.
func routeChainsFixtureSpec() map[string]specOperation {
	op := func(id string, codes ...int) specOperation {
		responses := map[int]bool{}
		for _, code := range codes {
			responses[code] = true
		}
		return specOperation{operationId: id, responses: responses}
	}
	return map[string]specOperation{
		"get /api/v1/widgets/{}":      op("getWidget", 200, 400, 401, 404),
		"post /api/v1/widgets/create": op("createWidget", 201, 400, 401, 429),
		"get /api/public/gadgets":     op("getGadgets", 200, 401),
		"get /api/public/sprockets":   op("getSprockets", 200),
		"get /widgets/{}":             op("getWidgetPage", 200, 403, 422),
		"get /api/v1/bolts/{}":        op("getBolt", 200, 400, 401),
		"get /api/v1/cogs/{}":         op("getCog", 200, 307),
	}
}

func TestRouteChains_EachMiddlewaresStatusesAreReadThroughItsCalls(t *testing.T) {
	root := t.TempDir()
	routeChainsFixture(t, root, "")

	routes, _, report := fixtureRouteChains(t, root, 1, 1)

	if report.Failed() {
		t.Fatalf("reading the fixture chains failed: %+v", report)
	}
	want := map[string][]int{
		"get /api/v1/widgets/{}":      {400, 401},
		"post /api/v1/widgets/create": {400, 401, 429},
		"get /api/public/gadgets":     {},
		"get /api/public/sprockets":   {},
		"get /widgets/{}":             {403, 422},
		"get /api/v1/bolts/{}":        {400, 401},
		"get /api/v1/cogs/{}":         {307},
	}
	got := map[string][]int{}
	for _, r := range routes {
		got[r.key] = sortedKeysInt(r.chain)
	}
	if !maps.EqualFunc(got, want, slices.Equal[[]int]) {
		t.Errorf("chains\n%v\nwant\n%v", got, want)
	}
}

func TestRouteStatuses_AStatusTheChainWritesThatTheSpecLacksFails(t *testing.T) {
	root := t.TempDir()
	routeChainsFixture(t, root, "")
	routes, handlers, report := fixtureRouteChains(t, root, 1, 1)
	if report.Failed() {
		t.Fatalf("reading the fixture failed: %+v", report)
	}
	spec := routeChainsFixtureSpec()
	delete(spec["get /api/v1/widgets/{}"].responses, 400)
	delete(spec["post /api/v1/widgets/create"].responses, 429)

	report = guard.Run(func(r guard.Reporter) {
		assertDeclaresEveryStatus(r, routes, handlers, spec)
	})

	if report.Stopped || len(report.Errors) != 2 ||
		!strings.Contains(report.Errors[0], "getWidget (GET /api/v1/widgets/{id}) can answer 400 from apiGuards.RequireToken") ||
		!strings.Contains(report.Errors[1], "createWidget (POST /api/v1/widgets/create) can answer 429 from limiter.LimitWidgets") {
		t.Errorf("want failures for the undeclared 400 and 429, got %+v", report)
	}
}

// A group's middleware includes the With arguments of the router it hangs off, and a redirect a
// middleware writes is a status the route can answer, where a recorder's starting 200 is not.
func TestRouteStatuses_AStatusAGroupsRouterOrARedirectWritesThatTheSpecLacksFails(t *testing.T) {
	root := t.TempDir()
	routeChainsFixture(t, root, "")
	routes, handlers, report := fixtureRouteChains(t, root, 1, 1)
	if report.Failed() {
		t.Fatalf("reading the fixture failed: %+v", report)
	}
	spec := routeChainsFixtureSpec()
	delete(spec["get /api/v1/bolts/{}"].responses, 400)
	delete(spec["get /api/v1/bolts/{}"].responses, 401)
	delete(spec["get /api/v1/cogs/{}"].responses, 307)

	report = guard.Run(func(r guard.Reporter) {
		assertDeclaresEveryStatus(r, routes, handlers, spec)
	})

	want := []string{
		"getBolt (GET /api/v1/bolts/{id}) can answer 400 from apiGuards.RequireToken",
		"getBolt (GET /api/v1/bolts/{id}) can answer 401 from apiGuards.RequireToken",
		"getCog (GET /api/v1/cogs/{id}) can answer 307 from middleware.Relocate",
	}
	if report.Stopped || len(report.Errors) != len(want) {
		t.Fatalf("want %d failures, got %+v", len(want), report)
	}
	for i, prefix := range want {
		if !strings.HasPrefix(report.Errors[i], prefix) {
			t.Errorf("failure %d is %q, want it to start %q", i, report.Errors[i], prefix)
		}
	}
}

func TestRouteStatuses_ASpecDeclaringEveryStatusTheRoutesWritePasses(t *testing.T) {
	root := t.TempDir()
	routeChainsFixture(t, root, "")
	routes, handlers, report := fixtureRouteChains(t, root, 1, 1)
	if report.Failed() {
		t.Fatalf("reading the fixture failed: %+v", report)
	}
	spec := routeChainsFixtureSpec()

	report = guard.Run(func(r guard.Reporter) {
		assertDeclaresEveryStatus(r, routes, handlers, spec)
		assertDeclaresNoUndeliverableStatus(r, routes, handlers, spec)
	})

	if report.Failed() {
		t.Errorf("a complete spec failed: %+v", report)
	}
}

func TestRouteStatuses_AJoinThatMatchedNoRouteStops(t *testing.T) {
	root := t.TempDir()
	routeChainsFixture(t, root, "")
	routes, handlers, report := fixtureRouteChains(t, root, 1, 1)
	if report.Failed() {
		t.Fatalf("reading the fixture failed: %+v", report)
	}

	for name, assert := range map[string]func(guard.Reporter, []routeRegistration, map[string]map[int]bool, map[string]specOperation){
		"forward": assertDeclaresEveryStatus,
		"reverse": assertDeclaresNoUndeliverableStatus,
	} {
		report := guard.Run(func(r guard.Reporter) {
			assert(r, routes, handlers, map[string]specOperation{})
		})
		if !report.Stopped || !strings.Contains(report.Fatal, "joined none of 7 routes") {
			t.Errorf("the %s check did not stop on a join that matched no route: %+v", name, report)
		}
	}
}

func TestRouteStatuses_ADeclared401NeitherTheHandlerNorTheChainWritesFails(t *testing.T) {
	root := t.TempDir()
	routeChainsFixture(t, root, "")
	routes, handlers, report := fixtureRouteChains(t, root, 1, 1)
	if report.Failed() {
		t.Fatalf("reading the fixture failed: %+v", report)
	}
	spec := routeChainsFixtureSpec()
	// getGadgets keeps its 401, which its handler writes. getSprockets has no middleware and a
	// handler that writes none; the page route's guard writes its refusals through pageRefusals,
	// which writes no 401, where apiRefusals does.
	spec["get /api/public/sprockets"].responses[401] = true
	spec["get /widgets/{}"].responses[401] = true

	report = guard.Run(func(r guard.Reporter) {
		assertDeclaresNoUndeliverableStatus(r, routes, handlers, spec)
	})

	if report.Stopped || len(report.Errors) != 2 ||
		!strings.Contains(report.Errors[0], "getSprockets (GET /api/public/sprockets) declares 401") ||
		!strings.Contains(report.Errors[1], "getWidgetPage (GET /widgets/{id}) declares 401") {
		t.Errorf("want failures for the two undeliverable 401s, got %+v", report)
	}
}

func TestRouteChains_AMiddlewareTheLintCannotReadFails(t *testing.T) {
	root := t.TempDir()
	routeChainsFixture(t, root, "\tapi.With(unknownGuard).Get(\"/api/public/cogs\", apihandlers.HandleSprocketsGet())\n")

	_, _, report := fixtureRouteChains(t, root, 1, 1)

	if report.Stopped || len(report.Errors) != 1 ||
		!strings.Contains(report.Errors[0], "GET /api/public/cogs mounts unknownGuard, which the status lint cannot read") {
		t.Errorf("an unreadable middleware did not fail the check once: %+v", report)
	}
}

func TestRouteChains_AResolverThatReadNoMiddlewareStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "internal/server/routes.go", "package server\n\n"+
		"func (s *Server) initRoutes(api *routing.Router) {\n"+
		"\tapi.Get(\"/api/public/sprockets\", apihandlers.HandleSprocketsGet())\n"+
		"}\n")
	writeDocFixture(t, root, "internal/handlers/apihandlers/handler_sprocket.go", "package apihandlers\n\n"+
		"func HandleSprocketsGet(w http.ResponseWriter, r *http.Request) {}\n")

	_, _, report := fixtureRouteChains(t, root, 1, 0)

	if !report.Stopped || !strings.Contains(report.Fatal, "read only 0 middleware") {
		t.Errorf("a resolver that read no middleware did not stop the check: %+v", report)
	}
}

func TestRouteChains_AResolverThatFollowedNoCallStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "internal/server/routes.go", "package server\n\n"+
		"import \"github.com/leodip/goiabada/authserver/internal/middleware\"\n\n"+
		"func (s *Server) initRoutes(api *routing.Router) {\n"+
		"\tapi.With(middleware.Refuse()).Get(\"/api/public/sprockets\", apihandlers.HandleSprocketsGet())\n"+
		"}\n")
	writeDocFixture(t, root, "internal/middleware/refuse.go", "package middleware\n\n"+
		"func Refuse() func(http.Handler) http.Handler {\n"+
		"\treturn func(next http.Handler) http.Handler {\n"+
		"\t\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })\n"+
		"\t}\n"+
		"}\n")
	writeDocFixture(t, root, "internal/handlers/apihandlers/handler_sprocket.go", "package apihandlers\n\n"+
		"func HandleSprocketsGet(w http.ResponseWriter, r *http.Request) {}\n")

	_, _, report := fixtureRouteChains(t, root, 1, 1)

	if !report.Stopped || !strings.Contains(report.Fatal, "followed only 0 calls") {
		t.Errorf("a resolver that followed no call did not stop the check: %+v", report)
	}
}

// routeShapesFixture is a tree whose routes.go mounts middleware in the shapes a chain is easy to
// misread in: a Use on the root router, a Use on another router than the group's beside one on an
// alias of it, a router variable reassigned between two registrations, a constructor that builds a
// second value of the type it returns and discards it, two fields of one type holding different
// refusal writers, and a middleware that only compares the status the handler answered. extra is
// appended to initRoutes's body.
func routeShapesFixture(t *testing.T, root string, extra string) {
	t.Helper()
	writeDocFixture(t, root, "internal/server/routes.go", `package server

import (
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/routing"
)

func (s *Server) initRoutes(api, pages, other *routing.Router) {
	api.Use(middleware.Refuse())
	api.Get("/api/v1/direct", apihandlers.HandleOkGet())
	api.Route("/api/v1/grouped", func(r *routing.Router) {
		r.Get("/{id}", apihandlers.HandleOkGet())
	})
	pages.Get("/plain", apihandlers.HandleOkGet())

	pages.Route("/foreign", func(r *routing.Router) {
		other.Use(middleware.Refuse())
		r.Get("/{id}", apihandlers.HandleOkGet())
	})
	pages.Route("/aliased", func(r *routing.Router) {
		group := r
		group.Use(middleware.Refuse())
		r.Get("/{id}", apihandlers.HandleOkGet())
	})

	guarded := pages
	guarded.Get("/before", apihandlers.HandleOkGet())
	guarded = pages.With(middleware.Refuse())
	guarded.Get("/after", apihandlers.HandleOkGet())

	probed := middleware.NewProbed()
	pages.With(probed.Check()).Get("/probed", apihandlers.HandleOkGet())
	pair := middleware.NewPair()
	pages.With(pair.Check()).Get("/paired", apihandlers.HandleOkGet())

	pages.With(middleware.Observe()).Get("/observed", apihandlers.HandleOkGet())
	pages.With(middleware.Missing()).Get("/missing", apihandlers.HandleOkGet())
`+extra+`}
`)
	writeDocFixture(t, root, "internal/middleware/shapes.go", `package middleware

import "net/http"

func Refuse() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
	}
}

func Missing() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}
}

type recorder struct {
	http.ResponseWriter
	status int
}

func Observe() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &recorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			if rec.status == http.StatusForbidden {
				w.Header().Set("X-Refused", "1")
			}
		})
	}
}

type writer interface {
	refuse(w http.ResponseWriter)
}

type forbid struct{}

func (forbid) refuse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
}

type unprocessable struct{}

func (unprocessable) refuse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnprocessableEntity)
}

type Probed struct {
	refusals writer
}

func NewProbed() *Probed {
	probed := &Probed{refusals: forbid{}}
	setup := &Probed{refusals: unprocessable{}}
	_ = setup
	return probed
}

func (p *Probed) Check() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.refusals.refuse(w)
		})
	}
}

type Guard struct {
	refusals writer
}

func (g *Guard) check(w http.ResponseWriter) {
	g.refusals.refuse(w)
}

type Pair struct {
	first  *Guard
	second *Guard
}

func NewPair() *Pair {
	return &Pair{first: &Guard{refusals: forbid{}}, second: &Guard{refusals: unprocessable{}}}
}

func (p *Pair) Check() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL == nil {
				p.first.check(w)
				return
			}
			p.second.check(w)
		})
	}
}
`)
	writeDocFixture(t, root, "internal/handlers/apihandlers/handler_ok.go", `package apihandlers

import "net/http"

func HandleOkGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}
`)
}

// assertRouteShapeChains reads the shapes fixture and holds the chain of each route want names to
// the statuses it lists.
func assertRouteShapeChains(t *testing.T, want map[string][]int) {
	t.Helper()
	root := t.TempDir()
	routeShapesFixture(t, root, "")
	routes, _, report := fixtureRouteChains(t, root, 1, 1)
	if report.Failed() {
		t.Fatalf("reading the fixture chains failed: %+v", report)
	}
	got := map[string][]int{}
	for _, r := range routes {
		if _, asked := want[r.key]; asked {
			got[r.key] = sortedKeysInt(r.chain)
		}
	}
	if !maps.EqualFunc(got, want, slices.Equal[[]int]) {
		t.Errorf("chains\n%v\nwant\n%v", got, want)
	}
}

// A Use on another router than the group's credits none of the group's routes, and one on an
// alias of the group's router covers them as r.Use does.
func TestRouteChains_AUseOnAnotherRouterCoversNoneOfTheGroupsRoutes(t *testing.T) {
	assertRouteShapeChains(t, map[string][]int{
		"get /foreign/{}": {},
		"get /aliased/{}": {403},
	})
}

// A Use on the root router covers the routes registered on it and those of its groups, and not
// those of another root.
func TestRouteChains_ARootRoutersUseCoversItsRoutesAndGroups(t *testing.T) {
	assertRouteShapeChains(t, map[string][]int{
		"get /api/v1/direct":     {403},
		"get /api/v1/grouped/{}": {403},
		"get /plain":             {},
	})
}

// A router variable reassigned between two registrations is read as each one sees it.
func TestRouteChains_ARouterReassignedBetweenRegistrationsIsReadAsEachSeesIt(t *testing.T) {
	assertRouteShapeChains(t, map[string][]int{
		"get /before": {},
		"get /after":  {403},
	})
}

// A field is read from the value the constructor returns, not from another value of the type it
// builds and discards.
func TestRouteChains_AFieldIsReadFromTheValueTheConstructorReturns(t *testing.T) {
	assertRouteShapeChains(t, map[string][]int{
		"get /probed": {403},
	})
}

// A method reached through two fields of one type is read with each field's refusal writer.
func TestRouteChains_AMethodIsReadForEachBindingOfItsReceiver(t *testing.T) {
	assertRouteShapeChains(t, map[string][]int{
		"get /paired": {403, 422},
	})
}

// A status a middleware only compares the handler's answer to is not one it writes, where one it
// writes, or one a shared writer such as http.NotFound writes for it, is.
func TestRouteChains_AStatusAMiddlewareOnlyComparesIsNotWritten(t *testing.T) {
	assertRouteShapeChains(t, map[string][]int{
		"get /observed":      {},
		"get /missing":       {404},
		"get /api/v1/direct": {403},
	})
}

// A router assigned inside a branch holds a value the walk cannot tell, so a route registered
// through it fails rather than being read with either value.
func TestRouteChains_ARouterAssignedInsideABlockFails(t *testing.T) {
	root := t.TempDir()
	routeShapesFixture(t, root, "\tlate := pages\n"+
		"\tif s != nil {\n"+
		"\t\tlate = pages.With(middleware.Refuse())\n"+
		"\t}\n"+
		"\tlate.Get(\"/late\", apihandlers.HandleOkGet())\n")

	_, _, report := fixtureRouteChains(t, root, 1, 1)

	if report.Stopped || len(report.Errors) != 1 ||
		!strings.Contains(report.Errors[0], "cannot tell which middleware GET /late runs behind: late is assigned inside a block") {
		t.Errorf("a route through a router assigned in a branch did not fail the check once: %+v", report)
	}
}

// A constructor whose returned value the lint cannot read is reported, rather than read from
// another literal of its type.
func TestRouteChains_AConstructorWhoseReturnTheLintCannotReadFails(t *testing.T) {
	root := t.TempDir()
	routeShapesFixture(t, root, "\tbuilt := middleware.NewBuilt()\n"+
		"\tpages.With(built.Check()).Get(\"/built\", apihandlers.HandleOkGet())\n")
	writeDocFixture(t, root, "internal/middleware/built.go", `package middleware

func NewBuilt() *Probed {
	unused := &Probed{refusals: unprocessable{}}
	_ = unused
	return build()
}

func build() *Probed {
	return &Probed{refusals: forbid{}}
}
`)

	_, _, report := fixtureRouteChains(t, root, 1, 1)

	if report.Stopped || len(report.Errors) != 1 ||
		!strings.Contains(report.Errors[0], "GET /built mounts built.Check, which the status lint cannot read") {
		t.Errorf("a constructor whose return cannot be read did not fail the check once: %+v", report)
	}
}

// A bare return of a named result returns the value the body assigned to it, so a constructor that
// returns nil on one branch and its named result on another is read with the named result's fields.
func TestRouteChains_ABareReturnOfANamedResultIsRead(t *testing.T) {
	root := t.TempDir()
	routeShapesFixture(t, root, "\tgate := middleware.NewGate(false)\n"+
		"\tpages.With(gate.Check()).Get(\"/gated\", apihandlers.HandleOkGet())\n")
	writeDocFixture(t, root, "internal/middleware/gate.go", `package middleware

import "net/http"

type Gate struct {
	refusals writer
}

func NewGate(disabled bool) (gate *Gate) {
	if disabled {
		return nil
	}
	gate = &Gate{refusals: forbid{}}
	return
}

func (g *Gate) Check() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.refusals.refuse(w)
		})
	}
}
`)

	routes, _, report := fixtureRouteChains(t, root, 1, 1)

	if report.Failed() {
		t.Fatalf("reading the fixture chains failed: %+v", report)
	}
	var got []int
	for _, r := range routes {
		if r.key == "get /gated" {
			got = sortedKeysInt(r.chain)
		}
	}
	if !slices.Equal(got, []int{403}) {
		t.Errorf("chain of GET /gated is %v, want [403]", got)
	}
}

// A named result assigned from a call is a value the lint cannot read, so the route is reported.
func TestRouteChains_ABareReturnOfANamedResultTheLintCannotReadFails(t *testing.T) {
	root := t.TempDir()
	routeShapesFixture(t, root, "\tgate := middleware.NewGate(false)\n"+
		"\tpages.With(gate.Check()).Get(\"/gated\", apihandlers.HandleOkGet())\n")
	writeDocFixture(t, root, "internal/middleware/gate.go", `package middleware

import "net/http"

type Gate struct {
	refusals writer
}

func NewGate(disabled bool) (gate *Gate) {
	if disabled {
		return nil
	}
	gate = build()
	return
}

func build() *Gate {
	return &Gate{refusals: forbid{}}
}

func (g *Gate) Check() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.refusals.refuse(w)
		})
	}
}
`)

	_, _, report := fixtureRouteChains(t, root, 1, 1)

	if report.Stopped || len(report.Errors) != 1 ||
		!strings.Contains(report.Errors[0], "GET /gated mounts gate.Check, which the status lint cannot read") {
		t.Errorf("a named result whose value cannot be read did not fail the check once: %+v", report)
	}
}

// ---------------------------------------------------------------------------
// The three parsers.
// ---------------------------------------------------------------------------

// parseRoutes reads routes.go rather than starting a server, because the registration is
// what the spec is a description of, and a running server would answer only the routes a
// test happened to call.
func parseRoutes(t *testing.T) []routeRegistration {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "routes.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing routes.go: %v", err)
	}

	out := collectRoutes(fset, file)

	// The floor. A parse that silently stopped matching chi's registration shape would make
	// every test above vacuous, and the failure would look like a pass.
	api := 0
	for _, r := range out {
		if strings.HasPrefix(r.path, "/api/v1/") {
			api++
		}
	}
	if api < 100 {
		t.Fatalf("parsed only %d routes under /api/v1 from routes.go; the parse is no longer "+
			"matching the way routes are registered", api)
	}
	return out
}

var httpVerbs = map[string]string{
	"Get": "get", "Post": "post", "Put": "put", "Delete": "delete",
	"Patch": "patch", "Head": "head", "Options": "options",
}

// specVerbs is the same set as the spec spells it, used to tell an operation apart from the
// path-level keys that sit beside it.
var specVerbs = func() map[string]bool {
	out := map[string]bool{}
	for _, v := range httpVerbs {
		out[v] = true
	}
	return out
}()

// collectRoutes reads each route registration in file, with the middleware routes.go mounts in
// front of it. It reads each function's statements in source order and tracks what every router
// name holds at each registration, as core/routing builds it: a router is a scope, the root or an
// r.Route group, with the With arguments added since. A scope's Use calls wrap every route
// registered in it, since the router refuses a Use after one (Router.Use), and a group runs behind
// the chain of its enclosing scope and the With arguments of the router it hangs off
// (Router.Route). A Use is credited to the scope of the router it is called on, so a Use on another
// router credits none of this group's routes, and a router reassigned between two registrations is
// read with the value each one sees.
//
// A name routes.go never assigns, such as initRoutes's parameters and the branches it unpacks, is
// a router built outside it, a root of its own: middleware mounted there is out of this lint's
// reach. A router name assigned inside a block, such as an if, has a value that depends on the
// branch taken, and a registration through it, or after a Use on it, is marked unresolved rather
// than read with either value.
func collectRoutes(fset *token.FileSet, file *ast.File) []routeRegistration {
	w := &routeWalk{fset: fset, top: map[ast.Stmt]bool{}}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			w.body(fn.Body, &routerEnv{names: map[string]routerValue{}}, "")
		}
	}
	return w.out
}

// routeScope is the root router or one r.Route group: the middleware every route registered in it
// runs behind, ahead of the With arguments of the router the route is registered through.
type routeScope struct {
	// base is, for a group, its enclosing scope's chain and the With arguments of the router it
	// hangs off; nil at a root.
	base []ast.Expr
	uses []ast.Expr
	// unresolved is set on a group created from a router collectRoutes cannot tell.
	unresolved string
}

func (s *routeScope) chain() []ast.Expr {
	return append(slices.Clone(s.base), s.uses...)
}

// routerValue is what a router name or expression of routes.go holds at one point of the walk:
// its scope and the With arguments added since, or why it cannot be told.
type routerValue struct {
	scope      *routeScope
	with       []ast.Expr
	unresolved string
}

// routerEnv is the router names of one function: its own, and its enclosing function's.
type routerEnv struct {
	parent *routerEnv
	names  map[string]routerValue
}

func (e *routerEnv) outermost() *routerEnv {
	for e.parent != nil {
		e = e.parent
	}
	return e
}

// lookup is what name holds, a root of its own for a name routes.go never assigned.
func (e *routerEnv) lookup(name string) routerValue {
	for env := e; env != nil; env = env.parent {
		if v, ok := env.names[name]; ok {
			return v
		}
	}
	v := routerValue{scope: &routeScope{}}
	e.outermost().names[name] = v
	return v
}

// assign binds name to v: here for a :=, and where the name was bound for an =.
func (e *routerEnv) assign(name string, v routerValue, define bool) {
	if !define {
		for env := e; env != nil; env = env.parent {
			if _, ok := env.names[name]; ok {
				env.names[name] = v
				return
			}
		}
		e = e.outermost()
	}
	e.names[name] = v
}

// routeWalk is collectRoutes's state.
type routeWalk struct {
	fset *token.FileSet
	// top is the statements at the top level of a function body the walk read, the ones that run
	// unconditionally, in order.
	top map[ast.Stmt]bool
	// poison is set by a Use on a router the walk cannot tell, after which no registration's chain
	// is known.
	poison string
	out    []routeRegistration
}

func (w *routeWalk) body(body *ast.BlockStmt, env *routerEnv, prefix string) {
	for _, stmt := range body.List {
		w.top[stmt] = true
	}
	for _, stmt := range body.List {
		w.node(stmt, env, prefix)
	}
}

func (w *routeWalk) node(n ast.Node, env *routerEnv, prefix string) {
	ast.Inspect(n, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			w.assign(x.Lhs, x.Rhs, x.Tok == token.DEFINE, !w.top[x], x.Pos(), env, prefix)
			return false
		case *ast.DeclStmt:
			gen, ok := x.Decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				return true
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				lhs := make([]ast.Expr, len(vs.Names))
				for i, name := range vs.Names {
					lhs[i] = name
				}
				w.assign(lhs, vs.Values, true, !w.top[x], x.Pos(), env, prefix)
			}
			return false
		case *ast.CallExpr:
			return w.call(x, env, prefix)
		}
		return true
	})
}

// assign binds each name of lhs to what the matching value of rhs holds. A name assigned inside a
// block becomes unresolved, since whether the block ran is not known here.
func (w *routeWalk) assign(lhs, rhs []ast.Expr, define, nested bool, pos token.Pos,
	env *routerEnv, prefix string) {

	values := make([]routerValue, len(rhs))
	for i, e := range rhs {
		values[i] = w.value(e, env, prefix)
	}
	for i, e := range lhs {
		id, ok := e.(*ast.Ident)
		if !ok || id.Name == "_" {
			continue
		}
		v := routerValue{scope: &routeScope{}} // one of several results of a call: no router of routes.go's
		if len(rhs) == len(lhs) {
			v = values[i]
		}
		if nested {
			v = routerValue{unresolved: fmt.Sprintf("%s is assigned inside a block at routes.go:%d, so "+
				"which router it holds depends on the branch taken", id.Name, w.fset.Position(pos).Line)}
		}
		env.assign(id.Name, v, define)
	}
}

// value is what a router expression holds: a name, a With call on a router, or an r.Route call,
// which returns the group's router. Anything else is a router of its own, after the walk reads
// the registrations inside it, such as a function literal's.
func (w *routeWalk) value(e ast.Expr, env *routerEnv, prefix string) routerValue {
	switch x := ast.Unparen(e).(type) {
	case *ast.Ident:
		return env.lookup(x.Name)
	case *ast.CallExpr:
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
			switch sel.Sel.Name {
			case "With":
				v := w.value(sel.X, env, prefix)
				v.with = append(slices.Clip(v.with), x.Args...)
				return v
			case "Route":
				if group, ok := w.route(x, sel, env, prefix); ok {
					return group
				}
			}
		}
	}
	w.node(e, env, prefix)
	return routerValue{scope: &routeScope{}}
}

// route reads r.Route("/api/v1/admin", func(r *routing.Router) { ... }): the body under the
// prefix, with its parameter naming the group's router, and returns that router.
func (w *routeWalk) route(call *ast.CallExpr, sel *ast.SelectorExpr, env *routerEnv, prefix string) (routerValue, bool) {
	if len(call.Args) != 2 {
		return routerValue{}, false
	}
	sub, subOK := routePath(call.Args[0])
	body, bodyOK := call.Args[1].(*ast.FuncLit)
	if !subOK || !bodyOK {
		return routerValue{}, false
	}
	parent := w.value(sel.X, env, prefix)
	scope := &routeScope{unresolved: parent.unresolved}
	if parent.scope != nil {
		scope.base = append(parent.scope.chain(), parent.with...)
		if parent.scope.unresolved != "" {
			scope.unresolved = parent.scope.unresolved
		}
	}
	group := routerValue{scope: scope}
	inner := &routerEnv{parent: env, names: map[string]routerValue{}}
	if params := body.Type.Params.List; len(params) == 1 && len(params[0].Names) == 1 {
		inner.names[params[0].Names[0].Name] = group
	}
	w.body(body.Body, inner, prefix+sub)
	return group, true
}

// call reads one call of the walk: a group, a Use, or a registration, r.Verb(path, pkg.HandleX(...))
// or getAndHead(r, path, pkg.HandleX(...)), which registers the handler for GET and for HEAD on r
// (server.go). It reports whether the walk goes on into the call's operands, which it does not
// where it read them itself.
func (w *routeWalk) call(call *ast.CallExpr, env *routerEnv, prefix string) bool {
	if fn, isIdent := call.Fun.(*ast.Ident); isIdent && fn.Name == "getAndHead" && len(call.Args) == 3 {
		path, pathOK := routePath(call.Args[1])
		handler, handlerOK := handlerConstructor(call.Args[2])
		if !pathOK || !handlerOK {
			return true
		}
		via := w.value(call.Args[0], env, prefix)
		for _, verb := range []string{"get", "head"} {
			w.register(verb, prefix+path, handler, via, call)
		}
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return true
	}
	switch sel.Sel.Name {
	case "Route":
		if _, ok := w.route(call, sel, env, prefix); ok {
			return false
		}
		return true
	case "Use":
		v := w.value(sel.X, env, prefix)
		switch {
		case v.unresolved != "":
			w.poison = fmt.Sprintf("routes.go:%d calls Use on %s, and %s", w.fset.Position(call.Pos()).Line,
				types.ExprString(sel.X), v.unresolved)
		case v.scope != nil:
			v.scope.uses = append(v.scope.uses, call.Args...)
		}
		return false
	}
	verb, isVerb := httpVerbs[sel.Sel.Name]
	if !isVerb || len(call.Args) != 2 {
		return true
	}
	path, pathOK := routePath(call.Args[0])
	handler, handlerOK := handlerConstructor(call.Args[1])
	if !pathOK || !handlerOK {
		return true
	}
	w.register(verb, prefix+path, handler, w.value(sel.X, env, prefix), call)
	return false
}

func (w *routeWalk) register(verb, path, handler string, via routerValue, call *ast.CallExpr) {
	r := routeRegistration{
		method:  verb,
		path:    path,
		key:     routeKey(verb, path),
		handler: handler,
		line:    w.fset.Position(call.Pos()).Line,
	}
	switch {
	case via.unresolved != "":
		r.unresolved = via.unresolved
	case via.scope.unresolved != "":
		r.unresolved = via.scope.unresolved
	case w.poison != "":
		r.unresolved = w.poison
	default:
		r.mounted = append(via.scope.chain(), via.with...)
	}
	w.out = append(w.out, r)
}

func stringLiteral(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// handlerConstructor pulls apihandlers.HandleX out of apihandlers.HandleX(deps...), package
// and all, because two handler packages can declare the same name: apihandlers.HandleClientLogoGet
// answers the admin API and handlers.HandleClientLogoGet the public logo URL. Every API route
// is registered that way; anything else (a file server, a bare http.HandlerFunc) is not an
// operation the spec describes and is left alone.
func handlerConstructor(e ast.Expr) (string, bool) {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		pkg, ok := fn.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		return pkg.Name + "." + fn.Sel.Name, strings.HasPrefix(fn.Sel.Name, "Handle")
	case *ast.Ident:
		return fn.Name, strings.HasPrefix(fn.Name, "Handle")
	}
	return "", false
}

// parseHandlerStatuses maps every Handle* constructor under internal/handlers, keyed by its
// package-qualified name as handlerConstructor reads it from routes.go, to the statuses it can
// write, as handlerStatuses reads them.
func parseHandlerStatuses(t *testing.T) map[string]map[int]bool {
	t.Helper()
	// go test runs with the package directory as the working directory, so this is
	// src/authserver/internal/handlers.
	return readHandlerStatuses(t, filepath.Join("..", "handlers"), handlerFloor, samePackageReferenceFloor)
}

// handlerFloor and samePackageReferenceFloor are how many Handle* functions the handlers hold
// and how many references to a function of their own package their functions make, as floors
// well below the real counts so ordinary growth does not move them. A walk that reached no
// handler, or a resolver that followed no reference, reads every handler as writing nothing,
// which the reverse test would pass for every operation that declares no failure.
const (
	handlerFloor              = 100
	samePackageReferenceFloor = 500
)

// readHandlerStatuses is the reporting half of handlerStatuses: one failure per finding, and a
// stop for a walk that could not be read, reached fewer Handle* functions than handlers, or
// followed fewer same-package references than references.
func readHandlerStatuses(r guard.Reporter, root string, handlers, references int) map[string]map[int]bool {
	r.Helper()
	statuses, followed, findings, err := handlerStatuses(root)
	if err != nil {
		r.Fatalf("%v", err)
		return nil
	}
	if len(statuses) < handlers {
		r.Fatalf("found only %d Handle* functions under %s; the walk is no longer reaching the "+
			"handler sources", len(statuses), root)
		return nil
	}
	if followed < references {
		r.Fatalf("followed only %d references to a same-package function under %s; the resolver "+
			"is no longer reading the statuses the handlers' helpers write", followed, root)
		return nil
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
	return statuses
}

// handlerSource is one parsed non-test Go file under the handlers.
type handlerSource struct {
	path string
	fset *token.FileSet
	file *ast.File
}

// handlerFunc is one plain function of a handler package: the statuses its own body writes, and
// the names of the plain functions of its package that its body refers to.
type handlerFunc struct {
	own  map[int]bool
	refs []string
}

// handlerStatuses walks the non-test Go sources under root and maps every Handle* function, keyed
// by its package-qualified name, to the statuses it can write: those its own body writes and those
// of every plain function of its package it reaches, through any number of references. It also
// returns how many such references it followed, and one finding per status it cannot read. Tests
// are skipped: a test names statuses to assert on them, and it is production code that decides
// what a route can answer.
//
// A package is a directory. A reference is any use of a same-package function's name in a body
// other than as the member of a selector, so a helper passed as a value is reached as one called
// is, and a local that shares a helper's name is read as the helper, which can only add statuses:
// the conservative direction, as for an unreachable branch. A call into another package is not
// followed. The shared writers there are read by name in ownStatuses.
func handlerStatuses(root string) (map[string]map[int]bool, int, []string, error) {
	byDir := map[string][]handlerSource{}
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if pErr != nil {
			return fmt.Errorf("parsing %s: %w", path, pErr)
		}
		files++
		dir := filepath.Dir(path)
		byDir[dir] = append(byDir[dir], handlerSource{path: filepath.ToSlash(path), fset: fset, file: file})
		return nil
	})
	if err != nil {
		return nil, 0, nil, fmt.Errorf("walking %s: %w", root, err)
	}
	if files == 0 {
		return nil, 0, nil, fmt.Errorf("walked no non-test Go files under %s", root)
	}

	out := map[string]map[int]bool{}
	seenIn := map[string]string{}
	followed := 0
	var findings []string
	for _, dir := range sortedKeys(byDir) {
		sources := byDir[dir]
		names := map[string]bool{}
		for _, src := range sources {
			for _, fn := range plainFuncs(src.file) {
				names[fn.Name.Name] = true
			}
		}
		// A name maps to every declaration of it, since build constraints can give one
		// function a file per platform, and the lint reads them all.
		funcs := map[string][]*handlerFunc{}
		type handler struct {
			name, path string
			fn         *handlerFunc
		}
		var handlers []handler
		for _, src := range sources {
			for _, fn := range plainFuncs(src.file) {
				own, unknown := ownStatuses(src.path, src.fset, fn)
				findings = append(findings, unknown...)
				hf := &handlerFunc{own: own, refs: samePackageReferences(fn.Body, names)}
				followed += len(hf.refs)
				funcs[fn.Name.Name] = append(funcs[fn.Name.Name], hf)
				if strings.HasPrefix(fn.Name.Name, "Handle") {
					handlers = append(handlers, handler{
						name: src.file.Name.Name + "." + fn.Name.Name, path: src.path, fn: hf})
				}
			}
		}
		for _, h := range handlers {
			// Two handler packages of the same name would make the lookup ambiguous and the
			// result arbitrary. There are none; this says so.
			if prev, dup := seenIn[h.name]; dup {
				return nil, 0, nil, fmt.Errorf("%s is declared in both %s and %s; the status scan "+
					"looks handlers up by package and name and cannot tell them apart", h.name, prev, h.path)
			}
			seenIn[h.name] = h.path
			out[h.name] = reachedStatuses(h.fn, funcs)
		}
	}
	return out, followed, findings, nil
}

// plainFuncs is a file's functions with a body and no receiver, the ones a bare name refers to.
// The blank function and init cannot be referred to, so they are no one's helper.
func plainFuncs(file *ast.File) []*ast.FuncDecl {
	var out []*ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil || fn.Name.Name == "_" || fn.Name.Name == "init" {
			continue
		}
		out = append(out, fn)
	}
	return out
}

// samePackageReferences is every use in body of one of names, the plain functions of the body's
// own package, other than as the member of a selector, which names a field, a method or another
// package's function.
func samePackageReferences(body *ast.BlockStmt, names map[string]bool) []string {
	var refs []string
	var visit func(ast.Node) bool
	visit = func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.SelectorExpr:
			ast.Inspect(e.X, visit)
			return false
		case *ast.Ident:
			if names[e.Name] {
				refs = append(refs, e.Name)
			}
		}
		return true
	}
	ast.Inspect(body, visit)
	return refs
}

// reachedStatuses is start's own statuses and those of every function of its package it reaches,
// each read once however many paths lead to it, so a helper that refers back to its caller ends
// the walk rather than looping it.
func reachedStatuses(start *handlerFunc, funcs map[string][]*handlerFunc) map[int]bool {
	out := maps.Clone(start.own)
	seen := map[string]bool{}
	queue := slices.Clone(start.refs)
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		for _, fn := range funcs[name] {
			maps.Copy(out, fn.own)
			queue = append(queue, fn.refs...)
		}
	}
	return out
}

// ownStatuses reads the statuses one function's own body writes, with one finding per status
// constant it does not know the number of. Four spellings write a status in this module and all
// four are read here; anything else is a fifth nobody has taught this file about, which is what
// the unknown-constant finding is for. A same-package helper is not named here: handlerStatuses
// follows the reference and reads the helper's own body.
func ownStatuses(path string, fset *token.FileSet, fn *ast.FuncDecl) (map[int]bool, []string) {
	out := map[int]bool{}
	var findings []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.SelectorExpr:
			// http.StatusXxx, wherever it appears: w.WriteHeader, writeJSONError's fourth
			// argument, or a comparison.
			pkg, ok := e.X.(*ast.Ident)
			if !ok || pkg.Name != "http" || !strings.HasPrefix(e.Sel.Name, "Status") {
				return true
			}
			if e.Sel.Name == "StatusText" {
				return true // the formatter, not a status
			}
			code, known := httpStatusConstants[e.Sel.Name]
			if !known {
				findings = append(findings, fmt.Sprintf("%s:%d: %s uses http.%s, which "+
					"openapi_contract_lint_test.go does not know the number of; add it to "+
					"httpStatusConstants", path, fset.Position(e.Pos()).Line, fn.Name.Name, e.Sel.Name))
				return true
			}
			out[code] = true
		case *ast.CallExpr:
			if code, ok := sharedWriterStatus(e); ok {
				out[code] = true
			}
		}
		return true
	})
	return out, findings
}

// sharedWriterStatus is the status a call to one of the shared writers outside the handler
// packages writes without being handed it as a constant.
func sharedWriterStatus(call *ast.CallExpr) (int, bool) {
	f, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return 0, false
	}
	pkg, _ := f.X.(*ast.Ident)
	switch f.Sel.Name {
	case "InternalServerError", "JSONError":
		// httpHelper's two error renderers. Both write 500 for a bare error, which is the only
		// kind these handlers hand them.
		return 500, true
	case "NotFound":
		if pkg != nil && pkg.Name == "http" {
			return 404, true
		}
	case "WriteInternalServerError", "WriteJSON":
		// apiresponse's 500 and its JSON writer, which buffers the encode before it writes
		// anything and answers 500 when the encode fails (#279 decisions 7 and 8). apihandlers
		// reaches them through writeInternalServerError and writeJSON, and the handlers outside
		// it, such as the public settings, call them directly.
		if pkg != nil && pkg.Name == "apiresponse" {
			return 500, true
		}
	}
	return 0, false
}

// parseRouteChains is parseRoutes with each route's chain read, as readRouteChains reads it.
func parseRouteChains(t *testing.T) []routeRegistration {
	t.Helper()
	// go test runs with the package directory as the working directory, so ".." is
	// src/authserver/internal.
	return readRouteChains(t, "routes.go", "..", parseRoutes(t), middlewareFloor, chainCallFloor)
}

// middlewareFloor and chainCallFloor are how many distinct middleware routes.go mounts and how
// many calls from a method to another method or through a field their walks follow, as floors
// well below the real counts so ordinary growth does not move them. A resolver that read no
// middleware reads every chain as writing nothing, and one that followed no call reads the bearer
// guards and the rate limiters as writing nothing, since every refusal they write is behind one:
// the forward test would then pass a route whose 401, 403 or 429 the spec lacks.
const (
	middlewareFloor = 20
	chainCallFloor  = 100
)

// authserverInternalImport is the import path prefix of the packages the chain resolver reads: a
// package routes.go imports under it lives in the directory of the same relative path.
const authserverInternalImport = "github.com/leodip/goiabada/authserver/internal/"

// readRouteChains is the reporting half of routeChains: one failure per finding, and a stop for a
// walk that could not be read, read fewer distinct middleware than middleware, or followed fewer
// calls than calls.
func readRouteChains(r guard.Reporter, routesPath, internalRoot string, routes []routeRegistration,
	middleware, calls int) []routeRegistration {

	r.Helper()
	out, read, followed, findings, err := routeChains(routesPath, internalRoot, routes)
	if err != nil {
		r.Fatalf("%v", err)
		return nil
	}
	if read < middleware {
		r.Fatalf("read only %d middleware mounted by %s; the resolver is no longer reading the "+
			"chains in front of the routes", read, routesPath)
		return nil
	}
	if followed < calls {
		r.Fatalf("followed only %d calls to a method or through a field from the middleware %s "+
			"mounts; the resolver is no longer reading the refusals they write", followed, routesPath)
		return nil
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
	return out
}

// routeChains returns routes with each one's chain filled: every status the middleware routes.go
// mounts in front of it can write, with the middleware that writes it. It also returns
// how many distinct middleware it read, how many calls it followed, and one finding per
// middleware it cannot read and per status constant it does not know.
//
// A route's chain is the middleware collectRoutes read as mounted in front of it, and a route
// whose chain it could not tell is a finding. Each one is read as a handler is, through
// ownStatuses and the plain functions of its package it reaches, from one of three shapes:
// pkg.F(...), a function of a package routes.go imports; v.M(...) or the method value v.M, a
// method of the type the constructor assigned to v returns, as apiBearer and rateLimiter are; or
// v, a local assigned from either. A method's walk follows the calls it makes on its receiver,
// m.other(...), as a rate limiter reaches its 429, and the calls through a field of the receiver
// the constructor filled with a value of a type of the package, m.field.M(...), as the bearer
// guards write every refusal. The field is read as that constructor filled it, so the guards
// routes.go builds for the API are read with the API's refusal writers and not with the
// /userinfo ones beside them, which no API route runs. A field filled with a constructor's
// parameter, and any call into another package, is not followed: ownStatuses names the shared
// writers there.
//
// A failure joins the chain wherever the middleware names it, as a handler's does. A success or a
// redirect joins it only where the middleware writes it, such as the 307 it hands http.Redirect,
// and not where it only names one, such as APIDebug's recorder starting at 200 for a handler that
// never calls WriteHeader: chainStatuses says which mentions those are.
func routeChains(routesPath, internalRoot string, routes []routeRegistration) ([]routeRegistration, int, int, []string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, routesPath, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, 0, 0, nil, fmt.Errorf("parsing %s: %w", routesPath, err)
	}
	c := &chainResolver{
		imports: map[string]string{},
		vars:    routesLocals(file),
		pkgs:    map[string]*goPackage{},
		cache:   map[string]map[int]bool{},
		unknown: map[string]bool{},
	}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || !strings.HasPrefix(path, authserverInternalImport) {
			continue
		}
		rel := strings.TrimPrefix(path, authserverInternalImport)
		name := filepath.Base(rel)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		c.imports[name] = filepath.Join(internalRoot, filepath.FromSlash(rel))
	}

	var findings []string
	out := slices.Clone(routes)
	for i, rt := range out {
		chain := map[int][]string{}
		if rt.unresolved != "" {
			findings = append(findings, fmt.Sprintf("routes.go:%d: the status lint cannot tell which "+
				"middleware %s %s runs behind: %s. Assign each router once, at the top level of its "+
				"function", rt.line, strings.ToUpper(rt.method), rt.path, rt.unresolved))
		}
		for _, e := range rt.mounted {
			label := middlewareLabel(e)
			statuses, ok := c.statuses(e)
			if c.err != nil {
				return nil, 0, 0, nil, c.err
			}
			if !ok {
				findings = append(findings, fmt.Sprintf("routes.go:%d: %s %s mounts %s, which the status "+
					"lint cannot read: it reads pkg.F(...), v.M(...), v.M and a local assigned from one of "+
					"them, with v assigned from a constructor of a package under internal", rt.line,
					strings.ToUpper(rt.method), rt.path, label))
				continue
			}
			for code := range statuses {
				if !slices.Contains(chain[code], label) {
					chain[code] = append(chain[code], label)
				}
			}
		}
		out[i].chain = chain
	}
	findings = append(findings, sortedKeys(c.unknown)...)
	return out, len(c.cache), c.followed, findings, nil
}

// middlewareLabel is a chain entry as a finding names it: the callee, without its arguments.
func middlewareLabel(e ast.Expr) string {
	if call, ok := e.(*ast.CallExpr); ok {
		e = call.Fun
	}
	return types.ExprString(e)
}

// routesLocals maps each name routes.go assigns once with := to the value it assigns. A name
// assigned twice, or assigned again with =, maps to nil, which the resolver cannot read, rather
// than to either value.
func routesLocals(file *ast.File) map[string]ast.Expr {
	out := map[string]ast.Expr{}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok {
				continue
			}
			if _, twice := out[id.Name]; twice || assign.Tok != token.DEFINE || len(assign.Lhs) != len(assign.Rhs) {
				out[id.Name] = nil
				continue
			}
			out[id.Name] = assign.Rhs[i]
		}
		return true
	})
	return out
}

// chainResolver reads the statuses the middleware of one routes.go can write.
type chainResolver struct {
	imports  map[string]string   // package name, as routes.go spells it, to its directory
	vars     map[string]ast.Expr // routes.go's locals
	pkgs     map[string]*goPackage
	cache    map[string]map[int]bool // by middleware read, so each is walked once
	followed int
	unknown  map[string]bool
	err      error
}

// goPackage is one directory's non-test Go sources, as the chain resolver reads them.
type goPackage struct {
	funcs   map[string][]funcSource // plain functions, by name
	methods map[string][]funcSource // methods, by Type.name
	plain   map[string]bool
}

type funcSource struct {
	path string
	fset *token.FileSet
	decl *ast.FuncDecl
}

// fieldBinding is the type a constructor gave a value, and the same for each field it filled with
// a composite literal of a type of its package.
type fieldBinding struct {
	typ    string
	fields map[string]fieldBinding
}

// chainWalk is one function a middleware's walk reads: a plain function by name, or a method by
// Type.name with what its receiver's fields hold.
type chainWalk struct {
	key     string
	method  bool
	binding fieldBinding
}

func (c *chainResolver) pkg(dir string) *goPackage {
	if p, ok := c.pkgs[dir]; ok {
		return p
	}
	p := &goPackage{funcs: map[string][]funcSource{}, methods: map[string][]funcSource{}, plain: map[string]bool{}}
	c.pkgs[dir] = p
	entries, err := os.ReadDir(dir)
	if err != nil {
		c.err = fmt.Errorf("reading %s: %w", dir, err)
		return p
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			c.err = fmt.Errorf("parsing %s: %w", path, err)
			return p
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			src := funcSource{path: filepath.ToSlash(path), fset: fset, decl: fn}
			if fn.Recv == nil {
				p.funcs[fn.Name.Name] = append(p.funcs[fn.Name.Name], src)
				p.plain[fn.Name.Name] = true
				continue
			}
			if typ, ok := receiverType(fn); ok {
				key := typ + "." + fn.Name.Name
				p.methods[key] = append(p.methods[key], src)
			}
		}
	}
	return p
}

// receiverType is the name of a method's receiver type, pointer or not.
func receiverType(fn *ast.FuncDecl) (string, bool) {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return "", false
	}
	return typeName(fn.Recv.List[0].Type)
}

// typeName is T for T and *T.
func typeName(e ast.Expr) (string, bool) {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	id, ok := e.(*ast.Ident)
	if !ok {
		return "", false
	}
	return id.Name, true
}

// statuses reads one chain entry, or reports false when it has none of the shapes routeChains
// reads.
func (c *chainResolver) statuses(e ast.Expr) (map[int]bool, bool) {
	key, p, start, ok := c.entry(e, 0)
	if !ok || c.err != nil {
		return nil, false
	}
	if cached, ok := c.cache[key]; ok {
		return cached, true
	}
	out := c.walk(p, start)
	c.cache[key] = out
	return out, true
}

// entry resolves a chain entry to the function its walk starts from, keyed by what it names.
func (c *chainResolver) entry(e ast.Expr, depth int) (string, *goPackage, chainWalk, bool) {
	if call, ok := e.(*ast.CallExpr); ok {
		e = call.Fun
	}
	switch x := e.(type) {
	case *ast.Ident:
		if v := c.vars[x.Name]; v != nil && depth == 0 {
			return c.entry(v, depth+1)
		}
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		if !ok {
			break
		}
		if dir, isPkg := c.imports[id.Name]; isPkg {
			p := c.pkg(dir)
			if len(p.funcs[x.Sel.Name]) == 0 {
				break
			}
			return dir + "." + x.Sel.Name, p, chainWalk{key: x.Sel.Name}, true
		}
		ctorCall, ok := c.vars[id.Name].(*ast.CallExpr)
		if !ok {
			break
		}
		ctorSel, ok := ctorCall.Fun.(*ast.SelectorExpr)
		if !ok {
			break
		}
		pkgID, ok := ctorSel.X.(*ast.Ident)
		if !ok {
			break
		}
		dir, isPkg := c.imports[pkgID.Name]
		if !isPkg {
			break
		}
		p := c.pkg(dir)
		ctors := p.funcs[ctorSel.Sel.Name]
		if len(ctors) != 1 {
			break
		}
		binding, ok := constructed(ctors[0].decl)
		method := binding.typ + "." + x.Sel.Name
		if !ok || len(p.methods[method]) == 0 {
			break
		}
		return dir + "." + ctorSel.Sel.Name + "." + method, p, chainWalk{key: method, method: true, binding: binding}, true
	}
	return "", nil, chainWalk{}, false
}

// constructed is what a constructor returns: its result type, and the fields the value it returns
// fills with a composite literal of a type of the package. The value is read from each return
// statement of the constructor's own body, not of a function literal inside it: a composite literal
// of the result type, its address, or a local the body assigns once, from one of those. A bare
// return returns the named result, read as such a local. A
// constructor returning anything else, or two values that fill one field with different types, is
// not read, rather than read from another literal of the type, such as one it builds and discards.
func constructed(ctor *ast.FuncDecl) (fieldBinding, bool) {
	if ctor.Type.Results == nil || len(ctor.Type.Results.List) == 0 {
		return fieldBinding{}, false
	}
	typ, ok := typeName(ctor.Type.Results.List[0].Type)
	if !ok {
		return fieldBinding{}, false
	}
	// A named result, which a bare return returns.
	var named *ast.Ident
	if names := ctor.Type.Results.List[0].Names; len(names) > 0 {
		named = names[0]
	}
	// Each local of the body, with every value assigned to it, a nil for one this cannot read.
	locals := map[string][]ast.Expr{}
	var returns []ast.Expr
	ast.Inspect(ctor.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					var value ast.Expr
					if len(x.Lhs) == len(x.Rhs) {
						value = x.Rhs[i]
					}
					locals[id.Name] = append(locals[id.Name], value)
				}
			}
		case *ast.ValueSpec:
			for i, name := range x.Names {
				var value ast.Expr
				if len(x.Names) == len(x.Values) {
					value = x.Values[i]
				}
				locals[name.Name] = append(locals[name.Name], value)
			}
		case *ast.ReturnStmt:
			switch {
			case len(x.Results) > 0:
				returns = append(returns, x.Results[0])
			case named != nil:
				returns = append(returns, named) // a bare return returns the named result
			}
		}
		return true
	})
	if len(returns) == 0 {
		return fieldBinding{}, false
	}
	out := fieldBinding{typ: typ, fields: map[string]fieldBinding{}}
	for _, ret := range returns {
		lit, ok := returnedLiteral(ret, locals, typ)
		if !ok {
			return fieldBinding{}, false
		}
		if lit == nil {
			continue // a nil, which has no fields
		}
		for name, field := range literalBinding(lit).fields {
			if prev, bound := out.fields[name]; bound && prev.key() != field.key() {
				return fieldBinding{}, false
			}
			out.fields[name] = field
		}
	}
	return out, true
}

// returnedLiteral is the composite literal of type typ a constructor's return statement returns:
// the literal, its address, or a local assigned once from one of those. It is nil for a returned
// nil, and false for anything else.
func returnedLiteral(e ast.Expr, locals map[string][]ast.Expr, typ string) (*ast.CompositeLit, bool) {
	e = ast.Unparen(e)
	if id, ok := e.(*ast.Ident); ok {
		if id.Name == "nil" {
			return nil, true
		}
		values := locals[id.Name]
		if len(values) != 1 || values[0] == nil {
			return nil, false
		}
		e = ast.Unparen(values[0])
	}
	if addr, ok := e.(*ast.UnaryExpr); ok && addr.Op == token.AND {
		e = ast.Unparen(addr.X)
	}
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	if name, ok := typeName(lit.Type); !ok || name != typ {
		return nil, false
	}
	return lit, true
}

// key spells a binding whole, its fields sorted, so two bindings compare by what they hold.
func (b fieldBinding) key() string {
	if len(b.fields) == 0 {
		return b.typ
	}
	parts := make([]string, 0, len(b.fields))
	for _, name := range sortedKeys(b.fields) {
		parts = append(parts, name+":"+b.fields[name].key())
	}
	return b.typ + "{" + strings.Join(parts, ",") + "}"
}

// literalBinding is a composite literal's type and the same for each field it fills with one.
func literalBinding(lit *ast.CompositeLit) fieldBinding {
	typ, _ := typeName(lit.Type)
	out := fieldBinding{typ: typ, fields: map[string]fieldBinding{}}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		field, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		value := kv.Value
		if addr, ok := value.(*ast.UnaryExpr); ok && addr.Op == token.AND {
			value = addr.X
		}
		if inner, ok := value.(*ast.CompositeLit); ok {
			if _, named := typeName(inner.Type); named {
				out.fields[field.Name] = literalBinding(inner)
			}
		}
	}
	return out
}

// walk reads the statuses of start and of every function of its package it reaches, each read
// once however many paths lead to it. A method is read once for each binding of its receiver it is
// reached with, since two fields of one type can hold different refusal writers.
func (c *chainResolver) walk(p *goPackage, start chainWalk) map[int]bool {
	out := map[int]bool{}
	seen := map[string]bool{}
	queue := []chainWalk{start}
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		visit := next.key
		if next.method {
			visit += " " + next.binding.key()
		}
		if seen[visit] {
			continue
		}
		seen[visit] = true
		decls := p.funcs[next.key]
		if next.method {
			decls = p.methods[next.key]
		}
		for _, src := range decls {
			own, unknown := chainStatuses(src.path, src.fset, src.decl)
			maps.Copy(out, own)
			for _, finding := range unknown {
				c.unknown[finding] = true
			}
			for _, name := range samePackageReferences(src.decl.Body, p.plain) {
				queue = append(queue, chainWalk{key: name})
			}
			if next.method {
				calls := receiverCalls(src.decl, next.binding, p)
				c.followed += len(calls)
				queue = append(queue, calls...)
			}
		}
	}
	return out
}

// chainStatuses is ownStatuses for a function of a middleware's walk: every status its body names
// other than as an operand of a comparison or a switch case, which observe what the handler
// answered without writing it, and every success or redirect other than as a composite literal's
// element, such as a recorder that starts at 200. A failure in a composite literal is read as
// written, as a refusal's status in a table of them is. Any other mention, such as an argument of
// w.WriteHeader or http.Redirect, or a value a helper returns, is read as written, the
// conservative direction, as an unreachable branch is, and so is the status a shared writer of
// another package writes without being handed it, as ownStatuses reads it.
func chainStatuses(path string, fset *token.FileSet, fn *ast.FuncDecl) (map[int]bool, []string) {
	_, findings := ownStatuses(path, fset, fn)
	observed := map[*ast.SelectorExpr]bool{}
	initial := map[*ast.SelectorExpr]bool{}
	mark := func(set map[*ast.SelectorExpr]bool, e ast.Expr) {
		if sel, ok := ast.Unparen(e).(*ast.SelectorExpr); ok {
			set[sel] = true
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			for _, elt := range x.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					elt = kv.Value
				}
				mark(initial, elt)
			}
		case *ast.BinaryExpr:
			switch x.Op {
			case token.EQL, token.NEQ, token.LSS, token.GTR, token.LEQ, token.GEQ:
				mark(observed, x.X)
				mark(observed, x.Y)
			}
		case *ast.CaseClause:
			for _, e := range x.List {
				mark(observed, e)
			}
		}
		return true
	})
	out := map[int]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			pkg, ok := x.X.(*ast.Ident)
			if !ok || pkg.Name != "http" || observed[x] {
				return true
			}
			if code, known := httpStatusConstants[x.Sel.Name]; known && (code >= 400 || !initial[x]) {
				out[code] = true
			}
		case *ast.CallExpr:
			if code, ok := sharedWriterStatus(x); ok {
				out[code] = true
			}
		}
		return true
	})
	return out, findings
}

// receiverCalls is every method of the package a method's body reaches through its receiver:
// recv.M, another method of the receiver's type, and recv.field.M, a method of the type the
// constructor filled field with.
func receiverCalls(fn *ast.FuncDecl, binding fieldBinding, p *goPackage) []chainWalk {
	if len(fn.Recv.List[0].Names) == 0 {
		return nil
	}
	recv := fn.Recv.List[0].Names[0].Name
	var out []chainWalk
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch x := sel.X.(type) {
		case *ast.Ident:
			key := binding.typ + "." + sel.Sel.Name
			if x.Name == recv && len(p.methods[key]) > 0 {
				out = append(out, chainWalk{key: key, method: true, binding: binding})
			}
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			if !ok || id.Name != recv {
				break
			}
			field, filled := binding.fields[x.Sel.Name]
			key := field.typ + "." + sel.Sel.Name
			if filled && len(p.methods[key]) > 0 {
				out = append(out, chainWalk{key: key, method: true, binding: field})
			}
		}
		return true
	})
	return out
}

// specOperation is the part of an operation these tests read.
type specOperation struct {
	operationId string
	path        string // as written, with the spec's own parameter names
	responses   map[int]bool
}

// parseSpec reads the embedded bytes rather than the file on disk, so what is checked is
// what GET /openapi.yaml serves.
func parseSpec(t *testing.T) map[string]specOperation {
	t.Helper()

	var doc struct {
		Paths map[string]map[string]struct {
			OperationId string               `yaml:"operationId"`
			Responses   map[string]yaml.Node `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(web.OpenAPISpec(), &doc); err != nil {
		t.Fatalf("parsing the embedded openapi.yaml: %v", err)
	}

	out := map[string]specOperation{}
	for path, item := range doc.Paths {
		for verb, op := range item {
			if !specVerbs[verb] {
				continue // parameters, summary and the other path-level keys
			}
			responses := map[int]bool{}
			for code := range op.Responses {
				n, err := strconv.Atoi(code)
				if err != nil {
					t.Errorf("%s %s declares a response keyed %q, which is not a status code",
						strings.ToUpper(verb), path, code)
					continue
				}
				responses[n] = true
			}
			out[routeKey(verb, path)] = specOperation{operationId: op.OperationId, path: path, responses: responses}
		}
	}

	if len(out) < 90 {
		t.Fatalf("read only %d operations out of the embedded openapi.yaml; the parse is no "+
			"longer matching the document's shape", len(out))
	}
	return out
}

func sortedCodes(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for code := range set {
		out = append(out, code)
	}
	sort.Ints(out)
	return out
}

// TestOpenAPI_ResponseRefsResolve is the structural guard on the reconciliation above. Most
// of the failure entries in this document are one line, a $ref into components/responses,
// and a $ref whose target is missing or misspelled is not a documentation slip: every
// generator resolves it, so the document stops being usable rather than merely being wrong.
// The alternative shape, an entry written out in place, has to carry a description, since an
// empty response body tells a caller nothing at all.
func TestOpenAPI_ResponseRefsResolve(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]struct {
			Responses map[string]map[string]yaml.Node `yaml:"responses"`
		} `yaml:"paths"`
		Components struct {
			Responses map[string]yaml.Node `yaml:"responses"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(web.OpenAPISpec(), &doc); err != nil {
		t.Fatalf("parsing the embedded openapi.yaml: %v", err)
	}

	checked := 0
	used := map[string]bool{}
	for path, item := range doc.Paths {
		for verb, op := range item {
			if !specVerbs[verb] {
				continue
			}
			for code, response := range op.Responses {
				checked++
				ref, isRef := response["$ref"]
				if !isRef {
					if _, described := response["description"]; !described {
						t.Errorf("%s %s '%s' is written out in place with no description",
							strings.ToUpper(verb), path, code)
					}
					continue
				}
				name := ref.Value[strings.LastIndex(ref.Value, "/")+1:]
				used[name] = true
				if _, ok := doc.Components.Responses[name]; !ok {
					t.Errorf("%s %s '%s' refers to %s, which components/responses does not "+
						"define", strings.ToUpper(verb), path, code, ref.Value)
				}
			}
		}
	}

	// The other direction. A shared response nothing refers to is dead weight in a published
	// contract, and the way one appears is a reconciliation that stopped half done.
	for name := range doc.Components.Responses {
		if !used[name] {
			t.Errorf("components/responses defines %s, which no operation refers to", name)
		}
	}

	if checked < 300 {
		t.Errorf("checked only %d response entries; the walk is no longer reaching the "+
			"document's operations", checked)
	}
}

// TestOpenAPI_EveryRefResolves is the same guard widened to every $ref in the document, not
// only the ones that are a whole response. The test above walks operations' response entries
// and resolves those into components/responses; a $ref to a schema, sitting one level deeper
// under content/application-json/schema, was reached by nothing. That is the ref a caller
// actually depends on: a generator that cannot resolve an operation's response schema emits
// no type for it, so a misspelling there costs more than a misspelled shared response, and
// until this test it shipped in silence. Found by mutation while writing the eleven
// operations that had never been documented (#245).
//
// The walk is over the parsed document rather than over the text, so it reaches a $ref
// wherever one is legal: inside a schema, a parameter, an array's items, an allOf member.
func TestOpenAPI_EveryRefResolves(t *testing.T) {
	var doc map[string]interface{}
	if err := yaml.Unmarshal(web.OpenAPISpec(), &doc); err != nil {
		t.Fatalf("parsing the embedded openapi.yaml: %v", err)
	}

	components, _ := doc["components"].(map[string]interface{})
	if components == nil {
		t.Fatal("openapi.yaml has no components section")
	}

	// defined reports whether components/<section>/<name> exists.
	defined := func(section, name string) bool {
		sec, ok := components[section].(map[string]interface{})
		if !ok {
			return false
		}
		_, ok = sec[name]
		return ok
	}

	refs := 0
	var walk func(node interface{}, where string)
	walk = func(node interface{}, where string) {
		switch n := node.(type) {
		case map[string]interface{}:
			for key, val := range n {
				if key == "$ref" {
					ref, isString := val.(string)
					if !isString {
						t.Errorf("%s: $ref is not a string", where)
						continue
					}
					refs++
					parts := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
					if !strings.HasPrefix(ref, "#/components/") || len(parts) != 3 {
						t.Errorf("%s: $ref %q is not a local reference into components, "+
							"which is the only shape this document uses", where, ref)
						continue
					}
					if !defined(parts[1], parts[2]) {
						t.Errorf("%s: $ref %q resolves to nothing. A generator reading this "+
							"document emits no type for it", where, ref)
					}
					continue
				}
				walk(val, where+"/"+key)
			}
		case []interface{}:
			for i, item := range n {
				walk(item, fmt.Sprintf("%s[%d]", where, i))
			}
		}
	}
	walk(doc, "")

	if refs < 300 {
		t.Errorf("resolved only %d references; the walk is no longer reaching the document",
			refs)
	}
}

// ---------------------------------------------------------------------------
// The schema half.
// ---------------------------------------------------------------------------

// TestOpenAPI_SchemaPropertiesMatchTheAPIStructs holds every component schema's property set
// to the json: tags of the src/core/api struct of the same name, in both directions. Routes
// and statuses were already guarded both ways by the tests above; schemas were guarded by
// nothing, and they had drifted: 19 properties across 8 schemas were undeclared when this was
// first measured, pkceRequired among them, so the published contract did not know PKCE
// configuration existed at all and a generated client could neither set it nor read it back
// (#245). Leaving a field out of the spec does not keep it off the wire; it only keeps it out
// of the client somebody generates from the spec.
//
// Composition is resolved on both sides. A property inherited through allOf or reached
// through a $ref counts as documented, and a Go field promoted from an embedded struct counts
// as declared. A first version of the measurement that did neither reported 21 phantom
// properties on the session detail schema alone, every one of which it inherits.
//
// Two limits, both real, both stated here rather than left to be discovered.
//
// Pairing is by identical name. A schema deliberately named differently from its struct is
// paired through schemaStructNames below rather than renamed: a published schema name is part
// of the contract a caller has already generated against, and an internal Go name is not.
//
// The check covers presence, not type. A named type that marshals to a scalar cannot be typed
// from the Go source lexically: the declared type is a selector, so a type check would infer
// "object" and call the spec's correct "string" a mismatch. No field in api/ is such a type
// today -- the last one, UserResponse.Subject, became a plain string in #278 -- but carrying a
// type map against the next one buys less than it costs, so type agreement stays a question
// for the census rather than a check here.
//
// A schema that no operation reaches is not this test's subject: TestOpenAPI_EveryRefResolves
// owns reachability, and this one owns content.
//
// SOME SHAPES ON THE WIRE WERE NOT core/api STRUCTS, and exempting them was a hole rather
// than a limit. Four nested schemas were waved through here on the true observation that no
// core/api type declared them, and all four turned out to be incomplete against the
// authserver/internal/record type they really serialized: fifteen fields the API emitted on
// every one of these responses had no entry in the contract, and adding a bogus property to one
// left this whole tier green (#245, final review finding 3). They were paired to
// authserver/internal/record here until #350 replaced every model-typed response field with a
// DTO, at which point the pairing had nothing left to reach: a core/api struct now checks each
// surviving one. What stays exempt is only what no Go type declares at all.

// schemaStructNames pairs a component schema with the src/core/api struct it describes where
// the two are deliberately named differently. An entry pairs rather than exempts, so the
// schema's properties are still checked; the name difference is the only thing waved through.
//
// Exact, like the two maps below: both ends must exist, and an entry is refused if a struct of
// the schema's own name also exists, because then the pairing is ambiguous rather than
// deliberate.
var schemaStructNames = map[string]string{
	// The spec has said CreateUserRequest since it was written and a caller has generated
	// against it. The Go type is CreateUserAdminRequest because there is a self-service
	// counterpart it has to be told apart from inside the server. Both names are right where
	// they are.
	"CreateUserRequest": "CreateUserAdminRequest",

	// These two published schema names predate the Go types behind them by several releases.
	// #350 gave each position a DTO -- api.RedirectURIResponse and api.WebOriginResponse --
	// rather than serializing the persistence row, and the Go names carry the Response suffix
	// every other response type here does. Renaming the schemas to match would break every
	// client already generated against them, for nothing.
	"RedirectURI": "RedirectURIResponse",
	"WebOrigin":   "WebOriginResponse",
}

// schemasWithNoAPIStruct is one half of the exemption, in the shape knownUndocumentedRoutes
// had: a name and the reason it is not a defect. Exact, so a schema that acquires a struct of
// its own name fails this test until its entry comes out.
var schemasWithNoAPIStruct = map[string]string{
	// Empty since #441. The last four entries were the picture and logo answers, whose handlers
	// built them as map[string]interface{} literals; each is a type in core/api/pictures.go now,
	// so their properties are checked here like every other schema's.
}

// apiStructsWithNoSchema is the other half. A struct here is a shape the server can write or
// read that this document does not declare, and the reason has to say why that is acceptable
// rather than merely true.
var apiStructsWithNoSchema = map[string]string{
	// Empty since #783. PublicSettingsResponse and PasswordRulesResponse were here, as the
	// answer of /api/public/settings, outside the Admin and Account API scope the document then
	// declared; the document describes that public operation now, beside the client logo, so
	// their properties are checked here like every other schema's.
}

func TestOpenAPI_SchemaPropertiesMatchTheAPIStructs(t *testing.T) {
	schemas := specSchemaProperties(t)
	structs := structFields(t, filepath.Join("..", "..", "..", "core", "api"), 100)

	// Pair first. A schema is checked against the struct of its own name unless an alias says
	// otherwise.
	pairedStruct := map[string]string{} // schema name -> struct name
	pairedSchema := map[string]string{} // struct name -> schema name
	for schema := range schemas {
		name := schema
		if alias, aliased := schemaStructNames[schema]; aliased {
			name = alias
		}
		if _, exists := structs[name]; !exists {
			continue
		}
		pairedStruct[schema] = name
		pairedSchema[name] = schema
	}

	// The forward direction, and the one that matters to a caller: a field the API really
	// carries must be in the contract it generates from.
	for _, schema := range sortedKeys(pairedStruct) {
		structName := pairedStruct[schema]
		for _, field := range sortedKeys(structs[structName]) {
			if schemas[schema][field] {
				continue
			}
			t.Errorf("api.%s marshals %q, which the %s schema does not declare: a client "+
				"generated from openapi.yaml has no field for it", structName, field, schema)
		}
	}

	// The reverse: a property the spec promises must be one the struct really marshals, or the
	// caller is told to expect a field that never arrives.
	for _, schema := range sortedKeys(pairedStruct) {
		structName := pairedStruct[schema]
		for _, prop := range sortedKeys(schemas[schema]) {
			if _, marshalled := structs[structName][prop]; marshalled {
				continue
			}
			t.Errorf("the %s schema declares %q, which api.%s does not marshal: the spec is "+
				"promising a field that cannot arrive", schema, prop, structName)
		}
	}

	// Names with no counterpart, both ways, against the two exemption maps.
	for _, schema := range sortedKeys(schemas) {
		if _, paired := pairedStruct[schema]; paired {
			continue
		}
		if _, allowed := schemasWithNoAPIStruct[schema]; allowed {
			continue
		}
		t.Errorf("the %s schema has no Go type checking its properties. Give it a struct in "+
			"src/core/api, pair it in schemaStructNames, or record why in "+
			"schemasWithNoAPIStruct", schema)
	}
	for _, structName := range sortedKeys(structs) {
		if _, paired := pairedSchema[structName]; paired {
			continue
		}
		if _, allowed := apiStructsWithNoSchema[structName]; allowed {
			continue
		}
		t.Errorf("api.%s is a shape this server reads or writes and openapi.yaml declares no "+
			"schema for it. Document it, pair it in schemaStructNames, or record why in "+
			"apiStructsWithNoSchema", structName)
	}

	// The maps are exact in both directions, so an entry that has stopped being a gap fails
	// here rather than sitting on as a stale allowance. That is what retired
	// knownUndocumentedRoutes: every one of its eleven entries eventually stopped being true.
	for _, schema := range sortedKeys(schemasWithNoAPIStruct) {
		if _, exists := schemas[schema]; !exists {
			t.Errorf("schemasWithNoAPIStruct exempts %s, which openapi.yaml no longer defines; "+
				"delete the entry", schema)
			continue
		}
		if structName, paired := pairedStruct[schema]; paired {
			t.Errorf("schemasWithNoAPIStruct exempts %s, but api.%s now pairs with it; delete "+
				"the entry so its properties are checked", schema, structName)
		}
	}
	for _, structName := range sortedKeys(apiStructsWithNoSchema) {
		if _, exists := structs[structName]; !exists {
			t.Errorf("apiStructsWithNoSchema exempts api.%s, which src/core/api no longer "+
				"declares; delete the entry", structName)
			continue
		}
		if schema, paired := pairedSchema[structName]; paired {
			t.Errorf("apiStructsWithNoSchema exempts api.%s, but the %s schema now pairs with "+
				"it; delete the entry so its properties are checked", structName, schema)
		}
	}
	for _, schema := range sortedKeys(schemaStructNames) {
		structName := schemaStructNames[schema]
		if _, exists := schemas[schema]; !exists {
			t.Errorf("schemaStructNames pairs %s with api.%s, but openapi.yaml defines no such "+
				"schema", schema, structName)
		}
		if _, exists := structs[structName]; !exists {
			t.Errorf("schemaStructNames pairs %s with api.%s, but src/core/api declares no such "+
				"struct", schema, structName)
		}
		if _, sameName := structs[schema]; sameName {
			t.Errorf("schemaStructNames pairs %s with api.%s, but api.%s also exists, so which "+
				"one the schema describes is a guess", schema, structName, schema)
		}
	}

	// The floor. A pairing that quietly stopped matching would make every loop above run over
	// nothing and the failure would look like a pass.
	if len(pairedStruct) < 100 {
		t.Errorf("paired only %d schemas with a struct; the name matching is no longer working",
			len(pairedStruct))
	}
}

// structFields reads one Go package directory and returns, per struct, the JSON names it
// marshals. src/core/api is the only package it is called for: since #350 that package is the
// whole of what reaches this API's wire.
//
// Every struct type declaration is read, not only those carrying json tags, so a struct that
// has none is visible to the pairing above rather than silently absent from it.
//
// Embedding is flattened transitively: an embedded struct's fields marshal as though declared
// on the outer one, which is the Go side of the spec's allOf.
//
// go test runs with the package directory as the working directory, so callers pass a path
// relative to src/authserver/internal/server, and a floor: the smallest number of struct
// declarations the package can honestly contain. A parse that quietly stopped matching would
// return nothing, every loop above would run over it, and the failure would look like a pass.
// goField is one marshalled field of a Go struct. The name it takes on the wire is the map key;
// what is recorded here is the one further fact the contract turns on, whether encoding/json may
// leave the field out. A field WITHOUT omitempty is written on every response, whatever its value.
type goField struct {
	omitempty bool
}

func structFields(t *testing.T, dir string, floor int) map[string]map[string]goField {
	t.Helper()

	sources, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("globbing %s: %v", dir, err)
	}

	own := map[string]map[string]goField{}
	embeds := map[string][]string{}
	for _, path := range sources {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, pErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if pErr != nil {
			t.Fatalf("parsing %s: %v", path, pErr)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				ts, isType := spec.(*ast.TypeSpec)
				if !isType {
					continue
				}
				st, isStruct := ts.Type.(*ast.StructType)
				if !isStruct {
					continue
				}
				fields := map[string]goField{}
				for _, f := range st.Fields.List {
					if len(f.Names) == 0 {
						// Embedded. Recorded by name and resolved below; a qualified
						// embed from another package would not be a core/api struct and
						// is not one this package has.
						if id, isIdent := f.Type.(*ast.Ident); isIdent {
							embeds[ts.Name.Name] = append(embeds[ts.Name.Name], id.Name)
						}
						continue
					}
					if name, omitempty, marshalled := jsonFieldName(f); marshalled {
						fields[name] = goField{omitempty: omitempty}
					}
				}
				own[ts.Name.Name] = fields
			}
		}
	}

	// Cycles are impossible in a Go struct graph, so the walk needs no visited set.
	var flatten func(string, map[string]goField)
	flatten = func(name string, into map[string]goField) {
		for field, detail := range own[name] {
			into[field] = detail
		}
		for _, embedded := range embeds[name] {
			flatten(embedded, into)
		}
	}
	out := map[string]map[string]goField{}
	for name := range own {
		flat := map[string]goField{}
		flatten(name, flat)
		out[name] = flat
	}

	if len(out) < floor {
		t.Fatalf("read only %d structs out of %s, fewer than the %d this package must have; "+
			"the parse is no longer matching it", len(out), dir, floor)
	}
	return out
}

var jsonTagValue = regexp.MustCompile(`json:"([^"]*)"`)

// jsonFieldName reports the name a field marshals under, following encoding/json's own rules:
// the tag's name part wins, "-" means the field is skipped, and an empty name or an absent tag
// falls back to the Go field name. An unexported field never marshals whatever its tag says.
func jsonFieldName(f *ast.Field) (name string, omitempty bool, marshalled bool) {
	goName := f.Names[0].Name
	if !ast.IsExported(goName) {
		return "", false, false
	}
	if f.Tag == nil {
		return goName, false, true
	}
	m := jsonTagValue.FindStringSubmatch(f.Tag.Value)
	if m == nil {
		return goName, false, true
	}
	tagged, opts, hasOptions := strings.Cut(m[1], ",")
	if tagged == "-" && !hasOptions {
		return "", false, false
	}
	for _, opt := range strings.Split(opts, ",") {
		if opt == "omitempty" {
			omitempty = true
		}
	}
	if tagged == "" {
		return goName, omitempty, true
	}
	return tagged, omitempty, true
}

// specSchemaProperties reads the embedded bytes, as every other test here does, and returns
// the properties each component schema exposes with allOf and $ref resolved.
func specSchemaProperties(t *testing.T) map[string]map[string]bool {
	t.Helper()

	var doc struct {
		Components struct {
			Schemas map[string]yaml.Node `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(web.OpenAPISpec(), &doc); err != nil {
		t.Fatalf("parsing the embedded openapi.yaml: %v", err)
	}

	out := map[string]map[string]bool{}
	for name := range doc.Components.Schemas {
		out[name] = resolveSchemaProperties(t, doc.Components.Schemas, name, map[string]bool{})
	}

	if len(out) < 100 {
		t.Fatalf("read only %d component schemas out of the embedded openapi.yaml; the parse "+
			"is no longer matching the document's shape", len(out))
	}
	return out
}

// resolveSchemaProperties collects one schema's properties, descending through allOf members
// and $ref targets so an inherited property counts as documented.
//
// oneOf and anyOf are refused rather than unioned. A property set has no single meaning across
// alternatives, so answering at all would be answering wrongly; the document uses neither
// today, and the first one somebody writes should fail here and be thought about.
func resolveSchemaProperties(t *testing.T, schemas map[string]yaml.Node, name string, seen map[string]bool) map[string]bool {
	t.Helper()

	out := map[string]bool{}
	if seen[name] {
		return out
	}
	seen[name] = true
	node, defined := schemas[name]
	if !defined {
		return out
	}

	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil || n.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i].Value, n.Content[i+1]
			switch key {
			case "properties":
				if val.Kind != yaml.MappingNode {
					continue
				}
				for j := 0; j+1 < len(val.Content); j += 2 {
					out[val.Content[j].Value] = true
				}
			case "allOf":
				for _, member := range val.Content {
					walk(member)
				}
			case "oneOf", "anyOf":
				t.Errorf("schema %s uses %s, which this check does not model: a property set "+
					"has no single meaning across alternatives", name, key)
			case "$ref":
				idx := strings.LastIndex(val.Value, "/")
				if idx < 0 {
					continue // TestOpenAPI_EveryRefResolves owns malformed references
				}
				for prop := range resolveSchemaProperties(t, schemas, val.Value[idx+1:], seen) {
					out[prop] = true
				}
			}
		}
	}
	walk(&node)
	return out
}

// sortedKeys makes every failure above deterministic, so a run that fails twice fails
// identically and a diff of two runs is about the code rather than about map ordering.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestOpenAPI_ResponseRequirednessMatchesOmitempty holds the OTHER half of a schema's contract.
// The test above owns which properties exist; this one owns which of them a caller may be told
// to expect.
//
// A property absent from a schema's `required` array is optional, and a generated client models
// an optional field as nullable, as an Option, or as a key it has to test for before reading. So
// leaving `required` off a response says "the server may omit any of these", and encoding/json
// settles whether that is true: a struct field WITHOUT omitempty is written on every response
// whatever its value, and one WITH omitempty is dropped when it is the zero value. 292 properties
// across 73 response schemas were always emitted and declared optional when this was first
// measured, and deleting the document's one correct entry, ErrorResponse.error_description, left
// the whole suite green, so requiredness was not merely wrong, it was unguarded (#245, final
// review round 2 finding 3).
//
// Both directions, because each catches a different lie. A missing entry under-declares, which is
// the defect above. A surplus entry over-declares: it promises a field the server really does
// omit, and a strict generated client then fails to decode a response that is perfectly valid.
//
// RESPONSES ONLY, and the scope is read off the document rather than off the name. `required` on
// a request schema means something else entirely, "the caller must send this", which is answered
// by the handler's validation and not by a struct tag. So a schema reached only through a
// requestBody is not this test's subject. A schema reached both ways would have to satisfy two
// different meanings at once, and there is none today; if one appears, this test names it rather
// than guessing which meaning was intended.
//
// A schema no Go type declares carries its expected set by hand in untypedResponseRequired below,
// exactly, because there is no tag for this test to read.

// untypedResponseRequired is the expected `required` set for each response schema that no Go type
// in core/api declares, so those are held to the same standard as the rest rather than skipped.
// Exact: the schema's array must equal this set, so both a deletion and an addition fail.
//
// Empty since #475, which also holds it exact below in the shape schemasWithNoAPIStruct and
// publishedRequestEnums already hold their exemptions. NullTime was the last entry: f9d27d14
// deleted its schema from openapi.yaml, and the entry left with this check.
var untypedResponseRequired = map[string][]string{}

func TestOpenAPI_ResponseRequirednessMatchesOmitempty(t *testing.T) {
	doc := specDocument(t)
	responseOnly, requestOnly, both := schemaReachability(t, doc)

	if len(responseOnly) < 50 {
		t.Fatalf("only %d schemas reachable from a response; the paths parse is no longer "+
			"matching the document's shape", len(responseOnly))
	}
	for _, name := range sortedKeys(both) {
		t.Errorf("schema %s is reached from both a response and a request body, so its "+
			"required array would have to mean two different things at once: add it to this "+
			"test deliberately rather than letting it be checked as a response", name)
	}
	_ = requestOnly // named for the reader: request schemas are not this test's subject

	structs := structFields(t, filepath.Join("..", "..", "..", "core", "api"), 100)

	for _, schema := range sortedKeys(responseOnly) {
		required := resolveSchemaRequired(t, doc.Components.Schemas, schema, map[string]bool{})

		// The hand-written ones first, checked exactly and then done with.
		if expected, untyped := untypedResponseRequired[schema]; untyped {
			want := map[string]bool{}
			for _, p := range expected {
				want[p] = true
			}
			for _, p := range expected {
				if !required[p] {
					t.Errorf("the %s schema does not require %q, which its handler writes on "+
						"every response: a generated client is told a field it always receives "+
						"may be absent", schema, p)
				}
			}
			for _, p := range sortedKeys(required) {
				if !want[p] {
					t.Errorf("the %s schema requires %q, which its handler writes only "+
						"conditionally: a strict generated client would fail to decode a valid "+
						"response", schema, p)
				}
			}
			continue
		}

		// Everything else is paired to a Go type the same way the test above pairs it.
		var fields map[string]goField
		var source string
		structName := schema
		if alias, aliased := schemaStructNames[schema]; aliased {
			structName = alias
		}
		if f, exists := structs[structName]; exists {
			fields, source = f, "api."+structName
		}
		if fields == nil {
			t.Errorf("response schema %s is paired to no Go type and has no entry in "+
				"untypedResponseRequired, so nothing establishes what it may omit", schema)
			continue
		}

		for _, wire := range sortedKeys(fields) {
			switch {
			case fields[wire].omitempty && required[wire]:
				t.Errorf("the %s schema requires %q, but %s tags it omitempty, so the server "+
					"drops it when it is the zero value: a strict generated client would fail "+
					"to decode a valid response", schema, wire, source)
			case !fields[wire].omitempty && !required[wire]:
				t.Errorf("the %s schema does not require %q, but %s emits it on every "+
					"response: a generated client is told a field it always receives may be "+
					"absent", schema, wire, source)
			}
		}
	}

	// The map is exact, in the shape unrecordedRequestEnums keeps publishedRequestEnums: an
	// entry that has stopped being a gap fails here rather than sitting on as a stale
	// allowance. A schema no response reaches, or one a core/api type now pairs with, makes
	// the entry dead either way, because the loop above consults the map before the pairing.
	reportStaleUntypedResponseRequired(t, untypedResponseRequired, responseOnly, structs,
		schemaStructNames)
}

// reportStaleUntypedResponseRequired is the reporting half of that check: one failure per entry
// staleUntypedResponseRequired finds dead. It takes a guard.Reporter so its rule test can drive
// it through guard.Run against the real document, since the map is empty and the run above
// reports nothing.
func reportStaleUntypedResponseRequired(r guard.Reporter, entries map[string][]string,
	responseOnly map[string]bool, structs map[string]map[string]goField, aliases map[string]string) {

	r.Helper()
	unreached, paired := staleUntypedResponseRequired(entries, responseOnly, structs, aliases)
	for _, schema := range unreached {
		r.Errorf("untypedResponseRequired holds %s, which no response reaches; delete the entry",
			schema)
	}
	for _, schema := range paired {
		r.Errorf("untypedResponseRequired holds %s, which a core/api type now pairs with; "+
			"delete the entry so the omitempty tags this test reads are what holds the schema",
			schema)
	}
}

// specDocument parses the embedded spec once into the shape the reachability walk needs.
func specDocument(t *testing.T) *openAPIDocument {
	t.Helper()
	var doc openAPIDocument
	if err := yaml.Unmarshal(web.OpenAPISpec(), &doc); err != nil {
		t.Fatalf("parsing the embedded openapi.yaml: %v", err)
	}
	return &doc
}

type openAPIDocument struct {
	Paths      map[string]map[string]yaml.Node `yaml:"paths"`
	Components struct {
		Schemas   map[string]yaml.Node `yaml:"schemas"`
		Responses map[string]yaml.Node `yaml:"responses"`
	} `yaml:"components"`
}

// schemaReachability splits the component schemas by how an operation can reach them: through a
// response, through a request body, or both. Each root set is closed over the schemas those
// schemas reference, so a nested shape inherits the position of whatever refers to it.
func schemaReachability(t *testing.T, doc *openAPIDocument) (responseOnly, requestOnly, both map[string]bool) {
	t.Helper()

	responseRoots, requestRoots := map[string]bool{}, map[string]bool{}
	for _, methods := range doc.Paths {
		for method, op := range methods {
			if method == "parameters" {
				continue // a path-level parameter list, not an operation
			}
			node := op
			collectSchemaRefsUnder(&node, "responses", responseRoots)
			collectSchemaRefsUnder(&node, "requestBody", requestRoots)
		}
	}
	// A shared component response (Unauthorized, Forbidden, ...) is reached by name, so its own
	// refs have to be followed too or ErrorResponse would look unreachable.
	for _, node := range doc.Components.Responses {
		n := node
		collectSchemaRefs(&n, responseRoots)
	}

	fromResponse := closeOverSchemaRefs(doc.Components.Schemas, responseRoots)
	fromRequest := closeOverSchemaRefs(doc.Components.Schemas, requestRoots)

	responseOnly, requestOnly, both = map[string]bool{}, map[string]bool{}, map[string]bool{}
	for name := range doc.Components.Schemas {
		switch {
		case fromResponse[name] && fromRequest[name]:
			both[name] = true
		case fromResponse[name]:
			responseOnly[name] = true
		case fromRequest[name]:
			requestOnly[name] = true
		}
	}
	return responseOnly, requestOnly, both
}

// collectSchemaRefsUnder gathers every component-schema $ref beneath one key of an operation.
func collectSchemaRefsUnder(op *yaml.Node, key string, into map[string]bool) {
	if op == nil || op.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(op.Content); i += 2 {
		if op.Content[i].Value == key {
			collectSchemaRefs(op.Content[i+1], into)
		}
	}
}

func collectSchemaRefs(n *yaml.Node, into map[string]bool) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "$ref" {
				if name, ok := componentSchemaName(n.Content[i+1].Value); ok {
					into[name] = true
				}
			}
			collectSchemaRefs(n.Content[i+1], into)
		}
		return
	}
	for _, c := range n.Content {
		collectSchemaRefs(c, into)
	}
}

func componentSchemaName(ref string) (string, bool) {
	const prefix = "#/components/schemas/"
	if strings.HasPrefix(ref, prefix) {
		return strings.TrimPrefix(ref, prefix), true
	}
	return "", false
}

func closeOverSchemaRefs(schemas map[string]yaml.Node, roots map[string]bool) map[string]bool {
	out := map[string]bool{}
	var visit func(string)
	visit = func(name string) {
		if out[name] {
			return
		}
		node, exists := schemas[name]
		if !exists {
			return // TestOpenAPI_EveryRefResolves owns dangling references
		}
		out[name] = true
		refs := map[string]bool{}
		collectSchemaRefs(&node, refs)
		for r := range refs {
			visit(r)
		}
	}
	for r := range roots {
		visit(r)
	}
	return out
}

// resolveSchemaRequired is resolveSchemaProperties for the required array: every property the
// schema requires, following allOf and $ref so a requirement inherited from a composed schema
// counts as declared.
func resolveSchemaRequired(t *testing.T, schemas map[string]yaml.Node, name string, seen map[string]bool) map[string]bool {
	t.Helper()

	out := map[string]bool{}
	if seen[name] {
		return out
	}
	seen[name] = true
	node, defined := schemas[name]
	if !defined {
		return out
	}

	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil || n.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i].Value, n.Content[i+1]
			switch key {
			case "required":
				if val.Kind != yaml.SequenceNode {
					continue // a property-level `required: true`, not a schema's array
				}
				for _, item := range val.Content {
					out[item.Value] = true
				}
			case "allOf":
				for _, member := range val.Content {
					walk(member)
				}
			case "$ref":
				ref, ok := componentSchemaName(val.Value)
				if !ok {
					continue
				}
				for prop := range resolveSchemaRequired(t, schemas, ref, seen) {
					out[prop] = true
				}
			}
		}
	}
	walk(&node)
	return out
}

// TestOpenAPI_APIFiveHundredsAreTheJSONEnvelope holds every 500 under /api/v1 to the one shape
// the API surface answers since #279 decision 7: the shared InternalServerError response, a JSON
// envelope naming INTERNAL_SERVER_ERROR and the request id.
//
// Three operations documented the opposite after decision 7 landed. getUserConsents and
// deleteUserConsent declared a text/html body, and deleteAccountProfilePicture declared two
// bodies, JSON on one branch and the HTML error page on another, because their handlers really
// did render error.html on those branches. The handlers were fixed on the pull request review's
// finding, and this is what keeps the document from telling a generated client the old story
// again: a status the spec declares as text/html on an endpoint that answers JSON is a client
// that parses a page as an envelope.
//
// One operation writes its 500 in place on purpose. rotateKeys answers KEY_SET_INCOMPLETE as
// well as INTERNAL_SERVER_ERROR, and a caller acts on the difference, so its entry names both
// codes; it is held to the JSON content type rather than to the $ref. The public /client/logo
// page is not under /api/v1 and is outside this rule: its handler renders the HTML page and its
// entry says so.
func TestOpenAPI_APIFiveHundredsAreTheJSONEnvelope(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]struct {
			OperationId string `yaml:"operationId"`
			Responses   map[string]struct {
				Ref     string               `yaml:"$ref"`
				Content map[string]yaml.Node `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(web.OpenAPISpec(), &doc); err != nil {
		t.Fatalf("parsing the embedded openapi.yaml: %v", err)
	}

	const (
		shared  = "#/components/responses/InternalServerError"
		inPlace = "rotateSettingsKeys"
	)

	checked := 0
	for path, item := range doc.Paths {
		if !strings.HasPrefix(path, "/api/v1/") {
			continue
		}
		for verb, op := range item {
			if !specVerbs[verb] {
				continue
			}
			response, declared := op.Responses["500"]
			if !declared {
				continue
			}
			checked++
			if response.Ref == shared {
				continue
			}
			if op.OperationId == inPlace {
				if _, ok := response.Content["application/json"]; !ok || len(response.Content) != 1 {
					t.Errorf("%s %s '500' (%s) is the one in-place API 500 and must declare "+
						"application/json alone", strings.ToUpper(verb), path, op.OperationId)
				}
				continue
			}
			t.Errorf("%s %s '500' (%s) is not $ref: '%s'. Every 500 on the API surface is "+
				"writeInternalServerError's JSON envelope since #279 decision 7, and "+
				"TestAPIHandlers_DoNotRenderPages in apihandlers keeps the handlers to it; the "+
				"document has to say the same", strings.ToUpper(verb), path, op.OperationId, shared)
		}
	}

	if checked < 80 {
		t.Errorf("checked only %d API 500 entries; the walk is no longer reaching the "+
			"document's operations", checked)
	}
}

// publishedRequestEnums records every closed enum this document publishes on a request-reachable
// schema, against what makes it honest. Nothing here can execute a handler, so enforcement cannot
// be derived: the entry is the claim, written by whoever published the enum, and the check below
// reports a site that arrives without one.
//
// An entry is therefore not a blessing. It says either "the handler refuses everything else, here"
// or "it does not, and this is a known gap", and which of the two it says is the whole content of
// the line. A gap left recorded is a burn-down item; an enforced site left recorded is what stops
// the next person having to re-derive that it is enforced.
var publishedRequestEnums = map[string]string{
	"CreateBrandRequest.appearance": "enforced: handler_api_brands.go refuses any appearance but " +
		"[auto, light, dark], an absent one included, with 400 before writing. Covered by " +
		"TestBrandCreate_Refusals' appearance cases. Published in #810",
	"UpdateBrandRequest.appearance": "enforced: handler_api_brands.go refuses any appearance but " +
		"[auto, light, dark], an absent one included, with 400 before writing. Covered by " +
		"TestBrandUpdate_Refusals' appearance cases. Published in #810",
	"CreateBrandRequest.corners": "enforced: handler_api_brands.go refuses any corners but " +
		"[square, rounded, pill], an absent one included, with 400 before writing. Covered by " +
		"TestBrandCreate_Refusals' corners cases. Published in #813",
	"CreateBrandRequest.font": "enforced: handler_api_brands.go refuses any font but " +
		"[system-ui, humanist, geometric, serif, neo-grotesque, rounded, uploaded], an absent one included, with 400 before writing. Covered by " +
		"TestBrandCreate_Refusals' font cases. Published in #813",
	"CreateBrandRequest.backgroundFit": "enforced: handler_api_brands.go refuses any background fit but " +
		"[cover, contain, tile], an absent one included, with 400 before writing. Covered by " +
		"TestBrandCreate_Refusals' background fit cases. Published in #813",
	"UpdateBrandRequest.corners": "enforced: handler_api_brands.go refuses any corners but " +
		"[square, rounded, pill], an absent one included, with 400 before writing. Covered by " +
		"TestBrandUpdate_Refusals' corners cases. Published in #813",
	"UpdateBrandRequest.font": "enforced: handler_api_brands.go refuses any font but " +
		"[system-ui, humanist, geometric, serif, neo-grotesque, rounded, uploaded], an absent one included, with 400 before writing. Covered by " +
		"TestBrandUpdate_Refusals' font cases. Published in #813",
	"UpdateBrandRequest.backgroundFit": "enforced: handler_api_brands.go refuses any background fit but " +
		"[cover, contain, tile], an absent one included, with 400 before writing. Covered by " +
		"TestBrandUpdate_Refusals' background fit cases. Published in #813",
	"BrandPalette.mode": "enforced: brand_palette.go refuses any palette mode but [basic, advanced], " +
		"an absent one included, with 400 before writing. Covered by TestBrandPalette_CreateRefusals' and " +
		"TestBrandPalette_UpdateRefusals' mode cases. Published in #815",
	"CreateLegalDocumentRequest.kind": "enforced: handler_api_legal_documents.go refuses any kind but " +
		"[must_accept, for_information], an absent one included, with 400 before writing. Covered by " +
		"TestLegalDocumentCreate_Refusals' unknown and missing kind cases. Published in #622",
	"CreateUserRequest.setPasswordType": "enforced: handler_api_users_crud.go refuses a present " +
		"value outside [now, email] with 400 before either arm is chosen, and treats absent as " +
		"\"now\" per the schema's default. Covered by " +
		"TestHandleUserCreatePost_SetPasswordTypeMatrix. Was the one known gap on this list " +
		"until #350: the handler compared against the two values and refused nothing else, so a " +
		"third value created an account with no password and no setup email",
	"UpdateClientTokensRequest.includeOpenIDConnectClaimsInAccessToken": "enforced: " +
		"handler_api_clients.go parses the trimmed value through record.ThreeStateSettingFromString " +
		"and refuses anything outside [on, off, default] with 400 before writing. Covered by " +
		"TestAPIClientTokensPut_ValidationErrors' invalid_three_state_access case. Published in #562",
	"UpdateClientTokensRequest.includeOpenIDConnectClaimsInIdToken": "enforced: " +
		"handler_api_clients.go parses the trimmed value through record.ThreeStateSettingFromString " +
		"and refuses anything outside [on, off, default] with 400 before writing. Covered by " +
		"TestAPIClientTokensPut_ValidationErrors' invalid_three_state_id case. Published in #562",
	"UpdateLegalDocumentAppsRequest.appliesTo": "enforced: handler_api_legal_document_apps.go refuses any " +
		"value but [all_apps, selected_apps], an absent one included, with 400 before writing. Covered by " +
		"TestLegalDocumentApps_Refusals' unknown and missing applies to cases. Published in #622",
	"UpdateSettingsGeneralRequest.passwordPolicy": "enforced: handler_api_settings_general.go parses " +
		"the trimmed value through record.PasswordPolicyFromString and refuses anything outside " +
		"[none, low, medium, high, nist] with 400 before saving. Covered by " +
		"TestAPISettingsGeneralPut_ValidationErrors' invalid-policy request. Published in #550, when nist " +
		"became the fifth",
	"UpdateSettingsSessionsRequest.keepSignedIn": "enforced: handler_api_settings_sessions.go refuses " +
		"any value but [always, ask, never], an absent or empty one included, with 400 before saving. " +
		"Covered by TestSettingsSessionsPut_RefusesAMissingOrUnknownKeepSignedIn and " +
		"TestAPISettingsSessionsPut_KeepSignedInIsRequiredAndOneOfThreeModes. Published in #743",
}

// A closed enum on a request property is a promise that the server refuses everything outside it,
// and a generated or validating client acts on that promise by rejecting the request before it is
// sent. So the enum may only be published where the handler really does refuse: a field the server
// reads permissively, giving every unlisted value a documented fallback, is narrower on paper than
// at the endpoint, and the caller is told to withhold a request the server would have answered.
//
// That is what the logout responseMode was when #350 first published it: enum [form_post, redirect]
// directly above a description reading "any other value, absent included, answers a redirect URL",
// with an integration case driving "", "form-post", "FORM_POST" and "fragment" through the endpoint
// to a 200 and the redirect shape. Exactly one value is significant there,
// api.AccountLogoutResponseModeFormPost, which is a fallback rather than a two-value set and is now
// documented as one.
//
// Response properties are deliberately not in this: an enum there is a promise the server keeps
// rather than a restriction on what it accepts, which is why AccountLogoutFormPostResponse.method
// may say POST and should.
func TestOpenAPI_RequestSchemasPublishNoUnenforcedEnum(t *testing.T) {
	doc := specDocument(t)
	_, requestOnly, both := schemaReachability(t, doc)

	reachable := map[string]bool{}
	for name := range requestOnly {
		reachable[name] = true
	}
	for name := range both {
		reachable[name] = true
	}
	if len(reachable) < 20 {
		t.Fatalf("only %d schemas reachable from a request body; the paths parse is no longer "+
			"matching the document's shape", len(reachable))
	}

	unrecorded, stale := unrecordedRequestEnums(doc.Components.Schemas, reachable,
		publishedRequestEnums)

	for _, site := range unrecorded {
		t.Errorf("the contract publishes a closed enum at %s, and publishedRequestEnums does not "+
			"say what enforces it. A validating client acts on that enum by refusing to send the "+
			"request at all, so publish one only where the server really does reject every other "+
			"value, and record here where it does; where a single value is significant and every "+
			"other one falls back, describe the fallback and leave the type open (#350)", site)
	}
	for _, site := range stale {
		t.Errorf("publishedRequestEnums records %s, which publishes no closed enum "+
			"on any request-reachable schema any more. Delete the entry: left standing it exempts "+
			"whatever is published there next, which is the regression the map exists to report "+
			"(#350)", site)
	}
}

// unrecordedRequestEnums is the decision behind that check, as a pure function so its boundary can
// be driven directly. It returns the request-reachable sites publishing a closed enum that the
// record does not carry, and the entries of that record no such site matched.
//
// The second half is what keeps the map a record rather than a blanket, and it is the shape
// schemasWithNoAPIStruct and apiStructsWithNoSchema already use above: an exemption outlives the
// defect it describes silently, so the entry left behind goes on exempting a property nobody
// weighed. Both halves come back sorted, because a map range would reorder the failures between
// runs.
func unrecordedRequestEnums(schemas map[string]yaml.Node, reachable map[string]bool,
	recorded map[string]string) (unrecorded, stale []string) {

	matched := map[string]bool{}
	for _, name := range sortedKeys(reachable) {
		schema, declared := schemas[name]
		if !declared {
			continue // reachable by name from a path, but the document defines no such schema
		}
		for _, site := range sortedKeys(enumSites(name, schema)) {
			if _, exempt := recorded[site]; exempt {
				matched[site] = true
				continue
			}
			unrecorded = append(unrecorded, site)
		}
	}
	for _, site := range sortedKeys(recorded) {
		if !matched[site] {
			stale = append(stale, site)
		}
	}
	return unrecorded, stale
}

// enumSites returns the places inside one schema that constrain a value to a closed set, each
// spelled the way it is reported and recorded: the schema's own name where the schema is itself an
// enum, and "<schema>.<property>" for a property of it.
//
// The schema's own name is in there because of how reachability works: a $ref is never followed
// from inside a schema, since schemaReachability closes over references and the target is reached
// as itself, so a property written as a $ref to a scalar enum schema is only ever seen when that
// target is visited. Reporting a root enum is what makes "reached as itself" true rather than a
// place the walk stops.
func enumSites(name string, node yaml.Node) map[string]bool {
	out := map[string]bool{}
	if declaresEnum(&node) {
		out[name] = true
	}
	for property := range enumProperties(node) {
		out[name+"."+property] = true
	}
	return out
}

// enumProperties returns the properties one schema constrains with an enum, descending inline
// allOf members. A $ref is not followed, for the reason enumSites gives.
func enumProperties(node yaml.Node) map[string]bool {
	out := map[string]bool{}

	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil || n.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i].Value, n.Content[i+1]
			switch key {
			case "properties":
				if val.Kind != yaml.MappingNode {
					continue
				}
				for j := 0; j+1 < len(val.Content); j += 2 {
					if declaresEnum(val.Content[j+1]) {
						out[val.Content[j].Value] = true
					}
				}
			case "allOf":
				for _, member := range val.Content {
					walk(member)
				}
			}
		}
	}
	walk(&node)
	return out
}

// declaresEnum reports whether one schema constrains its value to a closed set: on the node itself,
// on the items of an array of them, or inside any of the three composition keywords.
//
// The composition arms are not decoration. "enum" written directly and
// "allOf: [{type: string, enum: [...]}]" are the same published contract, and a generated client
// refuses the unlisted value on both, so a walk that reads only the first reports the spelling
// rather than the promise -- and the check's whole subject is the promise (#350).
func declaresEnum(n *yaml.Node) bool {
	if n == nil || n.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		switch n.Content[i].Value {
		case "enum":
			return true
		case "items":
			if declaresEnum(n.Content[i+1]) {
				return true
			}
		case "allOf", "oneOf", "anyOf":
			for _, member := range n.Content[i+1].Content {
				if declaresEnum(member) {
					return true
				}
			}
		}
	}
	return false
}

// schemaNode parses one inline schema the way doc.Components.Schemas holds it: the mapping itself,
// not the document wrapping it, so a fixture and a real component schema reach the walks alike.
func schemaNode(t *testing.T, y string) yaml.Node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(y), &doc); err != nil {
		t.Fatalf("parsing the fixture: %v", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		t.Fatalf("the fixture is not one YAML document: kind %d, %d children", doc.Kind,
			len(doc.Content))
	}
	return *doc.Content[0]
}

// The boundary of declaresEnum, stated as cases rather than left to the switch. Every form here is
// one a hand-written openapi.yaml can carry, and the four composition rows are the ones that made
// the first version of this guard report the spelling instead of the promise: allOf, oneOf and
// anyOf around the same closed set are the same contract to a generated client.
func TestDeclaresEnum_TheFormsAClosedSetCanTake(t *testing.T) {
	cases := []struct {
		name   string
		schema string
		want   bool
	}{
		{"a direct enum", "type: string\nenum: [a, b]\n", true},
		{"an enum on an array's items", "type: array\nitems:\n  type: string\n  enum: [a, b]\n", true},
		{"an enum inside allOf", "allOf:\n  - type: string\n    enum: [a, b]\n", true},
		{"an enum inside oneOf", "oneOf:\n  - type: string\n    enum: [a, b]\n", true},
		{"an enum inside anyOf", "anyOf:\n  - type: string\n    enum: [a, b]\n", true},
		{"an enum nested two deep", "allOf:\n  - oneOf:\n      - type: string\n        enum: [a]\n", true},
		{"an enum beneath an array inside allOf",
			"allOf:\n  - type: array\n    items:\n      enum: [a]\n", true},
		{"an open string", "type: string\ndescription: anything\n", false},
		{"an object whose property has one", "type: object\nproperties:\n  mode:\n    enum: [a]\n", false},
		{"a composition carrying no enum",
			"allOf:\n  - $ref: '#/components/schemas/Other'\n  - type: object\n    properties:\n      x:\n        type: boolean\n", false},
		{"a bare $ref", "$ref: '#/components/schemas/Other'\n", false},
		{"a scalar rather than a mapping", "just-a-string\n", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			node := schemaNode(t, c.schema)
			if got := declaresEnum(&node); got != c.want {
				t.Errorf("declaresEnum(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
	if declaresEnum(nil) {
		t.Errorf("declaresEnum(nil) = true, want false")
	}
}

// enumSites is where a schema's own enum becomes reportable. The root row is the one that matters:
// a property written as a $ref to a scalar enum schema is never read through the property, only
// when that schema is visited as itself, so a walk finding nothing at the root leaves the form
// unreachable from either direction.
func TestEnumSites_NamesTheSchemaAndItsProperties(t *testing.T) {
	cases := []struct {
		name   string
		schema string
		want   []string
	}{
		{"a scalar enum schema", "type: string\nenum: [now, email]\n", []string{"Mode"}},
		{"a property with one", "type: object\nproperties:\n  mode:\n    enum: [a]\n  other:\n    type: string\n",
			[]string{"Mode.mode"}},
		{"a property composing one", "type: object\nproperties:\n  mode:\n    allOf:\n      - type: string\n        enum: [a]\n",
			[]string{"Mode.mode"}},
		{"a property inside a schema-level allOf",
			"allOf:\n  - $ref: '#/components/schemas/Other'\n  - type: object\n    properties:\n      mode:\n        enum: [a]\n",
			[]string{"Mode.mode"}},
		{"both at once", "enum: [x]\nproperties:\n  mode:\n    enum: [a]\n", []string{"Mode", "Mode.mode"}},
		{"neither", "type: object\nproperties:\n  mode:\n    type: string\n", nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sortedKeys(enumSites("Mode", schemaNode(t, c.schema)))
			if len(got) != len(c.want) {
				t.Fatalf("enumSites(%s) = %v, want %v", c.name, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("enumSites(%s)[%d] = %q, want %q", c.name, i, got[i], c.want[i])
				}
			}
		})
	}
}

// The two halves of the decision, including the stale one. An exemption that outlives its defect
// is the failure this covers: left standing it goes on exempting whatever is published at that
// site next, which is exactly the regression the map exists to report.
func TestUnrecordedRequestEnums_ReportsUnrecordedSitesAndStaleEntries(t *testing.T) {
	schemas := map[string]yaml.Node{
		"CreateUserRequest": schemaNode(t, "type: object\nproperties:\n  setPasswordType:\n    enum: [now, email]\n"),
		"LogoutRequest":     schemaNode(t, "type: object\nproperties:\n  responseMode:\n    type: string\n"),
		"FormPostResponse":  schemaNode(t, "type: object\nproperties:\n  method:\n    enum: [POST]\n"),
	}
	reachable := map[string]bool{"CreateUserRequest": true, "LogoutRequest": true}

	t.Run("a recorded site is exempt and not stale", func(t *testing.T) {
		unrecorded, stale := unrecordedRequestEnums(schemas, reachable,
			map[string]string{"CreateUserRequest.setPasswordType": "why"})
		if len(unrecorded) != 0 {
			t.Errorf("unrecorded = %v, want none: the one enum site is recorded", unrecorded)
		}
		if len(stale) != 0 {
			t.Errorf("stale = %v, want none: the entry matched a live site", stale)
		}
	})

	t.Run("an unrecorded site is reported", func(t *testing.T) {
		unrecorded, _ := unrecordedRequestEnums(schemas, reachable, nil)
		if len(unrecorded) != 1 || unrecorded[0] != "CreateUserRequest.setPasswordType" {
			t.Errorf("unrecorded = %v, want [CreateUserRequest.setPasswordType]", unrecorded)
		}
	})

	t.Run("an entry matching nothing is stale", func(t *testing.T) {
		_, stale := unrecordedRequestEnums(schemas, reachable,
			map[string]string{
				"CreateUserRequest.setPasswordType": "why",
				"LogoutRequest.responseMode":        "the enum this recorded is gone",
			})
		if len(stale) != 1 || stale[0] != "LogoutRequest.responseMode" {
			t.Errorf("stale = %v, want [LogoutRequest.responseMode]", stale)
		}
	})

	t.Run("a response-only schema is neither", func(t *testing.T) {
		unrecorded, stale := unrecordedRequestEnums(schemas, reachable,
			map[string]string{"CreateUserRequest.setPasswordType": "why"})
		for _, site := range append(append([]string{}, unrecorded...), stale...) {
			if strings.HasPrefix(site, "FormPostResponse") {
				t.Errorf("reported %s, which no request body reaches", site)
			}
		}
	})

	t.Run("a schema named by reachability but absent from the document is skipped", func(t *testing.T) {
		unrecorded, stale := unrecordedRequestEnums(schemas,
			map[string]bool{"CreateUserRequest": true, "Vanished": true},
			map[string]string{"CreateUserRequest.setPasswordType": "why"})
		if len(unrecorded) != 0 || len(stale) != 0 {
			t.Errorf("unrecorded = %v, stale = %v, want neither", unrecorded, stale)
		}
	})
}

// staleUntypedResponseRequired is the decision behind that check, as a pure function so its
// boundary can be driven directly, in the shape unrecordedRequestEnums above already uses. It
// returns the entries naming a schema no response reaches, and the entries a core/api type now
// pairs with, directly or through schemaStructNames: either way the hand-written set has
// stopped being what the test reads, so the entry goes. Both halves come back sorted, because
// a map range would reorder the failures between runs.
func staleUntypedResponseRequired(entries map[string][]string, responseOnly map[string]bool,
	structs map[string]map[string]goField, aliases map[string]string) (unreached, paired []string) {

	for _, schema := range sortedKeys(entries) {
		if !responseOnly[schema] {
			unreached = append(unreached, schema)
			continue
		}
		structName, aliased := aliases[schema]
		if !aliased {
			structName = schema
		}
		if _, pairs := structs[structName]; pairs {
			paired = append(paired, schema)
		}
	}
	return unreached, paired
}

// The two failures the decision exists to report, driven at the boundary: an entry naming a
// schema no response reaches, and an entry a core/api type has come to pair with, directly or
// through schemaStructNames. Left standing, either one keeps the hand-written set answering for
// a schema the test no longer reads it for, which is the regression the map exists to prevent.
// The empty map is what the document holds today, and it passes.
func TestStaleUntypedResponseRequired_ReportsDeadEntries(t *testing.T) {
	responseOnly := map[string]bool{"UserResponse": true, "NullTime": true}
	structs := map[string]map[string]goField{
		"UserResponse":      {"Subject": {}},
		"WebOriginResponse": {"Value": {}},
	}
	aliases := map[string]string{"WebOrigin": "WebOriginResponse"}

	t.Run("an empty map passes", func(t *testing.T) {
		unreached, paired := staleUntypedResponseRequired(nil, responseOnly, structs, aliases)
		if len(unreached) != 0 || len(paired) != 0 {
			t.Errorf("unreached = %v, paired = %v, want neither", unreached, paired)
		}
	})

	t.Run("an entry naming a schema no response reaches is reported", func(t *testing.T) {
		// A type of the schema's name, so the pairing would report it too if the decision
		// went on to look for one.
		withVanished := map[string]map[string]goField{"Vanished": {"Time": {}}}
		unreached, paired := staleUntypedResponseRequired(
			map[string][]string{"Vanished": {"Time"}}, responseOnly, withVanished, aliases)
		if len(unreached) != 1 || unreached[0] != "Vanished" {
			t.Errorf("unreached = %v, want [Vanished]", unreached)
		}
		if len(paired) != 0 {
			t.Errorf("paired = %v, want none: an unreached entry is reported once, as unreached", paired)
		}
	})

	t.Run("an entry a type of its own name pairs with is reported", func(t *testing.T) {
		unreached, paired := staleUntypedResponseRequired(
			map[string][]string{"UserResponse": {"subject"}}, responseOnly, structs, aliases)
		if len(unreached) != 0 {
			t.Errorf("unreached = %v, want none: a response reaches the schema", unreached)
		}
		if len(paired) != 1 || paired[0] != "UserResponse" {
			t.Errorf("paired = %v, want [UserResponse]", paired)
		}
	})

	t.Run("an entry an aliased type pairs with is reported", func(t *testing.T) {
		aliasedOnly := map[string]bool{"WebOrigin": true}
		_, paired := staleUntypedResponseRequired(
			map[string][]string{"WebOrigin": {"value"}}, aliasedOnly, structs, aliases)
		if len(paired) != 1 || paired[0] != "WebOrigin" {
			t.Errorf("paired = %v, want [WebOrigin]: schemaStructNames pairs it with WebOriginResponse",
				paired)
		}
	})

	t.Run("an entry a response reaches and no type pairs with is kept", func(t *testing.T) {
		unreached, paired := staleUntypedResponseRequired(
			map[string][]string{"NullTime": {"Time", "Valid"}}, responseOnly, structs, aliases)
		if len(unreached) != 0 || len(paired) != 0 {
			t.Errorf("unreached = %v, paired = %v, want neither: the entry is still read", unreached, paired)
		}
	})
}

// The reporting half, driven through guard.Run over the real document as the main test builds
// it, because the map is empty and that test's run reports nothing: a call site that stopped
// turning a dead entry into a failure would otherwise stay green until an entry was added. The
// two seeds are real: NullTime's schema left openapi.yaml with f9d27d14, and WebOrigin pairs
// with api.WebOriginResponse through schemaStructNames.
func TestReportStaleUntypedResponseRequired_FailsEachDeadEntryOfTheRealDocument(t *testing.T) {
	doc := specDocument(t)
	responseOnly, _, _ := schemaReachability(t, doc)
	structs := structFields(t, filepath.Join("..", "..", "..", "core", "api"), 100)

	report := func(entries map[string][]string) guard.Report {
		return guard.Run(func(r guard.Reporter) {
			reportStaleUntypedResponseRequired(r, entries, responseOnly, structs, schemaStructNames)
		})
	}

	t.Run("an empty map records nothing", func(t *testing.T) {
		if got := report(map[string][]string{}); got.Failed() {
			t.Errorf("an empty map failed: %+v", got)
		}
	})

	t.Run("an entry naming a schema no response reaches is one failure", func(t *testing.T) {
		got := report(map[string][]string{"NullTime": {"Time", "Valid"}})
		want := []string{"untypedResponseRequired holds NullTime, which no response reaches; " +
			"delete the entry"}
		if got.Stopped || !slices.Equal(got.Errors, want) {
			t.Errorf("failures\n%q\nwant\n%q (stopped: %v)", got.Errors, want, got.Stopped)
		}
	})

	t.Run("an entry a core/api type pairs with is one failure", func(t *testing.T) {
		got := report(map[string][]string{"WebOrigin": {"id", "createdAt", "origin", "clientId"}})
		want := []string{"untypedResponseRequired holds WebOrigin, which a core/api type now " +
			"pairs with; delete the entry so the omitempty tags this test reads are what holds " +
			"the schema"}
		if got.Stopped || !slices.Equal(got.Errors, want) {
			t.Errorf("failures\n%q\nwant\n%q (stopped: %v)", got.Errors, want, got.Stopped)
		}
	})
}
