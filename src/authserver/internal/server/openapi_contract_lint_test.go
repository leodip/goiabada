package server

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/web"
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
// missed. No handler in this module does the latter today: writeJSONError is always called
// with an http.Status constant, which TestAPIHandlers_WriteStatusesAsConstants below is
// what keeps true.
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

// routeRegistration is one line of routes.go: what a caller reaches, where it lands, and
// whether a rate limiter sits in front of it.
type routeRegistration struct {
	method      string // lower case, as the spec spells it
	path        string // as written, with routes.go's own parameter names
	key         string // method + path with parameter names erased, the join key with the spec
	handler     string
	rateLimited bool
	// scopeGuarded is true when a scope-checking middleware stands in front of the route, so
	// the route can answer 403 without its handler containing the word. It is read from both
	// places such a guard can be mounted: r.With(...) on the registration itself, which is how
	// the Admin group does it per route, and r.Use(...) at the top of the enclosing r.Route
	// group, which is how the Account group does it once for all of them.
	scopeGuarded bool
	line         int
}

// pathParam erases the name of a path parameter. routes.go and the spec disagree on several
// of them (routes.go says /user-sessions/{id} where the spec says {sessionIdentifier}), and
// that disagreement is invisible on the wire: an OpenAPI path template's parameter names are
// local to the document. Joining on the erased form matches the two by the URL a caller
// actually sends.
var pathParam = regexp.MustCompile(`\{[^}]*\}`)

func routeKey(method, path string) string {
	return method + " " + pathParam.ReplaceAllString(path, "{}")
}

// TestOpenAPI_DeclaresEveryStatusTheHandlersEmit is the forward direction: a status a
// handler can write must appear in the spec. This is the one that matters to a caller,
// because the statuses it catches are the ones a generated client has no branch for.
//
// A status the ROUTE can write counts too, and the reason this test says so is that scanning
// handler bodies alone missed 103 of them. Every Admin and Account operation sits behind a
// scope guard that answers 403 before the handler runs, exactly as every one of them sits
// behind the bearer-token check that answers 401, and the document declared the 401 on all
// 105 and the 403 on two: the two whose handlers write it themselves. Middleware statuses are
// not less part of the contract for being written earlier, and a generated client has no
// branch for one either way (#245, final review finding 2).
func TestOpenAPI_DeclaresEveryStatusTheHandlersEmit(t *testing.T) {
	routes := parseRoutes(t)
	statuses := parseHandlerStatuses(t)
	spec := parseSpec(t)

	for _, r := range routes {
		op, documented := spec[r.key]
		if !documented {
			continue // TestOpenAPI_DescribesEveryAPIRoute owns this case
		}
		emitted, known := statuses[r.handler]
		if !known {
			t.Errorf("routes.go:%d: %s %s lands in %s, which no non-test source under "+
				"internal/handlers declares", r.line, strings.ToUpper(r.method), r.path, r.handler)
			continue
		}
		for _, code := range sortedCodes(emitted) {
			if op.responses[code] {
				continue
			}
			t.Errorf("%s (%s %s) can answer %d, which openapi.yaml does not declare: a "+
				"generated client has no branch for it. Handler: %s",
				op.operationId, strings.ToUpper(r.method), r.path, code, r.handler)
		}

		// The middleware's own status, which no handler body mentions.
		if r.scopeGuarded && !op.responses[403] {
			t.Errorf("%s (%s %s) is behind a scope guard at routes.go:%d, so it can answer "+
				"403 INSUFFICIENT_SCOPE before %s runs, and openapi.yaml does not declare it",
				op.operationId, strings.ToUpper(r.method), r.path, r.line, r.handler)
		}
	}
}

// TestOpenAPI_DeclaresNoStatusTheHandlersCannotEmit is the reverse: a documented failure
// must be one the handler can actually produce, so the spec does not send a caller off
// writing a branch that never runs. Two operations declared a 404 for exactly that reason.
// deleteSettingsKey answers 400 for an id that matches no key, and getResourcePermissions
// never looks its resource up at all, so an unknown id comes back as an empty list.
//
// Only failures are checked, because a success status can be implicit: a handler that calls
// httpHelper.EncodeJson and never touches WriteHeader answers 200 without naming it, so
// absence from the source would not be absence from the wire.
//
// Three failures can come from somewhere other than the handler, and none is merely waved
// through. 401 comes from the bearer-token middleware, which sits on every API route. 429
// comes from the rate limiter, which sits on three. 403 comes from the scope guards, which
// sit on all 105 API routes. The last two are checked in BOTH directions, here and in the
// forward test: declared only where the middleware is in front, and required wherever it is.
//
// 403 is the one that has to stay two-directional rather than becoming a blanket exemption
// like 401's, because an operation outside the API groups has no scope guard, and a 403 on
// one of those would be promising a failure that cannot arrive.
func TestOpenAPI_DeclaresNoStatusTheHandlersCannotEmit(t *testing.T) {
	routes := parseRoutes(t)
	statuses := parseHandlerStatuses(t)
	spec := parseSpec(t)

	for _, r := range routes {
		op, documented := spec[r.key]
		if !documented {
			continue
		}
		emitted := statuses[r.handler]
		for _, code := range sortedCodes(op.responses) {
			if code < 400 || emitted[code] {
				continue
			}
			if code == 401 {
				continue // the bearer-token middleware, not the handler
			}
			if code == 403 {
				if !r.scopeGuarded {
					t.Errorf("%s (%s %s) declares 403, but routes.go:%d puts no scope guard "+
						"in front of it and %s never writes one", op.operationId,
						strings.ToUpper(r.method), r.path, r.line, r.handler)
				}
				continue
			}
			if code == 429 {
				if !r.rateLimited {
					t.Errorf("%s (%s %s) declares 429, but routes.go:%d puts no rate "+
						"limiter in front of it", op.operationId, strings.ToUpper(r.method),
						r.path, r.line)
				}
				continue
			}
			t.Errorf("%s (%s %s) declares %d, which %s never writes: the spec is promising "+
				"a failure that cannot arrive", op.operationId, strings.ToUpper(r.method),
				r.path, code, r.handler)
		}
	}

	// The pair of the 429 rule above. A rate limiter in front of a route that does not
	// declare 429 is the same defect in the other direction: the caller is not told to
	// expect it, and a Retry-After it does not read is the whole point of the status.
	for _, r := range routes {
		op, documented := spec[r.key]
		if !documented || !r.rateLimited {
			continue
		}
		if !op.responses[429] {
			t.Errorf("%s (%s %s) is rate limited at routes.go:%d but does not declare 429",
				op.operationId, strings.ToUpper(r.method), r.path, r.line)
		}
	}
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
func TestOpenAPI_DescribesEveryAPIRoute(t *testing.T) {
	routes := parseRoutes(t)
	spec := parseSpec(t)

	routed := map[string]bool{}
	for _, r := range routes {
		routed[r.key] = true
		if !strings.HasPrefix(r.path, "/api/v1/") {
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
}

// TestAPIHandlers_WriteStatusesAsConstants is what lets the three tests above be lexical.
// Every writeJSONError call passes an http.Status constant, so reading the constants out of
// a handler reads its whole failure surface. A status computed at run time would be
// invisible to the scan and the spec could drift under it unnoticed, which is a hole worth
// closing at the one call site that could open it.
func TestAPIHandlers_WriteStatusesAsConstants(t *testing.T) {
	calls := 0
	forEachHandlerSource(t, func(t *testing.T, path string, fset *token.FileSet, file *ast.File) {
		if filepath.Base(path) == "api_common.go" {
			return // the helper's own signature takes the int; its callers are the subject
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok || name.Name != "writeJSONError" || len(call.Args) != 4 {
				return true
			}
			calls++
			sel, ok := call.Args[3].(*ast.SelectorExpr)
			if !ok {
				t.Errorf("%s:%d: writeJSONError is called with a computed status; the "+
					"openapi.yaml lint reads statuses lexically and cannot see it",
					path, fset.Position(call.Args[3].Pos()).Line)
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "http" || httpStatusConstants[sel.Sel.Name] == 0 {
				t.Errorf("%s:%d: writeJSONError is called with %s rather than an http.Status "+
					"constant", path, fset.Position(call.Args[3].Pos()).Line, sel.Sel.Name)
			}
			return true
		})
	})

	// A scan that inspected nothing passes while guarding nothing. This is the floor that
	// says the walk still reaches the handlers.
	if calls < 100 {
		t.Errorf("found only %d writeJSONError calls; the walk is no longer reaching the "+
			"API handlers", calls)
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

	var out []routeRegistration
	collectRoutes(t, fset, file, "", false, &out)

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

func collectRoutes(t *testing.T, fset *token.FileSet, node ast.Node, prefix string,
	groupScopeGuarded bool, out *[]routeRegistration) {

	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		// r.Route("/api/v1/admin", func(r chi.Router) { ... }): descend with the prefix and
		// stop the outer walk, so the body is read once and under the right path.
		if sel.Sel.Name == "Route" && len(call.Args) == 2 {
			sub, subOK := stringLiteral(call.Args[0])
			body, bodyOK := call.Args[1].(*ast.FuncLit)
			if subOK && bodyOK {
				// A guard mounted with r.Use here covers every route in the body, and a
				// group nested inside an already-guarded one stays guarded.
				collectRoutes(t, fset, body, prefix+sub,
					groupScopeGuarded || usesScopeGuard(body), out)
				return false
			}
		}

		verb, isVerb := httpVerbs[sel.Sel.Name]
		if !isVerb || len(call.Args) != 2 {
			return true
		}
		path, pathOK := stringLiteral(call.Args[0])
		handler, handlerOK := handlerConstructor(call.Args[1])
		if !pathOK || !handlerOK {
			return true
		}
		full := prefix + path
		*out = append(*out, routeRegistration{
			method:       verb,
			path:         full,
			key:          routeKey(verb, full),
			handler:      handler,
			rateLimited:  mentionsRateLimiter(sel.X),
			scopeGuarded: groupScopeGuarded || mentionsScopeGuard(sel.X),
			line:         fset.Position(call.Pos()).Line,
		})
		return true
	})
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

// handlerConstructor pulls HandleX out of apihandlers.HandleX(deps...). Every API route is
// registered that way; anything else (a file server, a bare http.HandlerFunc) is not an
// operation the spec describes and is left alone.
func handlerConstructor(e ast.Expr) (string, bool) {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name, strings.HasPrefix(fn.Sel.Name, "Handle")
	case *ast.Ident:
		return fn.Name, strings.HasPrefix(fn.Name, "Handle")
	}
	return "", false
}

// scopeGuards are the middlewares that can answer 403 INSUFFICIENT_SCOPE before a handler
// runs. All three live in internal/middleware/api_auth.go, and each returns 403 rather than
// 401 when the token is valid but does not carry what the route demands.
//
// Listed by name rather than detected structurally, so a fourth one is a deliberate addition
// here rather than something that silently starts or stops being checked.
var scopeGuards = map[string]bool{
	"RequireBearerTokenScope":      true,
	"RequireBearerTokenScopeAnyOf": true,
	"RequireUserBoundToken":        true,
}

// mentionsScopeGuard looks for one of those in the .With(...) chain a verb hangs off, which is
// how the Admin group mounts them: once per route, with the scopes that route accepts.
func mentionsScopeGuard(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && scopeGuards[sel.Sel.Name] {
			found = true
		}
		return !found
	})
	return found
}

// usesScopeGuard looks for one inside an r.Use(...) at the top of a route group, which is how
// the Account group mounts them: once, covering every route in the body. Only r.Use counts,
// because a guard named anywhere else in the body belongs to the single route that named it
// and mentionsScopeGuard has already found it there.
func usesScopeGuard(body *ast.FuncLit) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Use" {
			return true
		}
		for _, arg := range call.Args {
			if mentionsScopeGuard(arg) {
				found = true
			}
		}
		return !found
	})
	return found
}

// mentionsRateLimiter looks for the limiter in the .With(...) chain the verb hangs off.
func mentionsRateLimiter(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "rateLimiter" {
			found = true
		}
		return !found
	})
	return found
}

// parseHandlerStatuses maps every Handle* constructor under internal/handlers to the
// statuses its body can write.
func parseHandlerStatuses(t *testing.T) map[string]map[int]bool {
	t.Helper()

	out := map[string]map[int]bool{}
	seenIn := map[string]string{}
	forEachHandlerSource(t, func(t *testing.T, path string, fset *token.FileSet, file *ast.File) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Handle") {
				continue
			}
			// Two handlers of the same name in different packages would make the lookup by
			// name ambiguous and the result arbitrary. There are none; this says so.
			if prev, dup := seenIn[fn.Name.Name]; dup {
				t.Fatalf("%s is declared in both %s and %s; the status scan looks handlers "+
					"up by name and cannot tell them apart", fn.Name.Name, prev, path)
			}
			seenIn[fn.Name.Name] = path
			out[fn.Name.Name] = statusesWrittenIn(t, path, fset, fn)
		}
	})

	if len(out) < 100 {
		t.Fatalf("found only %d Handle* functions under internal/handlers; the walk is no "+
			"longer reaching the handler sources", len(out))
	}
	return out
}

// statusesWrittenIn reads one handler's failure surface. Four spellings write a status in
// this module and all four are read here; anything else is a fifth nobody has taught this
// file about, which is what the unknown-constant failure below is for.
func statusesWrittenIn(t *testing.T, path string, fset *token.FileSet, fn *ast.FuncDecl) map[int]bool {
	out := map[int]bool{}
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
				t.Errorf("%s:%d: %s uses http.%s, which openapi_contract_lint_test.go does "+
					"not know the number of; add it to httpStatusConstants",
					path, fset.Position(e.Pos()).Line, fn.Name.Name, e.Sel.Name)
				return true
			}
			out[code] = true
		case *ast.CallExpr:
			switch f := e.Fun.(type) {
			case *ast.Ident:
				// writeValidationError names no constant; it is a 400 by
				// construction. Nothing depends on this line today: every handler
				// that calls it also writes an http.StatusBadRequest somewhere
				// else, so removing it changes no result and a mutation of it
				// survives. It is here for the first handler that validates and
				// does nothing else, which would otherwise have its 400 go
				// undocumented with every test in this file still passing.
				if f.Name == "writeValidationError" {
					out[400] = true
				}
			case *ast.SelectorExpr:
				switch f.Sel.Name {
				case "InternalServerError", "JsonError":
					// httpHelper's two error renderers. Both write 500 for a bare error,
					// which is the only kind these handlers hand them.
					out[500] = true
				case "NotFound":
					if pkg, ok := f.X.(*ast.Ident); ok && pkg.Name == "http" {
						out[404] = true
					}
				}
			}
		}
		return true
	})
	return out
}

// forEachHandlerSource walks the non-test Go sources under internal/handlers. Tests are
// skipped: a test names statuses to assert on them, and it is production code that decides
// what a route can answer.
func forEachHandlerSource(t *testing.T, visit func(*testing.T, string, *token.FileSet, *ast.File)) {
	t.Helper()

	// go test runs with the package directory as the working directory, so this is
	// src/authserver/internal/handlers.
	root := filepath.Join("..", "handlers")
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
		visit(t, filepath.ToSlash(path), fset, file)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if files == 0 {
		t.Fatalf("walked no non-test Go files under %s", root)
	}
}

// specOperation is the part of an operation these tests read.
type specOperation struct {
	operationId string
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
			out[routeKey(verb, path)] = specOperation{operationId: op.OperationId, responses: responses}
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
// properties on EnhancedUserSessionResponse alone, every one of which it inherits.
//
// Two limits, both real, both stated here rather than left to be discovered.
//
// Pairing is by identical name. A schema deliberately named differently from its struct is
// paired through schemaStructNames below rather than renamed: a published schema name is part
// of the contract a caller has already generated against, and an internal Go name is not.
//
// The check covers presence, not type. A named type that marshals to a scalar cannot be typed
// from the Go source lexically: api.UserResponse.Subject is a uuid.UUID, so a type check would
// call the spec's correct "string" a mismatch against an "object" it inferred from the
// selector. Carrying a type map for the handful of such types buys less than the one live
// case costs to explain, so type agreement stays a question for the census.
//
// A schema that no operation reaches is not this test's subject: TestOpenAPI_EveryRefResolves
// owns reachability, and this one owns content.
//
// SOME SHAPES ON THE WIRE ARE NOT core/api STRUCTS, and exempting them was a hole rather than
// a limit. Four nested schemas were waved through here on the true observation that no
// core/api type declares them, and all four turned out to be incomplete against the
// core/models type they really serialize: fifteen fields the API emits on every one of these
// responses had no entry in the contract, and adding a bogus property to one left this whole
// tier green (#245, final review finding 3). So a schema backed by a core/models type is
// paired through schemaModelNames and checked exactly, the same way and to the same standard
// as a core/api one. What stays exempt is only what no Go type declares at all.

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
}

// schemasWithNoAPIStruct is one half of the exemption, in the shape knownUndocumentedRoutes
// had: a name and the reason it is not a defect. Exact, so a schema that acquires a struct of
// its own name fails this test until its entry comes out.
var schemasWithNoAPIStruct = map[string]string{
	// Four bodies their handlers build as a map[string]interface{} literal rather than from a
	// declared type, so there is nothing to pair with. The declared shapes are confirmed
	// against what the handlers actually write by the census, not by this test.
	"ClientLogoInfoResponse":       "handler_api_client_logo.go builds this body as a map literal; no Go type declares it",
	"ClientLogoUploadResponse":     "handler_api_client_logo.go builds this body as a map literal; no Go type declares it",
	"ProfilePictureInfoResponse":   "the profile picture handlers build this body as a map literal; no Go type declares it",
	"ProfilePictureUploadResponse": "the profile picture handlers build this body as a map literal; no Go type declares it",

	// A standard-library shape, not a Goiabada one. Every timestamp on the model-backed
	// schemas is a database/sql NullTime, which carries no JSON tags and no MarshalJSON, so
	// it reaches the wire as its own two exported fields. Declaring it once and referencing
	// it is what stops those two fields being written out six times.
	"NullTime": "database/sql.NullTime as encoding/json writes it; no Goiabada type declares it",
}

// schemaModelNames pairs a component schema with the src/core/models type it serializes. These
// are the shapes an API response embeds directly rather than converting: api.UserResponse
// carries []models.Group and []models.Permission, and api.ClientResponse carries
// []models.RedirectURI and []models.WebOrigin, so those model types ARE the wire contract at
// those positions.
//
// None of them carries a json: tag, which is why their properties are capitalised where the
// rest of this document is not. That is a fact about the wire, not a style choice, and the
// schemas say so in their own descriptions.
//
// Exact, like the maps above: both ends must exist, and a schema here must not also have a
// core/api struct of its own name, because then which one it describes is a guess.
var schemaModelNames = map[string]string{
	"GroupBasic":          "Group",
	"GroupAttributeBasic": "GroupAttribute",
	"PermissionBasic":     "Permission",
	"ResourceBasic":       "Resource",
	"RedirectURI":         "RedirectURI",
	"WebOrigin":           "WebOrigin",
}

// apiStructsWithNoSchema is the other half. A struct here is a shape the server can write or
// read that this document does not declare, and the reason has to say why that is acceptable
// rather than merely true.
var apiStructsWithNoSchema = map[string]string{
	// Outside the document's declared scope. info.description scopes this file to the Admin
	// API (/api/v1/admin/*) and the Account API (/api/v1/account/*); /connect/register is a
	// protocol endpoint and is neither, which is also why TestOpenAPI_DescribesEveryAPIRoute
	// scopes itself to /api/v1.
	"DynamicClientRegistrationRequest":  "RFC 7591 registration at /connect/register, outside the Admin and Account API scope this document declares",
	"DynamicClientRegistrationResponse": "RFC 7591 registration at /connect/register, outside the Admin and Account API scope this document declares",
	"DynamicClientRegistrationError":    "RFC 7591 registration at /connect/register, outside the Admin and Account API scope this document declares",

	// A shape no handler writes. HandleAPIAccountLogoutRequestPost ignores the request's
	// responseMode outright and always answers AccountLogoutRedirectResponse, so there is no
	// response for this document to declare. It is not dead code either: the admin console's
	// apiclient still decodes it, which is a defect in the console rather than a gap here.
	"AccountLogoutFormPostResponse": "no handler writes it; the logout endpoint always answers AccountLogoutRedirectResponse",
}

func TestOpenAPI_SchemaPropertiesMatchTheAPIStructs(t *testing.T) {
	schemas := specSchemaProperties(t)
	structs := structFields(t, filepath.Join("..", "..", "..", "core", "api"), 100)
	models := structFields(t, filepath.Join("..", "..", "..", "core", "models"), 20)

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

	// The model-backed shapes, checked to the same standard. They are a separate map rather
	// than a second pass over the same one because the two packages mean different things: a
	// core/api type is a shape written for this API, and a core/models type is a database row
	// that an API response happens to serialize whole.
	pairedModel := map[string]string{} // schema name -> models type name
	for schema, model := range schemaModelNames {
		if _, exists := schemas[schema]; !exists {
			t.Errorf("schemaModelNames pairs %s with models.%s, but openapi.yaml defines no "+
				"such schema", schema, model)
			continue
		}
		if _, exists := models[model]; !exists {
			t.Errorf("schemaModelNames pairs %s with models.%s, but src/core/models declares "+
				"no such type", schema, model)
			continue
		}
		if _, ambiguous := structs[schema]; ambiguous {
			t.Errorf("schemaModelNames pairs %s with models.%s, but api.%s also exists, so "+
				"which one the schema describes is a guess", schema, model, schema)
			continue
		}
		pairedModel[schema] = model
	}

	// Both directions, exactly, for each one. A field the response really carries must be in
	// the contract, and a property the contract promises must be one the type really
	// marshals.
	for _, schema := range sortedKeys(pairedModel) {
		model := pairedModel[schema]
		for _, field := range sortedKeys(models[model]) {
			if schemas[schema][field] {
				continue
			}
			t.Errorf("models.%s marshals %q, which the %s schema does not declare: a client "+
				"generated from openapi.yaml has no field for it", model, field, schema)
		}
		for _, prop := range sortedKeys(schemas[schema]) {
			if models[model][prop] {
				continue
			}
			t.Errorf("the %s schema declares %q, which models.%s does not marshal: the spec "+
				"is promising a field that cannot arrive", schema, prop, model)
		}
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
			if structs[structName][prop] {
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
		if _, paired := pairedModel[schema]; paired {
			continue
		}
		if _, allowed := schemasWithNoAPIStruct[schema]; allowed {
			continue
		}
		t.Errorf("the %s schema has no Go type checking its properties. Give it a struct in "+
			"src/core/api, pair it in schemaStructNames or schemaModelNames, or record why in "+
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
		if model, paired := pairedModel[schema]; paired {
			t.Errorf("schemasWithNoAPIStruct exempts %s, but models.%s now pairs with it; "+
				"delete the entry so its properties are checked", schema, model)
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
// marshals. It is called for src/core/api and for src/core/models, which are the two packages
// whose types reach this API's wire.
//
// Every struct type declaration is read, not only those carrying json tags, so a struct that
// has none is visible to the pairing above rather than silently absent from it. That matters
// more for core/models than for core/api: no type in core/models carries a json tag at all,
// which is exactly why its fields arrive capitalised.
//
// Embedding is flattened transitively: an embedded struct's fields marshal as though declared
// on the outer one, which is the Go side of the spec's allOf.
//
// go test runs with the package directory as the working directory, so callers pass a path
// relative to src/authserver/internal/server, and a floor: the smallest number of struct
// declarations the package can honestly contain. A parse that quietly stopped matching would
// return nothing, every loop above would run over it, and the failure would look like a pass.
// The floor is per package because the two are nothing like the same size.
func structFields(t *testing.T, dir string, floor int) map[string]map[string]bool {
	t.Helper()

	sources, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("globbing %s: %v", dir, err)
	}

	own := map[string]map[string]bool{}
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
				fields := map[string]bool{}
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
					if name, marshalled := jsonFieldName(f); marshalled {
						fields[name] = true
					}
				}
				own[ts.Name.Name] = fields
			}
		}
	}

	// Cycles are impossible in a Go struct graph, so the walk needs no visited set.
	var flatten func(string, map[string]bool)
	flatten = func(name string, into map[string]bool) {
		for field := range own[name] {
			into[field] = true
		}
		for _, embedded := range embeds[name] {
			flatten(embedded, into)
		}
	}
	out := map[string]map[string]bool{}
	for name := range own {
		flat := map[string]bool{}
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
func jsonFieldName(f *ast.Field) (string, bool) {
	goName := f.Names[0].Name
	if !ast.IsExported(goName) {
		return "", false
	}
	if f.Tag == nil {
		return goName, true
	}
	m := jsonTagValue.FindStringSubmatch(f.Tag.Value)
	if m == nil {
		return goName, true
	}
	name, _, hasOptions := strings.Cut(m[1], ",")
	if name == "-" && !hasOptions {
		return "", false
	}
	if name == "" {
		return goName, true
	}
	return name, true
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
