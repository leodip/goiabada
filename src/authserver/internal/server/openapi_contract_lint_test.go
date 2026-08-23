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
	line        int
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

// knownUndocumentedRoutes are the API routes web/openapi.yaml does not describe at all.
// Documenting them means writing full operations, several needing request and response
// schemas that do not exist yet (the profile picture endpoints carry image bytes, the audit
// log ones a query surface), which is a larger piece of work than reconciling the statuses
// of the operations that are already there.
//
// The list is exact in both directions. A new API route that is not documented fails
// TestOpenAPI_DescribesEveryAPIRoute unless it is added here deliberately, and an entry that
// stops being a gap fails it too, so documenting one of these forces the line to go.
var knownUndocumentedRoutes = map[string]string{
	"get /api/v1/admin/users/{}/profile-picture":    "image bytes, no schema in the spec yet",
	"post /api/v1/admin/users/{}/profile-picture":   "multipart upload, no schema in the spec yet",
	"delete /api/v1/admin/users/{}/profile-picture": "paired with the two above",
	"get /api/v1/account/profile-picture":           "image bytes, no schema in the spec yet",
	"post /api/v1/account/profile-picture":          "multipart upload, no schema in the spec yet",
	"delete /api/v1/account/profile-picture":        "paired with the two above",
	"get /api/v1/admin/groups/search":               "search response schema not in the spec yet",
	"get /api/v1/admin/clients/{}/sessions":         "session list schema not in the spec yet",
	"get /api/v1/admin/audit-logs":                  "audit log query surface not in the spec yet",
	"get /api/v1/admin/settings/audit-logs":         "audit log settings not in the spec yet",
	"put /api/v1/admin/settings/audit-logs":         "audit log settings not in the spec yet",
}

// TestOpenAPI_DeclaresEveryStatusTheHandlersEmit is the forward direction: a status a
// handler can write must appear in the spec. This is the one that matters to a caller,
// because the statuses it catches are the ones a generated client has no branch for.
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
// Two failures are exempt, both because something other than the handler writes them, and
// neither is merely waved through. 401 comes from the bearer-token middleware, which sits on
// every API route. 429 comes from the rate limiter, which sits on three, and that one is
// checked in both directions below: declared only where a limiter is in front, and required
// wherever one is.
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

// TestOpenAPI_DescribesEveryAPIRoute keeps the two surfaces the same size. Every route under
// /api/v1 is either in the spec or named in knownUndocumentedRoutes with a reason, and the
// spec describes no operation that no longer exists.
func TestOpenAPI_DescribesEveryAPIRoute(t *testing.T) {
	routes := parseRoutes(t)
	spec := parseSpec(t)

	routed := map[string]bool{}
	for _, r := range routes {
		routed[r.key] = true
		if !strings.HasPrefix(r.path, "/api/v1/") {
			continue
		}
		_, documented := spec[r.key]
		_, allowed := knownUndocumentedRoutes[r.key]
		switch {
		case documented && allowed:
			t.Errorf("%s %s is documented now, so its knownUndocumentedRoutes entry %q is "+
				"stale and must go", strings.ToUpper(r.method), r.path, r.key)
		case !documented && !allowed:
			t.Errorf("routes.go:%d: %s %s is not in openapi.yaml. Document it, or add it to "+
				"knownUndocumentedRoutes with the reason it cannot be documented yet",
				r.line, strings.ToUpper(r.method), r.path)
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
	collectRoutes(t, fset, file, "", &out)

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

func collectRoutes(t *testing.T, fset *token.FileSet, node ast.Node, prefix string, out *[]routeRegistration) {
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
				collectRoutes(t, fset, body, prefix+sub, out)
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
			method:      verb,
			path:        full,
			key:         routeKey(verb, full),
			handler:     handler,
			rateLimited: mentionsRateLimiter(sel.X),
			line:        fset.Position(call.Pos()).Line,
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
