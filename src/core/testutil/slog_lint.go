package testutil

import (
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
	"unicode"
	"unicode/utf8"

	"github.com/leodip/goiabada/core/errs"
)

// AssertSlogConvention holds production code to one logging convention, so that every record this
// tree writes is greppable by its message, queryable by its attributes and correlatable to the
// request that produced it. Five rules, each decidable from the text alone:
//
//  1. The message is a string literal. 125 sites used to build it with fmt.Sprintf, a +
//     concatenation, err.Error() or a variable, which makes a record ungreppable and puts the
//     value the reader wants inside the one field no collector can index.
//  2. The literal message starts with a lowercase letter, carries no "component: " prefix, and
//     does not open with "failed to" or "error ". 47 messages were capitalised, nine component
//     prefixes were in use (logout:, TokenParser:, i18n:, WARNING: and five more), and the tree
//     spelled the same event three ways. The one verb is "unable to".
//  3. Every attribute key matches ^[a-z][a-z0-9_]*$ and is none of err, request_id or request-id.
//     45 calls carried a camelCase key and one carried a dash, so the same value arrived under
//     clientId, clientIdentifier and client_identifier in three records of one request. err is
//     spelled error, and request_id is never written by a call site because the handler injects
//     it (decision 2); a site that wrote its own would produce the key twice in one record, so
//     core/logging, which is that handler, is the one package allowed to write it.
//  4. A slog call inside a function that takes a context.Context or an *http.Request, at any
//     enclosing depth, is a *Context variant. Only those pass a context to the handler, so a
//     plain slog.Info on a request path is a record with no request_id, and it is invisible
//     rather than wrong: it looks exactly like a correct record until someone tries to correlate
//     it. slog.Log and slog.LogAttrs take a context by construction and satisfy the rule.
//  5. slog.SetDefault, slog.New, slog.Default and slog.With are refused outside the files that
//     own the handler. slog.SetDefault is process-global, so a second install silently replaces
//     the one both servers configured, and a *slog.Logger obtained anywhere else carries
//     attributes this rule cannot see.
//  6. A function that takes the caller's key/value run as a variadic parameter and hands it to a
//     record is declared in slogAttrForwarders, and rule 3 then reads the keys at its call sites
//     and in any slice spread into it. Four exist. The API's 500 writer is why the rule does:
//     328 calls reach one record through it, and until this rule they were the one place in the
//     tree a key was never read, so 179 of them still spelled clientId, groupId and userId after
//     the sweep while all three tier callers passed. An unregistered forwarder is refused rather
//     than ignored, because the shape it creates is a hole in rule 3 that looks like nothing.
//
// Resolution is by import path rather than by the text at the call site, as errors_lint.go does
// and for the same reason: an aliased log/slog, context or net/http would walk straight past a
// textual check. A dot import of log/slog is refused outright, because it leaves no selector for
// any of the six rules to resolve.
//
// Rule 6 spans two boundaries, and each is closed by refusing what cannot be read rather than by
// matching the shapes that exist. How the callee resolves: a dot import of a forwarder's package
// and a forwarder named anywhere but at a call are both refused, because either one puts a record
// one indirection past every selector this rule resolves. How the run is built: a run spread into
// a record must be the enclosing function's own variadic parameter, which rule 6's declaration
// half already covers, or a local built only out of []any{...}, make([]any, ...) and appends onto
// itself. A builder's return value, an alias of another slice, an append onto a slice that is not
// the run, a spread of anything but the enclosing variadic parameter, and a write from inside a
// closure are each reported as a run this rule cannot read. Both halves are refusals rather than
// approximations on purpose: an enumeration of permitted forms is green on the forms nobody
// thought of, which is how 179 camelCase keys survived the sweep behind a wrapper in the first
// place.
//
// ceiling: three shapes are outside a parse and are therefore not held. An attribute key computed
// at runtime is skipped rather than reported, and a non-literal expression at a key position also
// costs the walk its alignment for the rest of that call's arguments, so a string literal after
// one may be read as a key. One production site writes a computed key: the rate limiter appends
// tier.keyField, whose value is a literal at each newTier call, and the key those literals spell
// is held by TestRateLimiter_EveryTierLogsUnderAConventionalKey in core/middleware rather than
// here, exactly as decision 5 pins a level the text cannot decide. An elided composite literal
// inside a []slog.Attr, {Key: "x"}, has no type to resolve and is skipped. And the methods on a
// *slog.Logger are not linted, which rule 5 is what makes safe: outside the handler's own files
// there is no way to get one. Revisit when a second site needs a computed key, since one test per
// site does not scale, or when rule 5 grows a sixth exemption; closing any of them means running
// this over go/packages-loaded type information rather than one parsed file (#320).
//
// Passing dirs restricts the walk to those subdirectories of the source root, forward slashes and
// relative to it. Scope and shape follow AssertNoLegacyErrors, which carries the reasoning for
// walking the source root rather than the calling module.
func AssertSlogConvention(t *testing.T, dirs ...string) {
	t.Helper()

	root := SourceRoot(t)

	violations, files, err := findSlogViolations(root, dirs)
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	// A root that somehow held no Go files walks nothing and would otherwise pass, which is the
	// one way a guard like this fails silently in the direction that matters.
	if files == 0 {
		t.Fatalf("walked no non-test Go files under %s (dirs: %s)", root, strings.Join(dirs, ", "))
	}
	if len(violations) == 0 {
		return
	}

	lines := make([]string, 0, len(violations))
	for _, v := range violations {
		lines = append(lines, v.file+":"+strconv.Itoa(v.line)+": "+v.what+" -- "+v.fix)
	}
	t.Errorf("%d slog convention violation(s) in %d non-test file(s):\n\t%s\n\n"+
		"Every record has a literal, lowercase, unprefixed message, snake_case attribute keys, "+
		"and a *Context variant wherever a context or a request is in scope so the handler can "+
		"inject request_id. core/logging owns the handler; testutil.CaptureSlog is how a test "+
		"reads records; a wrapper that forwards a caller's attributes is listed in "+
		"slogAttrForwarders so its call sites are read too (#320).",
		len(violations), files, strings.Join(lines, "\n\t"))
}

// slogViolation is one refused call, located.
type slogViolation struct {
	// file is relative to the source root, forward slashes.
	file string
	line int
	what string
	fix  string
}

const (
	slogImportPath    = "log/slog"
	contextImportPath = "context"
	httpImportPath    = "net/http"
)

// slogEmissions maps each package-level emission function in log/slog to the index its message
// occupies. The index is per function rather than one number because the forms differ:
// slog.Info(msg, ...) puts it first, slog.InfoContext(ctx, msg, ...) second, and both
// slog.Log(ctx, level, msg, ...) and slog.LogAttrs(ctx, level, msg, ...) third.
var slogEmissions = map[string]int{
	"Debug": 0, "Info": 0, "Warn": 0, "Error": 0,
	"DebugContext": 1, "InfoContext": 1, "WarnContext": 1, "ErrorContext": 1,
	"Log": 2, "LogAttrs": 2,
}

// slogAttrConstructors is every log/slog function whose first argument is an attribute key. Group
// is one of them and is also a container, so its remaining arguments are key/value pairs read the
// same way an emission's are.
var slogAttrConstructors = map[string]bool{
	"String": true, "Int": true, "Int64": true, "Uint64": true, "Float64": true,
	"Bool": true, "Duration": true, "Time": true, "Any": true, "Group": true,
}

// slogHandlerInstalls is rule 5's list: the four ways to replace the default logger or obtain one
// of your own. Handler constructors are absent on purpose, since building a slog.Handler installs
// nothing and core/logging's own code builds several.
var slogHandlerInstalls = map[string]bool{
	"SetDefault": true, "New": true, "Default": true, "With": true,
}

// slogHandlerOwners is rule 5's allowlist, by path rather than by package. Four are whole
// directories: the package that owns the handler, the two mains that install it, and schemadump,
// which is a one-file tool with the only other SetDefault in the tree. The fifth is a single
// file, because decision 11 makes testutil.CaptureSlog a non-test file that installs the handler
// over a recorder, and admitting the package rather than the file would let any other file in
// core/testutil install one unnoticed.
var slogHandlerOwners = []string{
	"core/logging",
	"core/cmd/schemadump",
	"authserver/cmd/goiabada-authserver",
	"adminconsole/cmd/goiabada-adminconsole",
	"core/testutil/slog_capture.go",
}

// slogAttrForwarder is one function that takes the caller's key/value run as a variadic ...any and
// puts it in a record, so the keys rule 3 has to read are at its call sites rather than at any
// slog call. firstAttr is the argument index that run begins at.
//
// pkgPath resolves a call written pkg.Name, through the file's imports like every other rule here.
// scope resolves a bare Name, which is how an unexported forwarder and a closure are called and
// the only way they can be: it is the file or directory, relative to the source root, inside which
// that identifier is this function. Both are set where a forwarder is called under both forms.
type slogAttrForwarder struct {
	pkgPath   string
	scope     string
	name      string
	firstAttr int
}

// apiresponseImportPath is the package holding the API's one 500, which is the reason rule 6
// exists: the two functions below reach one slog.ErrorContext, and 328 sites pass their
// attributes through them.
const apiresponseImportPath = "github.com/leodip/goiabada/authserver/internal/apiresponse"

// slogAttrForwarders is rule 6's table, and it is exhaustive by construction: every other
// production function taking a variadic ...any hands it to fmt or to a SQL driver, and rule 6
// refuses any new one that reaches a record without being listed here.
//
// The fourth entry is a closure, which is why scope can be a file: classifyIdTokenHint's reject
// helper builds the twenty id_token_hint refusals, and its keys are as much a part of the
// vocabulary as any other. A closure is reachable only from its own file, so the file is its
// scope exactly as the package directory is an unexported function's.
var slogAttrForwarders = []slogAttrForwarder{
	{pkgPath: apiresponseImportPath, scope: "authserver/internal/apiresponse",
		name: "WriteInternalServerError", firstAttr: 3},
	{pkgPath: apiresponseImportPath, scope: "authserver/internal/apiresponse",
		name: "LogInternalServerError", firstAttr: 2},
	{scope: "authserver/internal/handlers/apihandlers",
		name: "writeInternalServerError", firstAttr: 3},
	{scope: "authserver/internal/handlers/handler_account_logout.go",
		name: "reject", firstAttr: 1},
}

var (
	// slogKeyPattern is decision 3's vocabulary: a lowercase letter, then lowercase letters,
	// digits and underscores.
	slogKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	// slogComponentPrefix is one token, then a colon and a space. Anchored and token-shaped so a
	// colon later in the message is not read as a prefix.
	slogComponentPrefix = regexp.MustCompile(`^[^\s:]+: `)
)

// slogReservedKeys is the spelling refused in every file whatever it owns: an error value is
// named error everywhere, which is also the name the JSON handler rewrites to keep the stack.
var slogReservedKeys = map[string]string{
	"err": `spell it "error", the one name for an error value and what the JSON handler rewrites to keep the stack`,
}

// slogInjectedKeys are the two spellings of the one attribute a call site never writes, because
// the installed handler appends it from the context (decision 2). The ten sites that used to pass
// their own request id were removed during the sweep, and a site writing one again would put the
// key in the record twice.
var slogInjectedKeys = map[string]string{
	"request_id": "the installed handler injects request_id from the context; writing it puts the key in the record twice",
	"request-id": "the installed handler injects request_id from the context, spelled with an underscore",
}

// slogRequestIDOwner is the one package exempt from slogInjectedKeys, and it is exempt because it
// is the injector: WrapRequestID.Handle is the single site in the tree that writes request_id at
// all, and a rule refusing the key everywhere would refuse the mechanism that makes the rule
// worth having. Narrower than slogHandlerOwners on purpose -- schemadump and the two mains own a
// handler install and still have no business writing the key.
const slogRequestIDOwner = "core/logging"

// findSlogViolations parses every non-test Go file under root, or under the named subdirectories
// of root, and reports each refused call along with the number of files it parsed.
func findSlogViolations(root string, dirs []string) ([]slogViolation, int, error) {
	roots := []string{root}
	if len(dirs) > 0 {
		roots = roots[:0]
		for _, dir := range dirs {
			roots = append(roots, filepath.Join(root, filepath.FromSlash(dir)))
		}
	}

	var violations []slogViolation
	files := 0
	for _, start := range roots {
		err := filepath.WalkDir(start, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return errs.Wrapf(relErr, "relating %s to %s", path, root)
			}
			rel = filepath.ToSlash(rel)
			if slogExemptByPath(rel) {
				return nil
			}
			fset := token.NewFileSet()
			// ParseComments because the build constraint is a comment, and a file excluded from
			// every production build is exempt.
			file, pErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if pErr != nil {
				// A file that does not parse is a compile error the build tier owns, and
				// reporting it here would send the reader to the wrong place.
				return nil
			}
			if exemptByBuildConstraint(file, fset) {
				return nil
			}
			files++
			violations = append(violations, slogViolationsInFile(file, fset, rel)...)
			return nil
		})
		if err != nil {
			return nil, files, err
		}
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].file != violations[j].file {
			return violations[i].file < violations[j].file
		}
		if violations[i].line != violations[j].line {
			return violations[i].line < violations[j].line
		}
		return violations[i].what < violations[j].what
	})

	// A closure's body is walked both on its own and as part of the function enclosing it, so a
	// key inside one is reported twice. Reporting one finding once is what lets the rule table
	// assert an exact set.
	deduped := violations[:0]
	for i, v := range violations {
		if i > 0 && v == violations[i-1] {
			continue
		}
		deduped = append(deduped, v)
	}
	return deduped, files, nil
}

// slogExemptByPath covers a test file, which is not production code and reads records through
// testutil.CaptureSlog rather than writing them, and a mocks directory, which is generated or
// hand-written scaffolding that emits nothing. Both exemptions match AssertNoLegacyErrors, so one
// answer about what production code means holds for both lints.
func slogExemptByPath(rel string) bool {
	if strings.HasSuffix(rel, "_test.go") {
		return true
	}
	for _, segment := range strings.Split(rel, "/") {
		if segment == "mocks" {
			return true
		}
	}
	return false
}

// slogHandlerOwner reports whether rule 5 admits this file: an exact match on a listed file, or
// anything under a listed directory.
func slogHandlerOwner(rel string) bool {
	for _, owner := range slogHandlerOwners {
		if rel == owner || strings.HasPrefix(rel, owner+"/") {
			return true
		}
	}
	return false
}

// slogOwnsRequestID reports whether this file is part of the package that injects request_id.
func slogOwnsRequestID(rel string) bool {
	return rel == slogRequestIDOwner || strings.HasPrefix(rel, slogRequestIDOwner+"/")
}

// slogWithinScope reports whether rel is the scope itself or sits under it, which is the same
// file-or-directory test slogHandlerOwner applies to rule 5's allowlist.
func slogWithinScope(rel, scope string) bool {
	return scope != "" && (rel == scope || strings.HasPrefix(rel, scope+"/"))
}

// slogForwarderCall resolves a call to one of the forwarders in the table: pkg.Name through the
// file's imports, or a bare Name inside the scope where that identifier is this function.
func slogForwarderCall(call *ast.CallExpr, importPaths map[string]string, rel string) (slogAttrForwarder, bool) {
	switch fun := unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		pkg, name, ok := qualifiedSelector(fun, importPaths)
		if !ok {
			return slogAttrForwarder{}, false
		}
		for _, fwd := range slogAttrForwarders {
			if fwd.pkgPath == pkg && fwd.name == name {
				return fwd, true
			}
		}
	case *ast.Ident:
		for _, fwd := range slogAttrForwarders {
			if fwd.name == fun.Name && slogWithinScope(rel, fwd.scope) {
				return fwd, true
			}
		}
	}
	return slogAttrForwarder{}, false
}

// slogForwarderDeclared reports whether a function of this name declared in this file is one the
// table already covers, which is what rule 6 asks before refusing it.
func slogForwarderDeclared(name, rel string) bool {
	for _, fwd := range slogAttrForwarders {
		if fwd.name == name && slogWithinScope(rel, fwd.scope) {
			return true
		}
	}
	return false
}

// slogForwarderNamed resolves pkg.Name against the table without the scope test, which is what a
// selector reached outside a call needs: the import path is the whole of the resolution there.
func slogForwarderNamed(pkgPath, name string) bool {
	for _, fwd := range slogAttrForwarders {
		if fwd.pkgPath == pkgPath && fwd.name == name {
			return true
		}
	}
	return false
}

// slogForwarderPackage reports whether the path holds one, which is what makes a dot import of it
// a hole rather than a style choice.
func slogForwarderPackage(path string) bool {
	for _, fwd := range slogAttrForwarders {
		if fwd.pkgPath != "" && fwd.pkgPath == path {
			return true
		}
	}
	return false
}

// slogNameOnlyIdents collects every identifier occurrence that introduces or labels a name rather
// than referring to the value bound to one: a callee, the field half of a selector, a declared
// function, a parameter or struct field, a key in a composite literal, an assignment's left side,
// a label, an import name. Subtracting them leaves the references, which is what lets the walk
// tell a forwarder being called from a forwarder being handed round -- the same distinction
// calleeSelectors draws for a package-qualified one, at the bare name a closure is called by.
func slogNameOnlyIdents(file *ast.File) map[*ast.Ident]bool {
	nameOnly := map[*ast.Ident]bool{}
	mark := func(expr ast.Expr) {
		if id, isIdent := unparen(expr).(*ast.Ident); isIdent {
			nameOnly[id] = true
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			mark(node.Fun)
		case *ast.SelectorExpr:
			nameOnly[node.Sel] = true
		case *ast.FuncDecl:
			nameOnly[node.Name] = true
			if node.Recv != nil {
				for _, field := range node.Recv.List {
					for _, name := range field.Names {
						nameOnly[name] = true
					}
				}
			}
		case *ast.Field:
			for _, name := range node.Names {
				nameOnly[name] = true
			}
		case *ast.ValueSpec:
			for _, name := range node.Names {
				nameOnly[name] = true
			}
		case *ast.TypeSpec:
			nameOnly[node.Name] = true
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				mark(lhs)
			}
		case *ast.KeyValueExpr:
			mark(node.Key)
		case *ast.LabeledStmt:
			nameOnly[node.Label] = true
		case *ast.BranchStmt:
			if node.Label != nil {
				nameOnly[node.Label] = true
			}
		case *ast.ImportSpec:
			if node.Name != nil {
				nameOnly[node.Name] = true
			}
		}
		return true
	})
	return nameOnly
}

// slogViolationsInFile reports every refused call in one parsed file.
func slogViolationsInFile(file *ast.File, fset *token.FileSet, rel string) []slogViolation {
	var violations []slogViolation

	// importPaths maps the name this file writes at a call site to the path it imports, so an
	// aliased log/slog, context or net/http resolves like any other.
	importPaths := map[string]string{}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := defaultImportName(path)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "." {
			// A dot import binds Info, SetDefault and String unqualified, so no selector is left
			// for any of the six rules to resolve and the whole file walks past them. Refusing
			// the import is the answer rather than resolving unqualified calls, which would also
			// have to model every local declaration that shadows one.
			//
			// A forwarder's package is refused on the same argument and it is the same hole:
			// WriteInternalServerError bound unqualified is a call rule 6 cannot resolve, so the
			// keys at that call site are read by nothing. The scope half of the table cannot
			// stand in for it, because a dot import reaches the name from any directory.
			switch {
			case path == slogImportPath:
				violations = append(violations, slogViolation{
					file: rel,
					line: fset.Position(spec.Pos()).Line,
					what: `dot import of "log/slog"`,
					fix:  "import it under its own name; a dot import hides every slog call from this rule",
				})
			case slogForwarderPackage(path):
				violations = append(violations, slogViolation{
					file: rel,
					line: fset.Position(spec.Pos()).Line,
					what: `dot import of ` + strconv.Quote(path),
					fix: "import it under its own name; a dot import leaves a forwarder call with " +
						"no selector, so the attribute keys at that call site are read by nothing",
				})
			}
			continue
		}
		if name == "_" {
			continue
		}
		importPaths[name] = path
	}

	callees := calleeSelectors(file)
	nameOnly := slogNameOnlyIdents(file)
	lineOf := func(n ast.Node) int { return fset.Position(n.Pos()).Line }

	// requestScope runs parallel to the walk: each entry says whether the node sits inside a
	// function, at any depth, that takes a context.Context or an *http.Request. A closure nested
	// in a handler inherits its enclosing function's answer, which is the whole point of rule 4
	// being about enclosing depth rather than the immediate signature.
	var requestScope []bool
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			requestScope = requestScope[:len(requestScope)-1]
			return true
		}
		inScope := len(requestScope) > 0 && requestScope[len(requestScope)-1]
		switch fn := n.(type) {
		case *ast.FuncDecl:
			inScope = inScope || funcTakesRequestScope(fn.Type, importPaths)
		case *ast.FuncLit:
			inScope = inScope || funcTakesRequestScope(fn.Type, importPaths)
		}
		requestScope = append(requestScope, inScope)
		// Every arm below returns true. Returning false would skip ast.Inspect's closing nil
		// callback for this node and leave the stack one entry short for the rest of the file.

		if composite, isComposite := n.(*ast.CompositeLit); isComposite {
			violations = append(violations, slogAttrLiteralViolations(composite, importPaths, fset, rel)...)
			return true
		}

		if sel, isSelector := n.(*ast.SelectorExpr); isSelector {
			if callees[sel] {
				return true
			}
			pkg, fn, resolved := qualifiedSelector(sel, importPaths)
			if !resolved {
				return true
			}
			if pkg != slogImportPath {
				// A forwarder as a value is the emission-as-a-value hole one wrapper further
				// out: the call that eventually runs it writes its keys against an identifier
				// rule 6 cannot resolve to the table, so the run reaches a record unread.
				if slogForwarderNamed(pkg, fn) {
					violations = append(violations, slogViolation{file: rel, line: lineOf(sel),
						what: defaultImportName(pkg) + "." + fn + " as a value",
						fix: "call it where the attributes are written; as a value its call " +
							"sites carry keys this rule cannot find"})
				}
				return true
			}
			// An emission or an install handed round as a value reaches the same record one
			// indirection later, and the call that eventually runs it has no package selector
			// left to resolve, so every rule above walks past it. errors_lint.go refuses a
			// constructor value for the same reason and by the same argument.
			switch {
			case slogIsEmission(fn):
				violations = append(violations, slogViolation{file: rel, line: lineOf(sel),
					what: "slog." + fn + " as a value",
					fix:  "call it where the record is written; as a value its message and keys cannot be read"})
			case slogHandlerInstalls[fn] && !slogHandlerOwner(rel):
				violations = append(violations, slogViolation{file: rel, line: lineOf(sel),
					what: "slog." + fn + " as a value",
					fix:  "core/logging owns the handler; a test reads records through testutil.CaptureSlog"})
			}
			return true
		}

		// The same value, taken under the bare name an unexported forwarder and a closure are
		// called by. nameOnly holds every occurrence that names something rather than referring
		// to it -- the declaration itself, a parameter, a field, a callee -- so what reaches
		// here is a reference, and a reference to a forwarder that is not a call is a value.
		if id, isIdent := n.(*ast.Ident); isIdent {
			if !nameOnly[id] && slogForwarderDeclared(id.Name, rel) {
				violations = append(violations, slogViolation{file: rel, line: lineOf(id),
					what: id.Name + " as a value",
					fix: "call it where the attributes are written; as a value its call " +
						"sites carry keys this rule cannot find"})
			}
			return true
		}

		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}

		// A forwarder's call site is where its record's keys are written, so rule 3 reads them
		// here. The run is read with the same parity as an emission's, because that is what the
		// forwarder eventually hands to one.
		if fwd, isForwarder := slogForwarderCall(call, importPaths, rel); isForwarder {
			if len(call.Args) > fwd.firstAttr {
				violations = append(violations, slogBareKeyViolations(call.Args[fwd.firstAttr:], fset, rel)...)
			}
			return true
		}

		pkg, fn, resolved := qualifiedCall(call, importPaths)
		if !resolved || pkg != slogImportPath {
			return true
		}

		if slogHandlerInstalls[fn] && !slogHandlerOwner(rel) {
			violations = append(violations, slogViolation{file: rel, line: lineOf(call),
				what: "slog." + fn,
				fix:  "core/logging owns the handler; a test reads records through testutil.CaptureSlog"})
			return true
		}

		if slogAttrConstructors[fn] && len(call.Args) > 0 {
			if v, bad := slogKeyViolation(call.Args[0], "slog."+fn, fset, rel); bad {
				violations = append(violations, v)
			}
			if fn == "Group" {
				violations = append(violations, slogBareKeyViolations(call.Args[1:], fset, rel)...)
			}
			return true
		}

		msgIndex, isEmission := slogEmissions[fn]
		if !isEmission {
			return true
		}

		if inScope && !slogCarriesContext(fn) {
			violations = append(violations, slogViolation{file: rel, line: lineOf(call),
				what: "slog." + fn + " inside a function taking a context.Context or an *http.Request",
				fix:  "use slog." + fn + "Context(ctx, ...); only a *Context variant reaches the handler's request_id injection"})
		}
		if len(call.Args) <= msgIndex {
			return true
		}
		if v, bad := slogMessageViolation(call.Args[msgIndex], fset, rel); bad {
			violations = append(violations, v)
		}
		violations = append(violations, slogBareKeyViolations(call.Args[msgIndex+1:], fset, rel)...)
		return true
	})

	violations = append(violations, slogForwarderDeclarationViolations(file, importPaths, fset, rel)...)
	violations = append(violations, slogSpreadRunViolations(file, importPaths, fset, rel)...)

	return violations
}

// slogIsRecordCall reports whether this call puts its argument run in a record: a slog emission,
// or one of the forwarders that hands its own run to one.
func slogIsRecordCall(call *ast.CallExpr, importPaths map[string]string, rel string) bool {
	if _, isForwarder := slogForwarderCall(call, importPaths, rel); isForwarder {
		return true
	}
	pkg, fn, resolved := qualifiedCall(call, importPaths)
	return resolved && pkg == slogImportPath && slogIsEmission(fn)
}

// slogVariadicAnyParam returns the name of the signature's variadic ...any or ...interface{}
// parameter, which is the shape that carries a caller's key/value run.
func slogVariadicAnyParam(ft *ast.FuncType) string {
	if ft.Params == nil {
		return ""
	}
	for _, param := range ft.Params.List {
		ellipsis, isVariadic := param.Type.(*ast.Ellipsis)
		if !isVariadic || len(param.Names) == 0 {
			continue
		}
		switch elt := unparen(ellipsis.Elt).(type) {
		case *ast.Ident:
			if elt.Name == "any" {
				return param.Names[0].Name
			}
		case *ast.InterfaceType:
			if elt.Methods == nil || len(elt.Methods.List) == 0 {
				return param.Names[0].Name
			}
		}
	}
	return ""
}

// slogForwardsVariadic reports whether body hands param to a record, either by spreading it
// straight into one or by appending it onto a slice that is spread into one. Those are the two
// shapes the four real forwarders use, and a function doing neither is not forwarding attributes
// whatever else it does with the parameter.
func slogForwardsVariadic(body *ast.BlockStmt, param string, importPaths map[string]string, rel string) bool {
	spreadsParam, appendsParam, spreadsAnything := false, false, false
	ast.Inspect(body, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall || len(call.Args) == 0 {
			return true
		}
		last, isIdent := unparen(call.Args[len(call.Args)-1]).(*ast.Ident)
		if fn, isBuiltin := unparen(call.Fun).(*ast.Ident); isBuiltin && fn.Name == "append" {
			for _, arg := range call.Args[1:] {
				if id, ok := unparen(arg).(*ast.Ident); ok && id.Name == param && call.Ellipsis != token.NoPos {
					appendsParam = true
				}
			}
			return true
		}
		if call.Ellipsis == token.NoPos || !isIdent || !slogIsRecordCall(call, importPaths, rel) {
			return true
		}
		spreadsAnything = true
		if last.Name == param {
			spreadsParam = true
		}
		return true
	})
	return spreadsParam || (appendsParam && spreadsAnything)
}

// slogForwarderDeclarationViolations is rule 6: a function that forwards a caller's attribute run
// into a record and is not in slogAttrForwarders. Its call sites write keys no rule reads, which
// is how 179 camelCase keys survived a sweep that visited every slog call in the tree.
//
// A closure is named by the variable it is bound to, because that is the name its callers write.
// One bound to nothing is refused outright: it can be called, and nothing could ever name it in
// the table.
func slogForwarderDeclarationViolations(file *ast.File, importPaths map[string]string, fset *token.FileSet, rel string) []slogViolation {
	var violations []slogViolation
	litNames := map[*ast.FuncLit]string{}

	report := func(name string, pos token.Pos) {
		if slogForwarderDeclared(name, rel) {
			return
		}
		shown := name
		if shown == "" {
			shown = "an unnamed function literal"
		}
		violations = append(violations, slogViolation{file: rel, line: fset.Position(pos).Line,
			what: shown + " forwards a variadic ...any into a record",
			fix: "list it in testutil.slogAttrForwarders with the index its attributes start at, " +
				"so the keys its callers pass are read; an unlisted one is a hole in the key rule"})
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch decl := n.(type) {
		case *ast.AssignStmt:
			for i, rhs := range decl.Rhs {
				if lit, isLit := rhs.(*ast.FuncLit); isLit && i < len(decl.Lhs) {
					if id, isIdent := decl.Lhs[i].(*ast.Ident); isIdent {
						litNames[lit] = id.Name
					}
				}
			}
		case *ast.ValueSpec:
			for i, value := range decl.Values {
				if lit, isLit := value.(*ast.FuncLit); isLit && i < len(decl.Names) {
					litNames[lit] = decl.Names[i].Name
				}
			}
		case *ast.FuncDecl:
			if decl.Body == nil {
				return true
			}
			if param := slogVariadicAnyParam(decl.Type); param != "" &&
				slogForwardsVariadic(decl.Body, param, importPaths, rel) {
				report(decl.Name.Name, decl.Pos())
			}
		case *ast.FuncLit:
			if param := slogVariadicAnyParam(decl.Type); param != "" &&
				slogForwardsVariadic(decl.Body, param, importPaths, rel) {
				report(litNames[decl], decl.Pos())
			}
		}
		return true
	})
	return violations
}

// slogSpreadRunViolations is rule 6's second boundary: the run a record call spreads, which is the
// one attribute shape that is neither an argument at a call site nor a slog.Attr. attrs :=
// []any{"client_id", client.Id}, appended to and then spread, writes its keys in a composite
// literal no other rule looks at.
//
// It reads what it can follow and refuses what it cannot, rather than matching the constructions
// that happen to exist. A run is readable when it is the enclosing function's own variadic
// parameter, which rule 6's declaration half already covers, or a local built only out of an []any
// composite literal, a make of one, and appends onto itself. A builder's return, an alias of
// another slice, an append onto something that is not the run, a spread of anything but the
// enclosing variadic parameter, and a write from inside a closure are each reported, because each
// of them carries a key to a record past every rule that reads one.
//
// Each function body is read on its own, without descending into the closures inside it, so the
// variadic parameter in hand is always the one belonging to the body being read. That is also what
// makes a run built in one body and spread in another unreadable, which it is: neither reading has
// both halves in view.
func slogSpreadRunViolations(file *ast.File, importPaths map[string]string, fset *token.FileSet, rel string) []slogViolation {
	var violations []slogViolation

	inBody := func(ft *ast.FuncType, body *ast.BlockStmt) {
		if body == nil {
			return
		}
		variadic := slogVariadicAnyParam(ft)
		walk := func(visit func(ast.Node) bool) {
			ast.Inspect(body, func(n ast.Node) bool {
				if n == nil {
					return false
				}
				if _, isClosure := n.(*ast.FuncLit); isClosure {
					return false
				}
				return visit(n)
			})
		}

		// Every run this body spreads into a record, named where it is a plain identifier.
		type spreadSite struct {
			name string
			pos  token.Pos
		}
		var sites []spreadSite
		walk(func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall || call.Ellipsis == token.NoPos || len(call.Args) == 0 {
				return true
			}
			if !slogIsRecordCall(call, importPaths, rel) {
				return true
			}
			site := spreadSite{pos: call.Pos()}
			if id, isIdent := unparen(call.Args[len(call.Args)-1]).(*ast.Ident); isIdent {
				site.name = id.Name
			}
			sites = append(sites, site)
			return true
		})
		if len(sites) == 0 {
			return
		}

		runs := map[string]*slogRun{}
		for _, site := range sites {
			if site.name != "" && site.name != variadic {
				runs[site.name] = &slogRun{readable: true}
			}
		}

		build := func(name string, from ast.Expr) {
			run, tracked := runs[name]
			if !tracked {
				return
			}
			run.built = true
			elems, readable := slogReadRun(from, name, variadic)
			if !readable {
				run.readable = false
				return
			}
			run.elems = append(run.elems, elems...)
		}
		// A declaration or assignment with more names than values is one call filling several,
		// which carries no key this rule can pair off.
		unreadable := func(names []*ast.Ident) {
			for _, id := range names {
				if run, tracked := runs[id.Name]; tracked {
					run.built, run.readable = true, false
				}
			}
		}

		walk(func(n ast.Node) bool {
			switch stmt := n.(type) {
			case *ast.AssignStmt:
				if len(stmt.Lhs) != len(stmt.Rhs) {
					unreadable(identsOf(stmt.Lhs))
					return true
				}
				for i, lhs := range stmt.Lhs {
					if id, isIdent := unparen(lhs).(*ast.Ident); isIdent {
						build(id.Name, stmt.Rhs[i])
					}
				}
			case *ast.ValueSpec:
				switch {
				case len(stmt.Values) == 0:
					// var attrs []any: declared empty, and an empty run carries no key.
					for _, id := range stmt.Names {
						if run, tracked := runs[id.Name]; tracked {
							run.built = true
						}
					}
				case len(stmt.Values) != len(stmt.Names):
					unreadable(stmt.Names)
				default:
					for i, id := range stmt.Names {
						build(id.Name, stmt.Values[i])
					}
				}
			}
			return true
		})

		// A closure writing to a run declared out here is seen by neither reading: this one
		// does not descend into the closure, and the closure's own reading has no spread site
		// in view. := inside the closure declares a different variable and changes nothing.
		ast.Inspect(body, func(n ast.Node) bool {
			closure, isClosure := n.(*ast.FuncLit)
			if !isClosure {
				return true
			}
			ast.Inspect(closure.Body, func(inner ast.Node) bool {
				assign, isAssign := inner.(*ast.AssignStmt)
				if !isAssign || assign.Tok == token.DEFINE {
					return true
				}
				for _, id := range identsOf(assign.Lhs) {
					if run, tracked := runs[id.Name]; tracked {
						run.built, run.readable = true, false
					}
				}
				return true
			})
			return true
		})

		for _, site := range sites {
			line := fset.Position(site.pos).Line
			if site.name == "" {
				violations = append(violations, slogViolation{file: rel, line: line,
					what: "attribute run spread into a record is not a named slice",
					fix: "build it as []any{...} in this function and spread that; an expression " +
						"this rule cannot follow carries keys nothing reads"})
				continue
			}
			if site.name == variadic {
				// The enclosing function's own run. Rule 6's declaration half makes it a
				// forwarder, so its callers' keys are read at their call sites.
				continue
			}
			if run := runs[site.name]; !run.built || !run.readable {
				violations = append(violations, slogViolation{file: rel, line: line,
					what: "attribute run " + strconv.Quote(site.name) + " is built in a form this rule cannot read",
					fix: "build it in this function out of []any{...}, make([]any, ...) and appends " +
						"onto itself; a run assembled any other way carries keys nothing reads"})
			}
		}
		for _, run := range runs {
			if run.built && run.readable {
				violations = append(violations, slogBareKeyViolations(run.elems, fset, rel)...)
			}
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			inBody(fn.Type, fn.Body)
		case *ast.FuncLit:
			inBody(fn.Type, fn.Body)
		}
		return true
	})
	return violations
}

// slogRun is one spread attribute run as this rule was able to follow it: every key/value
// expression assigned into it, and whether every assignment into it was a form it could read.
type slogRun struct {
	elems    []ast.Expr
	built    bool
	readable bool
}

// slogReadRun reads one assignment into a spread run. target is the run being built, so an append
// onto it is the run growing; variadic is the enclosing function's ...any parameter, the one
// spread this rule permits inside an append because rule 6 reads its callers' keys instead.
func slogReadRun(from ast.Expr, target, variadic string) ([]ast.Expr, bool) {
	switch built := unparen(from).(type) {
	case *ast.CompositeLit:
		if slogIsAnySlice(built.Type) {
			return built.Elts, true
		}
		return nil, false
	case *ast.CallExpr:
		fn, isBuiltin := unparen(built.Fun).(*ast.Ident)
		if !isBuiltin {
			return nil, false
		}
		switch fn.Name {
		case "make":
			// make([]any, 0, n): the run starts empty and the appends below carry it.
			return nil, len(built.Args) > 0 && slogIsAnySlice(built.Args[0])
		case "append":
			if len(built.Args) == 0 {
				return nil, false
			}
			base, readable := slogReadAppendBase(built.Args[0], target, variadic)
			if !readable {
				return nil, false
			}
			added := built.Args[1:]
			if built.Ellipsis != token.NoPos {
				if len(added) == 0 {
					return nil, false
				}
				spread, isIdent := unparen(added[len(added)-1]).(*ast.Ident)
				if variadic == "" || !isIdent || spread.Name != variadic {
					return nil, false
				}
				added = added[:len(added)-1]
			}
			return append(base, added...), true
		}
		return nil, false
	}
	return nil, false
}

// slogReadAppendBase reads what an append starts from. The run itself is the ordinary case and
// carries nothing new, since its own assignments are read where they are written. Any other
// identifier is a second slice this rule has not followed, which is the alias the refusal exists
// for; nil is the empty slice spelled as a value.
func slogReadAppendBase(from ast.Expr, target, variadic string) ([]ast.Expr, bool) {
	if id, isIdent := unparen(from).(*ast.Ident); isIdent {
		return nil, id.Name == target || id.Name == "nil"
	}
	return slogReadRun(from, target, variadic)
}

// identsOf is the plain identifiers among expressions, which is what an assignment's left side is
// when it is naming variables rather than indexing or dereferencing something.
func identsOf(exprs []ast.Expr) []*ast.Ident {
	var idents []*ast.Ident
	for _, expr := range exprs {
		if id, isIdent := unparen(expr).(*ast.Ident); isIdent {
			idents = append(idents, id)
		}
	}
	return idents
}

// slogIsAnySlice reports whether the type is []any or []interface{}, the element type an
// attribute run is built in.
func slogIsAnySlice(expr ast.Expr) bool {
	slice, isSlice := unparen(expr).(*ast.ArrayType)
	if !isSlice || slice.Len != nil {
		return false
	}
	switch elt := unparen(slice.Elt).(type) {
	case *ast.Ident:
		return elt.Name == "any"
	case *ast.InterfaceType:
		return elt.Methods == nil || len(elt.Methods.List) == 0
	}
	return false
}

// slogIsEmission reports whether fn is one of the ten package-level emission functions.
func slogIsEmission(fn string) bool {
	_, ok := slogEmissions[fn]
	return ok
}

// slogCarriesContext reports whether fn passes a context to the handler. The four *Context
// variants do, and so do Log and LogAttrs, whose first parameter is a context by construction.
func slogCarriesContext(fn string) bool {
	return strings.HasSuffix(fn, "Context") || fn == "Log" || fn == "LogAttrs"
}

// funcTakesRequestScope reports whether the signature has a context.Context or an *http.Request
// parameter, resolved through the file's imports so an aliased context or net/http is seen.
func funcTakesRequestScope(ft *ast.FuncType, importPaths map[string]string) bool {
	if ft.Params == nil {
		return false
	}
	for _, param := range ft.Params.List {
		typ := unparen(param.Type)
		if star, isPointer := typ.(*ast.StarExpr); isPointer {
			if pkg, name, ok := selectorPath(star.X, importPaths); ok && pkg == httpImportPath && name == "Request" {
				return true
			}
			continue
		}
		if pkg, name, ok := selectorPath(typ, importPaths); ok && pkg == contextImportPath && name == "Context" {
			return true
		}
	}
	return false
}

// selectorPath resolves pkg.Name written as a type or an expression to the imported path and the
// name.
func selectorPath(expr ast.Expr, importPaths map[string]string) (string, string, bool) {
	sel, ok := unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	return qualifiedSelector(sel, importPaths)
}

// slogAttrLiteralViolations reads the key out of a slog.Attr{Key: "x", ...} composite literal,
// which is how an attribute is built where a constructor will not do. The literal is looked for
// anywhere in the file rather than only under an emission, because a helper returning []slog.Attr
// writes its keys nowhere else.
func slogAttrLiteralViolations(lit *ast.CompositeLit, importPaths map[string]string, fset *token.FileSet, rel string) []slogViolation {
	pkg, name, ok := selectorPath(lit.Type, importPaths)
	if !ok || pkg != slogImportPath || name != "Attr" {
		return nil
	}
	var violations []slogViolation
	for _, elt := range lit.Elts {
		kv, isKeyed := elt.(*ast.KeyValueExpr)
		if !isKeyed {
			continue
		}
		if field, isIdent := kv.Key.(*ast.Ident); !isIdent || field.Name != "Key" {
			continue
		}
		if v, bad := slogKeyViolation(kv.Value, "slog.Attr", fset, rel); bad {
			violations = append(violations, v)
		}
	}
	return violations
}

// slogBareKeyViolations reads the keys out of a run of key/value arguments the way slog's own
// argsToAttrSlice does: a string is a key and consumes the argument after it, anything else is an
// already-built Attr and consumes one. Index parity would be wrong for the mixed form, where one
// slog.String sits among bare pairs.
func slogBareKeyViolations(args []ast.Expr, fset *token.FileSet, rel string) []slogViolation {
	var violations []slogViolation
	for i := 0; i < len(args); i++ {
		lit, isLiteral := unparen(args[i]).(*ast.BasicLit)
		if !isLiteral || lit.Kind != token.STRING {
			// Either an Attr, which consumes one argument, or a key computed at runtime, which
			// is the ceiling above: the walk keeps going and may read the next literal as a key.
			continue
		}
		if v, bad := slogKeyViolation(lit, "attribute", fset, rel); bad {
			violations = append(violations, v)
		}
		i++ // step over the value this key binds
	}
	return violations
}

// slogKeyViolation checks one attribute key. A key that is not a string literal is the computed
// key the ceiling above describes, and is skipped rather than reported.
func slogKeyViolation(expr ast.Expr, where string, fset *token.FileSet, rel string) (slogViolation, bool) {
	lit, isLiteral := unparen(expr).(*ast.BasicLit)
	if !isLiteral || lit.Kind != token.STRING {
		return slogViolation{}, false
	}
	key, err := strconv.Unquote(lit.Value)
	if err != nil {
		return slogViolation{}, false
	}
	at := slogViolation{file: rel, line: fset.Position(lit.Pos()).Line,
		what: where + " key " + strconv.Quote(key)}
	if reason, reserved := slogReservedKeys[key]; reserved {
		at.fix = reason
		return at, true
	}
	if reason, injected := slogInjectedKeys[key]; injected && !slogOwnsRequestID(rel) {
		at.fix = reason
		return at, true
	}
	if !slogKeyPattern.MatchString(key) {
		at.fix = "attribute keys are snake_case, ^[a-z][a-z0-9_]*$; decision 3 fixes the name for each concept"
		return at, true
	}
	return slogViolation{}, false
}

// slogMessageViolation checks the message argument against rules 1 and 2, reporting the first
// rule it breaks. The order is what makes each report name the thing to fix first: a message that
// is not a literal has no text to judge, and a capitalised prefix is reported as the capital.
func slogMessageViolation(expr ast.Expr, fset *token.FileSet, rel string) (slogViolation, bool) {
	at := slogViolation{file: rel, line: fset.Position(expr.Pos()).Line}

	lit, isLiteral := unparen(expr).(*ast.BasicLit)
	if !isLiteral || lit.Kind != token.STRING {
		at.what = "message is not a string literal"
		at.fix = "make the message a fixed literal and move every value into an attribute"
		return at, true
	}
	msg, err := strconv.Unquote(lit.Value)
	if err != nil {
		return slogViolation{}, false
	}

	first, size := utf8.DecodeRuneInString(msg)
	if size == 0 || !unicode.IsLower(first) {
		at.what = "message " + strconv.Quote(msg) + " does not start with a lowercase letter"
		at.fix = "messages are lowercase sentences; an empty, digit-led or punctuation-led message is not one"
		return at, true
	}
	if slogComponentPrefix.MatchString(msg) {
		at.what = "message " + strconv.Quote(msg) + " starts with a component prefix"
		at.fix = "drop the prefix; where the component matters it is an attribute"
		return at, true
	}
	for _, banned := range []string{"failed to", "error "} {
		if strings.HasPrefix(msg, banned) {
			at.what = "message " + strconv.Quote(msg) + " starts with " + strconv.Quote(banned)
			at.fix = `the one verb is "unable to", so the same event is spelled one way everywhere`
			return at, true
		}
	}
	return slogViolation{}, false
}
