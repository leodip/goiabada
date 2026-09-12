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
//
// Resolution is by import path rather than by the text at the call site, as errors_lint.go does
// and for the same reason: an aliased log/slog, context or net/http would walk straight past a
// textual check. A dot import of log/slog is refused outright, because it leaves no selector for
// any of the five rules to resolve.
//
// ceiling: three shapes are outside a parse and are therefore not held. An attribute key computed
// at runtime is skipped rather than reported, and a non-literal expression at a key position also
// costs the walk its alignment for the rest of that call's arguments, so a string literal after
// one may be read as a key; nothing in this tree writes a computed key today. An elided composite
// literal inside a []slog.Attr, {Key: "x"}, has no type to resolve and is skipped. And the methods
// on a *slog.Logger are not linted, which rule 5 is what makes safe: outside the handler's own
// files there is no way to get one. Revisit when a site needs a computed key, or when rule 5
// grows a sixth exemption; closing any of them means running this over go/packages-loaded type
// information rather than one parsed file (#320).
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
		"reads records (#320).",
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
	return violations, files, nil
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
			// for any of the five rules to resolve and the whole file walks past them. Refusing
			// the import is the answer rather than resolving unqualified calls, which would also
			// have to model every local declaration that shadows one.
			if path == slogImportPath {
				violations = append(violations, slogViolation{
					file: rel,
					line: fset.Position(spec.Pos()).Line,
					what: `dot import of "log/slog"`,
					fix:  "import it under its own name; a dot import hides every slog call from this rule",
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
			if !resolved || pkg != slogImportPath {
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

		call, isCall := n.(*ast.CallExpr)
		if !isCall {
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

	return violations
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
