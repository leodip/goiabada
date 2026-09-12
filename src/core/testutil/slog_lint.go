package testutil

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/errs"
)

// AssertSlogConvention holds production code to the part of the logging convention that sloglint
// cannot express. sloglint, enabled in .golangci.yml at the repository root and run over
// golangci-lint's type information by run-tests.sh's lint tier and CI's Lint job, holds the rest:
// a literal message with a lowercase first rune, snake_case attribute keys, err and request_id
// refused, and a *Context variant inside any function that has a context.Context or an
// *http.Request parameter at any enclosing depth. Being type-checked it resolves an aliased
// import, a shadowed builtin or a type alias for free, which is what a parse of one file spent
// 2,300 lines refusing approximations of before the review of #320 replaced them with this file.
//
// Five rules remain, each decidable from the text alone:
//
//  1. The message is a string literal at the call, and it carries no "component: " prefix and does
//     not open with "failed to" or "error ". sloglint's static-msg accepts a constant as well as a
//     literal and its msg-style reads literals only, so a constant is the one shape that would
//     pass every guard while carrying an opener this rule refuses; refusing anything that is not a
//     literal closes that without resolving constants. Nine component prefixes were in use before
//     the sweep and the tree spelled the same event three ways; the one verb is "unable to"
//     (decision 4). sloglint has no message-text option, so this is what it leaves of that decision.
//  2. slog.SetDefault, slog.New, slog.Default and slog.With are refused outside the files that own
//     the handler (decision 12), whether called or named as a value. slog.SetDefault is
//     process-global, so a second install silently replaces the one both servers configured, and a
//     *slog.Logger obtained anywhere else carries attributes no lint can see. sloglint's no-global
//     would also refuse the package-level calls the whole tree uses by design, so it cannot stand
//     in for this rule.
//  3. A `...` spread into a record, or into a registered forwarder, is refused unless the enclosing
//     top-level function is listed in slogSpreadSites. sloglint reads a key only where it is a
//     literal at the call it inspects; a run spread from a slice is invisible to it, and 179
//     camelCase keys survived the first sweep behind exactly that shape. The table names each
//     function that may spread and why: a forwarder, whose callers' keys sloglint reads because
//     .golangci.yml registers it under custom-funcs, or a builder whose every key is a literal in
//     its own body or is pinned by a test beside it. A closure inside a listed function is inside
//     the function a reader registered, and is admitted with it.
//  4. The forwarders in slogSpreadSites and the custom-funcs in .golangci.yml are one set, so a
//     forwarder cannot be admitted to spread here without sloglint reading its callers there. The
//     comparison is by name: msg-pos and args-pos are not read back against the signatures, so a
//     forwarder that grows a parameter with its args-pos left stale would have sloglint read its
//     callers' keys one position out while this rule stays green. Accepted rather than closed:
//     there are four entries, each offset was checked by planting a camelCase key at a call site
//     and seeing it reported, and reading signatures back is the machinery this file was cut to
//     stop carrying (#320, review of #321).
//  5. A plain slog.Debug, Info, Warn or Error is refused inside the directories slogRequestPathDirs
//     lists, unless the enclosing top-level function is named in slogPlainSites. sloglint's
//     context: scope demands the *Context variant only where a context.Context or *http.Request
//     parameter exists, so a helper written without either is admitted by it, and 26 records were
//     found in exactly that shape after the sweep (decision 2, amended). This rule is what stops
//     the shape coming back: in a package a request runs through, a record with no context to
//     carry request_id is refused whatever the helper's signature. The directories are enumerated
//     rather than inferred, and the two admitted functions are named with the reason no context
//     can reach them.
//
// A dot import of log/slog is refused outright, since it leaves no selector for rule 2 to
// resolve. Test files and mocks are exempt, as they are for AssertNoLegacyErrors: a test reads
// records through CaptureSlog rather than writing them.
//
// Passing dirs restricts the walk to those subdirectories of the source root, forward slashes and
// relative to it. Rule 4 is checked whatever dirs are passed.
func AssertSlogConvention(t *testing.T, dirs ...string) {
	t.Helper()

	root := SourceRoot(t)
	golangci := filepath.Join(filepath.Dir(root), golangciConfigName)

	violations, files, err := findSlogViolations(root, golangci, dirs)
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
		"A message is a string literal at the call and opens with neither a component prefix nor "+
		"\"failed to\" or \"error \"; "+
		"core/logging owns the handler and testutil.CaptureSlog is how a test reads records; a "+
		"run is spread into a record only inside a function listed in slogSpreadSites, and a "+
		"forwarder listed there is registered under custom-funcs in .golangci.yml, where sloglint "+
		"holds every other rule; a record written in a request-path package carries a context, "+
		"outside the functions slogPlainSites names (#320).",
		len(violations), files, strings.Join(lines, "\n\t"))
}

// slogViolation is one refused site, located.
type slogViolation struct {
	// file is relative to the source root, forward slashes; rule 4 reports on golangciConfigName.
	file string
	line int
	what string
	fix  string
}

const (
	slogImportPath = "log/slog"
	// golangciConfigName is the file at the repository root, one directory above the source root,
	// that carries sloglint's settings and the custom-funcs rule 4 compares against.
	golangciConfigName = ".golangci.yml"
)

// slogEmissions maps each package-level emission function in log/slog to the index its message
// occupies. slog.Info(msg, ...) puts it first, slog.InfoContext(ctx, msg, ...) second, and both
// slog.Log(ctx, level, msg, ...) and slog.LogAttrs(ctx, level, msg, ...) third.
var slogEmissions = map[string]int{
	"Debug": 0, "Info": 0, "Warn": 0, "Error": 0,
	"DebugContext": 1, "InfoContext": 1, "WarnContext": 1, "ErrorContext": 1,
	"Log": 2, "LogAttrs": 2,
}

// slogHandlerInstalls is rule 2's list: the four ways to replace the default logger or obtain one
// of your own. Handler constructors are absent on purpose, since building a slog.Handler installs
// nothing and core/logging's own code builds several.
var slogHandlerInstalls = map[string]bool{
	"SetDefault": true, "New": true, "Default": true, "With": true,
}

// slogHandlerOwners is rule 2's allowlist, by path rather than by package. Four are whole
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

// slogSpreadSite is one function admitted to spread a run into a record or into a forwarder.
//
// scope is the file or directory, relative to the source root, that declares it; name is the
// function or method name. forwarder is empty for a builder, and for a forwarder it is the name
// .golangci.yml registers under custom-funcs: the import path, a dot, the function name. A
// forwarder's callers are also resolved through it, by import path where the call is qualified
// and by scope where it is bare, so a spread at one of its call sites is rule 3's concern too.
type slogSpreadSite struct {
	scope     string
	name      string
	forwarder string
}

const (
	apiresponseImportPath = "github.com/leodip/goiabada/authserver/internal/apiresponse"
	apihandlersImportPath = "github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	handlersImportPath    = "github.com/leodip/goiabada/authserver/internal/handlers"
)

// slogSpreadSites is rule 3's table. Every production function that spreads a run into a record
// is here with its reason, and rule 3 refuses any other.
//
// The four forwarders take the caller's key/value run as a variadic ...any and put it in one
// record: the API's 500 writer, which 328 sites reach, its logging half, the apihandlers wrapper
// over it, and the one answer for a refused id_token_hint. Their callers' keys are read by
// sloglint at the call sites, which is what registering them under custom-funcs buys and what
// rule 4 holds.
//
// The two builders spread a run they assemble themselves. reportTrip's keys are "limiter" and a
// tier's keyField, whose value is a literal at each newTier call and is held by
// TestRateLimiter_EveryTierLogsUnderAConventionalKey in core/middleware. MiddlewareRequestLogger
// appends the request line's attributes under literal keys in its own body, conditionally, which
// is why it is a run and not one call.
var slogSpreadSites = []slogSpreadSite{
	{scope: "authserver/internal/apiresponse", name: "WriteInternalServerError",
		forwarder: apiresponseImportPath + ".WriteInternalServerError"},
	{scope: "authserver/internal/apiresponse", name: "LogInternalServerError",
		forwarder: apiresponseImportPath + ".LogInternalServerError"},
	{scope: "authserver/internal/handlers/apihandlers", name: "writeInternalServerError",
		forwarder: apihandlersImportPath + ".writeInternalServerError"},
	{scope: "authserver/internal/handlers", name: "rejectIdTokenHint",
		forwarder: handlersImportPath + ".rejectIdTokenHint"},
	{scope: "core/middleware", name: "reportTrip"},
	{scope: "core/middleware", name: "MiddlewareRequestLogger"},
}

// slogRequestPathDirs is rule 5's list: the directories, relative to the source root, that a
// request runs through, so that every record written there is one an operator will filter by
// request_id after a user reports a refusal. Both servers' handlers and middleware, the
// authserver's API response writers and the admin console's client of the auth server's API, the
// audit path's two packages, and the core packages the handlers call into on a request: the shared
// middleware, the validators, token and code issuance, the token parsers, the handler helpers and
// the session store.
//
// Left out on purpose, each a ceiling recorded in the PR of #320 rather than a site this rule
// admits: core/data, whose transaction and statement records run under RunInTransaction with no
// context to reach them short of changing every Database method; and core/stringutil, whose one
// record is written from a template function like addUrlParam below. A startup, worker or main
// package is not a request path and is not listed.
//
// authserver/internal/audit and core/auditlog were the third such ceiling and are now listed:
// AuditLogger.Log takes a context and its 126 call sites pass the request's, so a plain record
// there is refused from #328 onward. The compiler forces the parameter; what it cannot force is
// that the context is the request's, which is AssertAuditLogContext's rule over this same list.
var slogRequestPathDirs = []string{
	"authserver/internal/audit",
	"authserver/internal/handlers",
	"authserver/internal/middleware",
	"authserver/internal/apiresponse",
	"adminconsole/internal/handlers",
	"adminconsole/internal/middleware",
	"adminconsole/internal/apiclient",
	"core/auditlog",
	"core/middleware",
	"core/validators",
	"core/oauth",
	"core/oauthdb",
	"core/handlerhelpers",
	"core/sessionstore",
}

// slogPlainSite is one top-level function inside slogRequestPathDirs admitted to write a plain
// record. scope is the file that declares it, relative to the source root, so an admission cannot
// leak to a namesake elsewhere in the package; name is the function name.
type slogPlainSite struct {
	scope string
	name  string
}

// slogPlainSites is rule 5's table. Two functions, each with the reason no context reaches it:
// parseCIDRs runs once, when the real-IP middleware is constructed at startup, and its record is
// about the configuration rather than a request; addUrlParam is a template function, and
// html/template calls it with no context, so a record it writes has nothing to carry request_id
// on. A third function of the second kind, stringutil.ConvertToString, sits outside the listed
// directories and is named in the comment on them.
var slogPlainSites = []slogPlainSite{
	{scope: "core/middleware/middleware_realip.go", name: "parseCIDRs"},
	{scope: "core/handlerhelpers/template_funcs.go", name: "addUrlParam"},
}

var (
	// slogComponentPrefix is one token, then a colon and a space. Anchored and token-shaped so a
	// colon later in the message is not read as a prefix.
	slogComponentPrefix = regexp.MustCompile(`^[^\s:]+: `)
	// slogRefusedOpeners are the two ways the tree used to spell what "unable to" says.
	slogRefusedOpeners = []string{"failed to", "error "}
)

// findSlogViolations parses every non-test Go file under root, or under the named subdirectories
// of root, reports each refused site along with the number of files it parsed, and then compares
// the forwarder table against the custom-funcs in the golangci-lint configuration at golangci.
func findSlogViolations(root, golangci string, dirs []string) ([]slogViolation, int, error) {
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

	tableViolations, err := slogForwarderTableViolations(golangci)
	if err != nil {
		return nil, files, err
	}
	violations = append(violations, tableViolations...)

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
// hand-written scaffolding that emits nothing. Both exemptions match AssertNoLegacyErrors and
// the exclusions in .golangci.yml, so one answer about what production code means holds for
// every guard.
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

// slogWithinScope reports whether rel is the scope itself or sits under it: an exact match on a
// file, or anything under a directory.
func slogWithinScope(rel, scope string) bool {
	return rel == scope || strings.HasPrefix(rel, scope+"/")
}

// slogHandlerOwner reports whether rule 2 admits this file.
func slogHandlerOwner(rel string) bool {
	for _, owner := range slogHandlerOwners {
		if slogWithinScope(rel, owner) {
			return true
		}
	}
	return false
}

// slogRequestPath reports whether rel sits under one of the directories rule 5 lists.
func slogRequestPath(rel string) bool {
	for _, dir := range slogRequestPathDirs {
		if slogWithinScope(rel, dir) {
			return true
		}
	}
	return false
}

// slogPlainAdmitted reports whether a top-level function named name in the file rel is listed in
// slogPlainSites. A call outside any top-level function, in a package-level composite literal for
// instance, has no name to admit and is refused.
func slogPlainAdmitted(rel, name string) bool {
	for _, site := range slogPlainSites {
		if site.name == name && rel == site.scope {
			return true
		}
	}
	return false
}

// slogSpreadAdmitted reports whether a top-level function named name in the file rel is listed in
// slogSpreadSites.
func slogSpreadAdmitted(rel, name string) bool {
	for _, site := range slogSpreadSites {
		if site.name == name && slogWithinScope(rel, site.scope) {
			return true
		}
	}
	return false
}

// slogForwarderPackage splits a forwarder's registered name into its import path and function
// name at the last dot.
func (s slogSpreadSite) forwarderPackage() (string, string) {
	i := strings.LastIndex(s.forwarder, ".")
	if i < 0 {
		return "", s.forwarder
	}
	return s.forwarder[:i], s.forwarder[i+1:]
}

// slogIsForwarderCall reports whether call reaches one of the registered forwarders, either
// qualified through an import of its package or bare from inside its scope.
func slogIsForwarderCall(call *ast.CallExpr, importPaths map[string]string, rel string) (slogSpreadSite, bool) {
	fun := unparen(call.Fun)
	if path, name, ok := qualifiedCall(call, importPaths); ok {
		for _, site := range slogSpreadSites {
			if site.forwarder == "" {
				continue
			}
			pkg, fn := site.forwarderPackage()
			if pkg == path && fn == name {
				return site, true
			}
		}
		return slogSpreadSite{}, false
	}
	ident, ok := fun.(*ast.Ident)
	if !ok {
		return slogSpreadSite{}, false
	}
	for _, site := range slogSpreadSites {
		if site.forwarder != "" && site.name == ident.Name && slogWithinScope(rel, site.scope) {
			return site, true
		}
	}
	return slogSpreadSite{}, false
}

// slogViolationsInFile applies rules 1, 2, 3 and 5 and the dot-import refusal to one parsed file.
func slogViolationsInFile(file *ast.File, fset *token.FileSet, rel string) []slogViolation {
	var violations []slogViolation
	report := func(pos token.Pos, what, fix string) {
		violations = append(violations, slogViolation{
			file: rel, line: fset.Position(pos).Line, what: what, fix: fix,
		})
	}

	// importPaths maps the name a file actually writes at a call site to the path it imports, so
	// an aliased log/slog resolves like any other, exactly as errors_lint.go reads its imports.
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
			if path == slogImportPath {
				report(spec.Pos(), `dot import of "log/slog"`,
					"import it under its own name; a dot import leaves no selector for the handler-ownership rule to resolve")
			}
			continue
		}
		if name == "_" {
			continue
		}
		importPaths[name] = path
	}

	// Rule 2 reads every selector rather than every call, so slog.New handed round as a value is
	// the same finding as slog.New(...): the logger it builds is obtained one indirection later.
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		path, name, ok := qualifiedSelector(sel, importPaths)
		if !ok || path != slogImportPath || !slogHandlerInstalls[name] {
			return true
		}
		if slogHandlerOwner(rel) {
			return true
		}
		report(sel.Pos(), "slog."+name+" outside the files that own the handler",
			"core/logging installs the one handler and testutil.CaptureSlog is how a test reads records; log through the package-level slog functions")
		return true
	})

	// Rules 1, 3 and 5 read calls, with the enclosing top-level function known for rules 3 and 5.
	for _, decl := range file.Decls {
		enclosing := ""
		if fn, ok := decl.(*ast.FuncDecl); ok {
			enclosing = fn.Name.Name
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			spread := call.Ellipsis.IsValid()
			admitted := enclosing != "" && slogSpreadAdmitted(rel, enclosing)

			if path, name, ok := qualifiedCall(call, importPaths); ok && path == slogImportPath {
				msgIndex, isEmission := slogEmissions[name]
				if !isEmission {
					return true
				}
				if msgIndex < len(call.Args) {
					msgArg := unparen(call.Args[msgIndex])
					if lit, isLit := msgArg.(*ast.BasicLit); isLit && lit.Kind == token.STRING {
						if msg, err := strconv.Unquote(lit.Value); err == nil {
							if what, fix, bad := slogMessageOpener(msg); bad {
								report(lit.Pos(), what, fix)
							}
						}
					} else {
						report(msgArg.Pos(), "message is not a string literal",
							"write the message as a literal at the call, and put the value in an attribute; a constant or an expression is the one shape that carries an opener past every guard")
					}
				}
				if spread && !admitted {
					report(call.Pos(), "a run spread into a record outside slogSpreadSites",
						"write the keys as literals at the call so sloglint reads them, or list the function in slogSpreadSites with the reason its keys are read elsewhere")
				}
				if msgIndex == 0 && slogRequestPath(rel) && !slogPlainAdmitted(rel, enclosing) {
					report(call.Pos(), "a plain slog."+name+" in a request-path package",
						"take a context.Context and call slog."+name+"Context so the handler injects request_id, or list the function in slogPlainSites with the reason no request reaches it")
				}
				return true
			}

			if site, isForwarder := slogIsForwarderCall(call, importPaths, rel); isForwarder && spread && !admitted {
				report(call.Pos(), "a run spread into "+site.name+" outside slogSpreadSites",
					"write the keys as literals at the call so sloglint reads them through custom-funcs, or list the function in slogSpreadSites")
			}
			return true
		})
	}

	return violations
}

// slogMessageOpener is rule 1: the three openers a literal message may not carry.
func slogMessageOpener(msg string) (what, fix string, bad bool) {
	if slogComponentPrefix.MatchString(msg) {
		return "message carries a component prefix",
			"drop the prefix; the component is an attribute where it matters, and the message is the event",
			true
	}
	for _, opener := range slogRefusedOpeners {
		if strings.HasPrefix(msg, opener) {
			return `message opens with "` + opener + `"`,
				`say what could not be done, opening with "unable to" where a verb is needed`,
				true
		}
	}
	return "", "", false
}

// slogForwarderTableViolations is rule 4. It reads the custom-funcs names out of the golangci-lint
// configuration at path and holds them equal to the forwarders in slogSpreadSites.
//
// The read is textual: the `- name:` entries under the `custom-funcs:` key, taken while the
// indentation stays deeper than that key's. That is enough for the one file this tree has, and a
// YAML parser would be a dependency the test tiers do not otherwise carry.
func slogForwarderTableViolations(path string) ([]slogViolation, error) {
	rel := filepath.Base(path)
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []slogViolation{{
				file: rel, line: 0,
				what: "no golangci-lint configuration beside the source root",
				fix:  "every forwarder in slogSpreadSites is registered under sloglint's custom-funcs there",
			}}, nil
		}
		return nil, errs.Wrapf(err, "reading %s", path)
	}

	registered := map[string]int{}
	customFuncsLine := 0
	indent := -1
	for i, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if indent < 0 {
			if strings.HasPrefix(trimmed, "custom-funcs:") {
				indent = len(line) - len(strings.TrimLeft(line, " "))
				customFuncsLine = i + 1
			}
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if len(line)-len(strings.TrimLeft(line, " ")) <= indent {
			break
		}
		if rest, ok := strings.CutPrefix(trimmed, "- name:"); ok {
			registered[strings.TrimSpace(rest)] = i + 1
		}
	}

	var violations []slogViolation
	if customFuncsLine == 0 {
		return []slogViolation{{
			file: rel, line: 0,
			what: "no custom-funcs under sloglint",
			fix:  "register every forwarder in slogSpreadSites so sloglint reads the keys at its call sites",
		}}, nil
	}

	listed := map[string]bool{}
	for _, site := range slogSpreadSites {
		if site.forwarder == "" {
			continue
		}
		listed[site.forwarder] = true
		if _, ok := registered[site.forwarder]; !ok {
			violations = append(violations, slogViolation{
				file: rel, line: customFuncsLine,
				what: site.forwarder + " is a forwarder in slogSpreadSites but not a custom-func",
				fix:  "register it with msg-pos -1 and the args-pos its run begins at, or its callers' keys are read by nothing",
			})
		}
	}
	for name, line := range registered {
		if !listed[name] {
			violations = append(violations, slogViolation{
				file: rel, line: line,
				what: name + " is a custom-func but not a forwarder in slogSpreadSites",
				fix:  "list it there so the spread in its body is admitted for the reason the registration states",
			})
		}
	}
	return violations, nil
}
