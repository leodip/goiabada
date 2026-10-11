package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/guard"
)

// TestHandlers_ErrorBindingsCarryNoEnglishSentence refuses a console page that writes its own
// refusal into the page in English.
//
// A page shows a refusal through its error binding: the "error" entry of the map it renders with,
// usually filled by a closure such as renderError that redraws the form. Nineteen refusals were
// written there as English literals, so an administrator reading the console in Portuguese met
// English on the page they had just filled in, beside labels and buttons in Portuguese. They come
// from the catalog now, through i18n.T or a LocalizedError, and this guard is what keeps the next
// one from being written the way the old ones were: a new form copied from an old one (#559
// decision 4).
//
// The rule is about what reaches the binding, not where the sentence was written. A string
// literal, a package-level string constant, a fmt.Sprint* call and a concatenation with a literal
// piece are each a sentence the catalog never saw. Anything else passes: i18n.T, a LocalizedError's
// Localize, the API's own description (apiErr.Message), a variable. The empty literal passes too,
// since it is the page drawn with no refusal at all.
//
// A binding is either the "error" entry itself, or a call to a function that puts one of its
// parameters into that entry: a closure assigned to a name inside the handler, whatever the name
// (renderError, renderEnrollmentError, renderDisableError), or a package-level function. The issue
// that found these counted eighteen by searching for `renderError("` and missed the nineteenth
// behind a closure named otherwise, which is why the binder is recognized by what it does rather
// than by its name.
//
// Two boundaries, stated rather than discovered later. A sentence stored in a variable first and
// then bound is not seen: the scan reads the expression at the binding and does not trace values.
// And the scope is the page handlers under internal/handlers; the JSON writers in internal/render
// write an "error" field that is an OAuth error code, not a sentence, and are out of it.
func TestHandlers_ErrorBindingsCarryNoEnglishSentence(t *testing.T) {
	assertNoErrorBindingSentences(t, guard.SourceRoot(t), errorBindingDirs)
}

// errorBindingDirs is the walk's scope, relative to the source root: the console's page handlers,
// this package and its six children.
var errorBindingDirs = []string{"adminconsole/internal/handlers"}

// errorBindingSentence is one sentence the walk found handed to an error binding, located.
type errorBindingSentence struct {
	file string
	line int
	// what says which binding it reached and what it was: `renderError's message is a string
	// literal`, `the "error" entry is a formatted string`.
	what string
}

// assertNoErrorBindingSentences is the reporting half, taking the root and the scope as parameters
// and failing through a guard.Reporter so a rule test can drive it against a fixture tree.
func assertNoErrorBindingSentences(r guard.Reporter, root string, dirs []string) {
	r.Helper()

	sentences, bindings, err := findErrorBindingSentences(root, dirs)
	if err != nil {
		r.Fatalf("%v", err)
	}
	// A walk that matched no binding at all would pass while checking nothing, which is the one way
	// a guard like this fails in the permissive direction.
	if bindings == 0 {
		r.Fatalf("found no error bindings under %s; the walk is no longer reaching the console's "+
			"pages, or the binding shape has moved", strings.Join(dirs, ", "))
	}

	for _, s := range sentences {
		r.Errorf("%s:%d: %s, so the page shows it in English whatever language it is rendered in. "+
			"Put the sentence in the catalogs, active.en.toml and active.pt-BR.toml, under an "+
			"adminconsole.* key (or a handler.* key the API shares), and bind "+
			"i18n.T(r.Context(), key) (#559 decision 4)", s.file, s.line, s.what)
	}
}

// findErrorBindingSentences walks dirs under root and returns every sentence handed to an error
// binding in a non-test Go file, and how many bindings it read.
func findErrorBindingSentences(root string, dirs []string) ([]errorBindingSentence, int, error) {
	packages := map[string][]string{}
	for _, dir := range dirs {
		start := filepath.Join(root, filepath.FromSlash(dir))
		err := filepath.WalkDir(start, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "mocks" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			packages[filepath.Dir(path)] = append(packages[filepath.Dir(path)], path)
			return nil
		})
		if err != nil {
			return nil, 0, errs.Wrapf(err, "walking %s", start)
		}
	}

	var sentences []errorBindingSentence
	bindings := 0
	fset := token.NewFileSet()
	for _, paths := range packages {
		files := map[string]*ast.File{}
		for _, path := range paths {
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				// A file that does not parse is a compile error the build owns, and reporting it
				// here would send the reader to the wrong place.
				continue
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return nil, 0, errs.Wrapf(err, "relating %s to %s", path, root)
			}
			files[filepath.ToSlash(rel)] = f
		}
		found, n := errorBindingSentencesInPackage(fset, files)
		sentences = append(sentences, found...)
		bindings += n
	}

	sort.Slice(sentences, func(i, j int) bool {
		if sentences[i].file != sentences[j].file {
			return sentences[i].file < sentences[j].file
		}
		return sentences[i].line < sentences[j].line
	})
	return sentences, bindings, nil
}

// errorBindingSentencesInPackage is the rule over one package: the package-level functions that
// bind a parameter are binders everywhere in it, and a closure that does is a binder in the
// function that names it.
func errorBindingSentencesInPackage(fset *token.FileSet, files map[string]*ast.File) ([]errorBindingSentence, int) {
	consts := map[string]bool{}
	topBinders := map[string]int{}
	for _, f := range files {
		for name, value := range packageStringConsts(f) {
			consts[name] = value != ""
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			if index, ok := boundParam(fn.Type, fn.Body); ok {
				topBinders[fn.Name.Name] = index
			}
		}
	}

	var sentences []errorBindingSentence
	bindings := 0
	for rel, f := range files {
		at := func(n ast.Node) int { return fset.Position(n.Pos()).Line }
		check := func(expr ast.Expr, binding string) {
			bindings++
			if what, ok := sentenceKind(expr, consts); ok {
				sentences = append(sentences, errorBindingSentence{file: rel, line: at(expr),
					what: binding + " is " + what})
			}
		}

		for _, decl := range f.Decls {
			binders := map[string]int{}
			for name, index := range topBinders {
				binders[name] = index
			}
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				for name, index := range closureBinders(fn.Body) {
					binders[name] = index
				}
			}

			ast.Inspect(decl, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.KeyValueExpr:
					if isErrorKey(node.Key) {
						check(node.Value, `the "error" entry`)
					}
				case *ast.CallExpr:
					ident, ok := ast.Unparen(node.Fun).(*ast.Ident)
					if !ok {
						return true
					}
					index, ok := binders[ident.Name]
					if ok && index < len(node.Args) {
						check(node.Args[index], ident.Name+"'s message")
					}
				}
				return true
			})
		}
	}
	return sentences, bindings
}

// closureBinders returns the closures a function body assigns to a name, `renderError := func(...)`
// or `var renderError = func(...)`, that put one of their parameters into an "error" entry, with
// the index of that parameter.
func closureBinders(body *ast.BlockStmt) map[string]int {
	binders := map[string]int{}
	record := func(names []*ast.Ident, values []ast.Expr) {
		if len(names) != len(values) {
			return
		}
		for i, value := range values {
			lit, ok := ast.Unparen(value).(*ast.FuncLit)
			if !ok {
				continue
			}
			if index, ok := boundParam(lit.Type, lit.Body); ok {
				binders[names[i].Name] = index
			}
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			var names []*ast.Ident
			for _, lhs := range node.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok {
					return true
				}
				names = append(names, ident)
			}
			record(names, node.Rhs)
		case *ast.ValueSpec:
			record(node.Names, node.Values)
		}
		return true
	})
	return binders
}

// boundParam reports the index of the parameter a function puts into an "error" entry, if it puts
// one there.
func boundParam(fnType *ast.FuncType, body *ast.BlockStmt) (int, bool) {
	params := map[string]int{}
	index := 0
	for _, field := range fnType.Params.List {
		if len(field.Names) == 0 {
			index++
			continue
		}
		for _, name := range field.Names {
			params[name.Name] = index
			index++
		}
	}
	found, bound := 0, false
	ast.Inspect(body, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok || !isErrorKey(kv.Key) {
			return true
		}
		ident, ok := ast.Unparen(kv.Value).(*ast.Ident)
		if !ok {
			return true
		}
		if i, ok := params[ident.Name]; ok {
			found, bound = i, true
		}
		return true
	})
	return found, bound
}

// isErrorKey reports whether a map key is the string "error".
func isErrorKey(key ast.Expr) bool {
	value, ok := stringLiteral(key)
	return ok && value == "error"
}

// sentenceKind reports whether an expression bound as a refusal is a sentence the catalog never
// saw, and says what kind.
func sentenceKind(expr ast.Expr, consts map[string]bool) (string, bool) {
	expr = ast.Unparen(expr)
	if value, ok := stringLiteral(expr); ok {
		return "a string literal", value != ""
	}
	switch e := expr.(type) {
	case *ast.Ident:
		if consts[e.Name] {
			return "a string constant", true
		}
	case *ast.BinaryExpr:
		if e.Op == token.ADD && (hasSentencePiece(e.X, consts) || hasSentencePiece(e.Y, consts)) {
			return "a concatenated string", true
		}
	case *ast.CallExpr:
		if sel, ok := ast.Unparen(e.Fun).(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" && strings.HasPrefix(sel.Sel.Name, "Sprint") {
				return "a formatted string", true
			}
		}
	}
	return "", false
}

// hasSentencePiece reports whether one operand of a concatenation is written text: a literal, a
// string constant, a formatted string, or a concatenation holding one.
func hasSentencePiece(expr ast.Expr, consts map[string]bool) bool {
	if _, ok := stringLiteral(ast.Unparen(expr)); ok {
		return true
	}
	_, ok := sentenceKind(expr, consts)
	return ok
}

// stringLiteral returns the value of a string literal.
func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

// packageStringConsts returns the file's package-level string constants and their values.
func packageStringConsts(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if i >= len(value.Values) {
					continue
				}
				if lit, ok := stringLiteral(value.Values[i]); ok {
					out[name.Name] = lit
				}
			}
		}
	}
	return out
}

// ---- the rule ------------------------------------------------------------------------------------

func TestErrorBindings_FinderRuleTable(t *testing.T) {
	tests := []struct {
		name  string
		src   string
		found []string
	}{
		{
			name: "renderError handed a literal",
			src: `package p
func HandleX() {
	renderError := func(message string) { bind := map[string]interface{}{"error": message}; _ = bind }
	renderError("Group identifier is required.")
}`,
			found: []string{"renderError's message is a string literal"},
		},
		{
			name: "a closure named otherwise is a binder by what it does",
			src: `package p
func HandleX() {
	renderEnrollmentError := func(message string) { _ = map[string]interface{}{"otpEnabled": false, "error": message} }
	renderEnrollmentError("OTP code is required.")
}`,
			found: []string{"renderEnrollmentError's message is a string literal"},
		},
		{
			name: "a closure declared with var, binding its second parameter",
			src: `package p
func HandleX() {
	var redraw = func(field, message string) { _ = map[string]interface{}{"field": field, "error": message} }
	redraw("email", "The email address cannot be empty.")
}`,
			found: []string{"redraw's message is a string literal"},
		},
		{
			name: "a package-level binder called from another function",
			src: `package p
func redrawForm(w int, message string) { _ = map[string]interface{}{"error": message} }
func HandleX() { redrawForm(1, "Attribute key is required") }`,
			found: []string{"redrawForm's message is a string literal"},
		},
		{
			name: "the error entry written as a literal",
			src: `package p
func HandleX() { _ = map[string]interface{}{"error": "The email and email confirmation entries must be identical."} }`,
			found: []string{`the "error" entry is a string literal`},
		},
		{
			name: "a formatted refusal",
			src: `package p
func HandleX(n int) {
	renderError := func(message string) { _ = map[string]interface{}{"error": message} }
	renderError(fmt.Sprintf("Invalid value %d.", n))
}`,
			found: []string{"renderError's message is a formatted string"},
		},
		{
			name: "a concatenated refusal",
			src: `package p
func HandleX(field string) { _ = map[string]interface{}{"error": "Invalid value for " + field} }`,
			found: []string{`the "error" entry is a concatenated string`},
		},
		{
			name: "a package-level string constant",
			src: `package p
const refusal = "Destination email is required."
func HandleX() { _ = map[string]interface{}{"error": refusal} }`,
			found: []string{`the "error" entry is a string constant`},
		},
		{
			name: "the catalog, the API's sentence, a variable and no refusal at all pass",
			src: `package p
func HandleX(apiErr *APIError, message string) {
	renderError := func(message string) { _ = map[string]interface{}{"error": message} }
	renderError(i18n.T(r.Context(), "adminconsole.admin_groups.delete.refusal.identifier_required"))
	renderError(i18n.NewLocalizedError(i18n.ErrCodeOtpCodeRequired, nil).Localize(r.Context()))
	renderError(apiErr.Message)
	renderError(message)
	_ = map[string]interface{}{"error": ""}
	_ = map[string]interface{}{"error": nil}
}`,
		},
		{
			name: "a closure that binds no error is not a binder",
			src: `package p
func HandleX() {
	setTitle := func(title string) { _ = map[string]interface{}{"title": title} }
	setTitle("Delete group")
}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "p.go", tc.src, 0)
			require.NoError(t, err)

			sentences, _ := errorBindingSentencesInPackage(fset, map[string]*ast.File{"p.go": f})

			var found []string
			for _, s := range sentences {
				found = append(found, s.what)
			}
			assert.ElementsMatch(t, tc.found, found)
		})
	}
}

// ---- the reporting half --------------------------------------------------------------------------

// errorBindingFixture writes a one-directory tree and returns its root.
func errorBindingFixture(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
	}
	return root
}

// TestErrorBindings_TheGuardPassesATreeBindingTheCatalog is the clean direction, and it is what
// keeps the failing case below from passing for the wrong reason.
func TestErrorBindings_TheGuardPassesATreeBindingTheCatalog(t *testing.T) {
	root := errorBindingFixture(t, map[string]string{
		"adminconsole/internal/handlers/admingrouphandlers/delete.go": `package admingrouphandlers

func HandleDeletePost() {
	renderError := func(message string) { _ = map[string]interface{}{"error": message} }
	renderError(i18n.T(r.Context(), "adminconsole.admin_groups.delete.refusal.identifier_required"))
}
`,
	})

	report := guard.Run(func(r guard.Reporter) {
		assertNoErrorBindingSentences(r, root, errorBindingDirs)
	})

	assert.False(t, report.Failed(), "a tree binding the catalog failed the guard: %s", report.Text())
}

// TestErrorBindings_TheGuardFailsOnAnEnglishSentence is the direction the guard exists for: a new
// form copied from an old one, with its refusal written in English.
func TestErrorBindings_TheGuardFailsOnAnEnglishSentence(t *testing.T) {
	root := errorBindingFixture(t, map[string]string{
		"adminconsole/internal/handlers/admingrouphandlers/delete.go": `package admingrouphandlers

func HandleDeletePost() {
	renderError := func(message string) { _ = map[string]interface{}{"error": message} }
	renderError("Group identifier is required.")
}
`,
	})

	report := guard.Run(func(r guard.Reporter) {
		assertNoErrorBindingSentences(r, root, errorBindingDirs)
	})

	require.True(t, report.Failed(), "an English refusal passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	require.Len(t, report.Errors, 1)
	assert.Contains(t, report.Text(), "adminconsole/internal/handlers/admingrouphandlers/delete.go:5")
	assert.Contains(t, report.Text(), "renderError's message is a string literal")
	assert.Contains(t, report.Text(), "i18n.T(r.Context(), key)")
	assert.Contains(t, report.Text(), "#559 decision 4")
}

// TestErrorBindings_TheGuardIsFatalOnAWalkThatReachedNothing pins this guard's answer to the empty
// walk: a scope that moved, or a binding shape that changed, would otherwise pass every run while
// checking nothing.
func TestErrorBindings_TheGuardIsFatalOnAWalkThatReachedNothing(t *testing.T) {
	root := errorBindingFixture(t, map[string]string{
		"adminconsole/internal/handlers/doc.go": "package handlers\n",
	})

	report := guard.Run(func(r guard.Reporter) {
		assertNoErrorBindingSentences(r, root, errorBindingDirs)
	})

	require.True(t, report.Stopped, "a walk that read no binding must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "found no error bindings under adminconsole/internal/handlers")
}
