package handlerhelpers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/guard"
)

// This package's production files name one thing from apiclient: the *APIError the classifiers
// route on.
//
// The edge came with the classifiers from the handlers package (#440). It is sound layering only
// that narrowly: apiclient is a leaf that imports nothing of this module, and the classifier and the
// error type it reads change together, which is not true of the executor or any of the 106 methods
// beside them. A renderer that started calling the API would be a page reaching past its handler.
//
// Imports are parsed rather than text matched, so an alias binds the name it binds, and a dot or
// blank import, which would hide what the file takes, is refused outright.

// apiclientPath is the package the edge is about.
const apiclientPath = "github.com/leodip/goiabada/adminconsole/internal/apiclient"

// apiclientAllowed is every apiclient name a production file here may select.
var apiclientAllowed = map[string]bool{"APIError": true}

// apiclientUse is one apiclient name a production file selects, or, with name empty, an import that
// binds no selectable name at all.
type apiclientUse struct {
	file string
	line int
	// name is the selected identifier, empty for a dot or blank import.
	name string
	// binding is the name the file imports apiclient under.
	binding string
}

// findApiclientUses reads the production Go files directly in dir, not its subdirectories, and
// returns every apiclient name they select that apiclientAllowed does not hold, and every dot or
// blank import of apiclient. It returns the number of files it parsed, so the reporting half can
// tell "nothing to report" from "nothing was read".
func findApiclientUses(dir string) ([]apiclientUse, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}

	var found []apiclientUse
	files := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			return nil, files, err
		}
		files++

		binding := ""
		var importPos token.Pos
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil || path != apiclientPath {
				continue
			}
			binding = "apiclient"
			if spec.Name != nil {
				binding = spec.Name.Name
			}
			importPos = spec.Pos()
		}
		if binding == "" {
			continue
		}
		if binding == "." || binding == "_" {
			found = append(found, apiclientUse{file: name, line: fset.Position(importPos).Line, binding: binding})
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == binding && !apiclientAllowed[sel.Sel.Name] {
				found = append(found, apiclientUse{
					file:    name,
					line:    fset.Position(sel.Pos()).Line,
					name:    sel.Sel.Name,
					binding: binding,
				})
			}
			return true
		})
	}
	return found, files, nil
}

// assertApiclientEdge is the reporting half, failing through a guard.Reporter so a rule test can
// drive it against a fixture directory.
func assertApiclientEdge(r guard.Reporter, dir string) {
	r.Helper()

	found, files, err := findApiclientUses(dir)
	if err != nil {
		r.Fatalf("reading %s: %v", dir, err)
	}
	if files == 0 {
		r.Fatalf("read no production Go files under %s, so the walk is not reaching the package", dir)
	}
	if len(found) == 0 {
		return
	}

	lines := make([]string, 0, len(found))
	for _, use := range found {
		if use.name == "" {
			lines = append(lines, use.file+":"+strconv.Itoa(use.line)+": imports apiclient as "+
				strconv.Quote(use.binding)+", which hides what it takes from it")
			continue
		}
		lines = append(lines, use.file+":"+strconv.Itoa(use.line)+": "+use.binding+"."+use.name)
	}
	r.Errorf("%d apiclient reference(s) under %s beyond APIError:\n\t%s\n\n"+
		"handlerhelpers names apiclient.APIError for the classifiers, and nothing else of apiclient "+
		"(#440): a page that calls the API reaches past its handler.",
		len(found), dir, strings.Join(lines, "\n\t"))
}

// TestApiclientEdge_NamesAPIErrorOnly holds this package's real files to the rule.
func TestApiclientEdge_NamesAPIErrorOnly(t *testing.T) {
	assertApiclientEdge(t, ".")
}

// The finder over each shape a file can take: the permitted name under the default binding and an
// alias, forbidden names under both, the two imports that hide what they take, and what is out of
// scope -- a test file, a subdirectory, and another package bound to the name apiclient.
func TestApiclientEdge_FinderReadsTheBindingAndNotTheSpelling(t *testing.T) {
	dir := t.TempDir()
	writeEdgeFixture(t, dir, "classifier.go", `package handlerhelpers

import (
	"errors"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
)

func classify(err error) bool {
	var apiErr *apiclient.APIError
	return errors.As(err, &apiErr)
}
`)
	writeEdgeFixture(t, dir, "aliased_allowed.go", `package handlerhelpers

import ac "github.com/leodip/goiabada/adminconsole/internal/apiclient"

var _ *ac.APIError
`)
	writeEdgeFixture(t, dir, "renderer.go", `package handlerhelpers

import "github.com/leodip/goiabada/adminconsole/internal/apiclient"

var _ = apiclient.NewAuthServerClient
var _ *apiclient.APIError
`)
	writeEdgeFixture(t, dir, "aliased.go", `package handlerhelpers

import ac "github.com/leodip/goiabada/adminconsole/internal/apiclient"

var _ *ac.AuthServerClient
`)
	writeEdgeFixture(t, dir, "dotted.go", `package handlerhelpers

import . "github.com/leodip/goiabada/adminconsole/internal/apiclient"

var _ *APIError
`)
	writeEdgeFixture(t, dir, "blank.go", `package handlerhelpers

import _ "github.com/leodip/goiabada/adminconsole/internal/apiclient"
`)
	writeEdgeFixture(t, dir, "other_package.go", `package handlerhelpers

import apiclient "example.com/elsewhere/apiclient"

var _ = apiclient.NewAuthServerClient
`)
	writeEdgeFixture(t, dir, "renderer_test.go", `package handlerhelpers

import "github.com/leodip/goiabada/adminconsole/internal/apiclient"

var _ = apiclient.NewAuthServerClient
`)
	writeEdgeFixture(t, dir, "sub/page.go", `package sub

import "github.com/leodip/goiabada/adminconsole/internal/apiclient"

var _ = apiclient.NewAuthServerClient
`)

	found, files, err := findApiclientUses(dir)
	require.NoError(t, err)
	assert.Equal(t, 7, files)

	got := make([]string, 0, len(found))
	for _, use := range found {
		got = append(got, use.file+":"+strconv.Itoa(use.line)+":"+use.binding+":"+use.name)
	}
	assert.ElementsMatch(t, []string{
		"renderer.go:5:apiclient:NewAuthServerClient",
		"aliased.go:5:ac:AuthServerClient",
		"dotted.go:3:.:",
		"blank.go:3:_:",
	}, got, "the finder matched the wrong set")
}

// The reporting half fails on a forbidden name, as an Errorf naming the file, the line and the
// selector, not as a Fatalf.
func TestApiclientEdge_FailsOnANameBeyondAPIError(t *testing.T) {
	dir := t.TempDir()
	writeEdgeFixture(t, dir, "renderer.go", `package handlerhelpers

import ac "github.com/leodip/goiabada/adminconsole/internal/apiclient"

var _ = ac.NewAuthServerClient
`)

	report := guard.Run(func(r guard.Reporter) {
		assertApiclientEdge(r, dir)
	})

	require.True(t, report.Failed(), "a renderer reaching the API client passed the guard")
	assert.False(t, report.Stopped, "a finding is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "renderer.go:5: ac.NewAuthServerClient")
	assert.Contains(t, report.Text(), "#440")
}

// A dot or blank import fails too, since either hides what the file takes from apiclient.
func TestApiclientEdge_FailsOnADotOrBlankImport(t *testing.T) {
	for _, binding := range []string{".", "_"} {
		t.Run(binding, func(t *testing.T) {
			dir := t.TempDir()
			writeEdgeFixture(t, dir, "classifier.go", "package handlerhelpers\n\nimport "+binding+
				" \"github.com/leodip/goiabada/adminconsole/internal/apiclient\"\n")

			report := guard.Run(func(r guard.Reporter) {
				assertApiclientEdge(r, dir)
			})

			require.True(t, report.Failed(), "a %q import of apiclient passed the guard", binding)
			assert.False(t, report.Stopped)
			assert.Contains(t, report.Text(), "classifier.go:3: imports apiclient as "+strconv.Quote(binding))
		})
	}
}

// The other direction: APIError alone, under the default binding and an alias, and files that do
// not import apiclient at all.
func TestApiclientEdge_PassesAPIErrorAlone(t *testing.T) {
	dir := t.TempDir()
	writeEdgeFixture(t, dir, "classifier.go", `package handlerhelpers

import "github.com/leodip/goiabada/adminconsole/internal/apiclient"

var _ *apiclient.APIError
`)
	writeEdgeFixture(t, dir, "aliased.go", `package handlerhelpers

import ac "github.com/leodip/goiabada/adminconsole/internal/apiclient"

var _ *ac.APIError
`)
	writeEdgeFixture(t, dir, "names.go", "package handlerhelpers\n\nfunc fullName() string { return \"\" }\n")

	report := guard.Run(func(r guard.Reporter) {
		assertApiclientEdge(r, dir)
	})

	assert.False(t, report.Failed(), "APIError alone failed the guard: %s", report.Text())
}

// A directory holding no production Go file reads nothing, and is fatal rather than a pass.
func TestApiclientEdge_IsFatalOnAnEmptyRead(t *testing.T) {
	dir := t.TempDir()
	writeEdgeFixture(t, dir, "classifier_test.go", "package handlerhelpers\n")
	writeEdgeFixture(t, dir, "sub/page.go", "package sub\n")

	report := guard.Run(func(r guard.Reporter) {
		assertApiclientEdge(r, dir)
	})

	require.True(t, report.Stopped, "an empty read must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "read no production Go files under")
}

// A directory that is not there is fatal as a read error, told apart from an empty one.
func TestApiclientEdge_IsFatalWhenTheDirectoryIsGone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "handlerhelpers")

	report := guard.Run(func(r guard.Reporter) {
		assertApiclientEdge(r, dir)
	})

	require.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "reading ")
	assert.NotContains(t, report.Fatal, "read no production Go files")
}

// writeEdgeFixture writes one file into a fixture directory, creating its subdirectories.
func writeEdgeFixture(t *testing.T, dir, rel, src string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(src), 0o644))
}
